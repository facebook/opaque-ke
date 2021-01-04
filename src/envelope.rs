// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    errors::{InternalPakeError, PakeError, ProtocolError},
    hash::Hash,
    serialization::{serialize, tokenize},
};
use digest::Digest;
use generic_array::{
    typenum::{Unsigned, U32},
    GenericArray,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use rand_core::{CryptoRng, RngCore};
use std::convert::TryFrom;

// Constant string used as salt for HKDF computation
const STR_ENVU: &[u8] = b"EnvU";

/// The length of the "export key" output by the client registration
/// and login finish steps
pub(crate) type ExportKeySize = U32;

const NONCE_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum InnerEnvelopeMode {
    Base = 0,
    CustomIdentifier = 1,
}

impl TryFrom<u8> for InnerEnvelopeMode {
    type Error = PakeError;
    fn try_from(x: u8) -> Result<Self, Self::Error> {
        match x {
            0 => Ok(InnerEnvelopeMode::Base),
            1 => Ok(InnerEnvelopeMode::CustomIdentifier),
            _ => Err(PakeError::SerializationError),
        }
    }
}

/// This struct is an instantiation of the envelope as described in
/// https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-06#section-4
///
/// Note that earlier versions of this specification described an
/// implementation of this envelope using an encryption scheme that
/// satisfied random-key robustness
/// (https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-05#section-4).
/// The specification update has simplified this assumption by taking
/// an XOR-based approach without compromising on security, and to avoid
/// the confusion around the implementation of an RKR-secure encryption.
pub(crate) struct Envelope<D: Hash> {
    mode: InnerEnvelopeMode,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    auth_data: Vec<u8>,
    hmac: GenericArray<u8, <D as Digest>::OutputSize>,
}

pub(crate) struct OpenedEnvelope {
    pub(crate) client_s_sk: Vec<u8>,
    pub(crate) export_key: GenericArray<u8, ExportKeySize>,
}

pub(crate) struct OpenedInnerEnvelope {
    pub(crate) plaintext: Vec<u8>,
    pub(crate) export_key: GenericArray<u8, ExportKeySize>,
}

impl<D: Hash> Envelope<D> {
    /// The additional number of bytes added to the plaintext
    pub(crate) fn additional_size() -> usize {
        NONCE_LEN + <D as Digest>::OutputSize::to_usize()
    }

    fn hmac_key_size() -> usize {
        <D as Digest>::OutputSize::to_usize()
    }

    fn export_key_size() -> usize {
        ExportKeySize::to_usize()
    }

    pub(crate) fn get_mode(&self) -> InnerEnvelopeMode {
        self.mode
    }

    pub(crate) fn new(
        mode: InnerEnvelopeMode,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        auth_data: Vec<u8>,
        hmac: GenericArray<u8, <D as Digest>::OutputSize>,
    ) -> Self {
        Self {
            mode,
            nonce,
            ciphertext,
            auth_data,
            hmac,
        }
    }

    /// The format of the output is:
    /// mode | nonce             | ciphertext       | hmac
    /// u8   | nonce_size bytes  | variable length  | hmac_size bytes
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, InternalPakeError> {
        let (result, remainder) = Self::deserialize(bytes)
            .map_err(|_| InternalPakeError::InvalidEnvelopeStructureError)?;
        if !remainder.is_empty() {
            return Err(InternalPakeError::InvalidEnvelopeStructureError);
        }
        Ok(result)
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.serialize()
    }

    pub(crate) fn serialize(&self) -> Vec<u8> {
        [
            &[self.mode as u8],
            &self.nonce[..],
            &serialize(&self.ciphertext, 2)[..],
            &serialize(&self.auth_data, 2)[..],
            &serialize(&self.hmac, 2)[..],
        ]
        .concat()
    }

    pub(crate) fn deserialize(input: &[u8]) -> Result<(Self, Vec<u8>), ProtocolError> {
        if input.is_empty() {
            return Err(ProtocolError::VerificationError(
                PakeError::SerializationError,
            ));
        }
        let mode = InnerEnvelopeMode::try_from(input[0])?;

        let bytes = &input[1..];
        if bytes.len() < NONCE_LEN {
            return Err(ProtocolError::VerificationError(
                PakeError::SerializationError,
            ));
        }

        let nonce = &bytes[..NONCE_LEN];
        let (ciphertext, remainder) = tokenize(&bytes[NONCE_LEN..], 2)?;
        let (auth_data, remainder) = tokenize(&remainder, 2)?;
        let (hmac, remainder) = tokenize(&remainder, 2)?;
        Ok((
            Self::new(
                mode,
                nonce.to_vec(),
                ciphertext,
                auth_data,
                GenericArray::clone_from_slice(&hmac[..]),
            ),
            remainder,
        ))
    }

    pub(crate) fn seal<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &[u8],
        client_s_sk: &[u8],
        server_s_pk: &[u8],
        optional_ids: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<(Self, GenericArray<u8, ExportKeySize>), InternalPakeError> {
        let plaintext = serialize(&client_s_sk, 2);
        let aad = construct_aad(server_s_pk, &optional_ids);
        Self::seal_raw(rng, key, &plaintext, &aad, mode_from_ids(&optional_ids))
    }

    /// Uses a key to convert the plaintext into an envelope, authenticated by the aad field.
    /// Note that a new nonce is sampled for each call to seal.
    pub(crate) fn seal_raw<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        mode: InnerEnvelopeMode,
    ) -> Result<(Self, GenericArray<u8, ExportKeySize>), InternalPakeError> {
        let mut nonce = vec![0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let h = Hkdf::<D>::new(Some(&nonce), &key);
        let mut okm = vec![0u8; plaintext.len() + Self::hmac_key_size() + Self::export_key_size()];
        h.expand(STR_ENVU, &mut okm)
            .map_err(|_| InternalPakeError::HkdfError)?;
        let xor_key = &okm[..plaintext.len()];
        let hmac_key = &okm[plaintext.len()..plaintext.len() + Self::hmac_key_size()];
        let export_key = &okm[plaintext.len() + Self::hmac_key_size()..];

        let ciphertext: Vec<u8> = xor_key
            .iter()
            .zip(plaintext.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        let mut hmac =
            Hmac::<D>::new_varkey(&hmac_key).map_err(|_| InternalPakeError::HmacError)?;
        hmac.update(&nonce);
        hmac.update(&ciphertext);
        hmac.update(&aad);

        Ok((
            Self::new(
                mode,
                nonce,
                ciphertext.to_vec(),
                aad.to_vec(),
                hmac.finalize().into_bytes(),
            ),
            *GenericArray::from_slice(&export_key),
        ))
    }

    pub(crate) fn open(
        &self,
        key: &[u8],
        server_s_pk: &[u8],
        optional_ids: &Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<OpenedEnvelope, InternalPakeError> {
        // First, check that mode matches
        if self.mode != mode_from_ids(optional_ids) {
            return Err(InternalPakeError::IncompatibleEnvelopeModeError);
        }

        let aad = construct_aad(server_s_pk, optional_ids);
        let opened = self.open_raw(key, &aad)?;

        let (client_s_sk, remainder) = tokenize(&opened.plaintext, 2)
            .map_err(|_| InternalPakeError::UnexpectedEnvelopeContentsError)?;
        if !remainder.is_empty() {
            // Should not have anything else in plaintext
            return Err(InternalPakeError::UnexpectedEnvelopeContentsError);
        }

        Ok(OpenedEnvelope {
            client_s_sk,
            export_key: opened.export_key,
        })
    }

    /// Attempts to decrypt the envelope using a key, which is successful only if the key and
    /// aad used to construct the envelope are the same.
    pub(crate) fn open_raw(
        &self,
        key: &[u8],
        aad: &[u8],
    ) -> Result<OpenedInnerEnvelope, InternalPakeError> {
        let h = Hkdf::<D>::new(Some(&self.nonce), &key);
        let mut okm =
            vec![0u8; self.ciphertext.len() + Self::hmac_key_size() + Self::export_key_size()];
        h.expand(STR_ENVU, &mut okm)
            .map_err(|_| InternalPakeError::HkdfError)?;
        let xor_key = &okm[..self.ciphertext.len()];
        let hmac_key = &okm[self.ciphertext.len()..self.ciphertext.len() + Self::hmac_key_size()];
        let export_key = &okm[self.ciphertext.len() + Self::hmac_key_size()..];

        let mut hmac =
            Hmac::<D>::new_varkey(&hmac_key).map_err(|_| InternalPakeError::HmacError)?;
        hmac.update(&self.nonce);
        hmac.update(&self.ciphertext);
        hmac.update(aad);
        if hmac.verify(&self.hmac).is_err() {
            return Err(InternalPakeError::SealOpenHmacError);
        }

        let plaintext: Vec<u8> = xor_key
            .iter()
            .zip(self.ciphertext.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        Ok(OpenedInnerEnvelope {
            plaintext,
            export_key: *GenericArray::from_slice(&export_key),
        })
    }
}

// Helper functions

fn construct_aad(server_s_pk: &[u8], optional_ids: &Option<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    optional_ids
        .iter()
        .flat_map(|(l, r)| [serialize(server_s_pk, 2), serialize(l, 2), serialize(r, 2)].concat())
        .collect()
}

pub(crate) fn mode_from_ids(optional_ids: &Option<(Vec<u8>, Vec<u8>)>) -> InnerEnvelopeMode {
    match optional_ids {
        Some(_) => InnerEnvelopeMode::CustomIdentifier,
        None => InnerEnvelopeMode::Base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn seal_and_open() {
        let mut rng = OsRng;
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);

        let mut msg = [0u8; 100];
        rng.fill_bytes(&mut msg);

        let (envelope, export_key_1) = Envelope::<sha2::Sha256>::seal_raw(
            &mut rng,
            &key,
            &msg,
            b"aad",
            InnerEnvelopeMode::Base,
        )
        .unwrap();
        let opened_envelope = envelope.open_raw(&key, b"aad").unwrap();
        assert_eq!(&msg.to_vec(), &opened_envelope.plaintext);
        assert_eq!(&export_key_1.to_vec(), &opened_envelope.export_key.to_vec());
    }
}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    errors::{utils::check_slice_size_atleast, InternalPakeError, PakeError, ProtocolError},
    hash::Hash,
    keypair::PublicKey,
    serialization::serialize,
};
use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};
use generic_bytes::SizedBytes;
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use rand::{CryptoRng, RngCore};
use std::convert::TryFrom;
use zeroize::Zeroize;

// Constant string used as salt for HKDF computation
const STR_PAD: &[u8] = b"Pad";
const STR_AUTH_KEY: &[u8] = b"AuthKey";
const STR_EXPORT_KEY: &[u8] = b"ExportKey";

const NONCE_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Zeroize)]
#[zeroize(drop)]
pub(crate) enum InnerEnvelopeMode {
    Base = 1,
    CustomIdentifier = 2,
}

impl TryFrom<u8> for InnerEnvelopeMode {
    type Error = PakeError;
    fn try_from(x: u8) -> Result<Self, Self::Error> {
        match x {
            1 => Ok(InnerEnvelopeMode::Base),
            2 => Ok(InnerEnvelopeMode::CustomIdentifier),
            _ => Err(PakeError::SerializationError),
        }
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub(crate) struct InnerEnvelope {
    mode: InnerEnvelopeMode,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl InnerEnvelope {
    pub(crate) fn serialize(&self) -> Vec<u8> {
        [&[self.mode as u8], &self.nonce[..], &self.ciphertext[..]].concat()
    }

    pub(crate) fn deserialize(input: &[u8]) -> Result<(Self, Vec<u8>), ProtocolError> {
        if input.is_empty() {
            return Err(ProtocolError::VerificationError(
                PakeError::SerializationError,
            ));
        }
        let mode = InnerEnvelopeMode::try_from(input[0])?;

        let key_len = <PublicKey as SizedBytes>::Len::to_usize();

        let bytes = &input[1..];
        if bytes.len() < NONCE_LEN + key_len {
            return Err(ProtocolError::VerificationError(
                PakeError::SerializationError,
            ));
        }

        Ok((
            Self {
                mode,
                nonce: bytes[..NONCE_LEN].to_vec(),
                ciphertext: bytes[NONCE_LEN..NONCE_LEN + key_len].to_vec(),
            },
            bytes[NONCE_LEN + key_len..].to_vec(),
        ))
    }

    #[cfg(test)]
    pub fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        vec![
            /* Cannot easily get raw pointer of enum value, otherwise would do self.mode.as_ptr() */
            (self.nonce.as_ptr(), self.nonce.len()),
            (self.ciphertext.as_ptr(), self.ciphertext.len()),
        ]
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
#[derive(Clone)]
pub(crate) struct Envelope<D: Hash> {
    inner_envelope: InnerEnvelope,
    hmac: GenericArray<u8, <D as Digest>::OutputSize>,
}

// Note that this struct represents an envelope that has been "opened" with the asssociated
// key. This key is also used to derive the export_key parameter, which is technically
// unrelated to the envelope's encrypted and authenticated contents.
pub(crate) struct OpenedEnvelope<D: Hash> {
    pub(crate) client_s_sk: Vec<u8>,
    pub(crate) export_key: GenericArray<u8, <D as Digest>::OutputSize>,
}

pub(crate) struct OpenedInnerEnvelope<D: Hash> {
    pub(crate) plaintext: Vec<u8>,
    pub(crate) export_key: GenericArray<u8, <D as Digest>::OutputSize>,
}

impl<D: Hash> Envelope<D> {
    fn hmac_key_size() -> usize {
        <D as Digest>::OutputSize::to_usize()
    }

    fn export_key_size() -> usize {
        <D as Digest>::OutputSize::to_usize()
    }

    pub(crate) fn get_mode(&self) -> InnerEnvelopeMode {
        self.inner_envelope.mode
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
        [&self.inner_envelope.serialize(), &self.hmac[..]].concat()
    }

    pub(crate) fn deserialize(input: &[u8]) -> Result<(Self, Vec<u8>), ProtocolError> {
        let (inner_envelope, remainder) = InnerEnvelope::deserialize(input)?;

        let hmac_key_size = Self::hmac_key_size();
        let hmac_and_remainder =
            check_slice_size_atleast(&remainder, hmac_key_size, "hmac_key_size")?;

        Ok((
            Self {
                inner_envelope,
                hmac: GenericArray::clone_from_slice(&hmac_and_remainder[..hmac_key_size]),
            },
            hmac_and_remainder[hmac_key_size..].to_vec(),
        ))
    }

    pub(crate) fn seal<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &[u8],
        client_s_sk: &[u8],
        server_s_pk: &[u8],
        optional_ids: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<(Self, GenericArray<u8, <D as Digest>::OutputSize>), InternalPakeError> {
        let aad = construct_aad(server_s_pk, &optional_ids);
        Self::seal_raw(rng, key, client_s_sk, &aad, mode_from_ids(&optional_ids))
    }

    /// Uses a key to convert the plaintext into an envelope, authenticated by the aad field.
    /// Note that a new nonce is sampled for each call to seal.
    pub(crate) fn seal_raw<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        mode: InnerEnvelopeMode,
    ) -> Result<(Self, GenericArray<u8, <D as Digest>::OutputSize>), InternalPakeError> {
        let mut nonce = vec![0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let h = Hkdf::<D>::new(Some(&nonce), key);
        let mut xor_key = vec![0u8; plaintext.len()];
        let mut hmac_key = vec![0u8; Self::hmac_key_size()];
        let mut export_key = vec![0u8; Self::export_key_size()];

        h.expand(STR_PAD, &mut xor_key)
            .map_err(|_| InternalPakeError::HkdfError)?;
        h.expand(STR_AUTH_KEY, &mut hmac_key)
            .map_err(|_| InternalPakeError::HkdfError)?;
        h.expand(STR_EXPORT_KEY, &mut export_key)
            .map_err(|_| InternalPakeError::HkdfError)?;

        let ciphertext: Vec<u8> = xor_key
            .iter()
            .zip(plaintext.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        let inner_envelope = InnerEnvelope {
            mode,
            nonce,
            ciphertext,
        };

        let mut hmac =
            Hmac::<D>::new_varkey(&hmac_key).map_err(|_| InternalPakeError::HmacError)?;
        hmac.update(&inner_envelope.serialize());
        hmac.update(aad);

        let hmac_bytes = hmac.finalize().into_bytes();

        Ok((
            Self {
                inner_envelope,
                hmac: hmac_bytes,
            },
            GenericArray::clone_from_slice(&export_key),
        ))
    }

    pub(crate) fn open(
        &self,
        key: &[u8],
        server_s_pk: &[u8],
        optional_ids: &Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<OpenedEnvelope<D>, InternalPakeError> {
        // First, check that mode matches
        if self.inner_envelope.mode != mode_from_ids(optional_ids) {
            return Err(InternalPakeError::IncompatibleEnvelopeModeError);
        }

        let aad = construct_aad(server_s_pk, optional_ids);
        let opened = self.open_raw(key, &aad)?;

        if opened.plaintext.len() != <PublicKey as SizedBytes>::Len::to_usize() {
            // Plaintext should consist of a single key
            return Err(InternalPakeError::UnexpectedEnvelopeContentsError);
        }

        Ok(OpenedEnvelope {
            client_s_sk: opened.plaintext,
            export_key: opened.export_key,
        })
    }

    /// Attempts to decrypt the envelope using a key, which is successful only if the key and
    /// aad used to construct the envelope are the same.
    pub(crate) fn open_raw(
        &self,
        key: &[u8],
        aad: &[u8],
    ) -> Result<OpenedInnerEnvelope<D>, InternalPakeError> {
        let h = Hkdf::<D>::new(Some(&self.inner_envelope.nonce), key);
        let mut xor_key = vec![0u8; self.inner_envelope.ciphertext.len()];
        let mut hmac_key = vec![0u8; Self::hmac_key_size()];
        let mut export_key = vec![0u8; Self::export_key_size()];

        h.expand(STR_PAD, &mut xor_key)
            .map_err(|_| InternalPakeError::HkdfError)?;
        h.expand(STR_AUTH_KEY, &mut hmac_key)
            .map_err(|_| InternalPakeError::HkdfError)?;
        h.expand(STR_EXPORT_KEY, &mut export_key)
            .map_err(|_| InternalPakeError::HkdfError)?;

        let mut hmac =
            Hmac::<D>::new_varkey(&hmac_key).map_err(|_| InternalPakeError::HmacError)?;
        hmac.update(&self.inner_envelope.serialize());
        hmac.update(aad);
        if hmac.verify(&self.hmac).is_err() {
            return Err(InternalPakeError::SealOpenHmacError);
        }

        let plaintext: Vec<u8> = xor_key
            .iter()
            .zip(self.inner_envelope.ciphertext.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        Ok(OpenedInnerEnvelope {
            plaintext,
            export_key: GenericArray::<u8, <D as Digest>::OutputSize>::clone_from_slice(
                &export_key,
            ),
        })
    }

    #[cfg(test)]
    pub fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        [
            self.inner_envelope.as_byte_ptrs(),
            vec![(self.hmac.as_ptr(), self.hmac.len())],
        ]
        .concat()
    }
}

// This can't be derived because of the use of a phantom parameter
impl<D: Hash> Zeroize for Envelope<D> {
    fn zeroize(&mut self) {
        self.inner_envelope.zeroize();
        self.hmac.zeroize();
    }
}

impl<D: Hash> Drop for Envelope<D> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Helper functions

fn construct_aad(server_s_pk: &[u8], optional_ids: &Option<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    let ids = optional_ids
        .iter()
        .flat_map(|(l, r)| [serialize(l, 2), serialize(r, 2)].concat())
        .collect();
    [server_s_pk.to_vec(), ids].concat()
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
    use rand::rngs::OsRng;

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

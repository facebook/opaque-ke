// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    errors::{InternalPakeError, ProtocolError},
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

// Constant string used as salt for HKDF computation
const STR_ENVU: &[u8] = b"EnvU";

/// The length of the "export key" output by the client registration
/// and login finish steps
pub(crate) type ExportKeySize = U32;

const NONCE_LEN: usize = 32;

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
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    hmac: GenericArray<u8, <D as Digest>::OutputSize>,
}

pub(crate) struct OpenedEnvelope {
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

    fn hmac_size() -> usize {
        <D as Digest>::OutputSize::to_usize()
    }

    fn export_key_size() -> usize {
        ExportKeySize::to_usize()
    }

    pub(crate) fn new(
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        hmac: GenericArray<u8, <D as Digest>::OutputSize>,
    ) -> Self {
        Self {
            nonce,
            ciphertext,
            hmac,
        }
    }

    /// The format of the output is:
    /// nonce             | ciphertext       | hmac
    /// nonce_size bytes  | variable length  | hmac_size bytes
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, InternalPakeError> {
        let ciphertext_start = NONCE_LEN;
        let ciphertext_end = bytes.len() - Self::hmac_size();

        Ok(Self::new(
            bytes[..ciphertext_start].to_vec(),
            bytes[ciphertext_start..ciphertext_end].to_vec(),
            GenericArray::clone_from_slice(&bytes[ciphertext_end..]),
        ))
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        [&self.nonce[..], &self.ciphertext[..], &self.hmac[..]].concat()
    }

    pub(crate) fn serialize(&self) -> Vec<u8> {
        [
            &self.nonce[..],
            &serialize((&self.ciphertext).to_vec(), 2)[..],
            &serialize(vec![], 2)[..],
            &serialize((&self.hmac).to_vec(), 2)[..],
        ]
        .concat()
    }

    pub(crate) fn deserialize(input: &[u8]) -> Result<(Self, Vec<u8>), ProtocolError> {
        let nonce = &input[..NONCE_LEN];
        let (ciphertext, remainder) = tokenize(input[NONCE_LEN..].to_vec(), 2)?;
        let (_, remainder) = tokenize(remainder, 2)?;
        let (hmac, remainder) = tokenize(remainder, 2)?;
        Ok((
            Self::new(
                nonce.to_vec(),
                ciphertext,
                GenericArray::clone_from_slice(&hmac[..]),
            ),
            remainder,
        ))
    }

    /// Uses a key to convert the plaintext into an envelope, authenticated by the aad field.
    /// Note that a new nonce is sampled for each call to seal.
    pub(crate) fn seal<R: RngCore + CryptoRng>(
        key: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        rng: &mut R,
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
            Self::new(nonce, ciphertext.to_vec(), hmac.finalize().into_bytes()),
            *GenericArray::from_slice(&export_key),
        ))
    }

    /// Attempts to decrypt the envelope using a key, which is successful only if the key and
    /// aad used to construct the envelope are the same.
    pub(crate) fn open(&self, key: &[u8], aad: &[u8]) -> Result<OpenedEnvelope, InternalPakeError> {
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
        Ok(OpenedEnvelope {
            plaintext,
            export_key: *GenericArray::from_slice(&export_key),
        })
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

        let (envelope, export_key_1) =
            Envelope::<sha2::Sha256>::seal(&key, &msg, b"aad", &mut rng).unwrap();
        let opened_envelope = envelope.open(&key, b"aad").unwrap();
        assert_eq!(&msg.to_vec(), &opened_envelope.plaintext);
        assert_eq!(&export_key_1.to_vec(), &opened_envelope.export_key.to_vec());
    }
}

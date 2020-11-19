// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    errors::{InternalPakeError, PakeError, ProtocolError},
    hash::Hash,
    serialization::{serialize, tokenize, u8_to_credential_type, CredentialType},
};
use digest::Digest;
use generic_array::{
    typenum::{Unsigned, U32},
    GenericArray,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use rand_core::{CryptoRng, RngCore};
use std::collections::HashMap;

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
    auth_data: Vec<u8>,
    hmac: GenericArray<u8, <D as Digest>::OutputSize>,
}

pub(crate) struct OpenedEnvelopeECF {
    pub(crate) credentials_map: HashMap<CredentialType, Vec<u8>>,
    pub(crate) export_key: GenericArray<u8, ExportKeySize>,
}

pub(crate) struct OpenedEnvelope {
    pub(crate) plaintext: Vec<u8>,
    pub(crate) export_key: GenericArray<u8, ExportKeySize>,
}

/// Representation for the format of the envelope
pub struct EnvelopeCredentialsFormat {
    pub(crate) secret_credentials: Vec<CredentialType>,
    pub(crate) cleartext_credentials: Vec<CredentialType>,
}

impl EnvelopeCredentialsFormat {
    /// Creates a new envelope credentials format with validity checking
    /// An ECF is valid if:
    /// - skU is a secret credential
    /// - pkS is either a secret or cleartext credential
    pub fn new(
        secret_credentials: Vec<CredentialType>,
        cleartext_credentials: Vec<CredentialType>,
    ) -> Result<Self, ProtocolError> {
        if !secret_credentials.iter().any(|&v| v == CredentialType::SkU) {
            // No skU found in secret credentials
            return Err(ProtocolError::ServerInvalidEnvelopeCredentialsFormatError);
        }
        if !secret_credentials.iter().any(|&v| v == CredentialType::PkS)
            && !cleartext_credentials
                .iter()
                .any(|&v| v == CredentialType::PkS)
        {
            // No pkS found in either secret credentials or cleartext_credentials
            return Err(ProtocolError::ServerInvalidEnvelopeCredentialsFormatError);
        }
        Ok(Self {
            secret_credentials,
            cleartext_credentials,
        })
    }

    /// Uses the default setting for the envelope credentials format
    pub fn default() -> Result<Self, ProtocolError> {
        Self::new(vec![CredentialType::SkU], vec![CredentialType::PkS])
    }
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

    pub(crate) fn new(
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        auth_data: Vec<u8>,
        hmac: GenericArray<u8, <D as Digest>::OutputSize>,
    ) -> Self {
        Self {
            nonce,
            ciphertext,
            auth_data,
            hmac,
        }
    }

    /// The format of the output is:
    /// nonce             | ciphertext       | hmac
    /// nonce_size bytes  | variable length  | hmac_size bytes
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, InternalPakeError> {
        let (result, remainder) = Self::deserialize(bytes)
            .map_err(|_| InternalPakeError::IncompatibleEnvelopeCredentialsError)?;
        if !remainder.is_empty() {
            return Err(InternalPakeError::IncompatibleEnvelopeCredentialsError);
        }
        Ok(result)
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.serialize()
    }

    pub(crate) fn serialize(&self) -> Vec<u8> {
        [
            &self.nonce[..],
            &serialize(&self.ciphertext, 2)[..],
            &serialize(&self.auth_data, 2)[..],
            &serialize(&self.hmac, 2)[..],
        ]
        .concat()
    }

    pub(crate) fn deserialize(input: &[u8]) -> Result<(Self, Vec<u8>), ProtocolError> {
        if input.len() < NONCE_LEN {
            return Err(ProtocolError::VerificationError(
                PakeError::SerializationError,
            ));
        }

        let nonce = &input[..NONCE_LEN];
        let (ciphertext, remainder) = tokenize(&input[NONCE_LEN..], 2)?;
        let (auth_data, remainder) = tokenize(&remainder, 2)?;
        let (hmac, remainder) = tokenize(&remainder, 2)?;
        Ok((
            Self::new(
                nonce.to_vec(),
                ciphertext,
                auth_data,
                GenericArray::clone_from_slice(&hmac[..]),
            ),
            remainder,
        ))
    }

    fn serialize_extensions(
        cred_format: Vec<CredentialType>,
        credentials: &HashMap<CredentialType, Vec<u8>>,
    ) -> Result<Vec<u8>, InternalPakeError> {
        let mut ret = Vec::new();
        for index_type in cred_format {
            match &credentials.get(&index_type) {
                Some(v) => {
                    ret.push(index_type as u8 + 1);
                    ret.extend(serialize(&v, 2));
                }
                None => return Err(InternalPakeError::IncompatibleEnvelopeCredentialsError),
            }
        }
        Ok(ret)
    }

    fn deserialize_extensions(
        bytes: &[u8],
    ) -> Result<HashMap<CredentialType, Vec<u8>>, InternalPakeError> {
        let mut credentials: HashMap<CredentialType, Vec<u8>> = HashMap::new();
        let mut bytes_copy: Vec<u8> = Vec::new();
        bytes_copy.extend_from_slice(&bytes);
        while !bytes_copy.is_empty() {
            let t = u8_to_credential_type(bytes_copy[0])
                .ok_or(InternalPakeError::IncompatibleEnvelopeCredentialsError)?;
            let (cred, remainder) = tokenize(&bytes_copy[1..], 2)
                .map_err(|_| InternalPakeError::IncompatibleEnvelopeCredentialsError)?;
            bytes_copy = remainder;
            credentials.insert(t, cred);
        }
        Ok(credentials)
    }

    pub(crate) fn seal<R: RngCore + CryptoRng>(
        key: &[u8],
        ecf: EnvelopeCredentialsFormat,
        credentials: HashMap<CredentialType, Vec<u8>>,
        rng: &mut R,
    ) -> Result<(Self, GenericArray<u8, ExportKeySize>), InternalPakeError> {
        let plaintext = Self::serialize_extensions(ecf.secret_credentials, &credentials)?;
        let aad = Self::serialize_extensions(ecf.cleartext_credentials, &credentials)?;
        Self::seal_raw(key, &plaintext, &aad, rng)
    }

    /// Uses a key to convert the plaintext into an envelope, authenticated by the aad field.
    /// Note that a new nonce is sampled for each call to seal.
    pub(crate) fn seal_raw<R: RngCore + CryptoRng>(
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
            Self::new(
                nonce,
                ciphertext.to_vec(),
                aad.to_vec(),
                hmac.finalize().into_bytes(),
            ),
            *GenericArray::from_slice(&export_key),
        ))
    }

    pub(crate) fn open(&self, key: &[u8]) -> Result<OpenedEnvelopeECF, InternalPakeError> {
        let mut credentials_map = Self::deserialize_extensions(&self.auth_data)?;
        let opened = self.open_raw(key, &self.auth_data)?;
        let plaintext_map = Self::deserialize_extensions(&opened.plaintext)?;

        for (i, plaintext) in plaintext_map {
            if credentials_map.contains_key(&i) {
                // Trying to set a credential that was already provided in the aad
                return Err(InternalPakeError::IncompatibleEnvelopeCredentialsError);
            }
            credentials_map.insert(i, plaintext);
        }

        Ok(OpenedEnvelopeECF {
            credentials_map,
            export_key: opened.export_key,
        })
    }

    /// Attempts to decrypt the envelope using a key, which is successful only if the key and
    /// aad used to construct the envelope are the same.
    pub(crate) fn open_raw(
        &self,
        key: &[u8],
        aad: &[u8],
    ) -> Result<OpenedEnvelope, InternalPakeError> {
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
            Envelope::<sha2::Sha256>::seal_raw(&key, &msg, b"aad", &mut rng).unwrap();
        let opened_envelope = envelope.open_raw(&key, b"aad").unwrap();
        assert_eq!(&msg.to_vec(), &opened_envelope.plaintext);
        assert_eq!(&export_key_1.to_vec(), &opened_envelope.export_key.to_vec());
    }
}

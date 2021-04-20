// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    errors::{utils::check_slice_size, InternalPakeError, PakeError, ProtocolError},
    group::Group,
    hash::Hash,
    keypair::{Key, KeyPair},
    map_to_curve::GroupWithMapToCurve,
    opaque::{bytestrings_from_identifiers, Identifiers},
};
use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};
use generic_bytes::SizedBytes;
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use rand::{CryptoRng, RngCore};
use std::convert::TryFrom;

// Constant string used as salt for HKDF computation
const STR_PAD: &[u8] = b"Pad";
const STR_AUTH_KEY: &[u8] = b"AuthKey";
const STR_EXPORT_KEY: &[u8] = b"ExportKey";
const STR_PRIVATE_KEY: &[u8] = b"PrivateKey";
const STR_OPAQUE_HASH_TO_SCALAR: &[u8] = b"OPAQUE-HashToScalar";

const NONCE_LEN: usize = 32;

fn build_inner_envelope_internal<CS: CipherSuite>(
    random_pwd: &[u8],
    nonce: &[u8],
) -> Result<Key, InternalPakeError> {
    let h = Hkdf::<CS::Hash>::new(None, &random_pwd);
    let mut keypair_seed = vec![0u8; <Key as SizedBytes>::Len::to_usize()];
    h.expand(&[&nonce, STR_PRIVATE_KEY].concat(), &mut keypair_seed)
        .map_err(|_| InternalPakeError::HkdfError)?;
    let client_static_keypair =
        KeyPair::<CS::Group>::from_private_key_slice(CS::Group::scalar_as_bytes(
            &CS::Group::hash_to_scalar::<CS::Hash>(&keypair_seed[..], STR_OPAQUE_HASH_TO_SCALAR)?,
        ))?;

    Ok(client_static_keypair.public().clone())
}

fn recover_keys_internal<CS: CipherSuite>(
    random_pwd: &[u8],
    nonce: &[u8],
) -> Result<KeyPair<CS::Group>, InternalPakeError> {
    let h = Hkdf::<CS::Hash>::new(None, &random_pwd);
    let mut keypair_seed = vec![0u8; <Key as SizedBytes>::Len::to_usize()];
    h.expand(&[&nonce, STR_PRIVATE_KEY].concat(), &mut keypair_seed)
        .map_err(|_| InternalPakeError::HkdfError)?;
    let client_static_keypair =
        KeyPair::<CS::Group>::from_private_key_slice(CS::Group::scalar_as_bytes(
            &CS::Group::hash_to_scalar::<CS::Hash>(&keypair_seed[..], STR_OPAQUE_HASH_TO_SCALAR)?,
        ))?;

    Ok(client_static_keypair)
}

fn build_inner_envelope_external<CS: CipherSuite>(
    random_pwd: &[u8],
    nonce: &[u8],
    client_s_sk: Key,
) -> Result<(Vec<u8>, Key), InternalPakeError> {
    let mut xor_key = vec![0u8; client_s_sk.len()];

    let h = Hkdf::<CS::Hash>::new(None, &random_pwd);
    h.expand(&[&nonce, STR_PAD].concat(), &mut xor_key)
        .map_err(|_| InternalPakeError::HkdfError)?;

    let ciphertext: Vec<u8> = xor_key
        .iter()
        .zip(client_s_sk.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();

    let client_s_pk = KeyPair::<CS::Group>::public_from_private(&client_s_sk);

    Ok((ciphertext, client_s_pk))
}

fn recover_keys_external<CS: CipherSuite>(
    random_pwd: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<KeyPair<CS::Group>, InternalPakeError> {
    let mut xor_key = vec![0u8; ciphertext.len()];

    let h = Hkdf::<CS::Hash>::new(None, &random_pwd);
    h.expand(&[&nonce, STR_PAD].concat(), &mut xor_key)
        .map_err(|_| InternalPakeError::HkdfError)?;

    let client_s_sk: Vec<u8> = xor_key
        .iter()
        .zip(ciphertext.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();

    KeyPair::<CS::Group>::from_private_key_slice(&client_s_sk)
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum InnerEnvelopeMode {
    Unused = 0,
    Internal = 1,
    External = 2,
}

impl TryFrom<u8> for InnerEnvelopeMode {
    type Error = PakeError;
    fn try_from(x: u8) -> Result<Self, Self::Error> {
        match x {
            1 => Ok(InnerEnvelopeMode::Internal),
            2 => Ok(InnerEnvelopeMode::External),
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
pub(crate) struct Envelope<CS: CipherSuite> {
    mode: InnerEnvelopeMode,
    nonce: Vec<u8>,
    inner_envelope: Vec<u8>,
    hmac: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
}

// Note that this struct represents an envelope that has been "opened" with the asssociated
// key. This key is also used to derive the export_key parameter, which is technically
// unrelated to the envelope's encrypted and authenticated contents.
pub(crate) struct OpenedEnvelope<CS: CipherSuite> {
    pub(crate) client_static_keypair: KeyPair<CS::Group>,
    pub(crate) export_key: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
}

pub(crate) struct OpenedInnerEnvelope<D: Hash> {
    pub(crate) export_key: GenericArray<u8, <D as Digest>::OutputSize>,
}

impl<CS: CipherSuite> Envelope<CS> {
    fn hmac_key_size() -> usize {
        <CS::Hash as Digest>::OutputSize::to_usize()
    }

    fn export_key_size() -> usize {
        <CS::Hash as Digest>::OutputSize::to_usize()
    }

    pub(crate) fn len() -> usize {
        1 + <CS::Hash as Digest>::OutputSize::to_usize() + NONCE_LEN
    }

    pub(crate) fn serialize(&self) -> Vec<u8> {
        // FIXME: hmac comes in between inner_env and hmac!
        [
            &[self.mode as u8],
            &self.nonce[..],
            &self.hmac[..],
            &self.inner_envelope[..],
        ]
        .concat()
    }

    pub(crate) fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
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
        let nonce = bytes[..NONCE_LEN].to_vec();

        let (inner_envelope, remainder) = match mode {
            InnerEnvelopeMode::Unused => {
                return Err(InternalPakeError::IncompatibleEnvelopeModeError.into())
            }
            InnerEnvelopeMode::Internal => (vec![], bytes[NONCE_LEN..].to_vec()),
            InnerEnvelopeMode::External => {
                let key_len = <Key as SizedBytes>::Len::to_usize();
                if bytes.len() < NONCE_LEN + key_len {
                    return Err(ProtocolError::InvalidInnerEnvelopeError);
                }
                (
                    bytes[NONCE_LEN..NONCE_LEN + key_len].to_vec(),
                    bytes[NONCE_LEN + key_len..].to_vec(),
                )
            }
        };

        let hmac_key_size = Self::hmac_key_size();
        let hmac = check_slice_size(&remainder, hmac_key_size, "hmac_key_size")?;

        Ok(Self {
            mode,
            nonce,
            inner_envelope,
            hmac: GenericArray::clone_from_slice(&hmac),
        })
    }

    // Creates a dummy envelope object that serializes to the all-zeros byte string
    pub(crate) fn dummy() -> Self {
        Self {
            mode: InnerEnvelopeMode::Unused,
            nonce: vec![0u8; NONCE_LEN],
            inner_envelope: vec![0u8; <Key as SizedBytes>::Len::to_usize()], // FIXME should be dependent on mode
            hmac: GenericArray::clone_from_slice(&vec![
                0u8;
                <CS::Hash as Digest>::OutputSize::to_usize()
            ]),
        }
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn seal<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &[u8],
        server_s_pk: &[u8],
        optional_client_s_sk: Option<Key>,
        optional_ids: Option<Identifiers>,
    ) -> Result<
        (
            Self,
            Key,
            GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
        ),
        InternalPakeError,
    > {
        let mut nonce = vec![0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let (mode, (ciphertext, client_s_pk)) = match optional_client_s_sk {
            None => (
                InnerEnvelopeMode::Internal,
                (vec![], build_inner_envelope_internal::<CS>(&key, &nonce)?),
            ),
            Some(client_s_sk) => (
                InnerEnvelopeMode::External,
                build_inner_envelope_external::<CS>(&key, &nonce, client_s_sk)?,
            ),
        };

        let aad = construct_aad(&client_s_pk, server_s_pk, &optional_ids);

        println!("seal ciphertext: {}", hex::encode(&ciphertext));

        let (envelope, export_key) = Self::seal_raw(key, &nonce, &ciphertext, &aad, mode)?;

        Ok((envelope, client_s_pk, export_key))
    }

    /// Uses a key to convert the plaintext into an envelope, authenticated by the aad field.
    /// Note that a new nonce is sampled for each call to seal.
    #[allow(clippy::type_complexity)]
    pub(crate) fn seal_raw(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        mode: InnerEnvelopeMode,
    ) -> Result<(Self, GenericArray<u8, <CS::Hash as Digest>::OutputSize>), InternalPakeError> {
        let h = Hkdf::<CS::Hash>::new(None, &key);
        let mut hmac_key = vec![0u8; Self::hmac_key_size()];
        let mut export_key = vec![0u8; Self::export_key_size()];

        h.expand(&[&nonce, STR_AUTH_KEY].concat(), &mut hmac_key)
            .map_err(|_| InternalPakeError::HkdfError)?;
        h.expand(&[&nonce, STR_EXPORT_KEY].concat(), &mut export_key)
            .map_err(|_| InternalPakeError::HkdfError)?;

        let mut hmac =
            Hmac::<CS::Hash>::new_varkey(&hmac_key).map_err(|_| InternalPakeError::HmacError)?;
        hmac.update(&[mode as u8]);
        hmac.update(&nonce);
        hmac.update(&ciphertext);
        hmac.update(&aad);

        let hmac_bytes = hmac.finalize().into_bytes();

        Ok((
            Self {
                mode,
                nonce: nonce.to_vec(),
                inner_envelope: ciphertext.to_vec(),
                hmac: hmac_bytes,
            },
            GenericArray::clone_from_slice(&export_key),
        ))
    }

    pub(crate) fn open(
        &self,
        key: &[u8],
        server_s_pk: &[u8],
        optional_ids: &Option<Identifiers>,
    ) -> Result<OpenedEnvelope<CS>, InternalPakeError> {
        // FIXME return errors if ciphertext doesn't exist, for instance
        let client_static_keypair = match self.mode {
            InnerEnvelopeMode::Unused => {
                return Err(InternalPakeError::IncompatibleEnvelopeModeError)
            }
            InnerEnvelopeMode::Internal => recover_keys_internal::<CS>(&key, &self.nonce)?,
            InnerEnvelopeMode::External => {
                recover_keys_external::<CS>(&key, &self.nonce, &self.inner_envelope)?
            }
        };

        let aad = construct_aad(
            &client_static_keypair.public().to_arr().to_vec(),
            server_s_pk,
            optional_ids,
        );
        let opened = self.open_raw(key, &aad)?;

        Ok(OpenedEnvelope {
            client_static_keypair,
            export_key: opened.export_key,
        })
    }

    /// Attempts to decrypt the envelope using a key, which is successful only if the key and
    /// aad used to construct the envelope are the same.
    pub(crate) fn open_raw(
        &self,
        key: &[u8],
        aad: &[u8],
    ) -> Result<OpenedInnerEnvelope<CS::Hash>, InternalPakeError> {
        let h = Hkdf::<CS::Hash>::new(None, &key);
        let mut hmac_key = vec![0u8; Self::hmac_key_size()];
        let mut export_key = vec![0u8; Self::export_key_size()];

        h.expand(&[&self.nonce, STR_AUTH_KEY].concat(), &mut hmac_key)
            .map_err(|_| InternalPakeError::HkdfError)?;
        h.expand(&[&self.nonce, STR_EXPORT_KEY].concat(), &mut export_key)
            .map_err(|_| InternalPakeError::HkdfError)?;

        let mut hmac =
            Hmac::<CS::Hash>::new_varkey(&hmac_key).map_err(|_| InternalPakeError::HmacError)?;
        hmac.update(&[self.mode as u8]);
        hmac.update(&self.nonce);
        hmac.update(&self.inner_envelope);
        hmac.update(aad);
        if hmac.verify(&self.hmac).is_err() {
            return Err(InternalPakeError::SealOpenHmacError);
        }

        Ok(OpenedInnerEnvelope {
            export_key: GenericArray::<u8, <CS::Hash as Digest>::OutputSize>::clone_from_slice(
                &export_key,
            ),
        })
    }
}

// Helper functions

fn construct_aad(
    client_s_pk: &[u8],
    server_s_pk: &[u8],
    optional_ids: &Option<Identifiers>,
) -> Vec<u8> {
    let (id_u, id_s) = bytestrings_from_identifiers(optional_ids, client_s_pk, server_s_pk);
    [server_s_pk.to_vec(), id_u, id_s].concat()
}

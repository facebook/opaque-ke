// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    errors::{utils::check_slice_size, InternalError, ProtocolError},
    group::Group,
    hash::Hash,
    keypair::{KeyPair, PublicKey},
    opaque::{bytestrings_from_identifiers, Identifiers},
};
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

// Constant string used as salt for HKDF computation
const STR_AUTH_KEY: &[u8] = b"AuthKey";
const STR_EXPORT_KEY: &[u8] = b"ExportKey";
const STR_PRIVATE_KEY: &[u8] = b"PrivateKey";
const STR_OPAQUE_DERIVE_AUTH_KEY_PAIR: &[u8] = b"OPAQUE-DeriveAuthKeyPair";
const NONCE_LEN: usize = 32;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Zeroize)]
#[zeroize(drop)]
pub(crate) enum InnerEnvelopeMode {
    Zero = 0,
    Internal = 1,
}

impl TryFrom<u8> for InnerEnvelopeMode {
    type Error = ProtocolError;
    fn try_from(x: u8) -> Result<Self, Self::Error> {
        match x {
            1 => Ok(InnerEnvelopeMode::Internal),
            _ => Err(ProtocolError::SerializationError),
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
    hmac: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
}

// Cannot be derived because it would require for CS to be Clone.
impl<CS: CipherSuite> Clone for Envelope<CS> {
    fn clone(&self) -> Self {
        Self {
            mode: self.mode.clone(),
            nonce: self.nonce.clone(),
            hmac: self.hmac.clone(),
        }
    }
}

impl_debug_eq_hash_for!(struct Envelope<CS: CipherSuite>, [mode, nonce, hmac]);

// Note that this struct represents an envelope that has been "opened" with the asssociated
// key. This key is also used to derive the export_key parameter, which is technically
// unrelated to the envelope's encrypted and authenticated contents.
pub(crate) struct OpenedEnvelope<CS: CipherSuite> {
    pub(crate) client_static_keypair: KeyPair<CS::KeGroup>,
    pub(crate) export_key: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
    pub(crate) id_u: Vec<u8>,
    pub(crate) id_s: Vec<u8>,
}

pub(crate) struct OpenedInnerEnvelope<D: Hash> {
    pub(crate) export_key: GenericArray<u8, <D as Digest>::OutputSize>,
}

#[cfg(not(test))]
type SealRawResult<CS> = (
    Envelope<CS>,
    GenericArray<u8, <<CS as CipherSuite>::Hash as Digest>::OutputSize>,
);
#[cfg(test)]
type SealRawResult<CS> = (
    Envelope<CS>,
    GenericArray<u8, <<CS as CipherSuite>::Hash as Digest>::OutputSize>,
    Vec<u8>,
);
#[cfg(not(test))]
type SealResult<CS> = (
    Envelope<CS>,
    PublicKey<<CS as CipherSuite>::KeGroup>,
    GenericArray<u8, <<CS as CipherSuite>::Hash as Digest>::OutputSize>,
);
#[cfg(test)]
type SealResult<CS> = (
    Envelope<CS>,
    PublicKey<<CS as CipherSuite>::KeGroup>,
    GenericArray<u8, <<CS as CipherSuite>::Hash as Digest>::OutputSize>,
    Vec<u8>,
);

impl<CS: CipherSuite> Envelope<CS> {
    #[allow(clippy::type_complexity)]
    pub(crate) fn seal<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &[u8],
        server_s_pk: &[u8],
        optional_ids: Option<Identifiers>,
    ) -> Result<SealResult<CS>, ProtocolError> {
        let mut nonce = vec![0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let (mode, client_s_pk) = (
            InnerEnvelopeMode::Internal,
            build_inner_envelope_internal::<CS>(key, &nonce)?,
        );

        let (id_u, id_s) =
            bytestrings_from_identifiers(&optional_ids, &client_s_pk.to_arr(), server_s_pk)?;
        let aad = construct_aad(&id_u, &id_s, server_s_pk);

        let result = Self::seal_raw(key, &nonce, &aad, mode)?;
        Ok((
            result.0,
            client_s_pk,
            result.1,
            #[cfg(test)]
            result.2,
        ))
    }

    /// Uses a key to convert the plaintext into an envelope, authenticated by the aad field.
    /// Note that a new nonce is sampled for each call to seal.
    #[allow(clippy::type_complexity)]
    pub(crate) fn seal_raw(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        mode: InnerEnvelopeMode,
    ) -> Result<SealRawResult<CS>, InternalError> {
        let h = Hkdf::<CS::Hash>::new(None, key);
        let mut hmac_key = vec![0u8; Self::hmac_key_size()];
        let mut export_key = vec![0u8; Self::export_key_size()];

        h.expand(&[nonce, STR_AUTH_KEY].concat(), &mut hmac_key)
            .map_err(|_| InternalError::HkdfError)?;
        h.expand(&[nonce, STR_EXPORT_KEY].concat(), &mut export_key)
            .map_err(|_| InternalError::HkdfError)?;

        let mut hmac =
            Hmac::<CS::Hash>::new_from_slice(&hmac_key).map_err(|_| InternalError::HmacError)?;
        hmac.update(nonce);
        hmac.update(aad);

        let hmac_bytes = hmac.finalize().into_bytes();

        Ok((
            Self {
                mode,
                nonce: nonce.to_vec(),
                hmac: hmac_bytes,
            },
            GenericArray::clone_from_slice(&export_key),
            #[cfg(test)]
            hmac_key,
        ))
    }

    pub(crate) fn open(
        &self,
        key: &[u8],
        server_s_pk: &[u8],
        optional_ids: &Option<Identifiers>,
    ) -> Result<OpenedEnvelope<CS>, ProtocolError> {
        let client_static_keypair = match self.mode {
            InnerEnvelopeMode::Zero => {
                return Err(InternalError::IncompatibleEnvelopeModeError.into())
            }
            InnerEnvelopeMode::Internal => recover_keys_internal::<CS>(key, &self.nonce)?,
        };

        let (id_u, id_s) = bytestrings_from_identifiers(
            optional_ids,
            &client_static_keypair.public().to_arr(),
            server_s_pk,
        )?;
        let aad = construct_aad(&id_u, &id_s, server_s_pk);

        let opened = self.open_raw(key, &aad)?;

        Ok(OpenedEnvelope {
            client_static_keypair,
            export_key: opened.export_key,
            id_u,
            id_s,
        })
    }

    /// Attempts to decrypt the envelope using a key, which is successful only if the key and
    /// aad used to construct the envelope are the same.
    pub(crate) fn open_raw(
        &self,
        key: &[u8],
        aad: &[u8],
    ) -> Result<OpenedInnerEnvelope<CS::Hash>, InternalError> {
        let h = Hkdf::<CS::Hash>::new(None, key);
        let mut hmac_key = vec![0u8; Self::hmac_key_size()];
        let mut export_key = vec![0u8; Self::export_key_size()];

        h.expand(&[&self.nonce, STR_AUTH_KEY].concat(), &mut hmac_key)
            .map_err(|_| InternalError::HkdfError)?;
        h.expand(&[&self.nonce, STR_EXPORT_KEY].concat(), &mut export_key)
            .map_err(|_| InternalError::HkdfError)?;

        let mut hmac =
            Hmac::<CS::Hash>::new_from_slice(&hmac_key).map_err(|_| InternalError::HmacError)?;
        hmac.update(&self.nonce);
        hmac.update(aad);
        if hmac.verify(&self.hmac).is_err() {
            return Err(InternalError::SealOpenHmacError);
        }

        Ok(OpenedInnerEnvelope {
            export_key: GenericArray::<u8, <CS::Hash as Digest>::OutputSize>::clone_from_slice(
                &export_key,
            ),
        })
    }

    // Creates a dummy envelope object that serializes to the all-zeros byte string
    pub(crate) fn dummy() -> Self {
        Self {
            mode: InnerEnvelopeMode::Zero,
            nonce: vec![0u8; NONCE_LEN],
            hmac: GenericArray::clone_from_slice(&vec![
                0u8;
                <CS::Hash as Digest>::OutputSize::USIZE
            ]),
        }
    }

    fn hmac_key_size() -> usize {
        <CS::Hash as Digest>::OutputSize::USIZE
    }

    fn export_key_size() -> usize {
        <CS::Hash as Digest>::OutputSize::USIZE
    }

    pub(crate) fn len() -> usize {
        <CS::Hash as Digest>::OutputSize::USIZE + NONCE_LEN
    }

    pub(crate) fn serialize(&self) -> Vec<u8> {
        [&self.nonce[..], &self.hmac[..]].concat()
    }
    pub(crate) fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mode = InnerEnvelopeMode::Internal; // Better way to hard-code this?

        if bytes.len() < NONCE_LEN {
            return Err(ProtocolError::SerializationError);
        }
        let nonce = bytes[..NONCE_LEN].to_vec();

        let remainder = match mode {
            InnerEnvelopeMode::Zero => {
                return Err(InternalError::IncompatibleEnvelopeModeError.into())
            }
            InnerEnvelopeMode::Internal => bytes[NONCE_LEN..].to_vec(),
        };

        let hmac_key_size = Self::hmac_key_size();
        let hmac = check_slice_size(&remainder, hmac_key_size, "hmac_key_size")?;

        Ok(Self {
            mode,
            nonce,
            hmac: GenericArray::clone_from_slice(hmac),
        })
    }

    #[cfg(test)]
    pub fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        vec![(self.hmac.as_ptr(), self.hmac.len())]
    }
}

// This can't be derived because of the use of a phantom parameter
impl<CS: CipherSuite> Zeroize for Envelope<CS> {
    fn zeroize(&mut self) {
        self.mode.zeroize();
        self.nonce.zeroize();
        self.hmac.zeroize();
    }
}

impl<CS: CipherSuite> Drop for Envelope<CS> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Helper functions

fn build_inner_envelope_internal<CS: CipherSuite>(
    random_pwd: &[u8],
    nonce: &[u8],
) -> Result<PublicKey<CS::KeGroup>, ProtocolError> {
    let h = Hkdf::<CS::Hash>::new(None, random_pwd);
    let mut keypair_seed = vec![0u8; <CS::KeGroup as Group>::ScalarLen::USIZE];
    h.expand(&[nonce, STR_PRIVATE_KEY].concat(), &mut keypair_seed)
        .map_err(|_| InternalError::HkdfError)?;
    let client_static_keypair = KeyPair::<CS::KeGroup>::from_private_key_slice(
        &CS::OprfGroup::scalar_as_bytes(CS::OprfGroup::hash_to_scalar::<CS::Hash>(
            &keypair_seed[..],
            STR_OPAQUE_DERIVE_AUTH_KEY_PAIR,
        )?),
    )?;

    Ok(client_static_keypair.public().clone())
}

fn recover_keys_internal<CS: CipherSuite>(
    random_pwd: &[u8],
    nonce: &[u8],
) -> Result<KeyPair<CS::KeGroup>, ProtocolError> {
    let h = Hkdf::<CS::Hash>::new(None, random_pwd);
    let mut keypair_seed = vec![0u8; <CS::KeGroup as Group>::ScalarLen::USIZE];
    h.expand(&[nonce, STR_PRIVATE_KEY].concat(), &mut keypair_seed)
        .map_err(|_| InternalError::HkdfError)?;
    let client_static_keypair = KeyPair::<CS::KeGroup>::from_private_key_slice(
        &CS::OprfGroup::scalar_as_bytes(CS::OprfGroup::hash_to_scalar::<CS::Hash>(
            &keypair_seed[..],
            STR_OPAQUE_DERIVE_AUTH_KEY_PAIR,
        )?),
    )?;

    Ok(client_static_keypair)
}

fn construct_aad(id_u: &[u8], id_s: &[u8], server_s_pk: &[u8]) -> Vec<u8> {
    [server_s_pk, id_s, id_u].concat()
}

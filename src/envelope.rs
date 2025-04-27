// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use core::convert::TryFrom;
use core::ops::Add;

use derive_where::derive_where;
use digest::Output;
use generic_array::sequence::Concat;
use generic_array::typenum::{Sum, U32};
use generic_array::{ArrayLength, GenericArray};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{CipherSuite, KeGroup, OprfHash};
use crate::errors::{InternalError, ProtocolError};
use crate::hash::OutputSize;
use crate::key_exchange::group::Group;
use crate::key_exchange::traits::SerializedIdentifiers;
use crate::keypair::{KeyPair, PrivateKey, PublicKey};
use crate::opaque::Identifiers;
use crate::serialization::{MacExt, SliceExt};

// Constant string used as salt for HKDF computation
const STR_AUTH_KEY: [u8; 7] = *b"AuthKey";
const STR_EXPORT_KEY: [u8; 9] = *b"ExportKey";
const STR_PRIVATE_KEY: [u8; 10] = *b"PrivateKey";
pub(crate) type NonceLen = U32;

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub(crate) enum InnerEnvelopeMode {
    Zero = 0,
    Internal = 1,
}

impl Zeroize for InnerEnvelopeMode {
    fn zeroize(&mut self) {
        *self = Self::Zero
    }
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

/// This struct is an instantiation of the envelope.
///
/// Note that earlier versions of this specification described an implementation
/// of this envelope using an encryption scheme that satisfied random-key
/// robustness.
/// The specification update has simplified this assumption by taking an
/// XOR-based approach without compromising on security, and to avoid the
/// confusion around the implementation of an RKR-secure encryption.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub(crate) struct Envelope<CS: CipherSuite> {
    pub(crate) mode: InnerEnvelopeMode,
    nonce: GenericArray<u8, NonceLen>,
    hmac: Output<OprfHash<CS>>,
}

// Note that this struct represents an envelope that has been "opened" with the
// asssociated key. This key is also used to derive the export_key parameter,
// which is technically unrelated to the envelope's encrypted and authenticated
// contents.
pub(crate) struct OpenedEnvelope<'a, CS: CipherSuite> {
    pub(crate) client_static_keypair: KeyPair<KeGroup<CS>>,
    pub(crate) export_key: Output<OprfHash<CS>>,
    pub(crate) identifiers: SerializedIdentifiers<'a, KeGroup<CS>>,
}

pub(crate) struct OpenedInnerEnvelope<CS: CipherSuite> {
    pub(crate) export_key: Output<OprfHash<CS>>,
}

#[cfg(not(test))]
type SealRawResult<CS: CipherSuite> = (Envelope<CS>, Output<OprfHash<CS>>);
#[cfg(test)]
type SealRawResult<CS: CipherSuite> = (Envelope<CS>, Output<OprfHash<CS>>, Output<OprfHash<CS>>);
#[cfg(not(test))]
type SealResult<CS: CipherSuite> = (Envelope<CS>, PublicKey<KeGroup<CS>>, Output<OprfHash<CS>>);
#[cfg(test)]
type SealResult<CS: CipherSuite> = (
    Envelope<CS>,
    PublicKey<KeGroup<CS>>,
    Output<OprfHash<CS>>,
    Output<OprfHash<CS>>,
);

pub(crate) type EnvelopeLen<CS: CipherSuite> = Sum<NonceLen, OutputSize<OprfHash<CS>>>;

impl<CS: CipherSuite> Envelope<CS> {
    #[allow(clippy::type_complexity)]
    pub(crate) fn seal<R: RngCore + CryptoRng>(
        rng: &mut R,
        randomized_pwd_hasher: Hkdf<OprfHash<CS>>,
        server_s_pk: &PublicKey<KeGroup<CS>>,
        ids: Identifiers,
    ) -> Result<SealResult<CS>, ProtocolError> {
        let mut nonce = GenericArray::default();
        rng.fill_bytes(&mut nonce);

        let (mode, client_s_pk) = (
            InnerEnvelopeMode::Internal,
            build_inner_envelope_internal::<CS>(randomized_pwd_hasher.clone(), nonce)?,
        );

        let server_s_pk_bytes = server_s_pk.serialize();
        let identifiers = SerializedIdentifiers::<KeGroup<CS>>::from_identifiers(
            ids,
            client_s_pk.serialize(),
            server_s_pk_bytes.clone(),
        )?;
        let aad = construct_aad(
            identifiers.client.iter(),
            identifiers.server.iter(),
            &server_s_pk_bytes,
        );

        let result = Self::seal_raw(randomized_pwd_hasher, nonce, aad, mode)?;
        Ok((
            result.0,
            client_s_pk,
            result.1,
            #[cfg(test)]
            result.2,
        ))
    }

    /// Uses a key to convert the plaintext into an envelope, authenticated by
    /// the aad field. Note that a new nonce is sampled for each call to seal.
    #[allow(clippy::type_complexity)]
    pub(crate) fn seal_raw<'a>(
        randomized_pwd_hasher: Hkdf<OprfHash<CS>>,
        nonce: GenericArray<u8, NonceLen>,
        aad: impl Iterator<Item = &'a [u8]>,
        mode: InnerEnvelopeMode,
    ) -> Result<SealRawResult<CS>, InternalError> {
        let mut hmac_key = Output::<OprfHash<CS>>::default();
        let mut export_key = Output::<OprfHash<CS>>::default();

        randomized_pwd_hasher
            .expand_multi_info(&[&nonce, &STR_AUTH_KEY], &mut hmac_key)
            .map_err(|_| InternalError::HkdfError)?;
        randomized_pwd_hasher
            .expand_multi_info(&[&nonce, &STR_EXPORT_KEY], &mut export_key)
            .map_err(|_| InternalError::HkdfError)?;

        let mut hmac = Hmac::<OprfHash<CS>>::new_from_slice(&hmac_key)
            .map_err(|_| InternalError::HmacError)?;
        hmac.update(&nonce);
        hmac.update_iter(aad);

        let hmac_bytes = hmac.finalize().into_bytes();

        Ok((
            Self {
                mode,
                nonce,
                hmac: hmac_bytes,
            },
            export_key,
            #[cfg(test)]
            hmac_key,
        ))
    }

    pub(crate) fn open<'a>(
        &self,
        randomized_pwd_hasher: Hkdf<OprfHash<CS>>,
        server_s_pk: PublicKey<KeGroup<CS>>,
        optional_ids: Identifiers<'a>,
    ) -> Result<OpenedEnvelope<'a, CS>, ProtocolError> {
        let client_static_keypair = match self.mode {
            InnerEnvelopeMode::Zero => {
                return Err(InternalError::IncompatibleEnvelopeModeError.into())
            }
            InnerEnvelopeMode::Internal => {
                recover_keys_internal::<CS>(randomized_pwd_hasher.clone(), self.nonce)?
            }
        };

        let server_s_pk_bytes = server_s_pk.serialize();
        let identifiers = SerializedIdentifiers::<KeGroup<CS>>::from_identifiers(
            optional_ids,
            client_static_keypair.public().serialize(),
            server_s_pk_bytes.clone(),
        )?;
        let aad = construct_aad(
            identifiers.client.iter(),
            identifiers.server.iter(),
            &server_s_pk_bytes,
        );

        let opened = self.open_raw(randomized_pwd_hasher, aad)?;

        Ok(OpenedEnvelope {
            client_static_keypair,
            export_key: opened.export_key,
            identifiers,
        })
    }

    /// Attempts to decrypt the envelope using a key, which is successful only
    /// if the key and aad used to construct the envelope are the same.
    pub(crate) fn open_raw<'a>(
        &self,
        randomized_pwd_hasher: Hkdf<OprfHash<CS>>,
        aad: impl Iterator<Item = &'a [u8]>,
    ) -> Result<OpenedInnerEnvelope<CS>, InternalError> {
        let mut hmac_key = Output::<OprfHash<CS>>::default();
        let mut export_key = Output::<OprfHash<CS>>::default();

        randomized_pwd_hasher
            .expand(&self.nonce.concat(STR_AUTH_KEY.into()), &mut hmac_key)
            .map_err(|_| InternalError::HkdfError)?;
        randomized_pwd_hasher
            .expand(&self.nonce.concat(STR_EXPORT_KEY.into()), &mut export_key)
            .map_err(|_| InternalError::HkdfError)?;

        let mut hmac = Hmac::<OprfHash<CS>>::new_from_slice(&hmac_key)
            .map_err(|_| InternalError::HmacError)?;
        hmac.update(&self.nonce);
        hmac.update_iter(aad);
        hmac.verify(&self.hmac)
            .map_err(|_| InternalError::SealOpenHmacError)?;

        Ok(OpenedInnerEnvelope { export_key })
    }

    // Creates a dummy envelope object that serializes to the all-zeros byte string
    pub(crate) fn dummy() -> Self {
        Self {
            mode: InnerEnvelopeMode::Zero,
            nonce: GenericArray::default(),
            hmac: GenericArray::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn len() -> usize {
        use generic_array::typenum::Unsigned;

        OutputSize::<OprfHash<CS>>::USIZE + NonceLen::USIZE
    }

    pub(crate) fn serialize(&self) -> GenericArray<u8, EnvelopeLen<CS>>
    where
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
    {
        self.nonce.concat(self.hmac.clone())
    }

    pub(crate) fn deserialize_take(bytes: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            mode: InnerEnvelopeMode::Internal,
            nonce: bytes.take_array("nonce")?,
            hmac: bytes.take_array("hmac")?,
        })
    }
}

// Helper functions

fn build_inner_envelope_internal<CS: CipherSuite>(
    randomized_pwd_hasher: Hkdf<OprfHash<CS>>,
    nonce: GenericArray<u8, NonceLen>,
) -> Result<PublicKey<KeGroup<CS>>, ProtocolError> {
    let mut keypair_seed = GenericArray::<_, <KeGroup<CS> as Group>::SkLen>::default();
    randomized_pwd_hasher
        .expand(&nonce.concat(STR_PRIVATE_KEY.into()), &mut keypair_seed)
        .map_err(|_| InternalError::HkdfError)?;
    let client_s_sk = PrivateKey::new(KeGroup::<CS>::derive_scalar(keypair_seed)?);

    Ok(client_s_sk.public_key())
}

fn recover_keys_internal<CS: CipherSuite>(
    randomized_pwd_hasher: Hkdf<OprfHash<CS>>,
    nonce: GenericArray<u8, NonceLen>,
) -> Result<KeyPair<KeGroup<CS>>, ProtocolError> {
    let mut keypair_seed = GenericArray::<_, <KeGroup<CS> as Group>::SkLen>::default();
    randomized_pwd_hasher
        .expand(&nonce.concat(STR_PRIVATE_KEY.into()), &mut keypair_seed)
        .map_err(|_| InternalError::HkdfError)?;
    let client_s_sk = PrivateKey::new(KeGroup::<CS>::derive_scalar(keypair_seed)?);
    let client_s_pk = client_s_sk.public_key();

    Ok(KeyPair::new(client_s_sk, client_s_pk))
}

fn construct_aad<'a>(
    id_u: impl Iterator<Item = &'a [u8]>,
    id_s: impl Iterator<Item = &'a [u8]>,
    server_s_pk: &'a [u8],
) -> impl Iterator<Item = &'a [u8]> {
    [server_s_pk].into_iter().chain(id_s).chain(id_u)
}

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl<CS: CipherSuite> AssertZeroized for Envelope<CS> {
    fn assert_zeroized(&self) {
        let Self { mode, nonce, hmac } = self;

        assert_eq!(mode, &InnerEnvelopeMode::Zero);

        for byte in nonce.iter().chain(hmac) {
            assert_eq!(byte, &0);
        }
    }
}

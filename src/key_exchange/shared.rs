// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use core::ops::Add;

use derive_where::derive_where;
use digest::core_api::BlockSizeUser;
use digest::{Output, OutputSizeUser};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, Le, NonZero, Sum, Unsigned, U1, U2, U256, U32};
use generic_array::{ArrayLength, GenericArray};
use hkdf::{Hkdf, HkdfExtract};
use rand::{CryptoRng, RngCore};

use crate::errors::{InternalError, ProtocolError};
use crate::hash::{Hash, OutputSize, ProxyHash};
use crate::key_exchange::group::Group;
use crate::key_exchange::traits::{Deserialize, Serialize};
use crate::keypair::{PrivateKey, PublicKey};
use crate::serialization::{i2osp, SliceExt};

///////////////
// Constants //
// ========= //
///////////////

pub(crate) type NonceLen = U32;
pub(super) static STR_CONTEXT: &[u8] = b"OPAQUEv1-";
static STR_CLIENT_MAC: &[u8] = b"ClientMAC";
static STR_HANDSHAKE_SECRET: &[u8] = b"HandshakeSecret";
static STR_SERVER_MAC: &[u8] = b"ServerMAC";
static STR_SESSION_KEY: &[u8] = b"SessionKey";
static STR_OPAQUE: &[u8] = b"OPAQUE-";

////////////////////////////
// High-level API Structs //
// ====================== //
////////////////////////////

/// The client state produced after the first key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Sk)]
pub struct Ke1State<G: Group> {
    pub(super) client_e_sk: PrivateKey<G>,
    pub(super) client_nonce: GenericArray<u8, NonceLen>,
}

/// The first key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Pk)]
pub struct Ke1Message<G: Group> {
    pub(super) client_nonce: GenericArray<u8, NonceLen>,
    pub(super) client_e_pk: PublicKey<G>,
}

/////////////////////////
// Convenience Structs //
//==================== //
/////////////////////////

// Consists of a session key, followed by two mac keys: (session_key, km2, km3)
pub(super) struct DerivedKeys<H: OutputSizeUser> {
    pub(super) session_key: Output<H>,
    pub(super) km2: Output<H>,
    pub(super) km3: Output<H>,
    #[cfg(test)]
    pub(super) handshake_secret: Output<H>,
}

////////////////////////////////////////////////
// Helper functions and Trait Implementations //
// ========================================== //
////////////////////////////////////////////////

// Helper functions

// Generate a random nonce up to NonceLen::USIZE bytes.
pub(super) fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> GenericArray<u8, NonceLen> {
    let mut nonce_bytes = GenericArray::default();
    rng.fill_bytes(&mut nonce_bytes);
    nonce_bytes
}

// Internal function which takes computed shared secrets, along with some
// auxiliary metadata, to produce the session key and two MAC keys
pub(super) fn derive_keys<'a, H: Hash>(
    ikms: impl Iterator<Item = &'a [u8]>,
    hashed_derivation_transcript: &[u8],
) -> Result<DerivedKeys<H>, ProtocolError>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let mut hkdf = HkdfExtract::<H>::new(None);

    for ikm in ikms {
        hkdf.input_ikm(ikm);
    }

    let (_, extracted_ikm) = hkdf.finalize();
    let handshake_secret = derive_secrets::<H>(
        &extracted_ikm,
        STR_HANDSHAKE_SECRET,
        hashed_derivation_transcript,
    )?;
    let session_key = derive_secrets::<H>(
        &extracted_ikm,
        STR_SESSION_KEY,
        hashed_derivation_transcript,
    )?;

    let km2 = hkdf_expand_label::<H>(&handshake_secret, STR_SERVER_MAC, b"")?;
    let km3 = hkdf_expand_label::<H>(&handshake_secret, STR_CLIENT_MAC, b"")?;

    Ok(DerivedKeys {
        session_key,
        km2,
        km3,
        #[cfg(test)]
        handshake_secret,
    })
}

fn hkdf_expand_label<H: Hash>(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
) -> Result<Output<H>, ProtocolError>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let h = Hkdf::<H>::from_prk(secret).map_err(|_| InternalError::HkdfError)?;
    hkdf_expand_label_extracted(&h, label, context)
}

fn hkdf_expand_label_extracted<H: Hash>(
    hkdf: &Hkdf<H>,
    label: &[u8],
    context: &[u8],
) -> Result<Output<H>, ProtocolError>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let mut okm = GenericArray::default();

    let length = i2osp::<U2>(OutputSize::<H>::USIZE)?;
    let label_length = i2osp::<U1>(STR_OPAQUE.len() + label.len())?;
    let context_len = i2osp::<U1>(context.len())?;

    let hkdf_label = [
        length.as_slice(),
        &label_length,
        STR_OPAQUE,
        label,
        &context_len,
        context,
    ];

    hkdf.expand_multi_info(&hkdf_label, &mut okm)
        .map_err(|_| InternalError::HkdfError)?;
    Ok(okm)
}

fn derive_secrets<H: Hash>(
    hkdf: &Hkdf<H>,
    label: &[u8],
    hashed_derivation_transcript: &[u8],
) -> Result<Output<H>, ProtocolError>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    hkdf_expand_label_extracted::<H>(hkdf, label, hashed_derivation_transcript)
}

// Serialization and deserialization implementations

impl<G: Group> Deserialize for Ke1State<G> {
    fn deserialize_take(bytes: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            client_e_sk: PrivateKey::deserialize_take(bytes)?,
            client_nonce: bytes.take_array("client nonce")?,
        })
    }
}

impl<G: Group> Serialize for Ke1State<G>
where
    // Ke1State: KeSk + Nonce
    G::SkLen: Add<NonceLen>,
    Sum<G::SkLen, NonceLen>: ArrayLength<u8>,
{
    type Len = Sum<G::SkLen, NonceLen>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.client_e_sk.serialize().concat(self.client_nonce)
    }
}

impl<G: Group> Deserialize for Ke1Message<G> {
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            client_nonce: input.take_array("client nonce")?,
            client_e_pk: PublicKey::deserialize_take(input)?,
        })
    }
}

impl<G: Group> Serialize for Ke1Message<G>
where
    // Ke1Message: Nonce + KePk
    NonceLen: Add<G::PkLen>,
    Sum<NonceLen, G::PkLen>: ArrayLength<u8>,
{
    type Len = Sum<NonceLen, G::PkLen>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.client_nonce.concat(self.client_e_pk.serialize())
    }
}

impl<G: Group> Ke1Message<G> {
    pub(crate) fn to_iter(&self) -> Ke1MessageIter<G> {
        Ke1MessageIter {
            client_nonce: self.client_nonce,
            client_e_pk: self.client_e_pk.serialize(),
        }
    }
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Zeroize)]
pub(crate) struct Ke1MessageIter<G: Group> {
    client_nonce: GenericArray<u8, NonceLen>,
    client_e_pk: GenericArray<u8, G::PkLen>,
}

pub(crate) type Ke1MessageIterLen<G: Group> = Sum<NonceLen, G::PkLen>;

impl<G: Group> Ke1MessageIter<G> {
    pub(crate) fn iter(&self) -> impl Clone + Iterator<Item = &[u8]> {
        [self.client_nonce.as_slice(), self.client_e_pk.as_slice()].into_iter()
    }

    pub(crate) fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Ke1MessageIter {
            client_nonce: input.take_array("client nonce")?,
            client_e_pk: input.take_array("client ephemeral public key")?,
        })
    }
}

impl<G: Group> Ke1MessageIter<G>
where
    NonceLen: Add<G::PkLen>,
    Ke1MessageIterLen<G>: ArrayLength<u8>,
{
    pub(crate) fn serialize(&self) -> GenericArray<u8, Ke1MessageIterLen<G>> {
        self.client_nonce.concat(self.client_e_pk.clone())
    }
}

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl<G: Group> AssertZeroized for Ke1State<G>
where
    G::Sk: AssertZeroized,
{
    fn assert_zeroized(&self) {
        let Self {
            client_e_sk,
            client_nonce,
        } = self;

        client_e_sk.assert_zeroized();
        assert_eq!(client_nonce, &GenericArray::default());
    }
}

#[cfg(test)]
impl<G: Group> AssertZeroized for Ke1Message<G>
where
    G::Pk: AssertZeroized,
{
    fn assert_zeroized(&self) {
        let Self {
            client_nonce,
            client_e_pk,
        } = self;

        assert_eq!(client_nonce, &GenericArray::default());
        client_e_pk.assert_zeroized();
    }
}

#[cfg(test)]
impl<G: Group> AssertZeroized for Ke1MessageIter<G> {
    fn assert_zeroized(&self) {
        let Self {
            client_nonce,
            client_e_pk,
        } = self;

        for byte in client_nonce.iter().chain(client_e_pk) {
            assert_eq!(byte, &0);
        }
    }
}

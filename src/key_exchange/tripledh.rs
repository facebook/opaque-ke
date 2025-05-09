// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! An implementation of the Triple Diffie-Hellman key exchange protocol
use core::convert::TryFrom;
use core::ops::Add;

use derive_where::derive_where;
use digest::core_api::BlockSizeUser;
use digest::{Digest, Output};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, Le, NonZero, Sum, Unsigned, U1, U2, U256, U32};
use generic_array::{ArrayLength, GenericArray};
use hkdf::{Hkdf, HkdfExtract};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::utils::{check_slice_size, check_slice_size_atleast};
use crate::errors::{InternalError, ProtocolError};
use crate::hash::{Hash, OutputSize, ProxyHash};
use crate::key_exchange::group::KeGroup;
use crate::key_exchange::traits::{
    Deserialize, GenerateKe2Result, GenerateKe3Result, KeyExchange, Serialize,
};
use crate::keypair::{KeyPair, PrivateKey, PublicKey};
use crate::serialization::{Input, UpdateExt};

///////////////
// Constants //
// ========= //
///////////////

pub(crate) type NonceLen = U32;
static STR_CONTEXT: &[u8] = b"OPAQUEv1-";
static STR_CLIENT_MAC: &[u8] = b"ClientMAC";
static STR_HANDSHAKE_SECRET: &[u8] = b"HandshakeSecret";
static STR_SERVER_MAC: &[u8] = b"ServerMAC";
static STR_SESSION_KEY: &[u8] = b"SessionKey";
static STR_OPAQUE: &[u8] = b"OPAQUE-";

////////////////////////////
// High-level API Structs //
// ====================== //
////////////////////////////

/// The Triple Diffie-Hellman key exchange implementation
///
/// # Remote Key
///
/// [`ServerLoginBuilder::data()`](crate::ServerLoginBuilder::data()) will
/// return the client's ephemeral public key.
/// [`ServerLoginBuilder::build()`](crate::ServerLoginBuilder::build()) expects
/// a shared secret computed through Diffie-Hellman from the server's private
/// key and the given public key.
pub struct TripleDh;

/// The client state produced after the first key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; KG::Sk)]
pub struct Ke1State<KG: KeGroup> {
    client_e_sk: PrivateKey<KG>,
    client_nonce: GenericArray<u8, NonceLen>,
}

/// The first key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; KG::Pk)]
pub struct Ke1Message<KG: KeGroup> {
    pub(crate) client_nonce: GenericArray<u8, NonceLen>,
    pub(crate) client_e_pk: PublicKey<KG>,
}

/// The server state produced after the second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub struct Ke2State<D: Hash>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    km3: Output<D>,
    hashed_transcript: Output<D>,
    session_key: Output<D>,
}

/// Builder for the second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "D: serde::Deserialize<'de>,  PublicKey<KG>: serde::Deserialize<'de>",
        serialize = "D: serde::Serialize,  PublicKey<KG>: serde::Serialize",
    ))
)]
#[derive_where(Clone)]
#[derive_where(Debug, Eq, Hash, PartialEq; D, PublicKey<KG>)]
pub struct Ke2Builder<D: Hash, KG: KeGroup>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    server_nonce: GenericArray<u8, NonceLen>,
    transcript_hasher: D,
    client_e_pk: PublicKey<KG>,
    server_e_pk: PublicKey<KG>,
    shared_secret_1: GenericArray<u8, KG::PkLen>,
    shared_secret_3: GenericArray<u8, KG::PkLen>,
}

/// The second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; KG::Pk)]
pub struct Ke2Message<D: Hash, KG: KeGroup>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: PublicKey<KG>,
    mac: Output<D>,
}

/// The third key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub struct Ke3Message<D: Hash>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    mac: Output<D>,
}

/// Trait required by [`KeGroup::Sk`] to be compatible with [`TripleDh`].
pub trait DiffieHellman<KG: KeGroup> {
    /// Diffie-Hellman key exchange.
    fn diffie_hellman(self, pk: KG::Pk) -> GenericArray<u8, KG::PkLen>;
}

////////////////////////////////
// High-level Implementations //
// ========================== //
////////////////////////////////

impl<D: Hash, KG: KeGroup + 'static> KeyExchange<D, KG> for TripleDh
where
    KG::Sk: DiffieHellman<KG>,
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Ke1State: KeSk + Nonce
    KG::SkLen: Add<NonceLen>,
    Sum<KG::SkLen, NonceLen>: ArrayLength<u8>,
    // Ke1Message: Nonce + KePk
    NonceLen: Add<KG::PkLen>,
    Sum<NonceLen, KG::PkLen>: ArrayLength<u8>,
    // Ke2State: (Hash + Hash) + Hash
    OutputSize<D>: Add<OutputSize<D>>,
    Sum<OutputSize<D>, OutputSize<D>>: ArrayLength<u8> + Add<OutputSize<D>>,
    Sum<Sum<OutputSize<D>, OutputSize<D>>, OutputSize<D>>: ArrayLength<u8>,
    // Ke2Message: (Nonce + KePk) + Hash
    NonceLen: Add<KG::PkLen>,
    Sum<NonceLen, KG::PkLen>: ArrayLength<u8> + Add<OutputSize<D>>,
    Sum<Sum<NonceLen, KG::PkLen>, OutputSize<D>>: ArrayLength<u8>,
{
    type KE1State = Ke1State<KG>;
    type KE2State = Ke2State<D>;
    type KE1Message = Ke1Message<KG>;
    type KE2Builder = Ke2Builder<D, KG>;
    type KE2BuilderData<'a> = &'a PublicKey<KG>;
    type KE2BuilderInput = GenericArray<u8, KG::PkLen>;
    type KE2Message = Ke2Message<D, KG>;
    type KE3Message = Ke3Message<D>;

    fn generate_ke1<OprfCs: voprf::CipherSuite, R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError> {
        let client_e_kp = KeyPair::<KG>::generate_random::<OprfCs, _>(rng);
        let client_nonce = generate_nonce::<R>(rng);

        let ke1_message = Ke1Message {
            client_nonce,
            client_e_pk: client_e_kp.public().clone(),
        };

        Ok((
            Ke1State {
                client_e_sk: client_e_kp.private().clone(),
                client_nonce,
            },
            ke1_message,
        ))
    }

    fn ke2_builder<'a, 'b, 'c, 'd, OprfCs: voprf::CipherSuite, R: RngCore + CryptoRng>(
        rng: &mut R,
        serialized_credential_request: impl Iterator<Item = &'a [u8]>,
        serialized_credential_response: impl Iterator<Item = &'b [u8]>,
        ke1_message: Self::KE1Message,
        client_s_pk: PublicKey<KG>,
        id_u: impl Iterator<Item = &'c [u8]>,
        id_s: impl Iterator<Item = &'d [u8]>,
        context: &[u8],
    ) -> Result<Self::KE2Builder, ProtocolError> {
        let server_e = KeyPair::<KG>::generate_random::<OprfCs, _>(rng);
        let server_nonce = generate_nonce::<R>(rng);

        let transcript_hasher = D::new()
            .chain(STR_CONTEXT)
            .chain_iter(Input::<U2>::from(context)?.iter())
            .chain_iter(id_u.into_iter())
            .chain_iter(serialized_credential_request)
            .chain_iter(id_s.into_iter())
            .chain_iter(serialized_credential_response)
            .chain(server_nonce)
            .chain(server_e.public().serialize());

        let shared_secret_1 = server_e
            .private()
            .ke_diffie_hellman(&ke1_message.client_e_pk);
        let shared_secret_3 = server_e.private().ke_diffie_hellman(&client_s_pk);

        Ok(Ke2Builder {
            server_nonce,
            transcript_hasher,
            client_e_pk: ke1_message.client_e_pk.clone(),
            server_e_pk: server_e.public().clone(),
            shared_secret_1,
            shared_secret_3,
        })
    }

    fn ke2_builder_data(builder: &Self::KE2Builder) -> Self::KE2BuilderData<'_> {
        &builder.client_e_pk
    }

    fn generate_ke2_input(
        builder: &Self::KE2Builder,
        server_s_sk: &PrivateKey<KG>,
    ) -> Self::KE2BuilderInput {
        server_s_sk.ke_diffie_hellman(&builder.client_e_pk)
    }

    fn build_ke2(
        mut builder: Self::KE2Builder,
        shared_secret_2: Self::KE2BuilderInput,
    ) -> Result<GenerateKe2Result<Self, D, KG>, ProtocolError> {
        let result = derive_3dh_keys::<D, KG>(
            builder.shared_secret_1.clone(),
            shared_secret_2,
            builder.shared_secret_3.clone(),
            &builder.transcript_hasher.clone().finalize(),
        )?;

        let mut mac_hasher =
            Hmac::<D>::new_from_slice(&result.1).map_err(|_| InternalError::HmacError)?;
        mac_hasher.update(&builder.transcript_hasher.clone().finalize());
        let mac = mac_hasher.finalize().into_bytes();

        Digest::update(&mut builder.transcript_hasher, &mac);

        Ok((
            Ke2State {
                km3: result.2,
                hashed_transcript: builder.transcript_hasher.clone().finalize(),
                session_key: result.0,
            },
            Ke2Message {
                server_nonce: builder.server_nonce,
                server_e_pk: builder.server_e_pk.clone(),
                mac,
            },
            #[cfg(test)]
            result.3,
            #[cfg(test)]
            result.1,
        ))
    }

    #[allow(clippy::type_complexity)]
    fn generate_ke3<'a, 'b, 'c, 'd>(
        l2_component: impl Iterator<Item = &'a [u8]>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        serialized_credential_request: impl Iterator<Item = &'b [u8]>,
        server_s_pk: PublicKey<KG>,
        client_s_sk: PrivateKey<KG>,
        id_u: impl Iterator<Item = &'c [u8]>,
        id_s: impl Iterator<Item = &'d [u8]>,
        context: &[u8],
    ) -> Result<GenerateKe3Result<Self, D, KG>, ProtocolError> {
        let mut transcript_hasher = D::new()
            .chain(STR_CONTEXT)
            .chain_iter(Input::<U2>::from(context)?.iter())
            .chain_iter(id_u)
            .chain_iter(serialized_credential_request)
            .chain_iter(id_s)
            .chain_iter(l2_component)
            .chain(ke2_message.to_bytes_without_mac());

        let result = derive_3dh_keys::<D, KG>(
            ke1_state
                .client_e_sk
                .ke_diffie_hellman(&ke2_message.server_e_pk),
            ke1_state.client_e_sk.ke_diffie_hellman(&server_s_pk),
            client_s_sk.ke_diffie_hellman(&ke2_message.server_e_pk),
            &transcript_hasher.clone().finalize(),
        )?;

        let mut server_mac =
            Hmac::<D>::new_from_slice(&result.1).map_err(|_| InternalError::HmacError)?;
        server_mac.update(&transcript_hasher.clone().finalize());

        server_mac
            .verify(&ke2_message.mac)
            .map_err(|_| ProtocolError::InvalidLoginError)?;

        Digest::update(&mut transcript_hasher, &ke2_message.mac);

        let mut client_mac =
            Hmac::<D>::new_from_slice(&result.2).map_err(|_| InternalError::HmacError)?;
        client_mac.update(&transcript_hasher.finalize());

        Ok((
            result.0,
            Ke3Message {
                mac: client_mac.finalize().into_bytes(),
            },
            #[cfg(test)]
            result.3,
            #[cfg(test)]
            result.2,
        ))
    }

    fn finish_ke(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State,
    ) -> Result<Output<D>, ProtocolError> {
        let mut client_mac =
            Hmac::<D>::new_from_slice(&ke2_state.km3).map_err(|_| InternalError::HmacError)?;
        client_mac.update(&ke2_state.hashed_transcript);

        client_mac
            .verify(&ke3_message.mac)
            .map_err(|_| ProtocolError::InvalidLoginError)?;

        Ok(ke2_state.session_key.clone())
    }
}

/////////////////////////
// Convenience Structs //
//==================== //
/////////////////////////

// Consists of a session key, followed by two mac keys: (session_key, km2, km3)
#[cfg(not(test))]
type TripleDhDerivationResult<D> = (Output<D>, Output<D>, Output<D>);
#[cfg(test)]
type TripleDhDerivationResult<D> = (Output<D>, Output<D>, Output<D>, Output<D>);

////////////////////////////////////////////////
// Helper functions and Trait Implementations //
// ========================================== //
////////////////////////////////////////////////

// Helper functions

// Internal function which takes the public and private components of the client
// and server keypairs, along with some auxiliary metadata, to produce the
// session key and two MAC keys
fn derive_3dh_keys<D: Hash, KG: KeGroup>(
    shared_secret_1: GenericArray<u8, KG::PkLen>,
    shared_secret_2: GenericArray<u8, KG::PkLen>,
    shared_secret_3: GenericArray<u8, KG::PkLen>,
    hashed_derivation_transcript: &[u8],
) -> Result<TripleDhDerivationResult<D>, ProtocolError>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let mut hkdf = HkdfExtract::<D>::new(None);

    hkdf.input_ikm(&shared_secret_1);
    hkdf.input_ikm(&shared_secret_2);
    hkdf.input_ikm(&shared_secret_3);

    let (_, extracted_ikm) = hkdf.finalize();
    let handshake_secret = derive_secrets::<D>(
        &extracted_ikm,
        STR_HANDSHAKE_SECRET,
        hashed_derivation_transcript,
    )?;
    let session_key = derive_secrets::<D>(
        &extracted_ikm,
        STR_SESSION_KEY,
        hashed_derivation_transcript,
    )?;

    let km2 = hkdf_expand_label::<D>(&handshake_secret, STR_SERVER_MAC, b"")?;
    let km3 = hkdf_expand_label::<D>(&handshake_secret, STR_CLIENT_MAC, b"")?;

    Ok((
        session_key,
        km2,
        km3,
        #[cfg(test)]
        handshake_secret,
    ))
}

fn hkdf_expand_label<D: Hash>(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
) -> Result<Output<D>, ProtocolError>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let h = Hkdf::<D>::from_prk(secret).map_err(|_| InternalError::HkdfError)?;
    hkdf_expand_label_extracted(&h, label, context)
}

fn hkdf_expand_label_extracted<D: Hash>(
    hkdf: &Hkdf<D>,
    label: &[u8],
    context: &[u8],
) -> Result<Output<D>, ProtocolError>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let mut okm = GenericArray::default();

    let length_u16: u16 =
        u16::try_from(OutputSize::<D>::USIZE).map_err(|_| ProtocolError::SerializationError)?;
    let label = Input::<U1>::from_label(STR_OPAQUE, label)?;
    let label = label.to_array_3();
    let context = Input::<U1>::from(context)?;
    let context = context.to_array_2();

    let hkdf_label = [
        &length_u16.to_be_bytes(),
        label[0],
        label[1],
        label[2],
        context[0],
        context[1],
    ];

    hkdf.expand_multi_info(&hkdf_label, &mut okm)
        .map_err(|_| InternalError::HkdfError)?;
    Ok(okm)
}

fn derive_secrets<D: Hash>(
    hkdf: &Hkdf<D>,
    label: &[u8],
    hashed_derivation_transcript: &[u8],
) -> Result<Output<D>, ProtocolError>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    hkdf_expand_label_extracted::<D>(hkdf, label, hashed_derivation_transcript)
}

// Generate a random nonce up to NonceLen::USIZE bytes.
fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> GenericArray<u8, NonceLen> {
    let mut nonce_bytes = GenericArray::default();
    rng.fill_bytes(&mut nonce_bytes);
    nonce_bytes
}

// Serialization and deserialization implementations

impl<KG: KeGroup> Deserialize for Ke1State<KG> {
    fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let key_len = KG::SkLen::USIZE;

        let nonce_len = NonceLen::USIZE;
        let checked_bytes = check_slice_size_atleast(bytes, key_len + nonce_len, "ke1_state")?;

        Ok(Self {
            client_e_sk: PrivateKey::deserialize(&checked_bytes[..key_len])?,
            client_nonce: GenericArray::clone_from_slice(
                &checked_bytes[key_len..key_len + nonce_len],
            ),
        })
    }
}

impl<KG: KeGroup> Serialize for Ke1State<KG>
where
    // Ke1State: KeSk + Nonce
    KG::SkLen: Add<NonceLen>,
    Sum<KG::SkLen, NonceLen>: ArrayLength<u8>,
{
    type Len = Sum<KG::SkLen, NonceLen>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.client_e_sk.serialize().concat(self.client_nonce)
    }
}

impl<KG: KeGroup> Deserialize for Ke1Message<KG> {
    fn deserialize(ke1_message_bytes: &[u8]) -> Result<Self, ProtocolError> {
        let nonce_len = NonceLen::USIZE;
        let checked_nonce = check_slice_size(
            ke1_message_bytes,
            nonce_len + <KG as KeGroup>::PkLen::USIZE,
            "ke1_message nonce",
        )?;

        Ok(Self {
            client_nonce: GenericArray::clone_from_slice(&checked_nonce[..nonce_len]),
            client_e_pk: PublicKey::deserialize(&checked_nonce[nonce_len..])?,
        })
    }
}

impl<KG: KeGroup> Serialize for Ke1Message<KG>
where
    // Ke1Message: Nonce + KePk
    NonceLen: Add<KG::PkLen>,
    Sum<NonceLen, KG::PkLen>: ArrayLength<u8>,
{
    type Len = Sum<NonceLen, KG::PkLen>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.client_nonce.concat(self.client_e_pk.serialize())
    }
}

impl<D: Hash> Deserialize for Ke2State<D>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let hash_len = OutputSize::<D>::USIZE;
        let checked_bytes = check_slice_size(input, 3 * hash_len, "ke2_state")?;

        Ok(Self {
            km3: GenericArray::clone_from_slice(&checked_bytes[..hash_len]),
            hashed_transcript: GenericArray::clone_from_slice(
                &checked_bytes[hash_len..2 * hash_len],
            ),
            session_key: GenericArray::clone_from_slice(&checked_bytes[2 * hash_len..3 * hash_len]),
        })
    }
}

impl<D: Hash> Serialize for Ke2State<D>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Ke2State: (Hash + Hash) + Hash
    OutputSize<D>: Add<OutputSize<D>>,
    Sum<OutputSize<D>, OutputSize<D>>: ArrayLength<u8> + Add<OutputSize<D>>,
    Sum<Sum<OutputSize<D>, OutputSize<D>>, OutputSize<D>>: ArrayLength<u8>,
{
    type Len = Sum<Sum<OutputSize<D>, OutputSize<D>>, OutputSize<D>>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.km3
            .clone()
            .concat(self.hashed_transcript.clone())
            .concat(self.session_key.clone())
    }
}

impl<KG: KeGroup, D: Hash> Drop for Ke2Builder<D, KG>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn drop(&mut self) {
        struct AssertZeroizeOnDrop<'a, T: ZeroizeOnDrop>(#[allow(unused)] &'a T);

        self.server_nonce.zeroize();
        self.transcript_hasher.reset();
        let _ = AssertZeroizeOnDrop(&self.client_e_pk);
        let _ = AssertZeroizeOnDrop(&self.server_e_pk);
        self.shared_secret_1.zeroize();
        self.shared_secret_3.zeroize();
    }
}

impl<KG: KeGroup, D: Hash> ZeroizeOnDrop for Ke2Builder<D, KG>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
}

impl<KG: KeGroup, D: Hash> Deserialize for Ke2Message<D, KG>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let key_len = <KG as KeGroup>::PkLen::USIZE;
        let nonce_len = NonceLen::USIZE;
        let checked_nonce = check_slice_size_atleast(input, nonce_len, "ke2_message nonce")?;

        let unchecked_server_e_pk = check_slice_size_atleast(
            &checked_nonce[nonce_len..],
            key_len,
            "ke2_message server_e_pk",
        )?;
        let checked_mac = check_slice_size(
            &unchecked_server_e_pk[key_len..],
            OutputSize::<D>::USIZE,
            "ke1_message mac",
        )?;

        // Check the public key bytes
        let server_e_pk = PublicKey::deserialize(&unchecked_server_e_pk[..key_len])?;

        Ok(Self {
            server_nonce: GenericArray::clone_from_slice(&checked_nonce[..nonce_len]),
            server_e_pk,
            mac: GenericArray::clone_from_slice(checked_mac),
        })
    }
}

impl<D: Hash, KG: KeGroup> Serialize for Ke2Message<D, KG>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Ke2Message: (Nonce + KePk) + Hash
    NonceLen: Add<KG::PkLen>,
    Sum<NonceLen, KG::PkLen>: ArrayLength<u8> + Add<OutputSize<D>>,
    Sum<Sum<NonceLen, KG::PkLen>, OutputSize<D>>: ArrayLength<u8>,
{
    type Len = Sum<Sum<NonceLen, KG::PkLen>, OutputSize<D>>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.server_nonce
            .concat(self.server_e_pk.serialize())
            .concat(self.mac.clone())
    }
}

impl<D: Hash, KG: KeGroup> Ke2Message<D, KG>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    NonceLen: Add<KG::PkLen>,
    Sum<NonceLen, KG::PkLen>: ArrayLength<u8>,
{
    fn to_bytes_without_mac(&self) -> GenericArray<u8, Sum<NonceLen, KG::PkLen>> {
        self.server_nonce.concat(self.server_e_pk.serialize())
    }
}

impl<D: Hash> Deserialize for Ke3Message<D>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let checked_bytes = check_slice_size(bytes, OutputSize::<D>::USIZE, "ke3_message")?;

        Ok(Self {
            mac: GenericArray::clone_from_slice(checked_bytes),
        })
    }
}

impl<D: Hash> Serialize for Ke3Message<D>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    type Len = OutputSize<D>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.mac.clone()
    }
}

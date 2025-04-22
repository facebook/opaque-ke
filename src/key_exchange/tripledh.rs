// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! An implementation of the Triple Diffie-Hellman key exchange protocol

use core::marker::PhantomData;
use core::ops::Add;

use derive_where::derive_where;
use digest::core_api::BlockSizeUser;
use digest::{Digest, Output, OutputSizeUser, Update};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, Le, NonZero, Sum, Unsigned, U2, U256};
use generic_array::{ArrayLength, GenericArray};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use subtle::{ConstantTimeEq, CtOption};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::utils::{check_slice_size, check_slice_size_atleast};
use crate::errors::{InternalError, ProtocolError};
use crate::hash::{Hash, OutputSize, ProxyHash};
use crate::key_exchange::group::Group;
use crate::key_exchange::shared::{self, Ke1Message, Ke1State, NonceLen, STR_CONTEXT};
use crate::key_exchange::traits::{
    Deserialize, GenerateKe2Result, GenerateKe3Result, KeyExchange, Serialize,
};
use crate::keypair::{KeyPair, PrivateKey, PublicKey};
use crate::serialization::{Input, UpdateExt};

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
/// a shared secret computed through Diffie-Hellman from the servers private key
/// and the given public key.
pub struct TripleDh<G, H>(PhantomData<(G, H)>);

/// The server state produced after the second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub struct Ke2State<H: OutputSizeUser> {
    session_key: Output<H>,
    expected_mac: Output<H>,
}

/// Builder for the second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "H: serde::Deserialize<'de>,  PublicKey<G>: serde::Deserialize<'de>",
        serialize = "H: serde::Serialize, PublicKey<G>: serde::Serialize",
    ))
)]
#[derive_where(Clone)]
#[derive_where(Debug, Eq, Hash, PartialEq; H, PublicKey<G>)]
pub struct Ke2Builder<G: Group, H: Hash>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    server_nonce: GenericArray<u8, NonceLen>,
    transcript_hasher: H,
    client_e_pk: PublicKey<G>,
    server_e_pk: PublicKey<G>,
    shared_secret_1: GenericArray<u8, G::PkLen>,
    shared_secret_3: GenericArray<u8, G::PkLen>,
}

/// The second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Pk)]
pub struct Ke2Message<G: Group, H: Hash>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: PublicKey<G>,
    mac: Output<H>,
}

/// The third key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub struct Ke3Message<H: Hash>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    mac: Output<H>,
}

/// Trait required by [`Group::Sk`] to be compatible with [`TripleDh`].
pub trait DiffieHellman<G: Group> {
    /// Diffie-Hellman key exchange.
    fn diffie_hellman(self, pk: G::Pk) -> GenericArray<u8, G::PkLen>;
}

////////////////////////////////
// High-level Implementations //
// ========================== //
////////////////////////////////

impl<G: Group + 'static, H: Hash> KeyExchange for TripleDh<G, H>
where
    G::Sk: DiffieHellman<G>,
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    type Group = G;
    type Hash = H;

    type KE1State = Ke1State<G>;
    type KE2State = Ke2State<H>;
    type KE1Message = Ke1Message<G>;
    type KE2Builder = Ke2Builder<G, H>;
    type KE2BuilderData<'a> = &'a PublicKey<G>;
    type KE2BuilderInput = GenericArray<u8, G::PkLen>;
    type KE2Message = Ke2Message<G, H>;
    type KE3Message = Ke3Message<H>;

    fn generate_ke1<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError> {
        let client_e_kp = KeyPair::<G>::derive_random(rng);
        let client_nonce = shared::generate_nonce::<R>(rng);

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

    fn ke2_builder<'a, 'b, 'c, 'd, R: RngCore + CryptoRng>(
        rng: &mut R,
        serialized_credential_request: impl Iterator<Item = &'a [u8]>,
        serialized_credential_response: impl Iterator<Item = &'b [u8]>,
        ke1_message: Self::KE1Message,
        client_s_pk: PublicKey<G>,
        id_u: impl Iterator<Item = &'c [u8]>,
        id_s: impl Iterator<Item = &'d [u8]>,
        context: &[u8],
    ) -> Result<Self::KE2Builder, ProtocolError> {
        let server_e = KeyPair::<G>::derive_random(rng);
        let server_nonce = shared::generate_nonce::<R>(rng);

        let transcript_hasher = transcript(
            context,
            id_u,
            serialized_credential_request,
            id_s,
            serialized_credential_response,
            server_nonce,
            server_e.public(),
        )?;

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

    fn generate_ke2_input<R: CryptoRng + RngCore>(
        builder: &Self::KE2Builder,
        _: &mut R,
        server_s_sk: &PrivateKey<G>,
    ) -> Self::KE2BuilderInput {
        server_s_sk.ke_diffie_hellman(&builder.client_e_pk)
    }

    fn build_ke2(
        mut builder: Self::KE2Builder,
        shared_secret_2: Self::KE2BuilderInput,
    ) -> Result<GenerateKe2Result<Self>, ProtocolError> {
        let derived_keys = shared::derive_keys::<H>(
            [
                builder.shared_secret_1.as_slice(),
                &shared_secret_2,
                &builder.shared_secret_3,
            ]
            .into_iter(),
            &builder.transcript_hasher.clone().finalize(),
        )?;

        let mut mac_hasher =
            Hmac::<H>::new_from_slice(&derived_keys.km2).map_err(|_| InternalError::HmacError)?;
        Mac::update(
            &mut mac_hasher,
            &builder.transcript_hasher.clone().finalize(),
        );
        let mac = mac_hasher.finalize().into_bytes();

        Digest::update(&mut builder.transcript_hasher, &mac);
        let mut mac_hasher =
            Hmac::<H>::new_from_slice(&derived_keys.km3).map_err(|_| InternalError::HmacError)?;
        Mac::update(
            &mut mac_hasher,
            &builder.transcript_hasher.clone().finalize(),
        );
        let expected_mac = mac_hasher.finalize().into_bytes();

        Ok((
            Ke2State {
                session_key: derived_keys.session_key,
                expected_mac,
            },
            Ke2Message {
                server_nonce: builder.server_nonce,
                server_e_pk: builder.server_e_pk.clone(),
                mac,
            },
            #[cfg(test)]
            derived_keys.handshake_secret,
            #[cfg(test)]
            derived_keys.km2,
        ))
    }

    #[allow(clippy::type_complexity)]
    fn generate_ke3<'a, 'b, 'c, 'd, R: CryptoRng + RngCore>(
        _: &mut R,
        serialized_credential_response: impl Iterator<Item = &'a [u8]>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        serialized_credential_request: impl Iterator<Item = &'b [u8]>,
        server_s_pk: PublicKey<G>,
        client_s_sk: PrivateKey<G>,
        id_u: impl Iterator<Item = &'c [u8]>,
        id_s: impl Iterator<Item = &'d [u8]>,
        context: &[u8],
    ) -> Result<GenerateKe3Result<Self>, ProtocolError> {
        let mut transcript_hasher = transcript::<G, H>(
            context,
            id_u,
            serialized_credential_request,
            id_s,
            serialized_credential_response,
            ke2_message.server_nonce,
            &ke2_message.server_e_pk,
        )?;

        let shared_secret_1 = ke1_state
            .client_e_sk
            .ke_diffie_hellman(&ke2_message.server_e_pk);
        let shared_secret_2 = ke1_state.client_e_sk.ke_diffie_hellman(&server_s_pk);
        let shared_secret_3 = client_s_sk.ke_diffie_hellman(&ke2_message.server_e_pk);

        let derived_keys = shared::derive_keys::<H>(
            [
                shared_secret_1.as_slice(),
                &shared_secret_2,
                &shared_secret_3,
            ]
            .into_iter(),
            &transcript_hasher.clone().finalize(),
        )?;

        let mut server_mac =
            Hmac::<H>::new_from_slice(&derived_keys.km2).map_err(|_| InternalError::HmacError)?;
        Mac::update(&mut server_mac, &transcript_hasher.clone().finalize());

        server_mac
            .verify(&ke2_message.mac)
            .map_err(|_| ProtocolError::InvalidLoginError)?;

        Digest::update(&mut transcript_hasher, &ke2_message.mac);

        let mut client_mac =
            Hmac::<H>::new_from_slice(&derived_keys.km3).map_err(|_| InternalError::HmacError)?;
        Mac::update(&mut client_mac, &transcript_hasher.finalize());

        Ok((
            derived_keys.session_key,
            Ke3Message {
                mac: client_mac.finalize().into_bytes(),
            },
            #[cfg(test)]
            derived_keys.handshake_secret,
            #[cfg(test)]
            derived_keys.km3,
        ))
    }

    fn finish_ke(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State,
    ) -> Result<Output<H>, ProtocolError> {
        CtOption::new(
            ke2_state.session_key.clone(),
            ke2_state.expected_mac.ct_eq(&ke3_message.mac),
        )
        .into_option()
        .ok_or(ProtocolError::InvalidLoginError)
    }
}

////////////////////////////////////////////////
// Helper functions and Trait Implementations //
// ========================================== //
////////////////////////////////////////////////

fn transcript<'a, 'b, 'c, 'd, G: Group, H: Digest + Update>(
    context: &[u8],
    id_u: impl Iterator<Item = &'a [u8]>,
    serialized_credential_request: impl Iterator<Item = &'c [u8]>,
    id_s: impl Iterator<Item = &'b [u8]>,
    serialized_credential_response: impl Iterator<Item = &'d [u8]>,
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: &PublicKey<G>,
) -> Result<H, ProtocolError> {
    Ok(H::new()
        .chain(STR_CONTEXT)
        .chain_iter(Input::<U2>::from(context)?.iter())
        .chain_iter(id_u)
        .chain_iter(serialized_credential_request)
        .chain_iter(id_s)
        .chain_iter(serialized_credential_response)
        .chain(server_nonce)
        .chain(server_e_pk.serialize()))
}

////////////////////////////////////////////////
// Trait Implementations //
// ========================================== //
////////////////////////////////////////////////

impl<H: Hash> Deserialize for Ke2State<H>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let hash_len = OutputSize::<H>::USIZE;
        let checked_bytes = check_slice_size(input, 2 * hash_len, "ke2_state")?;

        Ok(Self {
            session_key: GenericArray::clone_from_slice(&checked_bytes[..hash_len]),
            expected_mac: GenericArray::clone_from_slice(&checked_bytes[hash_len..]),
        })
    }
}

impl<H: Hash> Serialize for Ke2State<H>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Ke2State: Hash + Hash
    OutputSize<H>: Add<OutputSize<H>>,
    Sum<OutputSize<H>, OutputSize<H>>: ArrayLength<u8>,
{
    type Len = Sum<OutputSize<H>, OutputSize<H>>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.session_key.clone().concat(self.expected_mac.clone())
    }
}

impl<G: Group, H: Hash> Drop for Ke2Builder<G, H>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn drop(&mut self) {
        struct AssertZeroizeOnDrop<'a, T: ZeroizeOnDrop>(#[allow(unused)] &'a T);

        let Self {
            server_nonce,
            transcript_hasher,
            client_e_pk,
            server_e_pk,
            shared_secret_1,
            shared_secret_3,
        } = self;

        server_nonce.zeroize();
        transcript_hasher.reset();
        let _ = AssertZeroizeOnDrop(client_e_pk);
        let _ = AssertZeroizeOnDrop(server_e_pk);
        shared_secret_1.zeroize();
        shared_secret_3.zeroize();
    }
}

impl<G: Group, H: Hash> ZeroizeOnDrop for Ke2Builder<G, H>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
}

impl<G: Group, H: Hash> Deserialize for Ke2Message<G, H>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let key_len = <G as Group>::PkLen::USIZE;
        let nonce_len = NonceLen::USIZE;
        let checked_nonce = check_slice_size_atleast(input, nonce_len, "ke2_message nonce")?;

        let unchecked_server_e_pk = check_slice_size_atleast(
            &checked_nonce[nonce_len..],
            key_len,
            "ke2_message server_e_pk",
        )?;
        let checked_mac = check_slice_size(
            &unchecked_server_e_pk[key_len..],
            OutputSize::<H>::USIZE,
            "ke2_message mac",
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

impl<H: Hash, G: Group> Serialize for Ke2Message<G, H>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Ke2Message: (Nonce + KePk) + Hash
    NonceLen: Add<G::PkLen>,
    Sum<NonceLen, G::PkLen>: ArrayLength<u8> + Add<OutputSize<H>>,
    Sum<Sum<NonceLen, G::PkLen>, OutputSize<H>>: ArrayLength<u8>,
{
    type Len = Sum<Sum<NonceLen, G::PkLen>, OutputSize<H>>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.server_nonce
            .concat(self.server_e_pk.serialize())
            .concat(self.mac.clone())
    }
}

impl<H: Hash> Deserialize for Ke3Message<H>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let checked_bytes = check_slice_size(bytes, OutputSize::<H>::USIZE, "ke3_message")?;

        Ok(Self {
            mac: GenericArray::clone_from_slice(checked_bytes),
        })
    }
}

impl<H: Hash> Serialize for Ke3Message<H>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    type Len = OutputSize<H>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.mac.clone()
    }
}

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::util::AssertZeroized;

#[cfg(test)]
impl<H: OutputSizeUser> AssertZeroized for Ke2State<H> {
    fn assert_zeroized(&self) {
        let Self {
            session_key,
            expected_mac,
        } = self;

        for byte in session_key.iter().chain(expected_mac) {
            assert_eq!(byte, &0);
        }
    }
}

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
use digest::{Digest, Mac, Output, OutputSizeUser, Update};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, Le, NonZero, Sum, U256};
use generic_array::{ArrayLength, GenericArray};
use hmac::Hmac;
use rand::{CryptoRng, RngCore};
use subtle::{ConstantTimeEq, CtOption};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{CipherSuite, KeGroup, KeHash};
use crate::errors::{InternalError, ProtocolError};
use crate::hash::{Hash, OutputSize, ProxyHash};
use crate::key_exchange::group::Group;
use crate::key_exchange::shared::{self, NonceLen};
pub use crate::key_exchange::shared::{DiffieHellman, Ke1Message, Ke1State};
use crate::key_exchange::traits::{
    CredentialRequestParts, CredentialResponseParts, Deserialize, GenerateKe2Result,
    GenerateKe3Result, KeyExchange, Sealed, Serialize, SerializedContext, SerializedIdentifiers,
};
use crate::keypair::{KeyPair, PrivateKey, PublicKey};
use crate::serialization::{SliceExt, UpdateExt};

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
///
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
    type KE2State<CS: CipherSuite> = Ke2State<H>;
    type KE1Message = Ke1Message<G>;
    type KE2Builder<'a, CS: CipherSuite<KeyExchange = Self>> = Ke2Builder<G, H>;
    type KE2BuilderData<'a, CS: 'static + CipherSuite> = &'a PublicKey<G>;
    type KE2BuilderInput<CS: CipherSuite> = GenericArray<u8, G::PkLen>;
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

    fn ke2_builder<'a, CS: CipherSuite<KeyExchange = Self>, R: RngCore + CryptoRng>(
        rng: &mut R,
        credential_request: CredentialRequestParts<CS>,
        ke1_message: Self::KE1Message,
        credential_response: CredentialResponseParts<CS>,
        client_s_pk: &PublicKey<G>,
        identifiers: SerializedIdentifiers<'_, KeGroup<CS>>,
        context: SerializedContext<'a>,
    ) -> Result<Self::KE2Builder<'a, CS>, ProtocolError> {
        let server_e = KeyPair::<G>::derive_random(rng);
        let server_nonce = shared::generate_nonce::<R>(rng);

        let transcript_hasher = transcript(
            &context,
            &identifiers,
            &credential_request,
            &ke1_message,
            &credential_response,
            server_nonce,
            server_e.public(),
        );

        let shared_secret_1 = server_e
            .private()
            .ke_diffie_hellman(&ke1_message.client_e_pk);
        let shared_secret_3 = server_e.private().ke_diffie_hellman(client_s_pk);

        Ok(Ke2Builder {
            server_nonce,
            transcript_hasher,
            client_e_pk: ke1_message.client_e_pk.clone(),
            server_e_pk: server_e.public().clone(),
            shared_secret_1,
            shared_secret_3,
        })
    }

    fn ke2_builder_data<'a, CS: 'static + CipherSuite<KeyExchange = Self>>(
        builder: &'a Self::KE2Builder<'_, CS>,
    ) -> Self::KE2BuilderData<'a, CS> {
        &builder.client_e_pk
    }

    fn generate_ke2_input<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + RngCore>(
        builder: &Self::KE2Builder<'_, CS>,
        _: &mut R,
        server_s_sk: &PrivateKey<G>,
    ) -> Self::KE2BuilderInput<CS> {
        server_s_sk.ke_diffie_hellman(&builder.client_e_pk)
    }

    fn build_ke2<CS: CipherSuite<KeyExchange = Self>>(
        mut builder: Self::KE2Builder<'_, CS>,
        shared_secret_2: Self::KE2BuilderInput<CS>,
    ) -> Result<GenerateKe2Result<CS>, ProtocolError> {
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

        builder.transcript_hasher.update(&mac);
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

    fn generate_ke3<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + RngCore>(
        _: &mut R,
        credential_request: CredentialRequestParts<CS>,
        ke1_message: Self::KE1Message,
        credential_response: CredentialResponseParts<CS>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        server_s_pk: PublicKey<G>,
        client_s_sk: PrivateKey<G>,
        identifiers: SerializedIdentifiers<'_, KeGroup<CS>>,
        context: SerializedContext<'_>,
    ) -> Result<GenerateKe3Result<Self>, ProtocolError> {
        let mut transcript_hasher = transcript(
            &context,
            &identifiers,
            &credential_request,
            &ke1_message,
            &credential_response,
            ke2_message.server_nonce,
            &ke2_message.server_e_pk,
        );

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

        transcript_hasher.update(&ke2_message.mac);

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

    fn finish_ke<CS: CipherSuite>(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State<CS>,
        _: &PublicKey<G>,
        _: SerializedIdentifiers<'_, KeGroup<CS>>,
        _: SerializedContext<'_>,
    ) -> Result<Output<H>, ProtocolError> {
        CtOption::new(
            ke2_state.session_key.clone(),
            ke2_state.expected_mac.ct_eq(&ke3_message.mac),
        )
        .into_option()
        .ok_or(ProtocolError::InvalidLoginError)
    }
}

impl<G: Group + 'static, H: Hash> Sealed for TripleDh<G, H>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
}

////////////////////////////////////////////////
// Helper functions and Trait Implementations //
// ========================================== //
////////////////////////////////////////////////

fn transcript<CS: CipherSuite>(
    context: &SerializedContext<'_>,
    identifiers: &SerializedIdentifiers<'_, KeGroup<CS>>,
    credential_request: &CredentialRequestParts<CS>,
    ke1_message: &Ke1Message<KeGroup<CS>>,
    credential_response: &CredentialResponseParts<CS>,
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: &PublicKey<KeGroup<CS>>,
) -> KeHash<CS> {
    KeHash::<CS>::new()
        .chain_iter(context.iter())
        .chain_iter(identifiers.client.iter())
        .chain_iter(credential_request.iter())
        .chain_iter(ke1_message.to_iter().iter())
        .chain_iter(identifiers.server.iter())
        .chain_iter(credential_response.iter())
        .chain(server_nonce)
        .chain(server_e_pk.serialize())
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
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            session_key: input.take_array("session key")?,
            expected_mac: input.take_array("expected mac")?,
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
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            server_nonce: input.take_array("server nonce")?,
            server_e_pk: PublicKey::deserialize_take(input)?,
            mac: input.take_array("mac")?,
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
    fn deserialize_take(bytes: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            mac: bytes.take_array("mac")?,
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
use crate::serialization::AssertZeroized;

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

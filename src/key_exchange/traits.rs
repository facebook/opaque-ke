// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::hash::ProxyHash;
use crate::key_exchange::group::KeGroup;
use crate::{
    ciphersuite::CipherSuite,
    errors::ProtocolError,
    hash::Hash,
    keypair::{PrivateKey, PublicKey, SecretKey},
};
use digest::core_api::BlockSizeUser;
use digest::Output;
use generic_array::typenum::{IsLess, Le, NonZero, U256};
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

#[cfg(not(test))]
pub type GenerateKe2Result<K, D, G> = (
    <K as KeyExchange<D, G>>::KE2State,
    <K as KeyExchange<D, G>>::KE2Message,
);
#[cfg(test)]
pub type GenerateKe2Result<K, D, G> = (
    <K as KeyExchange<D, G>>::KE2State,
    <K as KeyExchange<D, G>>::KE2Message,
    Output<D>,
    Output<D>,
);
#[cfg(not(test))]
pub type GenerateKe3Result<K, D, G> = (Output<D>, <K as KeyExchange<D, G>>::KE3Message);
#[cfg(test)]
pub type GenerateKe3Result<K, D, G> = (
    Output<D>,
    <K as KeyExchange<D, G>>::KE3Message,
    Output<D>,
    Output<D>,
);

pub trait KeyExchange<D: Hash, G: KeGroup>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    type KE1State: FromBytes + ToBytes + Zeroize + Clone;
    type KE2State: FromBytes + ToBytes + Zeroize + Clone;
    type KE1Message: FromBytes + ToBytes + Zeroize + Clone;
    type KE2Message: FromBytes + ToBytes + Clone;
    type KE3Message: FromBytes + ToBytes + Clone;

    fn generate_ke1<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError>;

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn generate_ke2<'a, 'b, 'c, 'd, R: RngCore + CryptoRng, S: SecretKey<G>>(
        rng: &mut R,
        l1_bytes: impl Iterator<Item = &'a [u8]>,
        l2_bytes: impl Iterator<Item = &'b [u8]>,
        ke1_message: Self::KE1Message,
        client_s_pk: PublicKey<G>,
        server_s_sk: S,
        id_u: impl Iterator<Item = &'c [u8]>,
        id_s: impl Iterator<Item = &'d [u8]>,
        context: &[u8],
    ) -> Result<GenerateKe2Result<Self, D, G>, ProtocolError<S::Error>>;

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn generate_ke3<'a, 'b, 'c, 'd>(
        l2_component: impl Iterator<Item = &'a [u8]>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        serialized_credential_request: impl Iterator<Item = &'b [u8]>,
        server_s_pk: PublicKey<G>,
        client_s_sk: PrivateKey<G>,
        id_u: impl Iterator<Item = &'c [u8]>,
        id_s: impl Iterator<Item = &'d [u8]>,
        context: &[u8],
    ) -> Result<GenerateKe3Result<Self, D, G>, ProtocolError>;

    #[allow(clippy::type_complexity)]
    fn finish_ke(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State,
    ) -> Result<Output<D>, ProtocolError>;

    fn ke2_message_size() -> usize;
}

pub trait FromBytes: Sized {
    fn from_bytes(input: &[u8]) -> Result<Self, ProtocolError>;
}

pub trait ToBytes {
    type Len: ArrayLength<u8>;

    fn to_bytes(&self) -> GenericArray<u8, Self::Len>;
}

#[allow(dead_code, type_alias_bounds)]
pub type Ke1StateLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1State as ToBytes>::Len;
#[allow(type_alias_bounds)]
pub type Ke1MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1Message as ToBytes>::Len;
#[allow(type_alias_bounds)]
#[allow(type_alias_bounds)]
pub type Ke2StateLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE2State as ToBytes>::Len;
#[allow(type_alias_bounds)]
pub type Ke2MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE2Message as ToBytes>::Len;
#[allow(type_alias_bounds)]
pub type Ke3MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE3Message as ToBytes>::Len;

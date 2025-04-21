// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use digest::core_api::{BlockSizeUser, CoreProxy};
use digest::Output;
use generic_array::typenum::{IsLess, Le, NonZero, U256};
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::ciphersuite::CipherSuite;
use crate::errors::ProtocolError;
use crate::hash::{Hash, ProxyHash};
use crate::key_exchange::group::Group;
use crate::keypair::{PrivateKey, PublicKey};
use crate::util::AsIterator;

pub trait KeyExchange
where
    <Self::Hash as CoreProxy>::Core: ProxyHash,
    <<Self::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<Self::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    type Group: Group;
    type Hash: Hash;

    type KE1State: ZeroizeOnDrop + Clone;
    type KE2State: ZeroizeOnDrop + Clone;
    type KE1Message: SerializeIter + ZeroizeOnDrop + Clone;
    type KE2Builder: ZeroizeOnDrop + Clone;
    type KE2BuilderData<'a>;
    type KE2BuilderInput;
    type KE2Message: ZeroizeOnDrop + Clone;
    type KE3Message: ZeroizeOnDrop + Clone;

    fn generate_ke1<OprfCs: voprf::CipherSuite, R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError>;

    #[allow(clippy::too_many_arguments)]
    fn ke2_builder<'a, 'b, 'c, 'd, OprfCs: voprf::CipherSuite, R: RngCore + CryptoRng>(
        rng: &mut R,
        serialized_credential_request: impl Iterator<Item = &'a [u8]>,
        serialized_credential_response: impl Iterator<Item = &'b [u8]>,
        ke1_message: Self::KE1Message,
        client_s_pk: PublicKey<Self::Group>,
        id_u: impl Iterator<Item = &'c [u8]>,
        id_s: impl Iterator<Item = &'d [u8]>,
        context: &[u8],
    ) -> Result<Self::KE2Builder, ProtocolError>;

    fn ke2_builder_data(builder: &Self::KE2Builder) -> Self::KE2BuilderData<'_>;

    fn generate_ke2_input(
        builder: &Self::KE2Builder,
        server_s_sk: &PrivateKey<Self::Group>,
    ) -> Self::KE2BuilderInput;

    fn build_ke2(
        builder: Self::KE2Builder,
        input: Self::KE2BuilderInput,
    ) -> Result<GenerateKe2Result<Self>, ProtocolError>;

    #[allow(clippy::too_many_arguments)]
    fn generate_ke3<'a, 'b, 'c, 'd>(
        l2_component: impl Iterator<Item = &'a [u8]>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        serialized_credential_request: impl Iterator<Item = &'b [u8]>,
        server_s_pk: PublicKey<Self::Group>,
        client_s_sk: PrivateKey<Self::Group>,
        id_u: impl Iterator<Item = &'c [u8]>,
        id_s: impl Iterator<Item = &'d [u8]>,
        context: &[u8],
    ) -> Result<GenerateKe3Result<Self>, ProtocolError>;

    fn finish_ke(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State,
    ) -> Result<Output<Self::Hash>, ProtocolError>;
}

pub trait Deserialize: Sized {
    fn deserialize(input: &[u8]) -> Result<Self, ProtocolError>;
}

pub trait Serialize {
    type Len: ArrayLength<u8>;

    fn serialize(&self) -> GenericArray<u8, Self::Len>;
}

pub trait SerializeIter {
    type AsIter: for<'a> AsIterator<Item<'a> = &'a [u8]>;

    fn serialize_iter(&self) -> Self::AsIter;
}

#[cfg(not(test))]
pub type GenerateKe2Result<K: KeyExchange> = (K::KE2State, K::KE2Message);
#[cfg(test)]
pub type GenerateKe2Result<K: KeyExchange> =
    (K::KE2State, K::KE2Message, Output<K::Hash>, Output<K::Hash>);
#[cfg(not(test))]
pub type GenerateKe3Result<K: KeyExchange> = (Output<K::Hash>, K::KE3Message);
#[cfg(test)]
pub type GenerateKe3Result<K: KeyExchange> = (
    Output<K::Hash>,
    K::KE3Message,
    Output<K::Hash>,
    Output<K::Hash>,
);

pub type Ke1StateLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE1State as Serialize>::Len;
pub type Ke1MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE1Message as Serialize>::Len;
pub type Ke2StateLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE2State as Serialize>::Len;
pub type Ke2MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE2Message as Serialize>::Len;
pub type Ke3MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE3Message as Serialize>::Len;

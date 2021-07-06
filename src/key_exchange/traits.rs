// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    errors::{PakeError, ProtocolError},
    group::Group,
    hash::Hash,
    keypair::{PrivateKey, PublicKey},
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub trait KeyExchange<D: Hash, G: Group> {
    type KE1State: FromBytes + ToBytesWithPointers + Zeroize + Clone;
    type KE2State: FromBytes + ToBytesWithPointers + Zeroize + Clone;
    type KE1Message: FromBytes + ToBytes + Clone;
    type KE2Message: FromBytes + ToBytes + Clone;
    type KE3Message: FromBytes + ToBytes + Clone;

    fn generate_ke1<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError>;

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn generate_ke2<R: RngCore + CryptoRng>(
        rng: &mut R,
        l1_bytes: Vec<u8>,
        l2_bytes: Vec<u8>,
        ke1_message: Self::KE1Message,
        client_s_pk: PublicKey<G>,
        server_s_sk: PrivateKey<G>,
        id_u: Vec<u8>,
        id_s: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<(Self::KE2State, Self::KE2Message), ProtocolError>;

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn generate_ke3(
        l2_component: Vec<u8>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        serialized_credential_request: &[u8],
        server_s_pk: PublicKey<G>,
        client_s_sk: PrivateKey<G>,
        id_u: Vec<u8>,
        id_s: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::KE3Message), ProtocolError>;

    #[allow(clippy::type_complexity)]
    fn finish_ke(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State,
    ) -> Result<Vec<u8>, ProtocolError>;

    fn ke2_message_size() -> usize;
}

pub trait FromBytes: Sized {
    fn from_bytes<CS: CipherSuite>(input: &[u8]) -> Result<Self, PakeError>;
}

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait ToBytesWithPointers {
    fn to_bytes(&self) -> Vec<u8>;

    // Only used for tests to grab raw pointers to data
    #[cfg(test)]
    fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)>;
}

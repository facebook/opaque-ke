// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    errors::{InternalPakeError, ProtocolError},
    hash::Hash,
    keypair::KeyPair,
};
use rand_core::{CryptoRng, RngCore};

use std::convert::TryFrom;

pub trait KeyExchange<D: Hash, KeyFormat: KeyPair> {
    type KE1State: TryFrom<Vec<u8>, Error = InternalPakeError> + ToBytes;
    type KE2State: TryFrom<Vec<u8>, Error = ProtocolError> + ToBytes;
    type KE1Message: TryFrom<Vec<u8>, Error = InternalPakeError> + ToBytes;
    type KE2Message: TryFrom<Vec<u8>, Error = ProtocolError> + ToBytes;
    type KE3Message: TryFrom<Vec<u8>, Error = ProtocolError> + ToBytes;

    fn generate_ke1<R: RngCore + CryptoRng>(
        l1_component: Vec<u8>,
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError>;

    fn generate_ke2<R: RngCore + CryptoRng>(
        rng: &mut R,
        l1_bytes: Vec<u8>,
        l2_bytes: Vec<u8>,
        ke1_message: Self::KE1Message,
        client_s_pk: KeyFormat::Repr,
        server_s_sk: KeyFormat::Repr,
    ) -> Result<(Self::KE2State, Self::KE2Message), ProtocolError>;

    fn generate_ke3(
        l2_component: Vec<u8>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        server_s_pk: KeyFormat::Repr,
        client_s_sk: KeyFormat::Repr,
    ) -> Result<(Vec<u8>, Self::KE3Message), ProtocolError>;

    fn finish_ke(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State,
    ) -> Result<Vec<u8>, ProtocolError>;

    fn ke1_state_size() -> usize;

    fn ke2_message_size() -> usize;
}

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

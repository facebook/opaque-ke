// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    errors::{PakeError, ProtocolError},
    hash::Hash,
    keypair::KeyPair,
};
use rand_core::{CryptoRng, RngCore};

use std::convert::TryFrom;

pub trait KeyExchange<D: Hash, KeyFormat: KeyPair> {
    type KE1State: for<'r> TryFrom<&'r [u8], Error = PakeError> + ToBytes;
    type KE2State: for<'r> TryFrom<&'r [u8], Error = PakeError> + ToBytes;
    type KE1Message: for<'r> TryFrom<&'r [u8], Error = PakeError> + ToBytes;
    type KE2Message: for<'r> TryFrom<&'r [u8], Error = PakeError> + ToBytes;
    type KE3Message: for<'r> TryFrom<&'r [u8], Error = PakeError> + ToBytes;

    fn generate_ke1<R: RngCore + CryptoRng>(
        l1_component: Vec<u8>,
        info: Vec<u8>,
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError>;

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn generate_ke2<R: RngCore + CryptoRng>(
        rng: &mut R,
        l1_bytes: Vec<u8>,
        l2_bytes: Vec<u8>,
        ke1_message: Self::KE1Message,
        client_s_pk: KeyFormat::Repr,
        server_s_sk: KeyFormat::Repr,
        id_u: Vec<u8>,
        id_s: Vec<u8>,
        e_info: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::KE2State, Self::KE2Message), ProtocolError>;

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn generate_ke3(
        l2_component: Vec<u8>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        server_s_pk: KeyFormat::Repr,
        client_s_sk: KeyFormat::Repr,
        id_u: Vec<u8>,
        id_s: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>, Self::KE3Message), ProtocolError>;

    #[allow(clippy::type_complexity)]
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

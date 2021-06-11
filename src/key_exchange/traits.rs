// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    errors::{PakeError, ProtocolError},
    group::Group,
    hash::Hash,
    keypair::Key,
};
use rand::{CryptoRng, RngCore};

use std::convert::TryFrom;
use zeroize::Zeroize;

pub trait KeyExchange<D: Hash, G: Group> {
    type KE1State: for<'r> TryFrom<&'r [u8], Error = PakeError> + ToBytesWithPointers + Zeroize;
    type KE2State: for<'r> TryFrom<&'r [u8], Error = PakeError> + ToBytesWithPointers + Zeroize;
    type KE1Message: for<'r> TryFrom<&'r [u8], Error = PakeError> + ToBytes;
    type KE2Message: for<'r> TryFrom<&'r [u8], Error = PakeError> + ToBytes;
    type KE3Message: for<'r> TryFrom<&'r [u8], Error = PakeError> + ToBytes;

    fn generate_ke1<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError>;

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn generate_ke2<R: RngCore + CryptoRng>(
        rng: &mut R,
        l1_bytes: Vec<u8>,
        l2_bytes: Vec<u8>,
        ke1_message: Self::KE1Message,
        client_s_pk: Key,
        server_s_sk: Key,
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
        server_s_pk: Key,
        client_s_sk: Key,
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

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait ToBytesWithPointers {
    fn to_bytes(&self) -> Vec<u8>;

    // Only used for tests to grab raw pointers to data
    #[cfg(test)]
    fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)>;
}

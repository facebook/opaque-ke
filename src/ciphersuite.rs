// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Defines the CipherSuite trait to specify the underlying primitives for OPAQUE

use crate::{
    errors::InternalPakeError,
    group::Group,
    keypair::{Key, KeyPair},
    slow_hash::SlowHash,
};
use generic_array::typenum::{U32, U64};
use rand_core::{CryptoRng, RngCore};

/// Configures the underlying primitives used in OPAQUE
/// * Aead: an authenticated encryption scheme
/// * Group: a finite cyclic group along with a point representation
/// * KeyFormat: a keypair type composed of public and private components
/// * SlowHash: a slow hashing function, typically used for password hashing
pub trait CipherSuite {
    type Aead: aead::NewAead<KeySize = U32> + aead::Aead;
    type Group: Group<ScalarLen = U32, UniformBytesLen = U64>;
    type KeyFormat: KeyPair<Repr = Key> + PartialEq;
    type SlowHash: SlowHash;

    /// Generating a random key pair given a cryptographic rng
    fn generate_random_keypair<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<Self::KeyFormat, InternalPakeError> {
        Self::KeyFormat::generate_random(rng)
    }
}

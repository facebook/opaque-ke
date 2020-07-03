// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Defines the CipherSuite trait to specify the underlying primitives for OPAQUE

use crate::{
    errors::InternalPakeError,
    group::Group,
    keypair::{Key, KeyPair},
    oprf::HkdfDigest,
    slow_hash::SlowHash,
};
use digest::FixedOutput;
use generic_array::typenum::{U32};
use rand_core::{CryptoRng, RngCore};

/// Configures the underlying primitives used in OPAQUE
/// * `Digest`: a digest suitable for use in an Hkdf, with an output length equal
///     to the input of the hash-to-curve function of the `Group` parameter.
/// * `Group`: a finite cyclic group along with a point representation
/// * `KeyFormat`: a keypair type composed of public and private components
/// * `SlowHash`: a slow hashing function, typically used for password hashing
pub trait CipherSuite {
    type Digest: HkdfDigest;
    type Group: Group<ScalarLen = U32, UniformBytesLen = <Self::Digest as FixedOutput>::OutputSize>;
    type KeyFormat: KeyPair<Repr = Key> + PartialEq;
    type SlowHash: SlowHash;

    /// Generating a random key pair given a cryptographic rng
    fn generate_random_keypair<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<Self::KeyFormat, InternalPakeError> {
        Self::KeyFormat::generate_random(rng)
    }
}

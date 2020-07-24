// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Defines the CipherSuite trait to specify the underlying primitives for OPAQUE

use crate::{
    errors::InternalPakeError,
    key_exchange::traits::KeyExchange,
    keypair::{Key, KeyPair},
    map_to_curve::GroupWithMapToCurve,
    slow_hash::SlowHash,
};

use rand_core::{CryptoRng, RngCore};

/// Configures the underlying primitives used in OPAQUE
/// * `Group`: a finite cyclic group along with a point representation, along
///   with an extension trait PasswordToCurve that allows some customization on
///   how to hash a password to a curve point. See `group::Group` and
///   `map_to_curve::GroupWithMapToCurve`.
/// * `KeyFormat`: a keypair type composed of public and private components
/// * `KeyExchange`: The key exchange protocol to use in the login step
/// * `SlowHash`: a slow hashing function, typically used for password hashing
pub trait CipherSuite {
    /// A finite cyclic group along with a point representation along with
    /// an extension trait PasswordToCurve that allows some customization on
    /// how to hash a password to a curve point. See `group::Group` and
    /// `map_to_curve::GroupWithMapToCurve`.
    type Group: GroupWithMapToCurve;
    /// A keypair type composed of public and private components
    type KeyFormat: KeyPair<Repr = Key> + PartialEq;
    /// A key exchange protocol
    type KeyExchange: KeyExchange;
    /// A slow hashing function, typically used for password hashing
    type SlowHash: SlowHash;

    /// Generating a random key pair given a cryptographic rng
    fn generate_random_keypair<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<Self::KeyFormat, InternalPakeError> {
        Self::KeyFormat::generate_random(rng)
    }
}

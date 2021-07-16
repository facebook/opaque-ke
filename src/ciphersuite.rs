// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Defines the CipherSuite trait to specify the underlying primitives for OPAQUE

use crate::{
    hash::Hash, key_exchange::traits::KeyExchange, map_to_curve::GroupWithMapToCurve,
    slow_hash::SlowHash,
};
use digest::Digest;

/// Configures the underlying primitives used in OPAQUE
/// * `Group`: a finite cyclic group along with a point representation, along
///   with an extension trait PasswordToCurve that allows some customization on
///   how to hash a password to a curve point. See `group::Group` and
///   `map_to_curve::GroupWithMapToCurve`.
/// * `KeyExchange`: The key exchange protocol to use in the login step
/// * `Hash`: The main hashing function to use
/// * `SlowHash`: A slow hashing function, typically used for password hashing
pub trait CipherSuite {
    /// A finite cyclic group along with a point representation along with
    /// an extension trait PasswordToCurve that allows some customization on
    /// how to hash a password to a curve point. See `group::Group` and
    /// `map_to_curve::GroupWithMapToCurve`.
    type Group: GroupWithMapToCurve<UniformBytesLen = <Self::Hash as Digest>::OutputSize>;
    /// A key exchange protocol
    type KeyExchange: KeyExchange<Self::Hash, Self::Group>;
    /// The main hash function use (for HKDF computations and hashing transcripts)
    type Hash: Hash;
    /// A slow hashing function, typically used for password hashing
    type SlowHash: SlowHash<Self::Hash>;
}

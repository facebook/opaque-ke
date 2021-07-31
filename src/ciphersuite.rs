// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Defines the CipherSuite trait to specify the underlying primitives for OPAQUE

use crate::{
    ake::Ake, group::Group, hash::Hash, key_exchange::traits::KeyExchange, slow_hash::SlowHash,
};

/// Configures the underlying primitives used in OPAQUE
/// * `Ake`: a algorithm for the authenticated key exchange used in `KeyExchange`
/// * `Group`: a finite cyclic group along with a point representation, that can
///    hash a password to a curve point used for OPRF. See `group::Group`.
/// * `KeyExchange`: The key exchange protocol to use in the login step
/// * `Hash`: The main hashing function to use
/// * `SlowHash`: A slow hashing function, typically used for password hashing
pub trait CipherSuite {
    /// A algorithm for the authenticated key exchange used in `KeyExchange`
    type Ake: Ake;
    /// A finite cyclic group along with a point representation, that can
    /// hash a password to a curve point used for OPRF. See `group::Group`.
    type Group: Group;
    /// A key exchange protocol
    type KeyExchange: KeyExchange<Self::Hash, Self::Ake>;
    /// The main hash function use (for HKDF computations and hashing transcripts)
    type Hash: Hash;
    /// A slow hashing function, typically used for password hashing
    type SlowHash: SlowHash<Self::Hash>;
}

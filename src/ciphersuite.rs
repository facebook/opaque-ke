// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Defines the CipherSuite trait to specify the underlying primitives for
//! OPAQUE

use digest::core_api::{BlockSizeUser, CoreProxy};
use digest::OutputSizeUser;
use generic_array::typenum::{IsLess, IsLessOrEqual, Le, NonZero, U256};

use crate::hash::{Hash, ProxyHash};
use crate::key_exchange::group::KeGroup;
use crate::key_exchange::traits::KeyExchange;
use crate::slow_hash::SlowHash;

/// Configures the underlying primitives used in OPAQUE
/// * `OprfGroup`: a finite cyclic group along with a point representation,
///   along with an extension trait PasswordToCurve that allows some
///   customization on how to hash a password to a curve point. See
///   `group::Group`.
/// * `KeGroup`: A `Group` used for the `KeyExchange`.
/// * `KeyExchange`: The key exchange protocol to use in the login step
/// * `Hash`: The main hashing function to use
/// * `SlowHash`: A slow hashing function, typically used for password hashing
pub trait CipherSuite
where
    <OprfHash<Self> as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<OprfHash<Self> as BlockSizeUser>::BlockSize>,
    OprfHash<Self>: Hash,
    <OprfHash<Self> as CoreProxy>::Core: ProxyHash,
    <<OprfHash<Self> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<OprfHash<Self> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// A finite cyclic group along with a point representation along with an
    /// extension trait PasswordToCurve that allows some customization on how to
    /// hash a password to a curve point. See `group::Group`.
    type OprfGroup: voprf::CipherSuite;
    /// A `Group` used for the `KeyExchange`.
    type KeGroup: KeGroup;
    /// A key exchange protocol
    type KeyExchange: KeyExchange<OprfHash<Self>, Self::KeGroup>;
    /// A slow hashing function, typically used for password hashing
    type SlowHash: SlowHash;
}

pub(crate) type OprfGroup<CS> = <<CS as CipherSuite>::OprfGroup as voprf::CipherSuite>::Group;
pub(crate) type OprfHash<CS> = <<CS as CipherSuite>::OprfGroup as voprf::CipherSuite>::Hash;

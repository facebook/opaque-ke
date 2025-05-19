// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Defines the [`CipherSuite`] trait to specify the underlying primitives for
//! OPAQUE

use core::ops::Add;

use digest::core_api::{BlockSizeUser, CoreProxy};
use generic_array::typenum::{IsLess, Le, NonZero, Sum, U256};
use generic_array::ArrayLength;

use crate::envelope::NonceLen;
use crate::hash::{Hash, OutputSize, ProxyHash};
use crate::key_exchange::group::Group;
use crate::key_exchange::traits::KeyExchange;
use crate::ksf::Ksf;
use crate::opaque::MaskedResponseLen;

/// Configures the underlying primitives used in OPAQUE
/// * `OprfCs`: A VOPRF ciphersuite, see [`voprf::CipherSuite`].
/// * `KeGroup`: A `Group` used for the `KeyExchange`.
/// * `KeyExchange`: The key exchange protocol to use in the login step
/// * `Hash`: The main hashing function to use
/// * `Ksf`: A key stretching function, typically used for password hashing
pub trait CipherSuite
where
    OprfHash<Self>: Hash,
    <OprfHash<Self> as CoreProxy>::Core: ProxyHash,
    <<OprfHash<Self> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<OprfHash<Self> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Envelope: Nonce + Hash
    // MaskedResponse: (Nonce + Hash) + KePk
    OutputSize<OprfHash<Self>>: Add<NonceLen>,
    Sum<OutputSize<OprfHash<Self>>, NonceLen>:
        ArrayLength<u8> + Add<<KeGroup<Self> as Group>::PkLen>,
    MaskedResponseLen<Self>: ArrayLength<u8>,
{
    /// A VOPRF ciphersuite, see [`voprf::CipherSuite`].
    type OprfCs: voprf::CipherSuite;
    /// A key exchange protocol
    type KeyExchange: KeyExchange;
    /// A key stretching function, typically used for password hashing
    type Ksf: Ksf;
}

pub(crate) type OprfGroup<CS: CipherSuite> = <CS::OprfCs as voprf::CipherSuite>::Group;
pub(crate) type OprfHash<CS: CipherSuite> = <CS::OprfCs as voprf::CipherSuite>::Hash;
pub(crate) type KeGroup<CS: CipherSuite> = <CS::KeyExchange as KeyExchange>::Group;
pub(crate) type KeHash<CS: CipherSuite> = <CS::KeyExchange as KeyExchange>::Hash;

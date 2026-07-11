// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Convenience traits for digest bounds used throughout the library.

use digest::block_buffer::Eager;
use digest::core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore};
use digest::{FixedOutputReset, HashMarker, OutputSizeUser};
use generic_array::typenum::{IsLess, Le, NonZero, U256};

/// Output size of a hash function's core.
pub(crate) type OutputSize<H> =
    <<H as CoreProxy>::Core as OutputSizeUser>::OutputSize;

/// Marker trait enforcing OPAQUE's supported hash block-size bounds.
///
/// This constraint applies to a hash function's internal block size
/// (`BlockSizeUser::BlockSize`), not its digest output size.
///
/// Centralizing these bounds avoids repeating the same typenum constraints
/// across multiple trait definitions and implementations.
pub(crate) trait ValidBlockSize: BlockSizeUser
where
    <Self as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<Self as BlockSizeUser>::BlockSize, U256>: NonZero,
{
}

impl<T: BlockSizeUser> ValidBlockSize for T
where
    <Self as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<Self as BlockSizeUser>::BlockSize, U256>: NonZero,
{
}

/// Trait simplifying requirements for hash cores used by OPAQUE.
pub trait ProxyHash:
    HashMarker
    + FixedOutputCore
    + BufferKindUser<BufferKind = Eager>
    + Default
    + Clone
    + ValidBlockSize
{
}

impl<
        T: HashMarker
            + FixedOutputCore
            + BufferKindUser<BufferKind = Eager>
            + Default
            + Clone
            + ValidBlockSize,
    > ProxyHash for T
{
}

/// Trait inheriting the requirements from [`digest::Digest`] for
/// compatibility with HKDF and HMAC.
///
/// Associated types could be simplified when they are made defaults:
/// <https://github.com/rust-lang/rust/issues/29661>
pub trait Hash:
    Default
    + HashMarker
    + OutputSizeUser<OutputSize = OutputSize<Self>>
    + BlockSizeUser
    + FixedOutputReset
    + CoreProxy
    + Clone
where
    <Self as CoreProxy>::Core: ProxyHash,
{
}

impl<
        T: Default
            + HashMarker
            + OutputSizeUser<OutputSize = OutputSize<Self>>
            + BlockSizeUser
            + FixedOutputReset
            + CoreProxy
            + Clone,
    > Hash for T
where
    <Self as CoreProxy>::Core: ProxyHash,
{
}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A convenience trait for digest bounds used throughout the library

use digest::block_buffer::Eager;
use digest::core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore};
use digest::{Digest, FixedOutputReset, HashMarker, OutputSizeUser};
use generic_array::typenum::{IsLess, Le, NonZero, U256};

pub(crate) type OutputSize<D> = <<D as CoreProxy>::Core as OutputSizeUser>::OutputSize;

/// Trait to simplify requirements for [`Hash`].
pub trait ProxyHash:
    HashMarker + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone
where
    <Self as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<Self as BlockSizeUser>::BlockSize, U256>: NonZero,
{
}

impl<T: HashMarker + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone>
    ProxyHash for T
where
    <Self as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<Self as BlockSizeUser>::BlockSize, U256>: NonZero,
{
}

/// Trait inheriting the requirements from digest::Digest for compatibility with
/// HKDF and HMAC Associated types could be simplified when they are made as
/// defaults: <https://github.com/rust-lang/rust/issues/29661>
pub trait Hash:
    Digest
    + OutputSizeUser<OutputSize = OutputSize<Self>>
    + BlockSizeUser
    + FixedOutputReset
    + CoreProxy
    + Clone
where
    <Self as CoreProxy>::Core: ProxyHash,
    <<Self as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<Self as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
}

impl<
        T: Digest
            + OutputSizeUser<OutputSize = OutputSize<Self>>
            + BlockSizeUser
            + FixedOutputReset
            + CoreProxy
            + Clone,
    > Hash for T
where
    <Self as CoreProxy>::Core: ProxyHash,
    <<Self as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<Self as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
}

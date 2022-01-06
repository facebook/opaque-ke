// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Trait specifying a slow hashing function

use digest::core_api::BlockSizeUser;
use digest::Output;
use generic_array::typenum::{IsLess, Le, NonZero, U256};

use crate::errors::InternalError;
use crate::hash::{Hash, ProxyHash};

/// Used for the slow hashing function in OPAQUE
pub trait SlowHash<D: Hash>: Default
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// Computes the slow hashing function
    fn hash(&self, input: Output<D>) -> Result<Output<D>, InternalError>;
}

/// A no-op hash which simply returns its input
#[derive(Default)]
pub struct NoOpHash;

impl<D: Hash> SlowHash<D> for NoOpHash
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn hash(&self, input: Output<D>) -> Result<Output<D>, InternalError> {
        Ok(input)
    }
}

#[cfg(feature = "slow-hash")]
impl<D: Hash> SlowHash<D> for argon2::Argon2<'_>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn hash(&self, input: Output<D>) -> Result<Output<D>, InternalError> {
        let mut output = Output::<D>::default();
        self.hash_password_into(&input, &[0; argon2::MIN_SALT_LEN], &mut output)
            .map_err(|_| InternalError::SlowHashError)?;
        Ok(output)
    }
}

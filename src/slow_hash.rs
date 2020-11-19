// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Trait specifying a slow hashing function

use crate::{errors::InternalPakeError, hash::Hash};
use digest::Digest;
use generic_array::GenericArray;

/// Used for the slow hashing function in OPAQUE
pub trait SlowHash<D: Hash> {
    /// Computes the slow hashing function
    fn hash(
        input: GenericArray<u8, <D as Digest>::OutputSize>,
    ) -> Result<Vec<u8>, InternalPakeError>;
}

/// A no-op hash which simply returns its input
pub struct NoOpHash;

impl<D: Hash> SlowHash<D> for NoOpHash {
    fn hash(
        input: GenericArray<u8, <D as Digest>::OutputSize>,
    ) -> Result<Vec<u8>, InternalPakeError> {
        Ok(input.to_vec())
    }
}

#[cfg(feature = "slow-hash")]
impl<D: Hash> SlowHash<D> for scrypt::ScryptParams {
    fn hash(
        input: GenericArray<u8, <D as Digest>::OutputSize>,
    ) -> Result<Vec<u8>, InternalPakeError> {
        let params = scrypt::ScryptParams::new(15, 8, 1).unwrap();
        let mut output = [0u8; <D as Digest>::OutputSize::to_usize()];
        scrypt::scrypt(&input, &[], &params, &mut output)
            .map_err(|_| InternalPakeError::SlowHashError)?;
        Ok(output.to_vec())
    }
}

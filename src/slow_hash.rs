// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Trait specifying a slow hashing function

use generic_array::{ArrayLength, GenericArray};

use crate::errors::InternalError;

/// Used for the slow hashing function in OPAQUE
pub trait SlowHash: Default {
    /// Computes the slow hashing function
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError>;
}

/// A no-op hash which simply returns its input
#[derive(Default)]
pub struct Identity;

impl SlowHash for Identity {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        Ok(input)
    }
}

#[cfg(feature = "argon2")]
impl SlowHash for argon2::Argon2<'_> {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::default();
        self.hash_password_into(&input, &[0; argon2::MIN_SALT_LEN], &mut output)
            .map_err(|_| InternalError::SlowHashError)?;
        Ok(output)
    }
}

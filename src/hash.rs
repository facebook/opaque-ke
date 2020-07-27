// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use digest::{BlockInput, FixedOutput, Reset, Update};
use generic_array::ArrayLength;

/// Trait inheriting the requirements from digest::Digest for compatibility with HKDF and HMAC
// Associated types could be simplified when they are made as defaults:
// https://github.com/rust-lang/rust/issues/29661
pub trait Hash: Update + BlockInput + FixedOutput + Reset + Default + Clone {
    /// The block size for the hash function
    type BlockSize: ArrayLength<u8>;
    /// The output size of the hash function
    type OutputSize: ArrayLength<u8>;
}

impl<T: Update + BlockInput + FixedOutput + Reset + Default + Clone> Hash for T {
    type BlockSize = T::BlockSize;
    type OutputSize = T::OutputSize;
}

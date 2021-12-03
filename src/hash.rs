// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A convenience trait for digest bounds used throughout the library

use digest::{BlockInput, FixedOutput, Reset, Update};

/// Trait inheriting the requirements from digest::Digest for compatibility with HKDF and HMAC
// Associated types could be simplified when they are made as defaults:
// https://github.com/rust-lang/rust/issues/29661
pub trait Hash: Update + BlockInput + FixedOutput + Reset + Default + Clone {}

impl<T: Update + BlockInput + FixedOutput + Reset + Default + Clone> Hash for T {}

// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use derive_where::derive_where;
use digest::{Output, OutputSizeUser};
use generic_array::{ArrayLength, GenericArray};

use crate::errors::ProtocolError;
use crate::key_exchange::{Deserialize, Serialize};
use crate::serialization::SliceExt;

/// Pre-hash of the message to be verified.
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, Zeroize)]
#[derive_where(Copy; <H::OutputSize as ArrayLength<u8>>::ArrayType)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
pub struct PreHash<H: OutputSizeUser>(pub Output<H>);

impl<H: OutputSizeUser> Deserialize for PreHash<H> {
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self(input.take_array("pre-hash")?))
    }
}

impl<H: OutputSizeUser> Serialize for PreHash<H> {
    type Len = H::OutputSize;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.0.clone()
    }
}

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl<H: OutputSizeUser> AssertZeroized for PreHash<H> {
    fn assert_zeroized(&self) {
        assert_eq!(self.0, GenericArray::default());
    }
}

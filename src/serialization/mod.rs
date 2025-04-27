// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use digest::Update;
use generic_array::{ArrayLength, GenericArray};
use hmac::Mac;

use crate::errors::ProtocolError;

// Corresponds to the I2OSP() function from RFC8017
pub(crate) fn i2osp<L: ArrayLength<u8>>(
    input: usize,
) -> Result<GenericArray<u8, L>, ProtocolError> {
    const SIZEOF_USIZE: usize = core::mem::size_of::<usize>();

    // Make sure input fits in output.
    if (SIZEOF_USIZE as u32 - input.leading_zeros() / 8) > L::U32 {
        return Err(ProtocolError::SerializationError);
    }

    let mut output = GenericArray::default();
    output[L::USIZE.saturating_sub(SIZEOF_USIZE)..]
        .copy_from_slice(&input.to_be_bytes()[SIZEOF_USIZE.saturating_sub(L::USIZE)..]);
    Ok(output)
}

// Corresponds to the OS2IP() function from RFC8017
#[cfg(test)]
pub(crate) fn os2ip(input: &[u8]) -> Result<usize, ProtocolError> {
    if input.len() > core::mem::size_of::<usize>() {
        return Err(ProtocolError::SerializationError);
    }

    let mut output_array = [0u8; core::mem::size_of::<usize>()];
    output_array[core::mem::size_of::<usize>() - input.len()..].copy_from_slice(input);
    Ok(usize::from_be_bytes(output_array))
}

pub(crate) trait UpdateExt {
    fn chain_iter<'a>(self, iter: impl Iterator<Item = &'a [u8]>) -> Self;
}

impl<T: Update> UpdateExt for T {
    fn chain_iter<'a>(self, iter: impl Iterator<Item = &'a [u8]>) -> Self {
        let mut self_ = self;

        for bytes in iter {
            self_ = self_.chain(bytes);
        }

        self_
    }
}

pub(crate) trait MacExt {
    fn update_iter<'a>(&mut self, iter: impl Iterator<Item = &'a [u8]>);
}

impl<T: Mac> MacExt for T {
    fn update_iter<'a>(&mut self, iter: impl Iterator<Item = &'a [u8]>) {
        for bytes in iter {
            self.update(bytes);
        }
    }
}

pub(crate) trait SliceExt {
    fn take_array<L: ArrayLength<u8>>(
        self: &mut &Self,
        name: &'static str,
    ) -> Result<GenericArray<u8, L>, ProtocolError>;
}

impl SliceExt for [u8] {
    fn take_array<L: ArrayLength<u8>>(
        self: &mut &Self,
        name: &'static str,
    ) -> Result<GenericArray<u8, L>, ProtocolError> {
        if L::USIZE > self.len() {
            return Err(ProtocolError::SizeError {
                name,
                len: L::USIZE,
                actual_len: self.len(),
            });
        }

        let (front, back) = self.split_at(L::USIZE);
        *self = back;
        Ok(GenericArray::clone_from_slice(front))
    }
}

#[cfg(test)]
pub(crate) trait AssertZeroized {
    fn assert_zeroized(&self);
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod unit_tests {
    use generic_array::typenum::{U1, U2};

    use super::*;

    // Test the error condition for I2OSP
    #[test]
    fn test_i2osp_err_check() {
        assert!(i2osp::<U1>(0).is_ok());

        assert!(i2osp::<U1>(255).is_ok());
        assert!(i2osp::<U1>(256).is_err());
        assert!(i2osp::<U1>(257).is_err());

        assert!(i2osp::<U2>(256 * 256 - 1).is_ok());
        assert!(i2osp::<U2>(256 * 256).is_err());
        assert!(i2osp::<U2>(256 * 256 + 1).is_err());
    }
}

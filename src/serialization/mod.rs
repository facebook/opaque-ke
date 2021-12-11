// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::ProtocolError;
use alloc::vec::Vec;
use core::array::IntoIter;
use digest::Update;
use generic_array::{typenum::U0, ArrayLength, GenericArray};
use hmac::Mac;

// Corresponds to the I2OSP() function from RFC8017
pub(crate) fn i2osp<L: ArrayLength<u8>>(
    input: usize,
) -> Result<GenericArray<u8, L>, ProtocolError> {
    const SIZEOF_USIZE: usize = core::mem::size_of::<usize>();

    // Check if input >= 256^length
    if (SIZEOF_USIZE as u32 - input.leading_zeros() / 8) > L::U32 {
        return Err(ProtocolError::SerializationError);
    }

    if L::USIZE <= SIZEOF_USIZE {
        return Ok(GenericArray::clone_from_slice(
            &input.to_be_bytes()[SIZEOF_USIZE - L::USIZE..],
        ));
    }

    let mut output = GenericArray::default();
    output[L::USIZE - SIZEOF_USIZE..L::USIZE].copy_from_slice(&input.to_be_bytes());
    Ok(output)
}

// Corresponds to the OS2IP() function from RFC8017
pub(crate) fn os2ip(input: &[u8]) -> Result<usize, ProtocolError> {
    if input.len() > core::mem::size_of::<usize>() {
        return Err(ProtocolError::SerializationError);
    }

    let mut output_array = [0u8; core::mem::size_of::<usize>()];
    output_array[core::mem::size_of::<usize>() - input.len()..].copy_from_slice(input);
    Ok(usize::from_be_bytes(output_array))
}

/// Simplifies handling of [`serialize()`] output and implements [`Iterator`].
pub(crate) struct Serialized<'a, L1: ArrayLength<u8>, L2: ArrayLength<u8> = U0> {
    octet: GenericArray<u8, L1>,
    input: Input<'a, L2>,
}

enum Input<'a, L: ArrayLength<u8>> {
    Owned(GenericArray<u8, L>),
    Borrowed(&'a [u8]),
}

impl<'a, L1: ArrayLength<u8>, L2: ArrayLength<u8>> IntoIterator for &'a Serialized<'a, L1, L2> {
    type Item = &'a [u8];

    type IntoIter = IntoIter<&'a [u8], 2>;

    fn into_iter(self) -> Self::IntoIter {
        // MSRV: array `into_iter` isn't available in 1.51
        #[allow(deprecated)]
        IntoIter::new([
            &self.octet,
            match self.input {
                Input::Owned(ref bytes) => bytes,
                Input::Borrowed(bytes) => bytes,
            },
        ])
    }
}

impl<'a, L1: ArrayLength<u8>> Serialized<'a, L1, U0> {
    pub fn with_length<L2: ArrayLength<u8>>(self) -> Serialized<'a, L1, L2> {
        let input = if let Input::Borrowed(value) = self.input {
            Input::<L2>::Borrowed(value)
        } else {
            unreachable!("unexpected length constructed")
        };

        Serialized {
            octet: self.octet,
            input,
        }
    }
}

// Computes I2OSP(len(input), max_bytes) || input
pub(crate) fn serialize<L: ArrayLength<u8>>(
    input: &[u8],
) -> Result<Serialized<L, U0>, ProtocolError> {
    Ok(Serialized {
        octet: i2osp::<L>(input.len())?,
        input: Input::Borrowed(input),
    })
}

// Variation of `serialize` that takes an owned `input`
pub(crate) fn serialize_owned<L1: ArrayLength<u8>, L2: ArrayLength<u8>>(
    input: GenericArray<u8, L2>,
) -> Result<Serialized<'static, L1, L2>, ProtocolError> {
    Ok(Serialized {
        octet: i2osp::<L1>(input.len())?,
        input: Input::Owned(input),
    })
}

// Tokenizes an input of the format I2OSP(len(input), max_bytes) || input, outputting
// (input, remainder)
pub(crate) fn tokenize(
    input: &[u8],
    size_bytes: usize,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    if size_bytes > core::mem::size_of::<usize>() || input.len() < size_bytes {
        return Err(ProtocolError::SerializationError);
    }

    let size = os2ip(&input[..size_bytes])?;
    if size_bytes + size > input.len() {
        return Err(ProtocolError::SerializationError);
    }

    Ok((
        input[size_bytes..size_bytes + size].to_vec(),
        input[size_bytes + size..].to_vec(),
    ))
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

/// The purpose of this macro is to simplify [`concat`](alloc::slice::Concat::concat)ing
/// slices into an [`Iterator`] to avoid allocation
macro_rules! chain {
    (
        $item1:expr,
        $($item2:expr),+$(,)?
    ) => {
        $item1$(.chain($item2))+
    };
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod unit_tests {
    use super::*;
    use generic_array::typenum::{U1, U2};

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

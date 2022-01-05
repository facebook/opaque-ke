// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::ProtocolError;
use core::marker::PhantomData;
use digest::Update;
use generic_array::{
    typenum::{U0, U2},
    ArrayLength, GenericArray,
};
use hmac::Mac;

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

/// Computes `I2OSP(len(input), max_bytes) || input` and helps hold output without allocation.
pub(crate) struct Serialize<
    'a,
    L1: ArrayLength<u8>,
    L2: ArrayLength<u8> = U0,
    L3: ArrayLength<u8> = U0,
> {
    octet: GenericArray<u8, L1>,
    input: Input<'a, L2, L3>,
}

enum Input<'a, L1: ArrayLength<u8>, L2: ArrayLength<u8>> {
    Owned(GenericArray<u8, L1>),
    Borrowed(&'a [u8]),
    Label(([&'a [u8]; 2], PhantomData<L2>)),
}

impl<'a, L1: ArrayLength<u8>, L2: ArrayLength<u8>, L3: ArrayLength<u8>> Serialize<'a, L1, L2, L3> {
    // Variation of `serialize` that takes a borrowed `input
    pub(crate) fn from(input: &'a [u8]) -> Result<Serialize<'a, L1, L2>, ProtocolError> {
        Ok(Serialize {
            octet: i2osp::<L1>(input.len())?,
            input: Input::Borrowed(input),
        })
    }

    // Variation of `serialize` that takes an owned `input`
    pub(crate) fn from_owned(
        input: GenericArray<u8, L2>,
    ) -> Result<Serialize<'a, L1, L2>, ProtocolError> {
        Ok(Serialize {
            octet: i2osp::<L1>(input.len())?,
            input: Input::Owned(input),
        })
    }

    // Variation of `serialize` that takes a label
    pub(crate) fn from_label(
        opaque: &'a [u8],
        label: &'a [u8],
    ) -> Result<Serialize<'a, L1, U0, U2>, ProtocolError> {
        Ok(Serialize {
            octet: i2osp::<L1>(opaque.len() + label.len())?,
            input: Input::Label(([opaque, label], PhantomData)),
        })
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &[u8]> {
        // Some magic to make it output the same type in all branches.
        [self.octet.as_slice()]
            .into_iter()
            .chain(match &self.input {
                Input::Owned(bytes) => [bytes.as_slice()],
                Input::Borrowed(bytes) => [*bytes],
                Input::Label((iter, _)) => [iter[0]],
            })
            .chain(if let Input::Label((iter, _)) = &self.input {
                Some(iter[1])
            } else {
                None
            })
    }
}

impl<'a, L1: ArrayLength<u8>, L2: ArrayLength<u8>> Serialize<'a, L1, L2, U0> {
    pub(crate) fn to_array_2(&self) -> [&[u8]; 2] {
        let input = match &self.input {
            Input::Borrowed(value) => value,
            Input::Owned(value) => value.as_slice(),
            _ => unreachable!("unexpected `Serialize` constructed with wrong generics"),
        };

        [self.octet.as_slice(), input]
    }
}

impl<'a, L1: ArrayLength<u8>, L2: ArrayLength<u8>> Serialize<'a, L1, L2, U2> {
    pub(crate) fn to_array_3(&self) -> [&[u8]; 3] {
        match self.input {
            Input::Label((label, _)) => [self.octet.as_slice(), label[0], label[1]],
            _ => unreachable!("unexpected `Serialize` constructed with wrong generics"),
        }
    }
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

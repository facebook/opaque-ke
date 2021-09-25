// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::ProtocolError;
use alloc::vec::Vec;

// Corresponds to the I2OSP() function from RFC8017
pub(crate) fn i2osp(input: usize, length: usize) -> Result<alloc::vec::Vec<u8>, ProtocolError> {
    let sizeof_usize = core::mem::size_of::<usize>();

    // Check if input >= 256^length
    if (sizeof_usize as u32 - input.leading_zeros() / 8) > length as u32 {
        return Err(ProtocolError::SerializationError);
    }

    if length <= sizeof_usize {
        return Ok((&input.to_be_bytes()[sizeof_usize - length..]).to_vec());
    }

    let mut output = alloc::vec![0u8; length];
    output.splice(
        length - sizeof_usize..length,
        input.to_be_bytes().iter().cloned(),
    );
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

// Computes I2OSP(len(input), max_bytes) || input
pub(crate) fn serialize(input: &[u8], max_bytes: usize) -> Result<Vec<u8>, ProtocolError> {
    Ok([&i2osp(input.len(), max_bytes)?, input].concat())
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

#[cfg(test)]
mod tests;

#[cfg(test)]
mod unit_tests {
    use super::*;

    // Test the error condition for I2OSP
    #[test]
    fn test_i2osp_err_check() {
        assert!(i2osp(0, 1).is_ok());

        assert!(i2osp(255, 1).is_ok());
        assert!(i2osp(256, 1).is_err());
        assert!(i2osp(257, 1).is_err());

        assert!(i2osp(256 * 256 - 1, 2).is_ok());
        assert!(i2osp(256 * 256, 2).is_err());
        assert!(i2osp(256 * 256 + 1, 2).is_err());
    }
}

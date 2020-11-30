// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::PakeError;

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub enum CredentialType {
    SkU,
    PkU,
    PkS,
    IdU,
    IdS,
}

pub(crate) fn u8_to_credential_type(x: u8) -> Option<CredentialType> {
    match x {
        1 => Some(CredentialType::SkU),
        2 => Some(CredentialType::PkU),
        3 => Some(CredentialType::PkS),
        4 => Some(CredentialType::IdU),
        5 => Some(CredentialType::IdS),
        _ => None,
    }
}

// Corresponds to the I2OSP() function from RFC8017
pub(crate) fn i2osp(input: usize, length: usize) -> Vec<u8> {
    if length <= std::mem::size_of::<usize>() {
        return (&input.to_be_bytes()[std::mem::size_of::<usize>() - length..]).to_vec();
    }

    let mut output = vec![0u8; length];
    output.splice(
        length - std::mem::size_of::<usize>()..length,
        input.to_be_bytes().iter().cloned(),
    );
    output
}

// Corresponds to the OS2IP() function from RFC8017
pub(crate) fn os2ip(input: &[u8]) -> Result<usize, PakeError> {
    if input.len() > std::mem::size_of::<usize>() {
        // TODO:: check RFC compliance in refusing this
        return Err(PakeError::SerializationError);
    }

    let mut output_array = [0u8; std::mem::size_of::<usize>()];
    output_array[std::mem::size_of::<usize>() - input.len()..].copy_from_slice(input);
    Ok(usize::from_be_bytes(output_array))
}

// Computes I2OSP(len(input), max_bytes) || input
pub(crate) fn serialize(input: &[u8], max_bytes: usize) -> Vec<u8> {
    [&i2osp(input.len(), max_bytes), &input[..]].concat()
}

// Tokenizes an input of the format I2OSP(len(input), max_bytes) || input, outputting
// (input, remainder)
pub(crate) fn tokenize(input: &[u8], size_bytes: usize) -> Result<(Vec<u8>, Vec<u8>), PakeError> {
    if size_bytes > std::mem::size_of::<usize>() || input.len() < size_bytes {
        return Err(PakeError::SerializationError);
    }

    let size = os2ip(&input[..size_bytes])?;
    if size_bytes + size > input.len() {
        return Err(PakeError::SerializationError);
    }

    Ok((
        input[size_bytes..size_bytes + size].to_vec(),
        input[size_bytes + size..].to_vec(),
    ))
}

#[cfg(test)]
mod tests;

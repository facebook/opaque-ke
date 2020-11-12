// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::PakeError;

use crate::{
    ciphersuite::CipherSuite,
    hash::Hash,
    keypair::KeyPair,
    opaque::{
        LoginFirstMessage, LoginSecondMessage, LoginThirdMessage, RegisterFirstMessage,
        RegisterSecondMessage, RegisterThirdMessage,
    },
};

pub enum ProtocolMessageType {
    RegistrationRequest,
    RegistrationResponse,
    RegistrationUpload,
    CredentialRequest,
    CredentialResponse,
    KeyExchange,
}

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

impl<T> From<&RegisterFirstMessage<T>> for ProtocolMessageType {
    fn from(_mt: &RegisterFirstMessage<T>) -> Self {
        ProtocolMessageType::RegistrationRequest
    }
}

impl<T> From<&RegisterSecondMessage<T>> for ProtocolMessageType {
    fn from(_mt: &RegisterSecondMessage<T>) -> Self {
        ProtocolMessageType::RegistrationResponse
    }
}

impl<T: KeyPair, U: Hash> From<&RegisterThirdMessage<T, U>> for ProtocolMessageType {
    fn from(_mt: &RegisterThirdMessage<T, U>) -> Self {
        ProtocolMessageType::RegistrationUpload
    }
}

impl<T: CipherSuite> From<&LoginFirstMessage<T>> for ProtocolMessageType {
    fn from(_mt: &LoginFirstMessage<T>) -> Self {
        ProtocolMessageType::CredentialRequest
    }
}

impl<T: CipherSuite> From<&LoginSecondMessage<T>> for ProtocolMessageType {
    fn from(_mt: &LoginSecondMessage<T>) -> Self {
        ProtocolMessageType::CredentialResponse
    }
}

impl<T: CipherSuite> From<&LoginThirdMessage<T>> for ProtocolMessageType {
    fn from(_mt: &LoginThirdMessage<T>) -> Self {
        ProtocolMessageType::KeyExchange
    }
}

pub(crate) fn serialize(input: &[u8], max_bytes: usize) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    output
        .extend_from_slice(&input.len().to_be_bytes()[std::mem::size_of::<usize>() - max_bytes..]);
    output.extend_from_slice(&input[..]);
    output
}

pub(crate) fn tokenize(input: Vec<u8>, size_bytes: usize) -> Result<(Vec<u8>, Vec<u8>), PakeError> {
    if size_bytes > 8 || input.len() < size_bytes {
        return Err(PakeError::SerializationError);
    }

    let mut size_array = [0u8; 8];
    for i in 0..size_bytes {
        size_array[8 - size_bytes + i] = input[i];
    }

    let big_size = u64::from_be_bytes(size_array);

    // TODO:: check RFC compliance in refusing this
    if big_size >= u32::MAX as u64 {
        return Err(PakeError::SerializationError);
    }

    let size = big_size as usize;

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

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! A list of error types which are produced during an execution of the protocol

use thiserror::Error;

/// Represents an error in the manipulation of internal cryptographic data
#[derive(Debug, Error)]
pub enum InternalPakeError {
    #[error("Invalid length for {name}: expected {len}, but is actually {actual_len}.")]
    SizeError {
        name: &'static str,
        len: usize,
        actual_len: usize,
    },
    #[error("Could not decompress point.")]
    PointError,
    #[error("Key belongs to a small subgroup!")]
    SubGroupError,
    #[error("hashing to a key failed")]
    HashingFailure,
    #[error("Computing HKDF failed while deriving subkeys")]
    HkdfError,
    #[error("Computing HMAC failed while supplying a secret key")]
    HmacError,
    #[error("Computing the slow hashing function failed")]
    SlowHashError,
    #[cfg(feature = "noise")]
    #[error("Noise library operation failed")]
    NoiseError,
}

/// Represents an error in password checking
#[derive(Debug, Error)]
pub enum PakeError {
    /// This error results from an internal error during PRF construction
    ///
    #[error("Internal error during PRF verification: {0}")]
    CryptoError(InternalPakeError),
    /// This error occurs when the symmetric encryption fails
    #[error("Symmetric encryption failed.")]
    EncryptionError,
    /// This error occurs when the symmetric decryption fails
    #[error("Symmetric decryption failed.")]
    DecryptionError,
    /// This error occurs when the symmetric decryption's hmac check fails
    #[error("HMAC check in symmetric decryption failed.")]
    DecryptionHmacError,
    /// This error occurs when the server object that is being called finish() on is malformed
    #[error("Incomplete set of keys passed into finish() function")]
    IncompleteKeysError,
    #[error("The provided server public key doesn't match the encrypted one")]
    IncompatibleServerStaticPublicKeyError,
    #[error("Error in key exchange protocol when attempting to validate MACs")]
    KeyExchangeMacValidationError,
    #[error("Error in validating credentials")]
    InvalidLoginError,
}

// This is meant to express future(ly) non-trivial ways of converting the
// internal error into a PakeError
impl From<InternalPakeError> for PakeError {
    fn from(e: InternalPakeError) -> PakeError {
        PakeError::CryptoError(e)
    }
}

/// Represents an error in protocol handling
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// This error results from an error during password verification
    ///
    #[error("Internal error during password verification: {0}")]
    VerificationError(PakeError),
    /// This error occurs when the server answer cannot be handled
    #[error("Server response cannot be handled.")]
    ServerError,
    /// This error occurs when the client request cannot be handled
    #[error("Client request cannot be handled.")]
    ClientError,
}

// This is meant to express future(ly) non-trivial ways of converting the
// Pake error into a ProtocolError
impl From<PakeError> for ProtocolError {
    fn from(e: PakeError) -> ProtocolError {
        ProtocolError::VerificationError(e)
    }
}

// This is meant to express future(ly) non-trivial ways of converting the
// internal error into a ProtocolError
impl From<InternalPakeError> for ProtocolError {
    fn from(e: InternalPakeError) -> ProtocolError {
        ProtocolError::VerificationError(e.into())
    }
}

// See https://github.com/rust-lang/rust/issues/64715 and remove this when
// merged, and https://github.com/dtolnay/thiserror/issues/62 for why this
// comes up in our doc tests.
impl From<::std::convert::Infallible> for ProtocolError {
    fn from(_: ::std::convert::Infallible) -> Self {
        unreachable!()
    }
}

pub(crate) mod utils {
    use super::*;

    pub fn check_slice_size<'a>(
        slice: &'a [u8],
        expected_len: usize,
        arg_name: &'static str,
    ) -> Result<&'a [u8], InternalPakeError> {
        if slice.len() != expected_len {
            return Err(InternalPakeError::SizeError {
                name: arg_name,
                len: expected_len,
                actual_len: slice.len(),
            });
        }
        Ok(slice)
    }
}

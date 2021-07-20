// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! A list of error types which are produced during an execution of the protocol
use std::convert::Infallible;
use std::error::Error;
use std::fmt::Debug;

use displaydoc::Display;

/// Represents an error in the manipulation of internal cryptographic data
#[derive(Clone, Display, Eq, Hash, PartialEq)]
pub enum InternalPakeError<T = Infallible> {
    /// Custom [`SecretKey`](crate::keypair::SecretKey) error type
    Custom(T),
    /// Deserializing from a byte sequence failed
    InvalidByteSequence,
    /// Invalid length for {name}: expected {len}, but is actually {actual_len}.
    SizeError {
        /// name
        name: &'static str,
        /// length
        len: usize,
        /// actual
        actual_len: usize,
    },
    /// Could not decompress point.
    PointError,
    /// Key belongs to a small subgroup!
    SubGroupError,
    /// hashing to a key failed
    HashingFailure,
    /// Computing the hash-to-curve function failed
    HashToCurveError,
    /// Computing HKDF failed while deriving subkeys
    HkdfError,
    /// Computing HMAC failed while supplying a secret key
    HmacError,
    /// Computing the slow hashing function failed
    SlowHashError,
    /// This error occurs when the envelope seal fails
    /// Constructing the envelope seal failed.
    SealError,
    /// This error occurs when the envelope seal open fails
    /// Opening the envelope seal failed.
    SealOpenError,
    /// This error occurs when the envelope seal open hmac check fails
    /// HMAC check in seal open failed.
    SealOpenHmacError,
    /// This error occurs when the envelope cannot be constructed properly
    /// based on the credentials that were specified to be required.
    InvalidEnvelopeStructureError,
    /// This error occurs when attempting to open an envelope of the wrong
    /// type (base mode, custom identifier)
    IncompatibleEnvelopeModeError,
    /// This error occurs when the envelope is opened and deserialization
    /// fails
    UnexpectedEnvelopeContentsError,
}

impl<T: Debug> Debug for InternalPakeError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custom(custom) => f.debug_tuple("InvalidByteSequence").field(custom).finish(),
            Self::InvalidByteSequence => f.debug_tuple("InvalidByteSequence").finish(),
            Self::SizeError {
                name,
                len,
                actual_len,
            } => f
                .debug_struct("SizeError")
                .field("name", name)
                .field("len", len)
                .field("actual_len", actual_len)
                .finish(),
            Self::PointError => f.debug_tuple("PointError").finish(),
            Self::SubGroupError => f.debug_tuple("SubGroupError").finish(),
            Self::HashingFailure => f.debug_tuple("HashingFailure").finish(),
            Self::HashToCurveError => f.debug_tuple("HashToCurveError").finish(),
            Self::HkdfError => f.debug_tuple("HkdfError").finish(),
            Self::HmacError => f.debug_tuple("HmacError").finish(),
            Self::SlowHashError => f.debug_tuple("SlowHashError").finish(),
            Self::SealError => f.debug_tuple("SealError").finish(),
            Self::SealOpenError => f.debug_tuple("SealOpenError").finish(),
            Self::SealOpenHmacError => f.debug_tuple("SealOpenHmacError").finish(),
            Self::InvalidEnvelopeStructureError => {
                f.debug_tuple("InvalidEnvelopeStructureError").finish()
            }
            Self::IncompatibleEnvelopeModeError => {
                f.debug_tuple("IncompatibleEnvelopeModeError").finish()
            }
            Self::UnexpectedEnvelopeContentsError => {
                f.debug_tuple("UnexpectedEnvelopeContentsError").finish()
            }
        }
    }
}

impl<T: Error> Error for InternalPakeError<T> {}

impl InternalPakeError {
    /// Convert `InternalPakeError<Infallible>` into `InternalPakeError<T>
    pub fn into_custom<T>(self) -> InternalPakeError<T> {
        match self {
            Self::Custom(_) => unreachable!(),
            Self::InvalidByteSequence => InternalPakeError::InvalidByteSequence,
            Self::SizeError {
                name,
                len,
                actual_len,
            } => InternalPakeError::SizeError {
                name,
                len,
                actual_len,
            },
            Self::PointError => InternalPakeError::PointError,
            Self::SubGroupError => InternalPakeError::SubGroupError,
            Self::HashingFailure => InternalPakeError::HashingFailure,
            Self::HashToCurveError => InternalPakeError::HashToCurveError,
            Self::HkdfError => InternalPakeError::HkdfError,
            Self::HmacError => InternalPakeError::HmacError,
            Self::SlowHashError => InternalPakeError::SlowHashError,
            Self::SealError => InternalPakeError::SealError,
            Self::SealOpenError => InternalPakeError::SealOpenError,
            Self::SealOpenHmacError => InternalPakeError::SealOpenHmacError,
            Self::InvalidEnvelopeStructureError => InternalPakeError::InvalidEnvelopeStructureError,
            Self::IncompatibleEnvelopeModeError => InternalPakeError::IncompatibleEnvelopeModeError,
            Self::UnexpectedEnvelopeContentsError => {
                InternalPakeError::UnexpectedEnvelopeContentsError
            }
        }
    }
}

/// Represents an error in password checking
#[derive(Clone, Display, Eq, Hash, PartialEq)]
pub enum PakeError<T = Infallible> {
    /// This error results from an internal error during PRF construction
    ///
    /// Internal error during PRF verification: {0}
    CryptoError(InternalPakeError<T>),
    /// This error occurs when the server object that is being called finish() on is malformed
    /// Incomplete set of keys passed into finish() function
    IncompleteKeysError,
    /// The provided server public key doesn't match the sealed one
    IncompatibleServerStaticPublicKeyError,
    /// Error in key exchange protocol when attempting to validate MACs
    KeyExchangeMacValidationError,
    /// Error in validating credentials
    InvalidLoginError,
    /// Error with serializing / deserializing protocol messages
    SerializationError,
    /// Identity group element was encountered during deserialization, which is invalid
    IdentityGroupElementError,
}

impl<T: Debug> Debug for PakeError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CryptoError(internal_pake_error) => f
                .debug_tuple("CryptoError")
                .field(internal_pake_error)
                .finish(),
            Self::IncompleteKeysError => f.debug_tuple("IncompleteKeysError").finish(),
            Self::IncompatibleServerStaticPublicKeyError => f
                .debug_tuple("IncompatibleServerStaticPublicKeyError")
                .finish(),
            Self::KeyExchangeMacValidationError => {
                f.debug_tuple("KeyExchangeMacValidationError").finish()
            }
            Self::InvalidLoginError => f.debug_tuple("InvalidLoginError").finish(),
            Self::SerializationError => f.debug_tuple("SerializationError").finish(),
            Self::IdentityGroupElementError => f.debug_tuple("IdentityGroupElementError").finish(),
        }
    }
}

impl<T: Error> Error for PakeError<T> {}

// This is meant to express future(ly) non-trivial ways of converting the
// internal error into a PakeError
impl<T> From<InternalPakeError<T>> for PakeError<T> {
    fn from(e: InternalPakeError<T>) -> PakeError<T> {
        PakeError::CryptoError(e)
    }
}

impl PakeError {
    /// Convert `PakeError<Infallible>` into `PakeError<T>
    pub fn into_custom<T>(self) -> PakeError<T> {
        match self {
            Self::CryptoError(internal_pake_error) => {
                PakeError::CryptoError(internal_pake_error.into_custom())
            }
            Self::IncompleteKeysError => PakeError::IncompleteKeysError,
            Self::IncompatibleServerStaticPublicKeyError => {
                PakeError::IncompatibleServerStaticPublicKeyError
            }
            Self::KeyExchangeMacValidationError => PakeError::KeyExchangeMacValidationError,
            Self::InvalidLoginError => PakeError::InvalidLoginError,
            Self::SerializationError => PakeError::SerializationError,
            Self::IdentityGroupElementError => PakeError::IdentityGroupElementError,
        }
    }
}

/// Represents an error in protocol handling
#[derive(Clone, Display, Eq, Hash, PartialEq)]
pub enum ProtocolError<T = Infallible> {
    /// This error results from an error during password verification
    ///
    /// Internal error during password verification: {0}
    VerificationError(PakeError<T>),
    /// This error occurs when the inner envelope is malformed
    InvalidInnerEnvelopeError,
    /// This error occurs when the server answer cannot be handled
    /// Server response cannot be handled.
    ServerError,
    /// This error occurs when the server specifies an envelope credentials
    /// format that is invalid
    ServerInvalidEnvelopeCredentialsFormatError,
    /// This error occurs when the client request cannot be handled
    /// Client request cannot be handled.
    ClientError,
    /// This error occurs when the client detects that the server has
    /// reflected the OPRF value (beta == alpha)
    ReflectedValueError,
}

impl<T: Debug> Debug for ProtocolError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerificationError(pake_error) => f
                .debug_tuple("VerificationError")
                .field(pake_error)
                .finish(),
            Self::InvalidInnerEnvelopeError => f.debug_tuple("InvalidInnerEnvelopeError").finish(),
            Self::ServerError => f.debug_tuple("ServerError").finish(),
            Self::ServerInvalidEnvelopeCredentialsFormatError => f
                .debug_tuple("ServerInvalidEnvelopeCredentialsFormatError")
                .finish(),
            Self::ClientError => f.debug_tuple("ClientError").finish(),
            Self::ReflectedValueError => f.debug_tuple("ReflectedValueError").finish(),
        }
    }
}

impl<T: Error> Error for ProtocolError<T> {}

// This is meant to express future(ly) non-trivial ways of converting the
// Pake error into a ProtocolError
impl<T> From<PakeError<T>> for ProtocolError<T> {
    fn from(e: PakeError<T>) -> ProtocolError<T> {
        ProtocolError::VerificationError(e)
    }
}

// This is meant to express future(ly) non-trivial ways of converting the
// internal error into a ProtocolError
impl<T> From<InternalPakeError<T>> for ProtocolError<T> {
    fn from(e: InternalPakeError<T>) -> ProtocolError<T> {
        ProtocolError::VerificationError(e.into())
    }
}

// See https://github.com/rust-lang/rust/issues/64715 and remove this when
// merged, and https://github.com/dtolnay/thiserror/issues/62 for why this
// comes up in our doc tests.
impl<T> From<::std::convert::Infallible> for ProtocolError<T> {
    fn from(_: ::std::convert::Infallible) -> Self {
        unreachable!()
    }
}

impl ProtocolError {
    /// Convert `ProtocolError<Infallible>` into `ProtocolError<T>
    pub fn into_custom<T>(self) -> ProtocolError<T> {
        match self {
            Self::VerificationError(pake_error) => {
                ProtocolError::VerificationError(pake_error.into_custom())
            }
            Self::InvalidInnerEnvelopeError => ProtocolError::InvalidInnerEnvelopeError,
            Self::ServerError => ProtocolError::ServerError,
            Self::ServerInvalidEnvelopeCredentialsFormatError => {
                ProtocolError::ServerInvalidEnvelopeCredentialsFormatError
            }
            Self::ClientError => ProtocolError::ClientError,
            Self::ReflectedValueError => ProtocolError::ReflectedValueError,
        }
    }
}

impl<T> From<generic_bytes::TryFromSizedBytesError> for InternalPakeError<T> {
    fn from(_: generic_bytes::TryFromSizedBytesError) -> Self {
        InternalPakeError::InvalidByteSequence
    }
}

impl<T> From<generic_bytes::TryFromSizedBytesError> for PakeError<T> {
    fn from(e: generic_bytes::TryFromSizedBytesError) -> Self {
        PakeError::CryptoError(e.into())
    }
}

impl<T> From<generic_bytes::TryFromSizedBytesError> for ProtocolError<T> {
    fn from(e: generic_bytes::TryFromSizedBytesError) -> Self {
        PakeError::CryptoError(e.into()).into()
    }
}

pub(crate) mod utils {
    use super::*;

    pub fn check_slice_size<'a, T>(
        slice: &'a [u8],
        expected_len: usize,
        arg_name: &'static str,
    ) -> Result<&'a [u8], InternalPakeError<T>> {
        if slice.len() != expected_len {
            return Err(InternalPakeError::SizeError {
                name: arg_name,
                len: expected_len,
                actual_len: slice.len(),
            });
        }
        Ok(slice)
    }

    pub fn check_slice_size_atleast<'a>(
        slice: &'a [u8],
        expected_len: usize,
        arg_name: &'static str,
    ) -> Result<&'a [u8], InternalPakeError> {
        if slice.len() < expected_len {
            return Err(InternalPakeError::SizeError {
                name: arg_name,
                len: expected_len,
                actual_len: slice.len(),
            });
        }
        Ok(slice)
    }
}

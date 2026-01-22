// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! A list of error types which are produced during an execution of the protocol
use core::convert::Infallible;
use core::error::Error;
use core::fmt::Debug;

use displaydoc::Display;

/// Represents an error in the manipulation of internal cryptographic data
#[derive(Clone, Copy, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InternalError {
    /// Size of input is empty or longer then [`u16::MAX`].
    HashToScalar,
    /// Computing HKDF failed while deriving subkeys
    HkdfError,
    /// Computing HMAC failed while supplying a secret key
    HmacError,
    /// Computing the key stretching function failed
    KsfError,
    /// Error while performing a KEM operation
    KemError,
    /** This error occurs when the envelope seal open hmac check fails
    HMAC check in seal open failed. */
    SealOpenHmacError,
    /** This error occurs when attempting to open an envelope of the wrong
    type (base mode, custom identifier) */
    IncompatibleEnvelopeModeError,
    /// Error from the OPRF evaluation
    OprfError(voprf::Error),
    /// Error from the OPRF evaluation
    OprfInternalError(voprf::InternalError),
}

impl Debug for InternalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HashToScalar => f.debug_tuple("HashToScalar").finish(),
            Self::HkdfError => f.debug_tuple("HkdfError").finish(),
            Self::HmacError => f.debug_tuple("HmacError").finish(),
            Self::KsfError => f.debug_tuple("KsfError").finish(),
            Self::KemError => f.debug_tuple("KemError").finish(),
            Self::SealOpenHmacError => f.debug_tuple("SealOpenHmacError").finish(),
            Self::IncompatibleEnvelopeModeError => {
                f.debug_tuple("IncompatibleEnvelopeModeError").finish()
            }
            Self::OprfError(error) => f.debug_tuple("OprfError").field(error).finish(),
            Self::OprfInternalError(error) => {
                f.debug_tuple("OprfInternalError").field(error).finish()
            }
        }
    }
}

impl Error for InternalError {}

impl From<voprf::Error> for InternalError {
    fn from(voprf_error: voprf::Error) -> Self {
        Self::OprfError(voprf_error)
    }
}

impl From<voprf::Error> for ProtocolError {
    fn from(voprf_error: voprf::Error) -> Self {
        Self::LibraryError(InternalError::OprfError(voprf_error))
    }
}

impl From<voprf::InternalError> for ProtocolError {
    fn from(voprf_error: voprf::InternalError) -> Self {
        Self::LibraryError(InternalError::OprfInternalError(voprf_error))
    }
}

/// Represents an error in protocol handling
#[derive(Clone, Copy, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProtocolError<T = Infallible> {
    /// Internal error encountered
    LibraryError(InternalError),
    /// Error in validating credentials
    InvalidLoginError,
    /// Error with serializing / deserializing protocol messages
    SerializationError,
    /** Invalid length for `{name}`: expected {len}, actual {actual_len} */
    #[allow(clippy::doc_markdown, unused_assignments)]
    SizeError {
        /// name
        name: &'static str,
        /// length
        len: usize,
        /// actual
        actual_len: usize,
    },
    /** This error occurs when the client detects that the server has
    reflected the OPRF value (beta == alpha) */
    ReflectedValueError,
    /// Custom [`SecretKey`](crate::keypair::PrivateKeySerialization) error type
    Custom(T),
}

impl<T: Debug> Debug for ProtocolError<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LibraryError(pake_error) => {
                f.debug_tuple("LibraryError").field(pake_error).finish()
            }
            Self::InvalidLoginError => f.debug_tuple("InvalidLoginError").finish(),
            Self::SerializationError => f.debug_tuple("SerializationError").finish(),
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
            Self::ReflectedValueError => f.debug_tuple("ReflectedValueError").finish(),
            Self::Custom(custom) => f.debug_tuple("Custom").field(custom).finish(),
        }
    }
}

impl<T: Error> Error for ProtocolError<T> {}

// This is meant to express future(ly) non-trivial ways of converting the
// internal error into a ProtocolError
impl<T> From<InternalError> for ProtocolError<T> {
    fn from(e: InternalError) -> ProtocolError<T> {
        Self::LibraryError(e)
    }
}

// See https://github.com/rust-lang/rust/issues/64715 and remove this when merged,
// and https://github.com/dtolnay/thiserror/issues/62 for why this comes up in our
// doc tests.
impl<T> From<::core::convert::Infallible> for ProtocolError<T> {
    fn from(_: ::core::convert::Infallible) -> Self {
        unreachable!()
    }
}

impl ProtocolError {
    /// Convert `ProtocolError<Infallible>` into `ProtocolError<T>`
    pub fn into_custom<T>(self) -> ProtocolError<T> {
        match self {
            Self::LibraryError(internal_error) => ProtocolError::LibraryError(internal_error),
            Self::InvalidLoginError => ProtocolError::InvalidLoginError,
            Self::SerializationError => ProtocolError::SerializationError,
            Self::SizeError {
                name,
                len,
                actual_len,
            } => ProtocolError::SizeError {
                name,
                len,
                actual_len,
            },
            Self::ReflectedValueError => ProtocolError::ReflectedValueError,
        }
    }
}

// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Includes the [`Group`] trait and definitions for the key exchange groups

#[cfg(feature = "curve25519")]
pub mod curve25519;
#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(feature = "ed25519")]
pub mod ed25519;
pub mod eddsa;
pub mod elliptic_curve;
#[cfg(feature = "ristretto255")]
pub mod ristretto255;

use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::errors::{InternalError, ProtocolError};

const STR_OPAQUE_DERIVE_AUTH_KEY_PAIR: [u8; 33] = *b"OPAQUE-DeriveDiffieHellmanKeyPair";

/// A group representation for use in the key exchange
pub trait Group {
    /// Public key
    type Pk: Copy + Zeroize;
    /// Length of the public key
    type PkLen: ArrayLength<u8>;
    /// Secret key
    type Sk: Copy + Zeroize;
    /// Length of the secret key
    type SkLen: ArrayLength<u8>;

    /// Serializes `self`
    fn serialize_pk(pk: Self::Pk) -> GenericArray<u8, Self::PkLen>;

    /// Return a public key from its fixed-length bytes representation
    ///
    /// The deserialized bytes must be taken from `bytes`.
    fn deserialize_take_pk(bytes: &mut &[u8]) -> Result<Self::Pk, ProtocolError>;

    /// Generate a random secret key
    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk;

    /// Deterministically derive a [`Self::Sk`] from `seed`.
    fn derive_scalar(seed: GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError>;

    /// Return a public key from its secret key
    fn public_key(sk: Self::Sk) -> Self::Pk;

    /// Serializes `self`
    fn serialize_sk(sk: Self::Sk) -> GenericArray<u8, Self::SkLen>;

    /// Return a public key from its fixed-length bytes representation
    ///
    /// The deserialized bytes must be taken from `bytes`.
    fn deserialize_take_sk(bytes: &mut &[u8]) -> Result<Self::Sk, ProtocolError>;
}

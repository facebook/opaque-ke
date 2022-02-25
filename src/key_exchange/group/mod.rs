// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Includes the KeGroup trait and definitions for the key exchange groups

mod elliptic_curve;
#[cfg(feature = "ristretto255")]
pub mod ristretto255;
#[cfg(feature = "x25519")]
pub mod x25519;

use digest::core_api::BlockSizeUser;
use digest::Digest;
use generic_array::typenum::{IsLess, IsLessOrEqual, U256};
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::errors::InternalError;

/// A group representation for use in the key exchange
pub trait KeGroup {
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
    fn deserialize_pk(bytes: &GenericArray<u8, Self::PkLen>) -> Result<Self::Pk, InternalError>;

    /// Generate a random secret key
    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk;

    /// Hashes a slice of pseudo-random bytes to a scalar
    ///
    /// # Errors
    /// [`InternalError::HashToScalar`] if the `input` is empty or longer then
    /// [`u16::MAX`].
    fn hash_to_scalar<H>(input: &[&[u8]], dst: &[u8]) -> Result<Self::Sk, InternalError>
    where
        H: Digest + BlockSizeUser,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>;

    /// Return a public key from its secret key
    fn public_key(sk: Self::Sk) -> Self::Pk;

    /// Diffie-Hellman key exchange
    fn diffie_hellman(pk: Self::Pk, sk: Self::Sk) -> GenericArray<u8, Self::PkLen>;

    /// Serializes `self`
    fn serialize_sk(sk: Self::Sk) -> GenericArray<u8, Self::SkLen>;

    /// Return a public key from its fixed-length bytes representation
    fn deserialize_sk(bytes: &GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError>;
}

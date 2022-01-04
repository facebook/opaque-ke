// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Includes the KeGroup trait and definitions for the key exchange groups

use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};

use crate::errors::InternalError;

/// A group representation for use in the key exchange
pub trait KeGroup: Sized + Clone {
    /// Length of the public key
    type PkLen: ArrayLength<u8> + 'static;
    /// Length of the secret key
    type SkLen: ArrayLength<u8> + 'static;

    /// Return a public key from its fixed-length bytes representation
    fn from_pk_slice(element_bits: &GenericArray<u8, Self::PkLen>) -> Result<Self, InternalError>;

    /// Generate a random secret key
    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> GenericArray<u8, Self::SkLen>;

    /// Return a public key from its secret key
    fn public_key(sk: &GenericArray<u8, Self::SkLen>) -> Self;

    /// Serializes `self`
    fn to_arr(&self) -> GenericArray<u8, Self::PkLen>;

    /// Diffie-Hellman key exchange
    fn diffie_hellman(&self, sk: &GenericArray<u8, Self::SkLen>) -> GenericArray<u8, Self::PkLen>;
}

#[cfg(feature = "p256")]
pub mod p256;
#[cfg(feature = "ristretto255")]
pub mod ristretto255;
#[cfg(feature = "x25519")]
pub mod x25519;

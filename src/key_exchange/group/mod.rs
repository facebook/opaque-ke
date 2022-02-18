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

use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};

use crate::errors::InternalError;

/// A group representation for use in the key exchange
pub trait KeGroup {
    /// Public key
    type Pk: Clone + Sized;
    /// Length of the public key
    type PkLen: ArrayLength<u8> + 'static;
    /// Secret key
    type Sk: Clone + Sized;
    /// Length of the secret key
    type SkLen: ArrayLength<u8> + 'static;

    /// Serializes `self`
    fn serialize_pk(pk: &Self::Pk) -> GenericArray<u8, Self::PkLen>;

    /// Return a public key from its fixed-length bytes representation
    fn deserialize_pk(bytes: &GenericArray<u8, Self::PkLen>) -> Result<Self::Pk, InternalError>;

    /// Generate a random secret key
    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk;

    /// Return a public key from its secret key
    fn public_key(sk: &Self::Sk) -> Self::Pk;

    /// Diffie-Hellman key exchange
    fn diffie_hellman(pk: &Self::Pk, sk: &Self::Sk) -> GenericArray<u8, Self::PkLen>;

    /// Zeroize secret key on drop.
    fn zeroize_sk_on_drop(sk: &mut Self::Sk);

    /// Serializes `self`
    fn serialize_sk(sk: &Self::Sk) -> GenericArray<u8, Self::SkLen>;

    /// Return a public key from its fixed-length bytes representation
    fn deserialize_sk(bytes: &GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError>;
}

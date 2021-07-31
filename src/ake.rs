// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! A algorithm for the authenticated key exchange used in `KeyExchange`

use crate::errors::InternalPakeError;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use generic_array::typenum::U32;
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};

/// A algorithm for the authenticated key exchange used in `KeyExchange`
pub trait Ake: Sized {
    /// Length of the public key
    type PkLen: ArrayLength<u8> + 'static;
    /// Length of the secret key
    type SkLen: ArrayLength<u8> + 'static;

    /// Return a public key from its fixed-length bytes representation
    fn from_pk_slice(
        element_bits: &GenericArray<u8, Self::PkLen>,
    ) -> Result<Self, InternalPakeError>;

    /// Generate a random secret key
    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> GenericArray<u8, Self::SkLen>;

    /// Return a public key from its secret key
    fn public_key(sk: &GenericArray<u8, Self::SkLen>) -> Self;

    /// Serializes `self`
    fn to_arr(&self) -> GenericArray<u8, Self::PkLen>;

    /// Diffie-Hellman key exchange
    fn diffie_hellman(&self, sk: &GenericArray<u8, Self::SkLen>) -> GenericArray<u8, Self::PkLen>;
}

impl Ake for RistrettoPoint {
    type PkLen = U32;

    type SkLen = U32;

    fn from_pk_slice(
        element_bits: &GenericArray<u8, Self::PkLen>,
    ) -> Result<Self, InternalPakeError> {
        CompressedRistretto::from_slice(element_bits)
            .decompress()
            .ok_or(InternalPakeError::PointError)
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> GenericArray<u8, Self::SkLen> {
        loop {
            let scalar = {
                #[cfg(not(test))]
                {
                    let mut scalar_bytes = [0u8; 64];
                    rng.fill_bytes(&mut scalar_bytes);
                    Scalar::from_bytes_mod_order_wide(&scalar_bytes)
                }

                // Tests need an exact conversion from bytes to scalar, sampling only 32 bytes from rng
                #[cfg(test)]
                {
                    let mut scalar_bytes = [0u8; 32];
                    rng.fill_bytes(&mut scalar_bytes);
                    Scalar::from_bytes_mod_order(scalar_bytes)
                }
            };

            if scalar != Scalar::zero() {
                break scalar.to_bytes().into();
            }
        }
    }

    fn public_key(sk: &GenericArray<u8, Self::SkLen>) -> Self {
        RISTRETTO_BASEPOINT_POINT * Scalar::from_bits(*sk.as_ref())
    }

    fn to_arr(&self) -> GenericArray<u8, Self::PkLen> {
        self.compress().to_bytes().into()
    }

    fn diffie_hellman(&self, sk: &GenericArray<u8, Self::SkLen>) -> GenericArray<u8, Self::PkLen> {
        (self * Scalar::from_bits(*sk.as_ref())).to_arr()
    }
}

#[cfg(feature = "p256")]
impl Ake for p256_::ProjectivePoint {
    type PkLen = generic_array::typenum::U33;

    type SkLen = U32;

    fn from_pk_slice(
        element_bits: &GenericArray<u8, Self::PkLen>,
    ) -> Result<Self, InternalPakeError> {
        use p256_::elliptic_curve::group::GroupEncoding;

        Option::from(Self::from_bytes(element_bits)).ok_or(InternalPakeError::PointError)
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> GenericArray<u8, Self::SkLen> {
        use p256_::elliptic_curve::Field;

        p256_::Scalar::random(rng).into()
    }

    fn public_key(sk: &GenericArray<u8, Self::SkLen>) -> Self {
        Self::generator() * p256_::Scalar::from_bytes_reduced(sk)
    }

    fn to_arr(&self) -> GenericArray<u8, Self::PkLen> {
        use p256_::elliptic_curve::sec1::ToEncodedPoint;

        let mut bytes = self.to_affine().to_encoded_point(true).as_bytes().to_vec();
        bytes.resize(33, 0);
        *GenericArray::from_slice(&bytes)
    }

    fn diffie_hellman(&self, sk: &GenericArray<u8, Self::SkLen>) -> GenericArray<u8, Self::PkLen> {
        (self * &p256_::Scalar::from_bytes_reduced(sk)).to_arr()
    }
}

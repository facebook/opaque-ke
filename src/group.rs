// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Defines the Group trait to specify the underlying prime order group used in
//! OPAQUE's OPRF

use crate::errors::InternalPakeError;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use generic_array::{
    typenum::{U32, U64},
    ArrayLength, GenericArray,
};
use std::convert::TryInto;

use rand::{CryptoRng, RngCore};
use std::ops::Mul;
use zeroize::Zeroize;

/// A prime-order subgroup of a base field (EC, prime-order field ...). This
/// subgroup is noted additively — as in the draft RFC — in this trait.
pub trait Group: Copy + Sized + for<'a> Mul<&'a <Self as Group>::Scalar, Output = Self> {
    /// The type of base field scalars
    type Scalar: Zeroize + Copy;
    /// The byte length necessary to represent scalars
    type ScalarLen: ArrayLength<u8> + 'static;
    /// Return a scalar from its fixed-length bytes representation
    fn from_scalar_slice(
        scalar_bits: &GenericArray<u8, Self::ScalarLen>,
    ) -> Result<Self::Scalar, InternalPakeError>;
    /// picks a scalar at random
    fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar;
    /// Serializes a scalar to bytes
    fn scalar_as_bytes(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen>;
    /// The multiplicative inverse of this scalar
    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar;

    /// The byte length necessary to represent group elements
    type ElemLen: ArrayLength<u8> + 'static;
    /// Return an element from its fixed-length bytes representation
    fn from_element_slice(
        element_bits: &GenericArray<u8, Self::ElemLen>,
    ) -> Result<Self, InternalPakeError>;
    /// Serializes the `self` group element
    fn to_arr(&self) -> GenericArray<u8, Self::ElemLen>;

    /// Hashes points presumed to be uniformly random to the curve. The
    /// impl is allowed to perform additional hashes if it needs to, but this
    /// may not be necessary as this function is going to be called with the
    /// output of a kdf.
    type UniformBytesLen: ArrayLength<u8>;

    /// Hashes a slice of pseudo-random bytes of the correct length to a curve point
    fn hash_to_curve(
        uniform_bytes: &GenericArray<u8, Self::UniformBytesLen>,
    ) -> Result<Self, InternalPakeError>;

    /// Get the base point for the group
    fn base_point() -> Self;

    /// Multiply the point by a scalar, represented as a slice
    fn mult_by_slice(&self, scalar: &GenericArray<u8, Self::ScalarLen>) -> Self;

    /// Returns if the group element is equal to the identity (1)
    fn is_identity(&self) -> bool;

    /// Compares in constant time if the group elements are equal
    fn ct_equal(&self, other: &Self) -> bool;
}

/// The implementation of such a subgroup for Ristretto
impl Group for RistrettoPoint {
    type Scalar = Scalar;
    type ScalarLen = U32;
    fn from_scalar_slice(
        scalar_bits: &GenericArray<u8, Self::ScalarLen>,
    ) -> Result<Self::Scalar, InternalPakeError> {
        let mut bits = [0u8; 32];
        bits.copy_from_slice(scalar_bits);
        Ok(Scalar::from_bytes_mod_order(bits))
    }
    fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
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
                break scalar;
            }
        }
    }
    fn scalar_as_bytes(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
        scalar.to_bytes().into()
    }
    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    // The byte length necessary to represent group elements
    type ElemLen = U32;
    fn from_element_slice(
        element_bits: &GenericArray<u8, Self::ElemLen>,
    ) -> Result<Self, InternalPakeError> {
        CompressedRistretto::from_slice(element_bits)
            .decompress()
            .ok_or(InternalPakeError::PointError)
    }
    // serialization of a group element
    fn to_arr(&self) -> GenericArray<u8, Self::ElemLen> {
        let c = self.compress();
        *GenericArray::from_slice(c.as_bytes())
    }

    type UniformBytesLen = U64;
    fn hash_to_curve(
        uniform_bytes: &GenericArray<u8, Self::UniformBytesLen>,
    ) -> Result<Self, InternalPakeError> {
        // https://caniuse.rs/features/array_gt_32_impls
        let bits: [u8; 64] = {
            let mut bytes = [0u8; 64];
            bytes.copy_from_slice(uniform_bytes);
            bytes
        };
        Ok(RistrettoPoint::from_uniform_bytes(&bits))
    }

    fn base_point() -> Self {
        RISTRETTO_BASEPOINT_POINT
    }

    fn mult_by_slice(&self, scalar: &GenericArray<u8, Self::ScalarLen>) -> Self {
        let arr: [u8; 32] = scalar.as_slice().try_into().expect("Wrong length");
        self * Scalar::from_bits(arr)
    }

    /// Returns if the group element is equal to the identity (1)
    fn is_identity(&self) -> bool {
        self == &Self::identity()
    }

    fn ct_equal(&self, other: &Self) -> bool {
        constant_time_eq::constant_time_eq(&self.to_arr(), &other.to_arr())
    }
}

#[cfg(feature = "p256")]
impl Group for p256::ProjectivePoint {
    type ElemLen = generic_array::typenum::U33;
    type Scalar = p256::Scalar;
    type ScalarLen = U32;
    type UniformBytesLen = U32;

    fn from_scalar_slice(
        scalar_bits: &GenericArray<u8, Self::ScalarLen>,
    ) -> Result<Self::Scalar, InternalPakeError> {
        Ok(p256::Scalar::from_bytes_reduced(scalar_bits))
    }

    fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        use p256::elliptic_curve::Field;

        p256::Scalar::random(rng)
    }

    fn scalar_as_bytes(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
        scalar.into()
    }

    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        scalar.invert().unwrap_or(p256::Scalar::zero())
    }

    fn from_element_slice(
        element_bits: &GenericArray<u8, Self::ElemLen>,
    ) -> Result<Self, InternalPakeError> {
        use p256::elliptic_curve::group::GroupEncoding;

        Option::from(Self::from_bytes(element_bits)).ok_or(InternalPakeError::PointError)
    }

    fn to_arr(&self) -> GenericArray<u8, Self::ElemLen> {
        use p256::elliptic_curve::group::GroupEncoding;

        self.to_bytes()
    }

    fn hash_to_curve(
        uniform_bytes: &GenericArray<u8, Self::UniformBytesLen>,
    ) -> Result<Self, InternalPakeError> {
        use p256::elliptic_curve::sec1::FromEncodedPoint;

        Self::from_encoded_point(&p256::EncodedPoint::from_secret_key(
            &p256::SecretKey::new(p256::ScalarBytes::from_scalar(
                &p256::Scalar::from_bytes_reduced(uniform_bytes),
            )),
            true,
        ))
        .ok_or(InternalPakeError::PointError)
    }

    fn base_point() -> Self {
        Self::generator()
    }

    fn mult_by_slice(&self, scalar: &GenericArray<u8, Self::ScalarLen>) -> Self {
        self * &p256::Scalar::from_bytes_reduced(scalar)
    }

    fn is_identity(&self) -> bool {
        self == &p256::ProjectivePoint::identity()
    }
    fn ct_equal(&self, other: &Self) -> bool {
        constant_time_eq::constant_time_eq(&self.to_arr(), &other.to_arr())
    }
}

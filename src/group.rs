// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Defines the Group trait to specify the underlying prime order group used in
//! OPAQUE's OPRF

use crate::errors::InternalPakeError;

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use digest::Digest;
use generic_array::{
    typenum::{U32, U64},
    ArrayLength, GenericArray,
};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use std::ops::Mul;
use zeroize::Zeroize;

/// A prime-order subgroup of a base field (EC, prime-order field ...). This
/// subgroup is noted additively — as in the draft RFC — in this trait.
pub trait Group: Sized + for<'a> Mul<&'a <Self as Group>::Scalar, Output = Self> {
    /// The type of base field scalars
    type Scalar: Zeroize;
    /// The byte length necessary to represent scalars
    type ScalarLen: ArrayLength<u8>;
    /// Return a scalat from its fixed-length bytes representation
    fn from_scalar_slice(
        scalar_bits: &GenericArray<u8, Self::ScalarLen>,
    ) -> Result<Self::Scalar, InternalPakeError>;
    /// picks a scalar at random
    fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar;
    /// Serializes a scalar to bytes
    fn scalar_as_bytes(scalar: &Self::Scalar) -> &GenericArray<u8, Self::ScalarLen>;
    /// The multiplicative inverse of this scalar
    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar;

    /// The byte length necessary to represent group elements
    type ElemLen: ArrayLength<u8>;
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
    fn hash_to_curve(uniform_bytes: &GenericArray<u8, Self::UniformBytesLen>) -> Self;
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
    fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Scalar::random(rng)
    }
    fn scalar_as_bytes(scalar: &Self::Scalar) -> &GenericArray<u8, Self::ScalarLen> {
        GenericArray::from_slice(scalar.as_bytes())
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
            .ok_or_else(|| InternalPakeError::PointError)
    }
    // serialization of a group element
    fn to_arr(&self) -> GenericArray<u8, Self::ElemLen> {
        let c = self.compress();
        *GenericArray::from_slice(c.as_bytes())
    }

    type UniformBytesLen = U64;
    fn hash_to_curve(uniform_bytes: &GenericArray<u8, Self::UniformBytesLen>) -> Self {
        let mut bits = [0u8; 64];
        bits.copy_from_slice(&uniform_bytes);

        RistrettoPoint::from_uniform_bytes(&bits)
    }
}

/// The implementation of such a subgroup for points on the large Curve25519-subgroup
impl Group for EdwardsPoint {
    type Scalar = Scalar;
    type ScalarLen = U32;
    fn from_scalar_slice(
        scalar_bits: &GenericArray<u8, Self::ScalarLen>,
    ) -> Result<Self::Scalar, InternalPakeError> {
        let mut bits = [0u8; 32];
        bits.copy_from_slice(scalar_bits);
        Ok(Scalar::from_bytes_mod_order(bits))
    }
    fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Scalar::random(rng)
    }
    fn scalar_as_bytes(scalar: &Self::Scalar) -> &GenericArray<u8, Self::ScalarLen> {
        GenericArray::from_slice(scalar.as_bytes())
    }
    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    // The byte length necessary to represent group elements
    type ElemLen = U32;
    fn from_element_slice(
        element_bits: &GenericArray<u8, Self::ElemLen>,
    ) -> Result<Self, InternalPakeError> {
        let point = CompressedEdwardsY::from_slice(element_bits)
            .decompress()
            .ok_or_else(|| InternalPakeError::PointError)?;

        if point.is_small_order() {
            return Err(InternalPakeError::SubGroupError);
        }
        Ok(point)
    }
    // serialization of a group element
    fn to_arr(&self) -> GenericArray<u8, Self::ElemLen> {
        let c = self.compress();
        *GenericArray::from_slice(c.as_bytes())
    }

    type UniformBytesLen = U32;
    fn hash_to_curve(uniform_bytes: &GenericArray<u8, Self::UniformBytesLen>) -> Self {
        const HASH_SIZE: usize = 32;
        let mut result = [0u8; HASH_SIZE];
        let mut counter = 0;
        let mut wrapped_point: Option<EdwardsPoint> = None;

        while wrapped_point.is_none() {
            result.copy_from_slice(
                &Sha256::new()
                    .chain(&uniform_bytes[..HASH_SIZE])
                    .chain(&[counter])
                    .finalize()[..HASH_SIZE],
            );
            wrapped_point = CompressedEdwardsY::from_slice(&result).decompress();
            counter += 1;
        }

        wrapped_point
            .expect("guarded by loop exit condition")
            .mul_by_cofactor()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};

    const EIGHT_TORSION: [[u8; 32]; 8] = [
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250,
            44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 128,
        ],
        [
            38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223,
            172, 5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 5,
        ],
        [
            236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
        ],
        [
            38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223,
            172, 5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 133,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250,
            44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 250,
        ],
    ];

    fn deserialize_point(pt: &[u8]) -> Result<EdwardsPoint> {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&pt[..32]);

        curve25519_dalek::edwards::CompressedEdwardsY(bytes)
            .decompress()
            .ok_or_else(|| anyhow!("Point decompression failed!"))
    }

    #[test]
    fn test_small_subgroup_edwards() {
        for i in 0..8 {
            let pt = &EIGHT_TORSION[i][..];
            assert!(deserialize_point(&pt).is_ok());
            assert!(EdwardsPoint::from_element_slice(GenericArray::from_slice(&pt)).is_err());
        }
    }
}

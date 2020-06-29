// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::InternalPakeError;

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use generic_array::{typenum::U32, ArrayLength, GenericArray};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
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
    fn to_bytes(&self) -> GenericArray<u8, Self::ElemLen>;

    /// Hashes points presumed to be uniformly random to the curve. The
    /// impl is allowed to perform additional hashes if it needs to, but this
    /// may not be necessary as this function is going to be called with the
    /// output of a kdf.
    fn hash_to_curve(input: &[u8], pepper: Option<&[u8]>) -> Self;
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
    fn to_bytes(&self) -> GenericArray<u8, Self::ElemLen> {
        let c = self.compress();
        *GenericArray::from_slice(c.as_bytes())
    }

    fn hash_to_curve(input: &[u8], pepper: Option<&[u8]>) -> Self {
        // This is because RistrettoPoint is on an obsolete sha2 version
        let mut bits = [0u8; 64];
        let mut hasher = Sha512::new();
        hasher.update(input);
        if let Some(value) = pepper {
            hasher.update(value)
        }
        bits.copy_from_slice(&hasher.finalize());

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
        CompressedEdwardsY::from_slice(element_bits)
            .decompress()
            .ok_or_else(|| InternalPakeError::PointError)
    }
    // serialization of a group element
    fn to_bytes(&self) -> GenericArray<u8, Self::ElemLen> {
        let c = self.compress();
        *GenericArray::from_slice(c.as_bytes())
    }

    fn hash_to_curve(input: &[u8], pepper: Option<&[u8]>) -> Self {
        let (hashed_input, _) = Hkdf::<Sha256>::extract(pepper, &input);
        let mut result = [0u8; 32];
        let mut counter = 0;
        let mut wrapped_point: Option<EdwardsPoint> = None;

        while wrapped_point.is_none() {
            result.copy_from_slice(
                &Sha256::new()
                    .chain(&hashed_input[..32])
                    .chain(&[counter])
                    .finalize()[..32],
            );
            wrapped_point = CompressedEdwardsY::from_slice(&result).decompress();
            counter += 1;
        }

        wrapped_point
            .expect("guarded by loop exit condition")
            .mul_by_cofactor()
    }
}

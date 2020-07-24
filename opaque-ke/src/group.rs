// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Defines the Group trait to specify the underlying prime order group used in
//! OPAQUE's OPRF

use crate::{errors::InternalPakeError, keypair::SizedBytes};

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use generic_array::{
    typenum::{U32, U64},
    ArrayLength, GenericArray,
};
use rand_core::{CryptoRng, RngCore};

use sha2::{Digest, Sha256};

use std::ops::Mul;
use zeroize::Zeroize;

/// A prime-order subgroup of a base field (EC, prime-order field ...). This
/// subgroup is noted additively — as in the draft RFC — in this trait.
pub trait Group:
    Sized + for<'a> Mul<&'a <Self as Group>::Scalar, Output = Self> + SizedBytes
{
    /// The type of base field scalars
    type Scalar: Zeroize + SizedBytes;
    /// picks a scalar at random
    fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar;
    /// The multiplicative inverse of this scalar
    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar;

    // Proxy functions for Self::Scalar
    /// Deserialize a scalar from a correctly-sized slice, proxy for Scalar::form_arr
    fn scalar_from_slice(
        arr: &GenericArray<u8, <Self::Scalar as SizedBytes>::Len>,
    ) -> Result<Self::Scalar, InternalPakeError> {
        <Self::Scalar as SizedBytes>::from_arr(arr)
    }
    /// Serialize a scalar to a correctly-sized slice, proxy for Scalar::to_arr
    fn to_scalar_slice(
        scalar: &Self::Scalar,
    ) -> GenericArray<u8, <Self::Scalar as SizedBytes>::Len> {
        <Self::Scalar as SizedBytes>::to_arr(&scalar)
    }

    /// Hashes points presumed to be uniformly random to the curve. The
    /// impl is allowed to perform additional hashes if it needs to, but this
    /// may not be necessary as this function is going to be called with the
    /// output of a kdf.
    type UniformBytesLen: ArrayLength<u8>;
    /// Hashes a slice of pseudo-random bytes of the correct length to a curve point
    fn hash_to_curve(uniform_bytes: &GenericArray<u8, Self::UniformBytesLen>) -> Self;
}

impl SizedBytes for Scalar {
    type Len = U32;

    fn from_arr(arr: &GenericArray<u8, Self::Len>) -> Result<Self, InternalPakeError> {
        let mut bits = [0u8; 32];
        bits.copy_from_slice(arr);
        Ok(Scalar::from_bytes_mod_order(bits))
    }

    fn to_arr(&self) -> GenericArray<u8, Self::Len> {
        *GenericArray::from_slice(self.as_bytes())
    }
}

impl SizedBytes for RistrettoPoint {
    type Len = U32;

    fn from_arr(arr: &GenericArray<u8, Self::Len>) -> Result<Self, InternalPakeError> {
        CompressedRistretto::from_slice(arr)
            .decompress()
            .ok_or_else(|| InternalPakeError::PointError)
    }

    fn to_arr(&self) -> GenericArray<u8, Self::Len> {
        *GenericArray::from_slice(self.compress().as_bytes())
    }
}

/// The implementation of such a subgroup for Ristretto
impl Group for RistrettoPoint {
    type Scalar = Scalar;
    fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Scalar::random(rng)
    }
    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    type UniformBytesLen = U64;
    fn hash_to_curve(uniform_bytes: &GenericArray<u8, Self::UniformBytesLen>) -> Self {
        // This is because RistrettoPoint is on an obsolete sha2 version, see https://github.com/dalek-cryptography/curve25519-dalek/pull/327
        let mut bits = [0u8; 64];
        let mut hasher = sha2::Sha512::new();
        hasher.update(uniform_bytes);
        bits.copy_from_slice(&hasher.finalize());

        RistrettoPoint::from_uniform_bytes(&bits)
    }
}

impl SizedBytes for EdwardsPoint {
    type Len = U32;

    fn from_arr(arr: &GenericArray<u8, Self::Len>) -> Result<Self, InternalPakeError> {
        CompressedEdwardsY::from_slice(arr)
            .decompress()
            .ok_or_else(|| InternalPakeError::PointError)
    }

    fn to_arr(&self) -> GenericArray<u8, Self::Len> {
        *GenericArray::from_slice(self.compress().as_bytes())
    }
}

/// The implementation of such a subgroup for points on the large Curve25519-subgroup
impl Group for EdwardsPoint {
    type Scalar = Scalar;
    fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Scalar::random(rng)
    }
    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    type UniformBytesLen = U32;
    fn hash_to_curve(uniform_bytes: &GenericArray<u8, Self::UniformBytesLen>) -> Self {
        let mut result = [0u8; 32];
        let mut counter = 0;
        let mut wrapped_point: Option<EdwardsPoint> = None;

        while wrapped_point.is_none() {
            result.copy_from_slice(
                &Sha256::new()
                    .chain(&uniform_bytes[..32])
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

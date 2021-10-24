// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Key Exchange group implementation for p256

use super::KeGroup;
use crate::errors::InternalError;
use generic_array::typenum::{U32, U33};
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};

impl KeGroup for p256_::ProjectivePoint {
    type PkLen = U33;
    type SkLen = U32;

    fn from_pk_slice(element_bits: &GenericArray<u8, Self::PkLen>) -> Result<Self, InternalError> {
        use p256_::elliptic_curve::group::GroupEncoding;

        Option::from(Self::from_bytes(element_bits)).ok_or(InternalError::PointError)
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

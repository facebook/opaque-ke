// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Key Exchange group implementation for p256

use super::KeGroup;
use crate::errors::InternalError;
use generic_array::typenum::{U32, U33};
use generic_array::GenericArray;
use p256_::elliptic_curve::group::GroupEncoding;
use p256_::elliptic_curve::sec1::ToEncodedPoint;
use p256_::elliptic_curve::{PublicKey, SecretKey};
use p256_::NistP256;
use rand::{CryptoRng, RngCore};

impl KeGroup for PublicKey<NistP256> {
    type PkLen = U33;
    type SkLen = U32;

    fn from_pk_slice(element_bits: &GenericArray<u8, Self::PkLen>) -> Result<Self, InternalError> {
        Self::from_sec1_bytes(element_bits).map_err(|_| InternalError::PointError)
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> GenericArray<u8, Self::SkLen> {
        SecretKey::<NistP256>::random(rng).to_bytes()
    }

    fn public_key(sk: &GenericArray<u8, Self::SkLen>) -> Self {
        SecretKey::<NistP256>::from_bytes(sk).unwrap().public_key()
    }

    fn to_arr(&self) -> GenericArray<u8, Self::PkLen> {
        GenericArray::clone_from_slice(self.to_encoded_point(true).as_bytes())
    }

    fn diffie_hellman(&self, sk: &GenericArray<u8, Self::SkLen>) -> GenericArray<u8, Self::PkLen> {
        (self.to_projective()
            * SecretKey::<NistP256>::from_bytes(sk)
                .unwrap()
                .to_secret_scalar()
                .as_ref())
        .to_affine()
        .to_bytes()
    }
}

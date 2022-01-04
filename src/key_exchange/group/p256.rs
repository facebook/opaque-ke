// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Key Exchange group implementation for p256

use generic_array::typenum::{U32, U33};
use generic_array::GenericArray;
use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::{PublicKey, SecretKey};
use p256::NistP256;
use rand::{CryptoRng, RngCore};

use super::KeGroup;
use crate::errors::InternalError;

impl KeGroup for NistP256 {
    type Pk = PublicKey<Self>;
    type PkLen = U33;
    type Sk = SecretKey<Self>;
    type SkLen = U32;
    fn serialize_pk(pk: &Self::Pk) -> GenericArray<u8, Self::PkLen> {
        GenericArray::clone_from_slice(pk.to_encoded_point(true).as_bytes())
    }

    fn deserialize_pk(bytes: &GenericArray<u8, Self::PkLen>) -> Result<Self::Pk, InternalError> {
        Self::Pk::from_sec1_bytes(bytes).map_err(|_| InternalError::PointError)
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk {
        SecretKey::<NistP256>::random(rng)
    }

    fn public_key(sk: &Self::Sk) -> Self::Pk {
        sk.public_key()
    }

    fn diffie_hellman(pk: &Self::Pk, sk: &Self::Sk) -> GenericArray<u8, Self::PkLen> {
        (pk.to_projective() * sk.to_nonzero_scalar().as_ref())
            .to_affine()
            .to_bytes()
    }

    fn zeroize_sk_on_drop(_: &mut Self::Sk) {}

    fn serialize_sk(sk: &Self::Sk) -> GenericArray<u8, Self::SkLen> {
        sk.to_be_bytes()
    }

    fn deserialize_sk(bytes: &GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError> {
        Self::Sk::from_be_bytes(bytes).map_err(|_| InternalError::PointError)
    }
}

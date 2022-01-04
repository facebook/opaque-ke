// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Key Exchange group implementation for ristretto255

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use generic_array::typenum::U32;
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::KeGroup;
use crate::errors::InternalError;

/// Implementation for Ristretto255.
pub struct Ristretto255;

impl KeGroup for Ristretto255 {
    type Pk = RistrettoPoint;
    type PkLen = U32;
    type Sk = Scalar;
    type SkLen = U32;

    fn serialize_pk(pk: &Self::Pk) -> GenericArray<u8, Self::PkLen> {
        pk.compress().to_bytes().into()
    }

    fn deserialize_pk(bytes: &GenericArray<u8, Self::PkLen>) -> Result<Self::Pk, InternalError> {
        CompressedRistretto::from_slice(bytes)
            .decompress()
            .ok_or(InternalError::PointError)
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk {
        loop {
            let scalar = {
                #[cfg(not(test))]
                {
                    let mut scalar_bytes = [0u8; 64];
                    rng.fill_bytes(&mut scalar_bytes);
                    Scalar::from_bytes_mod_order_wide(&scalar_bytes)
                }

                // Tests need an exact conversion from bytes to scalar, sampling only 32 bytes
                // from rng
                #[cfg(test)]
                {
                    let mut scalar_bytes = [0u8; 32];
                    rng.fill_bytes(&mut scalar_bytes);
                    Scalar::from_bytes_mod_order(scalar_bytes)
                }
            };

            if scalar != Scalar::zero() && scalar.is_canonical() {
                break scalar;
            }
        }
    }

    fn public_key(sk: &Self::Sk) -> Self::Pk {
        RISTRETTO_BASEPOINT_POINT * sk
    }

    fn diffie_hellman(pk: &Self::Pk, sk: &Self::Sk) -> GenericArray<u8, Self::PkLen> {
        Self::serialize_pk(&(pk * sk))
    }

    fn zeroize_sk_on_drop(sk: &mut Self::Sk) {
        sk.zeroize()
    }

    fn serialize_sk(sk: &Self::Sk) -> GenericArray<u8, Self::SkLen> {
        sk.to_bytes().into()
    }

    fn deserialize_sk(bytes: &GenericArray<u8, Self::PkLen>) -> Result<Self::Sk, InternalError> {
        // TODO: When we implement `hash_to_field` we can re-enable this again.
        //Scalar::from_canonical_bytes((*bytes).into()).ok_or(InternalError::
        // PointError)

        Ok(Scalar::from_bits((*bytes).into()))
    }
}

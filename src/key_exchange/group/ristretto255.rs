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

use super::KeGroup;
use crate::errors::InternalError;

impl KeGroup for RistrettoPoint {
    type PkLen = U32;
    type SkLen = U32;

    fn from_pk_slice(element_bits: &GenericArray<u8, Self::PkLen>) -> Result<Self, InternalError> {
        CompressedRistretto::from_slice(element_bits)
            .decompress()
            .ok_or(InternalError::PointError)
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

                // Tests need an exact conversion from bytes to scalar, sampling only 32 bytes
                // from rng
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

    fn diffie_hellman(&self, sk: &GenericArray<u8, Self::SkLen>) -> GenericArray<u8, Self::SkLen> {
        (self * Scalar::from_bits(*sk.as_ref())).to_arr()
    }
}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Key Exchange group implementation for X25519

use generic_array::typenum::U32;
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

use super::KeGroup;
use crate::errors::InternalError;

/// The implementation of such a subgroup for Ristretto
impl KeGroup for PublicKey {
    type PkLen = U32;
    type SkLen = U32;

    fn from_pk_slice(element_bits: &GenericArray<u8, Self::PkLen>) -> Result<Self, InternalError> {
        Ok(Self::from(<[u8; 32]>::from(*element_bits)))
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> GenericArray<u8, Self::SkLen> {
        let mut scalar_bytes = [0u8; 32];

        loop {
            rng.fill_bytes(&mut scalar_bytes);

            if scalar_bytes != [0u8; 32] {
                break StaticSecret::from(scalar_bytes).to_bytes().into();
            }
        }
    }

    fn public_key(sk: &GenericArray<u8, Self::SkLen>) -> Self {
        Self::from(&StaticSecret::from(<[u8; 32]>::from(*sk)))
    }

    fn to_arr(&self) -> GenericArray<u8, Self::PkLen> {
        self.to_bytes().into()
    }

    fn diffie_hellman(&self, sk: &GenericArray<u8, Self::SkLen>) -> GenericArray<u8, Self::SkLen> {
        StaticSecret::from(<[u8; 32]>::from(*sk))
            .diffie_hellman(self)
            .to_bytes()
            .into()
    }
}

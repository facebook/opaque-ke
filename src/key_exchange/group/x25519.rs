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
use zeroize::Zeroize;

use super::KeGroup;
use crate::errors::InternalError;

/// Implementation for X25519.
pub struct X25519;

/// The implementation of such a subgroup for Ristretto
impl KeGroup for X25519 {
    type Pk = PublicKey;
    type PkLen = U32;
    type Sk = StaticSecret;
    type SkLen = U32;

    fn serialize_pk(pk: &Self::Pk) -> GenericArray<u8, Self::PkLen> {
        pk.to_bytes().into()
    }

    fn deserialize_pk(bytes: &GenericArray<u8, Self::PkLen>) -> Result<Self::Pk, InternalError> {
        if **bytes == [0; 32] {
            Err(InternalError::PointError)
        } else {
            Ok(PublicKey::from(<[_; 32]>::from(*bytes)))
        }
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk {
        let mut scalar_bytes = [0u8; 32];

        loop {
            rng.fill_bytes(&mut scalar_bytes);

            if scalar_bytes != [0u8; 32] {
                break StaticSecret::from(scalar_bytes);
            }
        }
    }

    fn public_key(sk: &Self::Sk) -> Self::Pk {
        PublicKey::from(sk)
    }

    fn diffie_hellman(pk: &Self::Pk, sk: &Self::Sk) -> GenericArray<u8, Self::PkLen> {
        sk.diffie_hellman(pk).to_bytes().into()
    }

    fn zeroize_sk_on_drop(sk: &mut Self::Sk) {
        sk.zeroize()
    }

    fn serialize_sk(sk: &Self::Sk) -> GenericArray<u8, Self::SkLen> {
        sk.to_bytes().into()
    }

    fn deserialize_sk(bytes: &GenericArray<u8, Self::PkLen>) -> Result<Self::Sk, InternalError> {
        if **bytes == [0; 32] {
            Err(InternalError::PointError)
        } else {
            let sk = StaticSecret::from(<[u8; 32]>::from(*bytes));

            // TODO: When we implement `hash_to_field` we can re-enable this again.
            // If any clamping was applied.
            //if sk.to_bytes() == **bytes {
            //    Ok(sk)
            //} else {
            //    Err(InternalError::PointError)
            //}

            Ok(sk)
        }
    }
}

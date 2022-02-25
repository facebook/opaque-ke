// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Key Exchange group implementation for X25519

use curve25519_dalek_3::scalar::Scalar;
use digest::core_api::BlockSizeUser;
use digest::Digest;
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use generic_array::typenum::{IsLess, IsLessOrEqual, U256, U32, U64};
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

    // Implements the `HashToScalar()` function from
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-4.1
    fn hash_to_scalar<'a, H>(input: &[&[u8]], dst: &[u8]) -> Result<Self::Sk, InternalError>
    where
        H: Digest + BlockSizeUser,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        let mut uniform_bytes = GenericArray::<_, U64>::default();
        ExpandMsgXmd::<H>::expand_message(input, dst, 64)
            .map_err(|_| InternalError::HashToScalar)?
            .fill_bytes(&mut uniform_bytes);

        Ok(StaticSecret::from(
            Scalar::from_bytes_mod_order_wide(&uniform_bytes.into()).to_bytes(),
        ))
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

            if sk.to_bytes() == **bytes {
                Ok(sk)
            } else {
                Err(InternalError::PointError)
            }
        }
    }
}

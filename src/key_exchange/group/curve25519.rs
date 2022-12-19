// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Key Exchange group implementation for Curve25519

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use digest::core_api::BlockSizeUser;
use digest::Digest;
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use generic_array::typenum::{IsLess, IsLessOrEqual, U256, U32, U64};
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use super::KeGroup;
use crate::errors::InternalError;

/// Implementation for Curve25519.
pub struct Curve25519;

/// The implementation of such a subgroup for Curve25519
impl KeGroup for Curve25519 {
    type Pk = MontgomeryPoint;
    type PkLen = U32;
    type Sk = Scalar;
    type SkLen = U32;

    fn serialize_pk(pk: Self::Pk) -> GenericArray<u8, Self::PkLen> {
        pk.to_bytes().into()
    }

    fn deserialize_pk(bytes: &[u8]) -> Result<Self::Pk, InternalError> {
        bytes
            .try_into()
            .ok()
            .map(MontgomeryPoint)
            .filter(|pk| pk != &MontgomeryPoint::identity())
            .ok_or(InternalError::PointError)
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk {
        loop {
            let scalar = Scalar::random(rng);

            if scalar != Scalar::ZERO {
                break scalar;
            }
        }
    }

    // Implements the `HashToScalar()` function from
    // <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-09.html#section-4.1>
    fn hash_to_scalar<'a, H>(input: &[&[u8]], dst: &[u8]) -> Result<Self::Sk, InternalError>
    where
        H: Digest + BlockSizeUser,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        let mut uniform_bytes = GenericArray::<_, U64>::default();
        ExpandMsgXmd::<H>::expand_message(input, dst, 64)
            .map_err(|_| InternalError::HashToScalar)?
            .fill_bytes(&mut uniform_bytes);

        let scalar = Scalar::from_bytes_mod_order_wide(&uniform_bytes.into());

        if scalar == Scalar::ZERO {
            Err(InternalError::HashToScalar)
        } else {
            Ok(scalar)
        }
    }

    fn is_zero_scalar(scalar: Self::Sk) -> subtle::Choice {
        scalar.ct_eq(&Scalar::ZERO)
    }

    fn public_key(sk: Self::Sk) -> Self::Pk {
        (&ED25519_BASEPOINT_TABLE * &sk).to_montgomery()
    }

    fn diffie_hellman(pk: Self::Pk, sk: Self::Sk) -> GenericArray<u8, Self::PkLen> {
        Self::serialize_pk(sk * pk)
    }

    fn serialize_sk(sk: Self::Sk) -> GenericArray<u8, Self::SkLen> {
        sk.to_bytes().into()
    }

    fn deserialize_sk(bytes: &[u8]) -> Result<Self::Sk, InternalError> {
        bytes
            .try_into()
            .ok()
            .and_then(|bytes| Scalar::from_canonical_bytes(bytes).into())
            .filter(|scalar| scalar != &Scalar::ZERO)
            .ok_or(InternalError::PointError)
    }
}

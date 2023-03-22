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
use digest::{FixedOutput, HashMarker, OutputSizeUser};
use generic_array::typenum::{IsLess, IsLessOrEqual, U256, U32};
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
                break Scalar::from_bits_clamped(scalar.to_bytes());
            }
        }
    }

    fn hash_to_scalar<'a, H>(_input: &[&[u8]], _dst: &[&[u8]]) -> Result<Self::Sk, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        unimplemented!()
    }

    fn derive_auth_keypair<CS: voprf::CipherSuite>(
        seed: GenericArray<u8, Self::SkLen>,
        _info: &[u8],
    ) -> Result<Self::Sk, InternalError>
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        Ok(Scalar::from_bits_clamped(seed.into()))
    }

    fn is_zero_scalar(scalar: Self::Sk) -> subtle::Choice {
        scalar.ct_eq(&Scalar::ZERO)
    }

    fn public_key(sk: Self::Sk) -> Self::Pk {
        (ED25519_BASEPOINT_TABLE * &sk).to_montgomery()
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
            .map(Scalar::from_bits_clamped)
            .filter(|scalar| scalar != &Scalar::ZERO)
            .ok_or(InternalError::PointError)
    }
}

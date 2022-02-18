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
use digest::core_api::BlockSizeUser;
use digest::OutputSizeUser;
use generic_array::typenum::{IsLess, IsLessOrEqual, U256, U32};
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};
use voprf::Group;
use zeroize::Zeroize;

use super::KeGroup;
use crate::errors::InternalError;

/// Implementation for Ristretto255.
// This is necessary because Rust lacks specialization, otherwise we could
// implement `KeGroup` for `voprf::Ristretto255`.
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
        Scalar::from_canonical_bytes((*bytes).into()).ok_or(InternalError::PointError)
    }
}

#[cfg(feature = "ristretto255_voprf")]
impl voprf::CipherSuite for Ristretto255 {
    const ID: u16 = voprf::Ristretto255::ID;

    type Group = <voprf::Ristretto255 as voprf::CipherSuite>::Group;

    type Hash = <voprf::Ristretto255 as voprf::CipherSuite>::Hash;
}

impl Group for Ristretto255 {
    type Elem = <voprf::Ristretto255 as Group>::Elem;

    type ElemLen = <voprf::Ristretto255 as Group>::ElemLen;

    type Scalar = <voprf::Ristretto255 as Group>::Scalar;

    type ScalarLen = <voprf::Ristretto255 as Group>::ScalarLen;

    fn hash_to_curve<CS: voprf::CipherSuite>(
        input: &[&[u8]],
        dst: &[u8],
    ) -> voprf::Result<Self::Elem, voprf::InternalError>
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        <voprf::Ristretto255 as Group>::hash_to_curve::<CS>(input, dst)
    }

    fn hash_to_scalar<CS: voprf::CipherSuite>(
        input: &[&[u8]],
        dst: &[u8],
    ) -> voprf::Result<Self::Scalar, voprf::InternalError>
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        <voprf::Ristretto255 as Group>::hash_to_scalar::<CS>(input, dst)
    }

    fn base_elem() -> Self::Elem {
        <voprf::Ristretto255 as Group>::base_elem()
    }

    fn identity_elem() -> Self::Elem {
        <voprf::Ristretto255 as Group>::identity_elem()
    }

    fn serialize_elem(elem: Self::Elem) -> GenericArray<u8, Self::ElemLen> {
        <voprf::Ristretto255 as Group>::serialize_elem(elem)
    }

    fn deserialize_elem(element_bits: &[u8]) -> voprf::Result<Self::Elem> {
        <voprf::Ristretto255 as Group>::deserialize_elem(element_bits)
    }

    fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        <voprf::Ristretto255 as Group>::random_scalar(rng)
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        <voprf::Ristretto255 as Group>::invert_scalar(scalar)
    }

    fn is_zero_scalar(scalar: Self::Scalar) -> subtle::Choice {
        <voprf::Ristretto255 as Group>::is_zero_scalar(scalar)
    }

    fn serialize_scalar(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
        <voprf::Ristretto255 as Group>::serialize_scalar(scalar)
    }

    fn deserialize_scalar(scalar_bits: &[u8]) -> voprf::Result<Self::Scalar> {
        <voprf::Ristretto255 as Group>::deserialize_scalar(scalar_bits)
    }
}

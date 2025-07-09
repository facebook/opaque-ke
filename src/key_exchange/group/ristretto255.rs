// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Key Exchange group implementation for ristretto255

pub use curve25519_dalek;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use digest::core_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker};
use generic_array::GenericArray;
use generic_array::typenum::{IsLess, IsLessOrEqual, U32, U256};
use rand::{CryptoRng, RngCore};
use voprf::Mode;

use super::{Group, STR_OPAQUE_DERIVE_AUTH_KEY_PAIR};
use crate::errors::{InternalError, ProtocolError};
use crate::key_exchange::shared::DiffieHellman;
use crate::serialization::SliceExt;

/// Implementation for Ristretto255.
// This is necessary because Rust lacks specialization, otherwise we could
// implement `KeGroup` for `voprf::Ristretto255`.
pub struct Ristretto255;

impl Group for Ristretto255 {
    type Pk = RistrettoPoint;
    type PkLen = U32;
    type Sk = Scalar;
    type SkLen = U32;

    fn serialize_pk(pk: Self::Pk) -> GenericArray<u8, Self::PkLen> {
        pk.compress().to_bytes().into()
    }

    fn deserialize_take_pk(bytes: &mut &[u8]) -> Result<Self::Pk, ProtocolError> {
        CompressedRistretto::from_slice(&bytes.take_array::<U32>("public key")?)
            .map_err(|_| ProtocolError::SerializationError)?
            .decompress()
            .filter(|point| point != &RistrettoPoint::identity())
            .ok_or(ProtocolError::SerializationError)
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk {
        loop {
            let scalar = Scalar::random(rng);

            if scalar != Scalar::ZERO {
                break scalar;
            }
        }
    }

    fn derive_scalar(seed: GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError> {
        voprf::derive_key::<Self>(&seed, &STR_OPAQUE_DERIVE_AUTH_KEY_PAIR, Mode::Oprf)
            .map_err(InternalError::from)
    }

    fn public_key(sk: Self::Sk) -> Self::Pk {
        RISTRETTO_BASEPOINT_POINT * sk
    }

    fn serialize_sk(sk: Self::Sk) -> GenericArray<u8, Self::SkLen> {
        sk.to_bytes().into()
    }

    fn deserialize_take_sk(bytes: &mut &[u8]) -> Result<Self::Sk, ProtocolError> {
        bytes
            .take_array::<U32>("secret key")
            .ok()
            .and_then(|bytes| Scalar::from_canonical_bytes(bytes.into()).into())
            .filter(|scalar| scalar != &Scalar::ZERO)
            .ok_or(ProtocolError::SerializationError)
    }
}

impl voprf::CipherSuite for Ristretto255 {
    const ID: &'static str = voprf::Ristretto255::ID;

    type Group = <voprf::Ristretto255 as voprf::CipherSuite>::Group;

    type Hash = <voprf::Ristretto255 as voprf::CipherSuite>::Hash;
}

impl voprf::Group for Ristretto255 {
    type Elem = <voprf::Ristretto255 as voprf::Group>::Elem;

    type ElemLen = <voprf::Ristretto255 as voprf::Group>::ElemLen;

    type Scalar = <voprf::Ristretto255 as voprf::Group>::Scalar;

    type ScalarLen = <voprf::Ristretto255 as voprf::Group>::ScalarLen;

    fn hash_to_curve<H>(
        input: &[&[u8]],
        dst: &[&[u8]],
    ) -> voprf::Result<Self::Elem, voprf::InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        <voprf::Ristretto255 as voprf::Group>::hash_to_curve::<H>(input, dst)
    }

    fn hash_to_scalar<H>(
        input: &[&[u8]],
        dst: &[&[u8]],
    ) -> voprf::Result<Self::Scalar, voprf::InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        <voprf::Ristretto255 as voprf::Group>::hash_to_scalar::<H>(input, dst)
    }

    fn base_elem() -> Self::Elem {
        <voprf::Ristretto255 as voprf::Group>::base_elem()
    }

    fn identity_elem() -> Self::Elem {
        <voprf::Ristretto255 as voprf::Group>::identity_elem()
    }

    fn serialize_elem(elem: Self::Elem) -> GenericArray<u8, Self::ElemLen> {
        <voprf::Ristretto255 as voprf::Group>::serialize_elem(elem)
    }

    fn deserialize_elem(element_bits: &[u8]) -> voprf::Result<Self::Elem> {
        <voprf::Ristretto255 as voprf::Group>::deserialize_elem(element_bits)
    }

    fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        <voprf::Ristretto255 as voprf::Group>::random_scalar(rng)
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        <voprf::Ristretto255 as voprf::Group>::invert_scalar(scalar)
    }

    fn is_zero_scalar(scalar: Self::Scalar) -> subtle::Choice {
        <voprf::Ristretto255 as voprf::Group>::is_zero_scalar(scalar)
    }

    fn serialize_scalar(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
        <voprf::Ristretto255 as voprf::Group>::serialize_scalar(scalar)
    }

    fn deserialize_scalar(scalar_bits: &[u8]) -> voprf::Result<Self::Scalar> {
        <voprf::Ristretto255 as voprf::Group>::deserialize_scalar(scalar_bits)
    }
}

impl DiffieHellman<Ristretto255> for Scalar {
    fn diffie_hellman(self, pk: RistrettoPoint) -> GenericArray<u8, U32> {
        Ristretto255::serialize_pk(pk * self)
    }
}

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl AssertZeroized for RistrettoPoint {
    fn assert_zeroized(&self) {
        assert_eq!(*self, RistrettoPoint::default());
    }
}

#[cfg(test)]
impl AssertZeroized for Scalar {
    fn assert_zeroized(&self) {
        assert_eq!(*self, Scalar::default());
    }
}

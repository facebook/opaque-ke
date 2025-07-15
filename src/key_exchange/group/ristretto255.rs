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
use curve25519_dalek::traits::IsIdentity;
use digest::core_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker};
use generic_array::GenericArray;
use generic_array::typenum::{IsLess, IsLessOrEqual, U32, U256};
use rand::{CryptoRng, RngCore};
use voprf::Mode;
use zeroize::Zeroize;

use super::{Group, STR_OPAQUE_DERIVE_AUTH_KEY_PAIR};
use crate::errors::{InternalError, ProtocolError};
use crate::key_exchange::shared::DiffieHellman;
use crate::serialization::SliceExt;

/// Implementation for Ristretto255.
// This is necessary because Rust lacks specialization, otherwise we could
// implement `KeGroup` for `voprf::Ristretto255`.
pub struct Ristretto255;

impl Group for Ristretto255 {
    type Pk = NonIdentity;
    type PkLen = U32;
    type Sk = NonZeroScalar;
    type SkLen = U32;

    fn serialize_pk(pk: Self::Pk) -> GenericArray<u8, Self::PkLen> {
        pk.0.compress().to_bytes().into()
    }

    fn deserialize_take_pk(bytes: &mut &[u8]) -> Result<Self::Pk, ProtocolError> {
        CompressedRistretto(bytes.take_array("public key")?.into())
            .decompress()
            .ok_or(ProtocolError::SerializationError)
            .and_then(NonIdentity::from_point)
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk {
        loop {
            let scalar = Scalar::random(rng);

            if scalar != Scalar::ZERO {
                break NonZeroScalar(scalar);
            }
        }
    }

    fn derive_scalar(seed: GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError> {
        voprf::derive_key::<Self>(&seed, &STR_OPAQUE_DERIVE_AUTH_KEY_PAIR, Mode::Oprf)
            .map(NonZeroScalar)
            .map_err(InternalError::from)
    }

    fn public_key(sk: Self::Sk) -> Self::Pk {
        NonIdentity(RISTRETTO_BASEPOINT_POINT * sk.0)
    }

    fn serialize_sk(sk: Self::Sk) -> GenericArray<u8, Self::SkLen> {
        sk.0.to_bytes().into()
    }

    fn deserialize_take_sk(bytes: &mut &[u8]) -> Result<Self::Sk, ProtocolError> {
        Scalar::from_canonical_bytes(bytes.take_array("secret key")?.into())
            .into_option()
            .ok_or(ProtocolError::SerializationError)
            .and_then(NonZeroScalar::from_scalar)
    }
}

impl DiffieHellman<Ristretto255> for NonZeroScalar {
    fn diffie_hellman(self, pk: NonIdentity) -> GenericArray<u8, U32> {
        Ristretto255::serialize_pk(NonIdentity(pk.0 * self.0))
    }
}

/// Non-identity point wrapper for [`RistrettoPoint`].
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub struct NonIdentity(
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_deserialize_pk"))] RistrettoPoint,
);

impl NonIdentity {
    fn from_point(point: RistrettoPoint) -> Result<Self, ProtocolError> {
        if point.is_identity() {
            Err(ProtocolError::SerializationError)
        } else {
            Ok(NonIdentity(point))
        }
    }
}

#[cfg(feature = "serde")]
fn serde_deserialize_pk<'de, D>(deserializer: D) -> Result<RistrettoPoint, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Deserialize, Error};

    let point = RistrettoPoint::deserialize(deserializer)?;

    NonIdentity::from_point(point)
        .map(|point| point.0)
        .map_err(Error::custom)
}

/// Non-zero scalar wrapper for [`Scalar`]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Zeroize)]
pub struct NonZeroScalar(
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_deserialize_sk"))] Scalar,
);

impl NonZeroScalar {
    fn from_scalar(scalar: Scalar) -> Result<Self, ProtocolError> {
        if scalar == Scalar::ZERO {
            Err(ProtocolError::SerializationError)
        } else {
            Ok(Self(scalar))
        }
    }
}

#[cfg(feature = "serde")]
fn serde_deserialize_sk<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Deserialize, Error};

    let scalar = Scalar::deserialize(deserializer)?;

    NonZeroScalar::from_scalar(scalar)
        .map(|scalar| scalar.0)
        .map_err(Error::custom)
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

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl AssertZeroized for NonIdentity {
    fn assert_zeroized(&self) {
        assert_eq!(self.0, RistrettoPoint::default());
    }
}

#[cfg(test)]
impl AssertZeroized for NonZeroScalar {
    fn assert_zeroized(&self) {
        assert_eq!(self.0, Scalar::default());
    }
}

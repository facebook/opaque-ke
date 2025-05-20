// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Key Exchange group implementation for Curve25519

pub use curve25519_dalek;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar;
use curve25519_dalek::traits::IsIdentity;
use generic_array::GenericArray;
use generic_array::typenum::U32;
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::Group;
use crate::errors::{InternalError, ProtocolError};
use crate::key_exchange::shared::DiffieHellman;
use crate::serialization::SliceExt;

/// Implementation for Curve25519.
pub struct Curve25519;

/// The implementation of such a subgroup for Curve25519
impl Group for Curve25519 {
    type Pk = NonIdentity;
    type PkLen = U32;
    type Sk = Scalar;
    type SkLen = U32;

    fn serialize_pk(pk: Self::Pk) -> GenericArray<u8, Self::PkLen> {
        pk.0.to_bytes().into()
    }

    fn deserialize_take_pk(bytes: &mut &[u8]) -> Result<Self::Pk, ProtocolError> {
        bytes
            .take_array::<U32>("public key")
            .and_then(|bytes| NonIdentity::from_bytes(bytes.into()))
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk {
        // Sample 32 random bytes and then clamp, as described in https://cr.yp.to/ecdh.html
        let mut scalar_bytes = [0u8; 32];
        rng.fill_bytes(&mut scalar_bytes);
        let scalar = scalar::clamp_integer(scalar_bytes);

        Scalar(scalar)
    }

    fn derive_scalar(seed: GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError> {
        Ok(Scalar(scalar::clamp_integer(seed.into())))
    }

    fn public_key(sk: Self::Sk) -> Self::Pk {
        NonIdentity(MontgomeryPoint::mul_base_clamped(sk.0))
    }

    fn serialize_sk(sk: Self::Sk) -> GenericArray<u8, Self::SkLen> {
        sk.0.into()
    }

    fn deserialize_take_sk(bytes: &mut &[u8]) -> Result<Self::Sk, ProtocolError> {
        bytes
            .take_array::<U32>("secret key")
            .and_then(|bytes| Scalar::from_bytes(bytes.into()))
    }
}

impl DiffieHellman<Curve25519> for Scalar {
    fn diffie_hellman(self, pk: NonIdentity) -> GenericArray<u8, U32> {
        Curve25519::serialize_pk(NonIdentity(pk.0.mul_clamped(self.0)))
    }
}

/// Non-identity point wrapper for [`MontgomeryPoint`].
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Zeroize)]
pub struct NonIdentity(
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_deserialize_pk"))]
    MontgomeryPoint,
);

impl NonIdentity {
    fn from_bytes(bytes: [u8; 32]) -> Result<Self, ProtocolError> {
        let point = MontgomeryPoint(bytes);

        if point.is_identity() {
            Err(ProtocolError::SerializationError)
        } else {
            Ok(NonIdentity(point))
        }
    }
}

#[cfg(feature = "serde")]
fn serde_deserialize_pk<'de, D>(deserializer: D) -> Result<MontgomeryPoint, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Deserialize, Error};

    let point = MontgomeryPoint::deserialize(deserializer)?;

    NonIdentity::from_bytes(point.0)
        .map(|point| point.0)
        .map_err(Error::custom)
}

/// Curve25519 scalar.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Zeroize)]
pub struct Scalar(
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_deserialize_sk"))] [u8; 32],
);

impl Scalar {
    fn from_bytes(bytes: [u8; 32]) -> Result<Self, ProtocolError> {
        let scalar = scalar::clamp_integer(bytes);

        if scalar.ct_eq(&bytes).into() {
            Ok(Self(scalar))
        } else {
            Err(ProtocolError::SerializationError)
        }
    }
}

#[cfg(feature = "serde")]
fn serde_deserialize_sk<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Deserialize, Error};

    Scalar::from_bytes(<[u8; 32]>::deserialize(deserializer)?)
        .map(|scalar| scalar.0)
        .map_err(D::Error::custom)
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
        assert_eq!(self.0, MontgomeryPoint::default());
    }
}

#[cfg(test)]
impl AssertZeroized for Scalar {
    fn assert_zeroized(&self) {
        assert_eq!(*self, Scalar(<_>::default()));
    }
}

#[test]
fn non_zero_scalar() {
    use std::vec;

    use crate::tests::mock_rng::CycleRng;

    let mut rng = CycleRng::new(vec![0]);
    let sk = Curve25519::random_sk(&mut rng);
    assert_ne!(sk.0, curve25519_dalek::Scalar::ZERO.to_bytes());
}

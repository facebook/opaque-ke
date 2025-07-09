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
use curve25519_dalek::traits::Identity;
use generic_array::GenericArray;
use generic_array::typenum::U32;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::Group;
use crate::errors::{InternalError, ProtocolError};
use crate::key_exchange::shared::DiffieHellman;
use crate::serialization::SliceExt;

/// Implementation for Curve25519.
pub struct Curve25519;

/// The implementation of such a subgroup for Curve25519
impl Group for Curve25519 {
    type Pk = MontgomeryPoint;
    type PkLen = U32;
    type Sk = Scalar;
    type SkLen = U32;

    fn serialize_pk(pk: Self::Pk) -> GenericArray<u8, Self::PkLen> {
        pk.to_bytes().into()
    }

    fn deserialize_take_pk(bytes: &mut &[u8]) -> Result<Self::Pk, ProtocolError> {
        bytes
            .take_array::<U32>("public key")
            .ok()
            .map(|array| MontgomeryPoint(array.into()))
            .filter(|pk| pk != &MontgomeryPoint::identity())
            .ok_or(ProtocolError::SerializationError)
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
        MontgomeryPoint::mul_base_clamped(sk.0)
    }

    fn serialize_sk(sk: Self::Sk) -> GenericArray<u8, Self::SkLen> {
        sk.0.into()
    }

    fn deserialize_take_sk(bytes: &mut &[u8]) -> Result<Self::Sk, ProtocolError> {
        bytes
            .take_array::<U32>("secret key")
            .ok()
            .and_then(|bytes| {
                let scalar = scalar::clamp_integer(bytes.into());
                (scalar == *bytes).then_some(scalar)
            })
            .map(Scalar)
            .ok_or(ProtocolError::SerializationError)
    }
}

/// Curve25519 scalar.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Zeroize)]
pub struct Scalar([u8; 32]);

impl DiffieHellman<Curve25519> for Scalar {
    fn diffie_hellman(self, pk: MontgomeryPoint) -> GenericArray<u8, U32> {
        Curve25519::serialize_pk(pk.mul_clamped(self.0))
    }
}

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl AssertZeroized for MontgomeryPoint {
    fn assert_zeroized(&self) {
        assert_eq!(*self, MontgomeryPoint::default());
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

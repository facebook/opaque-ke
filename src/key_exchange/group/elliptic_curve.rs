// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytesSize, Group as _, ProjectivePoint, PublicKey, Scalar,
    SecretKey,
};
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};
use voprf::Mode;

use super::{Group, STR_OPAQUE_DERIVE_AUTH_KEY_PAIR};
use crate::errors::{InternalError, ProtocolError};
use crate::key_exchange::tripledh::DiffieHellman;

impl<G> Group for G
where
    Self: CurveArithmetic + voprf::CipherSuite<Group = Self> + voprf::Group<Scalar = Scalar<Self>>,
    FieldBytesSize<Self>: ModulusSize,
    AffinePoint<Self>: FromEncodedPoint<Self> + ToEncodedPoint<Self>,
    ProjectivePoint<Self>: ToEncodedPoint<Self>,
{
    type Pk = ProjectivePoint<Self>;

    type PkLen = <FieldBytesSize<Self> as ModulusSize>::CompressedPointSize;

    type Sk = Scalar<Self>;

    type SkLen = FieldBytesSize<Self>;

    fn serialize_pk(pk: Self::Pk) -> GenericArray<u8, Self::PkLen> {
        GenericArray::clone_from_slice(pk.to_encoded_point(true).as_bytes())
    }

    fn deserialize_pk(bytes: &[u8]) -> Result<Self::Pk, ProtocolError> {
        PublicKey::<Self>::from_sec1_bytes(bytes)
            .map(|public_key| public_key.to_projective())
            .map_err(|_| ProtocolError::SerializationError)
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk {
        *SecretKey::<Self>::random(rng).to_nonzero_scalar()
    }

    fn derive_scalar(seed: GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError> {
        voprf::derive_key::<Self>(&seed, &STR_OPAQUE_DERIVE_AUTH_KEY_PAIR, Mode::Oprf)
            .map_err(InternalError::from)
    }

    fn public_key(sk: Self::Sk) -> Self::Pk {
        ProjectivePoint::<Self>::generator() * sk
    }

    fn serialize_sk(sk: Self::Sk) -> GenericArray<u8, Self::SkLen> {
        sk.into()
    }

    fn deserialize_sk(bytes: &[u8]) -> Result<Self::Sk, ProtocolError> {
        SecretKey::<Self>::from_slice(bytes)
            .map(|secret_key| *secret_key.to_nonzero_scalar())
            .map_err(|_| ProtocolError::SerializationError)
    }
}

impl<G> DiffieHellman<G> for Scalar<G>
where
    G: CurveArithmetic + voprf::CipherSuite<Group = G> + voprf::Group<Scalar = Scalar<G>>,
    FieldBytesSize<G>: ModulusSize,
    AffinePoint<G>: FromEncodedPoint<G> + ToEncodedPoint<G>,
    ProjectivePoint<G>: ToEncodedPoint<G>,
{
    fn diffie_hellman(
        self,
        pk: ProjectivePoint<G>,
    ) -> GenericArray<u8, <FieldBytesSize<G> as ModulusSize>::CompressedPointSize> {
        GenericArray::clone_from_slice((pk * self).to_encoded_point(true).as_bytes())
    }
}

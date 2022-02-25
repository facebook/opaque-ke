// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use digest::core_api::BlockSizeUser;
use digest::Digest;
use elliptic_curve::group::cofactor::CofactorGroup;
use elliptic_curve::hash2curve::{ExpandMsgXmd, FromOkm, GroupDigest};
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{
    AffinePoint, FieldSize, Group, ProjectivePoint, PublicKey, Scalar, SecretKey,
};
use generic_array::typenum::{IsLess, IsLessOrEqual, U256};
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};

use super::KeGroup;
use crate::errors::InternalError;

impl<G> KeGroup for G
where
    G: GroupDigest,
    FieldSize<Self>: ModulusSize,
    AffinePoint<Self>: FromEncodedPoint<Self> + ToEncodedPoint<Self>,
    ProjectivePoint<Self>: CofactorGroup + ToEncodedPoint<Self>,
    Scalar<Self>: FromOkm,
{
    type Pk = ProjectivePoint<Self>;

    type PkLen = <FieldSize<Self> as ModulusSize>::CompressedPointSize;

    type Sk = Scalar<Self>;

    type SkLen = FieldSize<Self>;

    fn serialize_pk(pk: Self::Pk) -> GenericArray<u8, Self::PkLen> {
        let bytes = pk.to_encoded_point(true);
        let bytes = bytes.as_bytes();
        let mut result = GenericArray::default();
        result[..bytes.len()].copy_from_slice(bytes);
        result
    }

    fn deserialize_pk(bytes: &GenericArray<u8, Self::PkLen>) -> Result<Self::Pk, InternalError> {
        PublicKey::<Self>::from_sec1_bytes(bytes)
            .map(|public_key| public_key.to_projective())
            .map_err(|_| InternalError::PointError)
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk {
        *SecretKey::<Self>::random(rng).to_nonzero_scalar()
    }

    // Implements the `HashToScalar()` function
    fn hash_to_scalar<H>(input: &[&[u8]], dst: &[u8]) -> Result<Self::Sk, InternalError>
    where
        H: Digest + BlockSizeUser,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        Self::hash_to_scalar::<ExpandMsgXmd<H>>(input, dst).map_err(|_| InternalError::HashToScalar)
    }

    fn public_key(sk: Self::Sk) -> Self::Pk {
        ProjectivePoint::<Self>::generator() * sk
    }

    fn diffie_hellman(pk: Self::Pk, sk: Self::Sk) -> GenericArray<u8, Self::PkLen> {
        // This should be unable to fail because we should pass a zero scalar.
        GenericArray::clone_from_slice((pk * sk).to_encoded_point(true).as_bytes())
    }

    fn serialize_sk(sk: Self::Sk) -> GenericArray<u8, Self::SkLen> {
        sk.into()
    }

    fn deserialize_sk(bytes: &GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError> {
        SecretKey::<Self>::from_be_bytes(bytes)
            .map(|secret_key| *secret_key.to_nonzero_scalar())
            .map_err(|_| InternalError::PointError)
    }
}

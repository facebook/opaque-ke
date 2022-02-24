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
    AffinePoint, Curve, FieldSize, NonZeroScalar, ProjectiveArithmetic, ProjectivePoint, PublicKey,
    Scalar, SecretKey,
};
use generic_array::typenum::{IsLess, IsLessOrEqual, U256};
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};

use super::KeGroup;
use crate::errors::InternalError;

impl<G: Curve + GroupDigest + ProjectiveArithmetic> KeGroup for G
where
    FieldSize<Self>: ModulusSize,
    AffinePoint<Self>: FromEncodedPoint<Self> + ToEncodedPoint<Self>,
    ProjectivePoint<Self>: CofactorGroup + ToEncodedPoint<Self>,
    Scalar<Self>: FromOkm,
    //AffinePoint<Self>: FromEncodedPoint<Self> + ToEncodedPoint<Self>,
{
    type Pk = PublicKey<Self>;

    type PkLen = <FieldSize<Self> as ModulusSize>::CompressedPointSize;

    type Sk = SecretKey<Self>;

    type SkLen = FieldSize<Self>;

    fn serialize_pk(pk: &Self::Pk) -> GenericArray<u8, Self::PkLen> {
        GenericArray::clone_from_slice(pk.to_encoded_point(true).as_bytes())
    }

    fn deserialize_pk(bytes: &GenericArray<u8, Self::PkLen>) -> Result<Self::Pk, InternalError> {
        PublicKey::<Self>::from_sec1_bytes(bytes).map_err(|_| InternalError::PointError)
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk {
        SecretKey::<Self>::random(rng)
    }

    // Implements the `HashToScalar()` function
    fn hash_to_scalar<H>(input: &[&[u8]], dst: &[u8]) -> Result<Self::Sk, InternalError>
    where
        H: Digest + BlockSizeUser,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        Option::<NonZeroScalar<Self>>::from(NonZeroScalar::new(
            <Self as GroupDigest>::hash_to_scalar::<ExpandMsgXmd<H>>(input, dst)
                .map_err(|_| InternalError::HashToScalar)?,
        ))
        .map(SecretKey::from)
        .ok_or(InternalError::HashToScalar)
    }

    fn public_key(sk: &Self::Sk) -> Self::Pk {
        sk.public_key()
    }

    fn diffie_hellman(pk: &Self::Pk, sk: &Self::Sk) -> GenericArray<u8, Self::PkLen> {
        GenericArray::clone_from_slice(
            (pk.to_projective() * sk.to_nonzero_scalar().as_ref())
                .to_encoded_point(true)
                .as_bytes(),
        )
    }

    fn zeroize_sk_on_drop(_sk: &mut Self::Sk) {}

    fn serialize_sk(sk: &Self::Sk) -> GenericArray<u8, Self::SkLen> {
        sk.to_be_bytes()
    }

    fn deserialize_sk(bytes: &GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError> {
        Self::Sk::from_be_bytes(bytes).map_err(|_| InternalError::PointError)
    }
}

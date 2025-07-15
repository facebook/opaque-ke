// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Implementation for EC curves via [`elliptic_curve`] traits.

use core::fmt::{self, Debug, Formatter};

use derive_where::derive_where;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::ops::MulByGenerator;
use elliptic_curve::sec1::{ModulusSize, ToEncodedPoint};
use elliptic_curve::{
    CurveArithmetic, FieldBytesSize, Group as _, NonZeroScalar, ProjectivePoint, Scalar, SecretKey,
    point,
};
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};
use voprf::Mode;
use zeroize::Zeroize;

use super::{Group, STR_OPAQUE_DERIVE_AUTH_KEY_PAIR};
use crate::errors::{InternalError, ProtocolError};
use crate::key_exchange::shared::DiffieHellman;
use crate::serialization::SliceExt;

impl<G> Group for G
where
    Self: CurveArithmetic + voprf::CipherSuite<Group = Self> + voprf::Group<Scalar = Scalar<Self>>,
    FieldBytesSize<Self>: ModulusSize,
    ProjectivePoint<Self>: GroupEncoding<
            Repr = GenericArray<u8, <FieldBytesSize<Self> as ModulusSize>::CompressedPointSize>,
        > + ToEncodedPoint<Self>,
{
    type Pk = NonIdentity<Self>;

    type PkLen = <FieldBytesSize<Self> as ModulusSize>::CompressedPointSize;

    type Sk = NonZeroScalar<Self>;

    type SkLen = FieldBytesSize<Self>;

    fn serialize_pk(pk: Self::Pk) -> GenericArray<u8, Self::PkLen> {
        GenericArray::clone_from_slice(pk.0.to_encoded_point(true).as_bytes())
    }

    fn deserialize_take_pk(bytes: &mut &[u8]) -> Result<Self::Pk, ProtocolError> {
        point::NonIdentity::<ProjectivePoint<Self>>::from_bytes(&bytes.take_array("public key")?)
            .into_option()
            .map(NonIdentity)
            .ok_or(ProtocolError::SerializationError)
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk {
        SecretKey::<Self>::random(rng).to_nonzero_scalar()
    }

    fn derive_scalar(seed: GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError> {
        voprf::derive_key::<Self>(&seed, &STR_OPAQUE_DERIVE_AUTH_KEY_PAIR, Mode::Oprf)
            .map(|scalar| {
                NonZeroScalar::new(scalar).expect("`voprf::derive_key()` returned a zero scalar")
            })
            .map_err(InternalError::from)
    }

    fn public_key(sk: Self::Sk) -> Self::Pk {
        // Non-panicking version in https://github.com/RustCrypto/traits/pull/1833.
        NonIdentity(
            point::NonIdentity::new(ProjectivePoint::<Self>::mul_by_generator(&*sk))
                .expect("multiplying with a non-zero scalar can never yield the identity element"),
        )
    }

    fn serialize_sk(sk: Self::Sk) -> GenericArray<u8, Self::SkLen> {
        sk.into()
    }

    fn deserialize_take_sk(bytes: &mut &[u8]) -> Result<Self::Sk, ProtocolError> {
        SecretKey::<Self>::from_bytes(&bytes.take_array("secret key")?)
            .map(|secret_key| secret_key.to_nonzero_scalar())
            .map_err(|_| ProtocolError::SerializationError)
    }
}

impl<G> DiffieHellman<G> for NonZeroScalar<G>
where
    G: CurveArithmetic + voprf::CipherSuite<Group = G> + voprf::Group<Scalar = Scalar<G>>,
    FieldBytesSize<G>: ModulusSize,
    ProjectivePoint<G>: GroupEncoding<
            Repr = GenericArray<u8, <FieldBytesSize<G> as ModulusSize>::CompressedPointSize>,
        > + ToEncodedPoint<G>,
{
    fn diffie_hellman(
        self,
        pk: NonIdentity<G>,
    ) -> GenericArray<u8, <FieldBytesSize<G> as ModulusSize>::CompressedPointSize> {
        GenericArray::clone_from_slice((pk.0 * self).to_encoded_point(true).as_bytes())
    }
}

/// Wrapper around [`NonIdentity`](point::NonIdentity) to implement [`Zeroize`].
// TODO: remove after https://github.com/RustCrypto/traits/pull/1832.
#[derive_where(Clone, Copy)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(
        bound(
            deserialize = "point::NonIdentity<ProjectivePoint<G>>: serde::Deserialize<'de>",
            serialize = "point::NonIdentity<ProjectivePoint<G>>: serde::Serialize"
        ),
        transparent
    )
)]
pub struct NonIdentity<G: CurveArithmetic>(pub point::NonIdentity<ProjectivePoint<G>>);

impl<G: CurveArithmetic> Debug for NonIdentity<G> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NonIdentity")
            .field(&self.0.to_point())
            .finish()
    }
}

impl<G: CurveArithmetic> PartialEq for NonIdentity<G> {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_point().eq(&other.0.to_point())
    }
}

impl<G: CurveArithmetic> Eq for NonIdentity<G> {}

impl<G: CurveArithmetic> Zeroize for NonIdentity<G> {
    fn zeroize(&mut self) {
        self.0 = point::NonIdentity::new(ProjectivePoint::<G>::generator()).unwrap();
    }
}

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl<G: CurveArithmetic> AssertZeroized for NonIdentity<G> {
    fn assert_zeroized(&self) {
        assert_eq!(self.0.to_point(), ProjectivePoint::<G>::generator());
    }
}

#[cfg(test)]
impl<G: CurveArithmetic> AssertZeroized for NonZeroScalar<G> {
    fn assert_zeroized(&self) {
        use elliptic_curve::Field;

        assert_eq!(**self, Scalar::<G>::ONE);
    }
}

// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! ECDSA implementation for [`elliptic_curve`] [`Group`] implementations to
//! support [`SigmaI`](crate::key_exchange::sigma_i::SigmaI);

use derive_where::derive_where;
use ecdsa::hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive};
use ecdsa::signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};
use ecdsa::{PrimeCurve, SignatureSize, SigningKey, VerifyingKey};
use elliptic_curve::{
    AffinePoint, CurveArithmetic, Field, FieldBytes, FieldBytesSize, NonZeroScalar, PublicKey,
    Scalar,
};
use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::elliptic_curve::NonIdentity;
use super::Group;
use crate::errors::ProtocolError;
use crate::key_exchange::sigma_i::{Sign, Verify};
use crate::key_exchange::traits::{Deserialize, Serialize};

/// Wrapper around [`ecdsa::Signature`] to implement
/// [`Zeroize`](crate::Zeroize).
// TODO: remove after https://github.com/RustCrypto/signatures/pull/948.
#[derive_where(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "ecdsa::Signature<G>: serde::Deserialize<'de>",
        serialize = "ecdsa::Signature<G>: serde::Serialize"
    ))
)]
pub struct Signature<G: CurveArithmetic + PrimeCurve>(pub ecdsa::Signature<G>)
where
    SignatureSize<G>: ArrayLength<u8>;

impl<G: CurveArithmetic + PrimeCurve> Deserialize for Signature<G>
where
    SignatureSize<G>: ArrayLength<u8>,
{
    fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        ecdsa::Signature::from_slice(input)
            .map(Signature)
            .map_err(|_| ProtocolError::SerializationError)
    }
}

impl<G: CurveArithmetic + PrimeCurve> Zeroize for Signature<G>
where
    SignatureSize<G>: ArrayLength<u8>,
{
    fn zeroize(&mut self) {
        self.0 = ecdsa::Signature::from_scalars(
            Into::<FieldBytes<G>>::into(Scalar::<G>::ONE),
            Into::<FieldBytes<G>>::into(Scalar::<G>::ONE),
        )
        .expect("failed to create `Signature` with non-zero `Scalar`s");
    }
}

impl<G: CurveArithmetic + PrimeCurve> Serialize for Signature<G>
where
    SignatureSize<G>: ArrayLength<u8>,
{
    type Len = SignatureSize<G>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.0.to_bytes()
    }
}

impl<G> Sign for NonZeroScalar<G>
where
    G: CurveArithmetic + DigestPrimitive,
    Scalar<G>: SignPrimitive<G>,
    SignatureSize<G>: ArrayLength<u8>,
{
    type Signature = Signature<G>;

    fn sign<R: CryptoRng + RngCore>(self, rng: &mut R, prehash: &[u8]) -> Self::Signature {
        if prehash.len() < FieldBytesSize::<G>::USIZE / 2 {
            unreachable!("transcript shorter than a scalar");
        }

        // This can only fail if the prehash is too short, which we check beforehand, or
        // if the computed `r` or `s` are zero, in which case we just retry with a new
        // `k`. See https://github.com/RustCrypto/signatures/issues/950.
        loop {
            if let Ok(signature) = SigningKey::<G>::from(self)
                .sign_prehash_with_rng(rng, prehash)
                .map(Signature)
            {
                break signature;
            }
        }
    }
}

impl<G: Group> Verify<G> for NonIdentity<G>
where
    G::Sk: Sign<Signature = Signature<G>>,
    G: CurveArithmetic + DigestPrimitive,
    AffinePoint<G>: VerifyPrimitive<G>,
    SignatureSize<G>: ArrayLength<u8>,
{
    fn verify(
        self,
        prehash: &[u8],
        signature: &<G::Sk as Sign>::Signature,
    ) -> Result<(), ProtocolError> {
        let key = VerifyingKey::<G>::from(PublicKey::from(self.0));
        key.verify_prehash(prehash, &signature.0)
            .map_err(|_| ProtocolError::InvalidLoginError)
    }
}

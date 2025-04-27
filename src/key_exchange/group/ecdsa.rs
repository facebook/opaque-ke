// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! ECDSA implementation for [`elliptic_curve`] [`Group`] implementations to
//! support [`SigmaI`](crate::key_exchange::sigma_i::SigmaI).

use core::marker::PhantomData;

use derive_where::derive_where;
use digest::core_api::BlockSizeUser;
use digest::{FixedOutputReset, HashMarker, Output, OutputSizeUser};
use ecdsa::{hazmat, PrimeCurve, SignatureSize};
use elliptic_curve::{
    CurveArithmetic, Field, FieldBytes, FieldBytesEncoding, FieldBytesSize, NonZeroScalar,
    PrimeField, Scalar,
};
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::elliptic_curve::NonIdentity;
use super::Group;
use crate::errors::ProtocolError;
use crate::key_exchange::sigma_i::SignatureGroup;
use crate::key_exchange::traits::{Deserialize, Serialize};
use crate::serialization::{SliceExt, UpdateExt};

/// Implements ECDSA for [`SigmaI`](crate::key_exchange::sigma_i::SigmaI).
pub struct Ecdsa<G, H>(PhantomData<(G, H)>);

impl<G, H> SignatureGroup for Ecdsa<G, H>
where
    G: CurveArithmetic + Group<Sk = NonZeroScalar<G>, Pk = NonIdentity<G>> + PrimeCurve,
    SignatureSize<G>: ArrayLength<u8>,
    H: Default + BlockSizeUser + FixedOutputReset<OutputSize = FieldBytesSize<G>> + HashMarker,
{
    type Group = G;
    type Signature = Signature<G>;
    type VerifyState = PreHash<H>;

    fn sign<'a, R: CryptoRng + RngCore>(
        sk: &<Self::Group as Group>::Sk,
        rng: &mut R,
        message: impl Iterator<Item = &'a [u8]>,
    ) -> (Self::Signature, Self::VerifyState) {
        // We use a manual implementation of `RandomizedPrehashSigner` to use the same
        // hash for the message as for generating `k`. See
        // https://github.com/RustCrypto/signatures/issues/949.
        let pre_hash = H::default().chain_iter(message).finalize_fixed();
        let repr = sk.to_repr();
        let order = G::ORDER.encode_field_bytes();
        let z = hazmat::bits2field::<G>(&pre_hash)
            .expect("hash output can not be shorter than a scalar");

        let signature = loop {
            let mut ad = FieldBytes::<G>::default();
            rng.fill_bytes(&mut ad);

            let k = Scalar::<G>::from_repr(rfc6979::generate_k::<H, _>(&repr, &order, &z, &ad))
                .unwrap();

            // This can only fail if the computed `r` or `s` are zero, in which case we just
            // retry with a new `k`. See https://github.com/RustCrypto/signatures/pull/951.
            if let Ok((signature, _)) = hazmat::sign_prehashed::<G, _>(sk, k, &z) {
                break signature;
            }
        };

        (Signature(signature), PreHash(pre_hash))
    }

    fn verify(
        pk: &<Self::Group as Group>::Pk,
        state: Self::VerifyState,
        signature: &Self::Signature,
    ) -> Result<(), ProtocolError> {
        let z = hazmat::bits2field::<G>(&state.0)
            .expect("hash output can not be shorter than a scalar");
        hazmat::verify_prehashed(&pk.0.to_point(), &z, &signature.0)
            .map_err(|_| ProtocolError::InvalidLoginError)
    }
}

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
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        ecdsa::Signature::from_bytes(&input.take_array("signature")?)
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

/// Prehash to re-use when verifying the client signature.
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Zeroize)]
#[derive_where(Copy; <H::OutputSize as ArrayLength<u8>>::ArrayType)]
pub struct PreHash<H: OutputSizeUser>(pub Output<H>);

impl<H: OutputSizeUser> Deserialize for PreHash<H> {
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self(input.take_array("pre-hash")?))
    }
}

impl<H: OutputSizeUser> Serialize for PreHash<H> {
    type Len = H::OutputSize;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.0.clone()
    }
}

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl<H: OutputSizeUser> AssertZeroized for PreHash<H> {
    fn assert_zeroized(&self) {
        assert_eq!(self.0, GenericArray::default());
    }
}

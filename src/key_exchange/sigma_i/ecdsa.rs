// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! ECDSA implementation for [`elliptic_curve`] [`Group`] implementations to
//! support [`SigmaI`](crate::SigmaI).

use core::marker::PhantomData;

use derive_where::derive_where;
use digest::core_api::BlockSizeUser;
use digest::{FixedOutputReset, HashMarker};
use ecdsa::{hazmat, PrimeCurve, SignatureSize};
use elliptic_curve::{
    CurveArithmetic, Field, FieldBytes, FieldBytesEncoding, FieldBytesSize, NonZeroScalar,
    PrimeField, Scalar,
};
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::{Message, MessageBuilder, SignatureProtocol};
use crate::ciphersuite::CipherSuite;
use crate::errors::ProtocolError;
use crate::key_exchange::group::elliptic_curve::NonIdentity;
use crate::key_exchange::group::Group;
pub use crate::key_exchange::sigma_i::shared::PreHash;
use crate::serialization::SliceExt;

/// ECDSA for [`SigmaI`](crate::SigmaI).
///
/// The ["verification state"](Self::VerifyState) is the pre-hash for the
/// message to be verified.
pub struct Ecdsa<G, H>(PhantomData<(G, H)>);

impl<G, H> SignatureProtocol for Ecdsa<G, H>
where
    G: CurveArithmetic + Group<Sk = NonZeroScalar<G>, Pk = NonIdentity<G>> + PrimeCurve,
    SignatureSize<G>: ArrayLength<u8>,
    H: Clone
        + Default
        + BlockSizeUser
        + FixedOutputReset<OutputSize = FieldBytesSize<G>>
        + HashMarker,
{
    type Group = G;
    type Signature = Signature<G>;
    type SignatureLen = SignatureSize<G>;
    type VerifyState<CS: CipherSuite, KE: Group> = PreHash<H>;

    // We use a manual implementation of `RandomizedPrehashSigner` to use the same
    // hash for the message as for generating `k`. See
    // https://github.com/RustCrypto/signatures/issues/949.
    fn sign<'a, R: CryptoRng + RngCore, CS: CipherSuite, KE: Group>(
        sk: &<Self::Group as Group>::Sk,
        rng: &mut R,
        message: &Message<CS, KE>,
    ) -> (Self::Signature, Self::VerifyState<CS, KE>) {
        let hash = message.hash::<H>();

        (
            Signature(sign::<_, G, H>(sk, rng, &hash.sign.finalize_fixed())),
            PreHash(hash.verify.finalize_fixed()),
        )
    }

    fn verify<CS: CipherSuite, KE: Group>(
        pk: &<Self::Group as Group>::Pk,
        _: MessageBuilder<'_, CS>,
        state: Self::VerifyState<CS, KE>,
        signature: &Self::Signature,
    ) -> Result<(), ProtocolError> {
        verify(pk, &state.0, &signature.0)
    }

    fn serialize_signature(signature: &Self::Signature) -> GenericArray<u8, Self::SignatureLen> {
        signature.0.to_bytes()
    }

    fn deserialize_take_signature(bytes: &mut &[u8]) -> Result<Self::Signature, ProtocolError> {
        ecdsa::Signature::from_bytes(&bytes.take_array("signature")?)
            .map(Signature)
            .map_err(|_| ProtocolError::SerializationError)
    }
}

fn sign<R, C, H>(sk: &NonZeroScalar<C>, rng: &mut R, pre_hash: &[u8]) -> ecdsa::Signature<C>
where
    R: CryptoRng + RngCore,
    C: CurveArithmetic + PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
    H: Default + BlockSizeUser + FixedOutputReset<OutputSize = FieldBytesSize<C>> + HashMarker,
{
    let repr = sk.to_repr();
    let order = C::ORDER.encode_field_bytes();
    let z =
        hazmat::bits2field::<C>(pre_hash).expect("hash output can not be shorter than a scalar");

    // This can only fail if the computed `r` or `s` are zero, in which case we just
    // retry with a new `k`. See https://github.com/RustCrypto/signatures/pull/951.
    loop {
        let mut ad = FieldBytes::<C>::default();
        rng.fill_bytes(&mut ad);

        let k =
            Scalar::<C>::from_repr(rfc6979::generate_k::<H, _>(&repr, &order, &z, &ad)).unwrap();

        if let Ok((signature, _)) = hazmat::sign_prehashed::<C, _>(sk, k, &z) {
            break signature;
        }
    }
}

fn verify<C>(
    pk: &NonIdentity<C>,
    pre_hash: &[u8],
    signature: &ecdsa::Signature<C>,
) -> Result<(), ProtocolError>
where
    C: CurveArithmetic + PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    let z =
        hazmat::bits2field::<C>(pre_hash).expect("hash output can not be shorter than a scalar");
    hazmat::verify_prehashed(&pk.0.to_point(), &z, signature)
        .map_err(|_| ProtocolError::InvalidLoginError)
}

/// Wrapper around [`ecdsa::Signature`] to implement [`Zeroize`].
// TODO: remove after https://github.com/RustCrypto/signatures/pull/948.
#[derive_where(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
pub struct Signature<G: CurveArithmetic + PrimeCurve>(pub ecdsa::Signature<G>)
where
    SignatureSize<G>: ArrayLength<u8>;

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

#[test]
fn ecdsa() {
    use std::vec;

    use digest::Digest;
    use p256::ecdsa::signature::{DigestVerifier, RandomizedDigestSigner};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p256::{NistP256, PublicKey};
    use rand::rngs::OsRng;
    use sha2::Sha256;

    use crate::tests::mock_rng::CycleRng;

    let mut rng = CycleRng::new(vec![1; 32]);

    let mut message = [0; 1024];
    OsRng.fill_bytes(&mut message);
    let hash = Sha256::new_with_prefix(message);

    let sk = NistP256::random_sk(&mut OsRng);
    let signing_key = SigningKey::from(sk);

    let signature: Signature = signing_key.sign_digest_with_rng(&mut rng, hash.clone());
    let custom_signature = sign::<_, _, Sha256>(&sk, &mut rng, &hash.clone().finalize());

    assert_eq!(signature, custom_signature);

    let pk = NistP256::public_key(sk);
    let verifying_key = VerifyingKey::from(PublicKey::from(pk.0));

    verifying_key
        .verify_digest(hash.clone(), &signature)
        .unwrap();
    verify(&pk, &hash.finalize(), &custom_signature).unwrap();
}

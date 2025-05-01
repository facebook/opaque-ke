// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Key Exchange group implementation for Ed25519

use core::iter;

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::{EdwardsPoint, Scalar};
use digest::Digest;
pub use ed25519_dalek;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use ed25519_dalek::{SecretKey, Sha512};
use generic_array::sequence::Concat;
use generic_array::typenum::{U32, U64};
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::Group;
use crate::ciphersuite::CipherSuite;
use crate::errors::{InternalError, ProtocolError};
use crate::key_exchange::sigma_i::hash_eddsa::implementation::HashEddsaImpl;
use crate::key_exchange::sigma_i::pure_eddsa::implementation::PureEddsaImpl;
pub use crate::key_exchange::sigma_i::shared::PreHash;
use crate::key_exchange::sigma_i::{CachedMessage, Message, MessageBuilder};
use crate::key_exchange::traits::{Deserialize, Serialize};
use crate::serialization::{SliceExt, UpdateExt};

/// Implementation for Ed25519.
pub struct Ed25519;

impl Group for Ed25519 {
    type Pk = VerifyingKey;
    type PkLen = U32;
    type Sk = SigningKey;
    type SkLen = U32;

    fn serialize_pk(pk: Self::Pk) -> GenericArray<u8, Self::PkLen> {
        pk.compressed.0.into()
    }

    fn deserialize_take_pk(bytes: &mut &[u8]) -> Result<Self::Pk, ProtocolError> {
        let compressed = bytes
            .take_array("public key")
            .map(|bytes| CompressedEdwardsY(bytes.into()))?;

        if let Some(point) = compressed.decompress().filter(|point| !point.is_identity()) {
            Ok(VerifyingKey { point, compressed })
        } else {
            Err(ProtocolError::SerializationError)
        }
    }

    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk {
        let mut sk = <[u8; 32]>::default();
        rng.fill_bytes(&mut sk);

        SigningKey::from_bytes(sk)
    }

    fn derive_scalar(seed: GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError> {
        Ok(SigningKey::from_bytes(seed.into()))
    }

    fn public_key(sk: Self::Sk) -> Self::Pk {
        sk.verifying_key
    }

    fn serialize_sk(sk: Self::Sk) -> GenericArray<u8, Self::SkLen> {
        sk.sk.into()
    }

    fn deserialize_take_sk(bytes: &mut &[u8]) -> Result<Self::Sk, ProtocolError> {
        Ok(SigningKey::from_bytes(
            bytes.take_array("secret key")?.into(),
        ))
    }
}

/// Ed25519 verifying key.
// `ed25519_dalek::VerifyingKey` doesn't implement `Zeroize`.
// TODO: remove after https://github.com/dalek-cryptography/curve25519-dalek/pull/747.
// Required for manual implementation of EdDSA.
// TODO: remove after https://github.com/dalek-cryptography/curve25519-dalek/pull/556.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub struct VerifyingKey {
    point: EdwardsPoint,
    compressed: CompressedEdwardsY,
}

/// Ed25519 siging key.
// We store the `ExpandedSecret` in memory to avoid computing it on demand and then discarding it
// again.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub struct SigningKey {
    // `ed25519_dalek::SigningKey` doesn't implement `Zeroize`. See
    // https://github.com/dalek-cryptography/curve25519-dalek/pull/747
    // Required for manual implementation of EdDSA.
    // TODO: remove after https://github.com/dalek-cryptography/curve25519-dalek/pull/556.
    sk: SecretKey,
    verifying_key: VerifyingKey,
    // `ed25519_dalek::ExpandedSecret` doesn't implement traits we need. See
    // https://github.com/dalek-cryptography/curve25519-dalek/pull/748 and
    // https://github.com/dalek-cryptography/curve25519-dalek/pull/747
    scalar: Scalar,
    hash_prefix: [u8; 32],
}

impl SigningKey {
    fn from_bytes(sk: [u8; 32]) -> Self {
        let ExpandedSecretKey {
            scalar,
            hash_prefix,
        } = ExpandedSecretKey::from(&sk);
        let point = EdwardsPoint::mul_base(&scalar);
        let verifying_key = VerifyingKey {
            point,
            compressed: point.compress(),
        };

        SigningKey {
            sk,
            verifying_key,
            scalar,
            hash_prefix,
        }
    }
}

impl PureEddsaImpl for Ed25519 {
    type Signature = Signature;
    type VerifyState<CS: CipherSuite, KE: Group> = CachedMessage<CS, KE>;

    fn sign<CS: CipherSuite, KE: Group>(
        sk: &Self::Sk,
        message: &Message<CS, KE>,
    ) -> (Self::Signature, Self::VerifyState<CS, KE>) {
        (sign(sk, false, message.sign_message()), message.to_cached())
    }

    /// Validates that the signature was created by signing the given message
    /// with the corresponding private key.
    fn verify<CS: CipherSuite, KE: Group>(
        pk: &Self::Pk,
        message_builder: MessageBuilder<'_, CS>,
        state: Self::VerifyState<CS, KE>,
        signature: &Self::Signature,
    ) -> Result<(), ProtocolError> {
        verify(
            pk,
            false,
            message_builder.build::<KE>(state).verify_message(),
            signature,
        )
    }
}

impl HashEddsaImpl for Ed25519 {
    type Signature = Signature;
    type VerifyState<CS: CipherSuite, KE: Group> = PreHash<Sha512>;

    fn sign<CS: CipherSuite, KE: Group>(
        sk: &Self::Sk,
        message: &Message<CS, KE>,
    ) -> (Self::Signature, Self::VerifyState<CS, KE>) {
        let hash = message.hash::<Sha512>();

        (
            sign(sk, true, iter::once(hash.sign.finalize().as_slice())),
            PreHash(hash.verify.finalize()),
        )
    }

    /// Validates that the signature was created by signing the given message
    /// with the corresponding private key.
    fn verify<CS: CipherSuite, KE: Group>(
        pk: &Self::Pk,
        state: Self::VerifyState<CS, KE>,
        signature: &Self::Signature,
    ) -> Result<(), ProtocolError> {
        verify(pk, true, iter::once(state.0.as_slice()), signature)
    }
}

// This contains a manual implementation of EdDSA because `ed25519-dalek`
// doesn't support message streaming. See
// TODO: remove after https://github.com/dalek-cryptography/curve25519-dalek/pull/556.
fn sign<'a>(
    sk: &SigningKey,
    pre_hash: bool,
    message: impl Clone + Iterator<Item = &'a [u8]>,
) -> Signature {
    let mut h = Sha512::new();

    if pre_hash {
        h.update(b"SigEd25519 no Ed25519 collisions");
        h.update([1]); // Ed25519ph
        h.update([0]);
    }

    h.update(sk.hash_prefix);
    h.update_iter(message.clone());

    let r = Scalar::from_hash(h);
    #[allow(non_snake_case)]
    let R = EdwardsPoint::mul_base(&r).compress();

    h = Sha512::new();

    if pre_hash {
        h.update(b"SigEd25519 no Ed25519 collisions");
        h.update([1]); // Ed25519ph
        h.update([0]);
    }

    h.update(R.as_bytes());
    h.update(sk.verifying_key.compressed.0);
    h.update_iter(message);

    let k = Scalar::from_hash(h);
    let s: Scalar = (k * sk.scalar) + r;

    Signature { R, s }
}

fn verify<'a>(
    pk: &VerifyingKey,
    pre_hash: bool,
    message: impl Iterator<Item = &'a [u8]>,
    signature: &Signature,
) -> Result<(), ProtocolError> {
    let mut h = Sha512::new();

    if pre_hash {
        h.update(b"SigEd25519 no Ed25519 collisions");
        h.update([1]); // Ed25519ph
        h.update([0]);
    }

    h.update(signature.R.as_bytes());
    h.update(pk.compressed.as_bytes());
    h.update_iter(message);
    let k = Scalar::from_hash(h);

    #[allow(non_snake_case)]
    let minus_A: EdwardsPoint = -pk.point;
    #[allow(non_snake_case)]
    let expected_R =
        EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(minus_A), &signature.s).compress();

    if expected_R == signature.R {
        Ok(())
    } else {
        Err(ProtocolError::InvalidLoginError)
    }
}

/// Ed25519 Signature.
// `ed25519_dalek::Signature` doesn't implement validation with Serde de/serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_snake_case)]
pub struct Signature {
    R: CompressedEdwardsY,
    s: Scalar,
}

impl Signature {
    /// Expects the `R` and `s` components of a Ed25519 signature with no added
    /// framing.
    pub fn from_slice(mut bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::deserialize_take(&mut bytes)
    }
}

impl Deserialize for Signature {
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        #[allow(non_snake_case)]
        let R = CompressedEdwardsY(input.take_array("signature R")?.into());

        let s = Scalar::from_canonical_bytes(input.take_array("signature s")?.into())
            .into_option()
            .ok_or(ProtocolError::SerializationError)?;

        Ok(Signature { R, s })
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        Signature::deserialize_take(
            &mut (GenericArray::<_, U64>::deserialize(deserializer)?.as_slice()),
        )
        .map_err(D::Error::custom)
    }
}

impl Serialize for Signature {
    type Len = U64;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        GenericArray::from(self.R.0).concat(GenericArray::from(self.s.to_bytes()))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Signature {
    fn serialize<SK>(&self, serializer: SK) -> Result<SK::Ok, SK::Error>
    where
        SK: serde::Serializer,
    {
        <Signature as Serialize>::serialize(self).serialize(serializer)
    }
}

impl Zeroize for Signature {
    fn zeroize(&mut self) {
        self.R.0 = [0; 32];
        self.s = Scalar::default();
    }
}

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl AssertZeroized for VerifyingKey {
    fn assert_zeroized(&self) {
        use curve25519_dalek::traits::Identity;

        let Self { point, compressed } = self;

        assert_eq!(point, &EdwardsPoint::identity());
        assert_eq!(compressed, &EdwardsPoint::identity().compress());
    }
}

#[cfg(test)]
impl AssertZeroized for SigningKey {
    fn assert_zeroized(&self) {
        let Self {
            sk,
            verifying_key,
            scalar,
            hash_prefix,
        } = self;

        verifying_key.assert_zeroized();

        for byte in sk.iter().chain(scalar.to_bytes().iter()).chain(hash_prefix) {
            assert_eq!(byte, &0);
        }
    }
}

#[cfg(test)]
mod test {
    use std::iter;

    use ecdsa::signature::{Signer, Verifier};
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn pure_eddsa() {
        let mut message = [0; 1024];
        OsRng.fill_bytes(&mut message);

        let mut sk = SecretKey::default();
        OsRng.fill_bytes(&mut sk);
        let signing_key = SigningKey::from_bytes(&sk);

        let signature = signing_key.sign(&message);

        let custom_sk = Ed25519::deserialize_take_sk(&mut sk.as_slice()).unwrap();
        let custom_signature = sign(&custom_sk, false, iter::once(message.as_slice()));

        assert_eq!(
            signature.to_bytes(),
            custom_signature.serialize().as_slice()
        );

        let verifying_key = VerifyingKey::from(&signing_key);
        verifying_key.verify(&message, &signature).unwrap();

        let custom_pk = Ed25519::public_key(custom_sk);
        verify(
            &custom_pk,
            false,
            iter::once(message.as_slice()),
            &custom_signature,
        )
        .unwrap();
    }

    #[test]
    fn hash_eddsa() {
        let mut message = [0; 1024];
        OsRng.fill_bytes(&mut message);
        let message = Sha512::new_with_prefix(message);
        let pre_hash = message.clone().finalize();

        let mut sk = SecretKey::default();
        OsRng.fill_bytes(&mut sk);
        let signing_key = SigningKey::from_bytes(&sk);

        let signature = signing_key.sign_prehashed(message.clone(), None).unwrap();

        let custom_sk = Ed25519::deserialize_take_sk(&mut sk.as_slice()).unwrap();
        let custom_signature = sign(&custom_sk, true, iter::once(pre_hash.as_slice()));

        assert_eq!(
            signature.to_bytes(),
            custom_signature.serialize().as_slice()
        );

        let verifying_key = VerifyingKey::from(&signing_key);
        verifying_key
            .verify_prehashed(message, None, &signature)
            .unwrap();

        let custom_pk = Ed25519::public_key(custom_sk);
        verify(
            &custom_pk,
            true,
            iter::once(pre_hash.as_slice()),
            &custom_signature,
        )
        .unwrap();
    }
}

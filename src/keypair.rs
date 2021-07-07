// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains the keypair types that must be supplied for the OPAQUE API

#![allow(unsafe_code)]

use crate::errors::InternalPakeError;
use crate::group::Group;
#[cfg(test)]
use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};
use generic_bytes::{SizedBytes, TryFromSizedBytesError};
#[cfg(test)]
use proptest::prelude::*;
#[cfg(test)]
use rand::{rngs::StdRng, SeedableRng};
use rand::{CryptoRng, RngCore};
use std::fmt::Debug;
use std::ops::Deref;
use zeroize::Zeroize;

/// Convenience extension trait of SizedBytes
pub trait SizedBytesExt: SizedBytes {
    /// Convert from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, TryFromSizedBytesError> {
        <Self as SizedBytes>::from_arr(GenericArray::from_slice(bytes))
    }
}

// blanket implementation
impl<T> SizedBytesExt for T where T: SizedBytes {}

/// A Keypair trait with public-private verification
#[cfg_attr(
    feature = "serialize",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
pub struct KeyPair<G: Group> {
    pk: PublicKey<G>,
    sk: PrivateKey<G>,
}

impl_clone_for!(
    struct KeyPair<G: Group>,
    [pk, sk],
);
impl_debug_eq_hash_for!(
    struct KeyPair<G: Group>,
    [pk, sk],
);

// This can't be derived because of the use of a generic parameter
impl<G: Group> Zeroize for KeyPair<G> {
    fn zeroize(&mut self) {
        self.pk.zeroize();
        self.sk.zeroize();
    }
}

impl<G: Group> Drop for KeyPair<G> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<G: Group> KeyPair<G> {
    /// The public key component
    pub fn public(&self) -> &PublicKey<G> {
        &self.pk
    }

    /// The private key component
    pub fn private(&self) -> &PrivateKey<G> {
        &self.sk
    }

    /// Generating a random key pair given a cryptographic rng
    pub(crate) fn generate_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sk = G::random_nonzero_scalar(rng);
        let sk_bytes = G::scalar_as_bytes(sk);
        let pk = G::base_point().mult_by_slice(&sk_bytes);
        Self {
            pk: PublicKey(Key(pk.to_arr())),
            sk: PrivateKey(Key(sk_bytes)),
        }
    }

    /// Obtaining a public key from secret bytes. At all times, we should have
    /// &public_from_private(self.private()) == self.public()
    pub(crate) fn public_from_private(bytes: &PrivateKey<G>) -> PublicKey<G> {
        let bytes_data = GenericArray::<u8, G::ScalarLen>::from_slice(&bytes.0[..]);
        PublicKey(Key(G::base_point().mult_by_slice(bytes_data).to_arr()))
    }

    /// Check whether a public key is valid. This is meant to be applied on
    /// material provided through the network which fits the key
    /// representation (i.e. can be mapped to a curve point), but presents
    /// some risk - e.g. small subgroup check
    pub(crate) fn check_public_key(key: PublicKey<G>) -> Result<PublicKey<G>, InternalPakeError> {
        G::from_element_slice(GenericArray::from_slice(&key.0)).map(|_| key)
    }

    /// Computes the diffie hellman function on a public key and private key
    pub(crate) fn diffie_hellman(
        pk: PublicKey<G>,
        sk: PrivateKey<G>,
    ) -> Result<Vec<u8>, InternalPakeError> {
        let pk_data = GenericArray::<u8, G::ElemLen>::from_slice(&pk.0[..]);
        let point = G::from_element_slice(pk_data)?;
        let secret_data = GenericArray::<u8, G::ScalarLen>::from_slice(&sk.0[..]);
        Ok(G::mult_by_slice(&point, secret_data).to_arr().to_vec())
    }

    /// Obtains a KeyPair from a slice representing the private key
    pub fn from_private_key_slice(input: &[u8]) -> Result<Self, InternalPakeError> {
        let sk = PrivateKey(Key(GenericArray::clone_from_slice(input)));
        let pk = Self::public_from_private(&sk);
        Ok(Self { pk, sk })
    }

    #[cfg(test)]
    pub fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        vec![
            (self.pk.as_ptr(), G::ElemLen::to_usize()),
            (self.sk.as_ptr(), G::ScalarLen::to_usize()),
        ]
    }
}

#[cfg(test)]
impl<G: Group + Debug> KeyPair<G> {
    /// Test-only strategy returning a proptest Strategy based on
    /// generate_random
    fn uniform_keypair_strategy() -> BoxedStrategy<Self> {
        // The no_shrink is because keypairs should be fixed -- shrinking would cause a different
        // keypair to be generated, which appears to not be very useful.
        any::<[u8; 32]>()
            .prop_filter_map("valid random keypair", |seed| {
                let mut rng = StdRng::from_seed(seed);
                Some(Self::generate_random(&mut rng))
            })
            .no_shrink()
            .boxed()
    }
}

/// A minimalist key type built around a \[u8; 32\]
#[cfg_attr(
    feature = "serialize",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[repr(transparent)]
pub struct Key<L: ArrayLength<u8>>(GenericArray<u8, L>);

impl<L: ArrayLength<u8>> Clone for Key<L> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<L: ArrayLength<u8>> Debug for Key<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Key").field(&self.0).finish()
    }
}

impl<L: ArrayLength<u8>> Eq for Key<L> {}

impl<L: ArrayLength<u8>> PartialEq for Key<L> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<L: ArrayLength<u8>> std::hash::Hash for Key<L> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

// This can't be derived because of the use of a generic parameter
impl<L: ArrayLength<u8>> Zeroize for Key<L> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<L: ArrayLength<u8>> Drop for Key<L> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<L: ArrayLength<u8>> Deref for Key<L> {
    type Target = GenericArray<u8, L>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Don't make it implement SizedBytes so that it's not constructible outside of this module.
impl<L: ArrayLength<u8>> Key<L> {
    fn to_arr(&self) -> GenericArray<u8, L> {
        GenericArray::clone_from_slice(&self.0[..])
    }

    #[allow(clippy::unnecessary_wraps)]
    fn from_arr(key_bytes: &GenericArray<u8, L>) -> Result<Self, TryFromSizedBytesError> {
        Ok(Key(key_bytes.to_owned()))
    }
}

/// Wrapper around a Key to enforce that it's a private one.
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
#[repr(transparent)]
pub struct PrivateKey<G: Group>(Key<G::ScalarLen>);

impl_clone_for!(
    tuple PrivateKey<G: Group>,
    [0],
);
impl_debug_eq_hash_for!(
    tuple PrivateKey<G: Group>,
    [0],
);

// This can't be derived because of the use of a generic parameter
impl<G: Group> Zeroize for PrivateKey<G> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<G: Group> Drop for PrivateKey<G> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<G: Group> Deref for PrivateKey<G> {
    type Target = Key<G::ScalarLen>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<G: Group> SizedBytes for PrivateKey<G> {
    type Len = G::ScalarLen;

    fn to_arr(&self) -> GenericArray<u8, Self::Len> {
        self.0.to_arr()
    }

    fn from_arr(key_bytes: &GenericArray<u8, Self::Len>) -> Result<Self, TryFromSizedBytesError> {
        Ok(PrivateKey(Key::from_arr(key_bytes)?))
    }
}

/// Wrapper around a Key to enforce that it's a public one.
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
#[repr(transparent)]
pub struct PublicKey<G: Group>(Key<G::ElemLen>);

impl_clone_for!(
    tuple PublicKey<G: Group>,
    [0],
);
impl_debug_eq_hash_for!(
    tuple PublicKey<G: Group>,
    [0],
);

// This can't be derived because of the use of a generic parameter
impl<G: Group> Zeroize for PublicKey<G> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<G: Group> Drop for PublicKey<G> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<G: Group> Deref for PublicKey<G> {
    type Target = Key<G::ElemLen>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<G: Group> SizedBytes for PublicKey<G> {
    type Len = G::ElemLen;

    fn to_arr(&self) -> GenericArray<u8, Self::Len> {
        self.0.to_arr()
    }

    fn from_arr(key_bytes: &GenericArray<u8, Self::Len>) -> Result<Self, TryFromSizedBytesError> {
        Ok(PublicKey(Key::from_arr(key_bytes)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use generic_array::typenum::Unsigned;
    use rand::rngs::OsRng;
    use std::slice::from_raw_parts;

    #[test]
    fn test_zeroize_key() -> Result<(), ProtocolError> {
        let key_len = <RistrettoPoint as Group>::ElemLen::to_usize();
        let mut key =
            Key::<<RistrettoPoint as Group>::ElemLen>(GenericArray::clone_from_slice(&vec![
                1u8;
                key_len
            ]));
        let ptr = key.as_ptr();

        key.zeroize();

        let bytes = unsafe { from_raw_parts(ptr, key_len) };
        assert!(bytes.iter().all(|&x| x == 0));

        Ok(())
    }

    #[test]
    fn test_zeroize_keypair() -> Result<(), ProtocolError> {
        let mut rng = OsRng;
        let mut keypair = KeyPair::<RistrettoPoint>::generate_random(&mut rng);
        let ptrs = keypair.as_byte_ptrs();

        keypair.zeroize();

        for (ptr, len) in ptrs {
            let bytes = unsafe { from_raw_parts(ptr, len) };
            assert!(bytes.iter().all(|&x| x == 0));
        }

        Ok(())
    }

    proptest! {
        #[test]
        fn test_ristretto_check(kp in KeyPair::<RistrettoPoint>::uniform_keypair_strategy()) {
            let pk = kp.public();
            prop_assert!(KeyPair::<RistrettoPoint>::check_public_key(pk.clone()).is_ok());
        }

        #[test]
        fn test_ristretto_pub_from_priv(kp in KeyPair::<RistrettoPoint>::uniform_keypair_strategy()) {
            let pk = kp.public();
            let sk = kp.private();
            prop_assert_eq!(&KeyPair::<RistrettoPoint>::public_from_private(sk), pk);
        }

        #[test]
        fn test_ristretto_dh(kp1 in KeyPair::<RistrettoPoint>::uniform_keypair_strategy(),
                          kp2 in KeyPair::<RistrettoPoint>::uniform_keypair_strategy()) {

            let dh1 = KeyPair::<RistrettoPoint>::diffie_hellman(kp1.public().clone(), kp2.private().clone())?;
            let dh2 = KeyPair::<RistrettoPoint>::diffie_hellman(kp2.public().clone(), kp1.private().clone())?;

            prop_assert_eq!(dh1, dh2);
        }

        #[test]
        fn test_private_key_slice(kp in KeyPair::<RistrettoPoint>::uniform_keypair_strategy()) {
            let sk_bytes = kp.private().to_vec();

            let kp2 = KeyPair::<RistrettoPoint>::from_private_key_slice(&sk_bytes)?;
            let kp2_private_bytes = kp2.private().to_vec();

            prop_assert_eq!(sk_bytes, kp2_private_bytes);
        }
    }
}

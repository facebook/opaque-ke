// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains the keypair types that must be supplied for the OPAQUE API

use crate::errors::InternalPakeError;
use crate::group::Group;
use generic_array::{typenum::U32, GenericArray};
use generic_bytes::{SizedBytes, TryFromSizedBytesError};
use generic_bytes_derive::TryFromForSizedBytes;
#[cfg(test)]
use proptest::prelude::*;
#[cfg(test)]
use rand::{rngs::StdRng, SeedableRng};
use rand_core::{CryptoRng, RngCore};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;

// Pub(crate) convenience extension trait of SizedBytes for our purposes
pub(crate) trait SizedBytesExt: SizedBytes {
    fn from_bytes(bytes: &[u8]) -> Result<Self, TryFromSizedBytesError> {
        <Self as SizedBytes>::from_arr(GenericArray::from_slice(bytes))
    }
}

// blanket implementation
impl<T> SizedBytesExt for T where T: SizedBytes {}

/// A Keypair trait with public-private verification
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPair<G> {
    pk: Key,
    sk: Key,
    _g: PhantomData<G>,
}

impl<G: Group> KeyPair<G> {
    /// The public key component
    pub fn public(&self) -> &Key {
        &self.pk
    }

    /// The private key component
    pub fn private(&self) -> &Key {
        &self.sk
    }

    /// A constructor that receives public and private key independently as
    /// bytes
    pub fn new(public: Key, private: Key) -> Result<Self, InternalPakeError> {
        Ok(Self {
            pk: public,
            sk: private,
            _g: PhantomData,
        })
    }

    /// Generating a random key pair given a cryptographic rng
    pub(crate) fn generate_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sk = G::random_scalar(rng);
        let sk_bytes = G::scalar_as_bytes(&sk);
        let pk = G::base_point().mult_by_slice(&sk_bytes);
        Self {
            pk: Key(pk.to_arr().to_vec()),
            sk: Key(sk_bytes.to_vec()),
            _g: PhantomData,
        }
    }

    /// Obtaining a public key from secret bytes. At all times, we should have
    /// &public_from_private(self.private()) == self.public()
    pub(crate) fn public_from_private(bytes: &Key) -> Key {
        let bytes_data = GenericArray::<u8, G::ScalarLen>::from_slice(&bytes.0[..]);
        Key(G::base_point().mult_by_slice(&bytes_data).to_arr().to_vec())
    }

    /// Check whether a public key is valid. This is meant to be applied on
    /// material provided through the network which fits the key
    /// representation (i.e. can be mapped to a curve point), but presents
    /// some risk - e.g. small subgroup check
    pub(crate) fn check_public_key(key: Key) -> Result<Key, InternalPakeError> {
        G::from_element_slice(GenericArray::from_slice(&key.0)).map(|_| key)
    }

    /// Computes the diffie hellman function on a public key and private key
    pub(crate) fn diffie_hellman(pk: Key, sk: Key) -> Result<Vec<u8>, InternalPakeError> {
        let pk_data = GenericArray::<u8, G::ElemLen>::from_slice(&pk.0[..]);
        let point = G::from_element_slice(&pk_data)?;
        let secret_data = GenericArray::<u8, G::ScalarLen>::from_slice(&sk.0[..]);
        Ok(G::mult_by_slice(&point, &secret_data).to_arr().to_vec())
    }

    /// Obtains a KeyPair from a slice representing the private key
    pub fn from_private_key_slice(input: &[u8]) -> Result<Self, InternalPakeError> {
        let sk = Key::from_arr(GenericArray::from_slice(&input))?;
        let pk = Self::public_from_private(&sk);
        Self::new(pk, sk)
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

/// A minimalist key type built around [u8;32]
#[derive(Debug, PartialEq, Eq, Clone, TryFromForSizedBytes)]
#[ErrorType = "::generic_bytes::TryFromSizedBytesError"]
#[repr(transparent)]
pub struct Key(Vec<u8>);

impl Deref for Key {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SizedBytes for Key {
    type Len = U32;

    fn to_arr(&self) -> GenericArray<u8, Self::Len> {
        GenericArray::clone_from_slice(&self.0[..])
    }

    fn from_arr(key_bytes: &GenericArray<u8, Self::Len>) -> Result<Self, TryFromSizedBytesError> {
        Ok(Key(key_bytes.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;

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

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains the keypair types that must be supplied for the OPAQUE API

#![allow(unsafe_code)]

use crate::errors::{InternalPakeError, PakeError};
use crate::group::Group;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;
use generic_array::{typenum::U32, GenericArray};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// A Keypair trait with public-private verification
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPair<G> {
    pk: Key,
    sk: Key,
    _g: PhantomData<G>,
}

// This can't be derived because of the use of a phantom parameter
impl<G> Zeroize for KeyPair<G> {
    fn zeroize(&mut self) {
        self.pk.zeroize();
        self.sk.zeroize();
    }
}

impl<G> Drop for KeyPair<G> {
    fn drop(&mut self) {
        self.zeroize();
    }
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

    /// Generating a random key pair given a cryptographic rng
    pub(crate) fn generate_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sk = G::random_nonzero_scalar(rng);
        let sk_bytes = G::scalar_as_bytes(&sk);
        let pk = G::base_point().mult_by_slice(sk_bytes);
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
        Key(G::base_point().mult_by_slice(bytes_data).to_arr().to_vec())
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
        let point = G::from_element_slice(pk_data)?;
        let secret_data = GenericArray::<u8, G::ScalarLen>::from_slice(&sk.0[..]);
        Ok(G::mult_by_slice(&point, secret_data).to_arr().to_vec())
    }

    /// Obtains a KeyPair from a slice representing the private key
    pub fn from_private_key_slice(input: &[u8]) -> Result<Self, InternalPakeError> {
        let sk = Key(input.to_vec());
        let pk = Self::public_from_private(&sk);
        Ok(Self {
            pk,
            sk,
            _g: PhantomData,
        })
    }

    #[cfg(test)]
    pub fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        alloc::vec![
            (self.pk.0.as_ptr(), Key::LEN),
            (self.sk.0.as_ptr(), Key::LEN),
        ]
    }
}

#[cfg(test)]
impl<G: Group + Debug> KeyPair<G> {
    /// Test-only strategy returning a proptest Strategy based on
    /// generate_random
    fn uniform_keypair_strategy() -> proptest::prelude::BoxedStrategy<Self> {
        use proptest::prelude::*;
        use rand::{rngs::StdRng, SeedableRng};

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
#[derive(Debug, PartialEq, Eq, Clone, Zeroize)]
// Ensure Key material is zeroed after use.
#[zeroize(drop)]
#[repr(transparent)]
pub struct Key(Vec<u8>);

impl core::ops::Deref for Key {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Key {
    pub(crate) const LEN: usize = 32;

    /// Convert to bytes
    pub fn to_arr(&self) -> GenericArray<u8, U32> {
        GenericArray::clone_from_slice(&self.0)
    }

    /// Convert from bytes
    pub fn from_bytes(input: &[u8]) -> Result<Self, PakeError> {
        if input.len() != Self::LEN {
            return Err(PakeError::SerializationError);
        }
        Ok(Self(
            GenericArray::<u8, U32>::clone_from_slice(input).to_vec(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::*;
    use core::slice::from_raw_parts;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use proptest::prelude::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_zeroize_key() -> Result<(), ProtocolError> {
        let key_len = Key::LEN;
        let mut key = Key(alloc::vec![1u8; key_len]);
        let ptr = key.0.as_ptr();

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

    #[cfg(feature = "std")]
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
            let sk_bytes = kp.private().0.clone();

            let kp2 = KeyPair::<RistrettoPoint>::from_private_key_slice(&sk_bytes)?;
            let kp2_private_bytes = kp2.private().0.clone();

            prop_assert_eq!(sk_bytes, kp2_private_bytes);
        }
    }
}

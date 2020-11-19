// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains the keypair types that must be supplied for the OPAQUE API

use crate::errors::InternalPakeError;
use generic_array::{typenum::U32, GenericArray};
use generic_bytes::{SizedBytes, TryFromSizedBytesError};
use generic_bytes_derive::{SizedBytes, TryFromForSizedBytes};
#[cfg(test)]
use proptest::prelude::*;
#[cfg(test)]
use rand::{rngs::StdRng, SeedableRng};
use rand_core::{CryptoRng, RngCore};
use std::convert::TryInto;
use std::fmt::Debug;
use x25519_dalek::{PublicKey, StaticSecret};

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
pub trait KeyPair: Sized {
    /// The single key representation must have a specific byte size itself
    type Repr: SizedBytes + Clone;

    /// The public key component
    fn public(&self) -> &Self::Repr;

    /// The private key component
    fn private(&self) -> &Self::Repr;

    /// A constructor that receives public and private key independently as
    /// bytes
    fn new(public: Self::Repr, private: Self::Repr) -> Result<Self, InternalPakeError>;

    /// Generating a random key pair given a cryptographic rng
    fn generate_random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, InternalPakeError>;

    /// Obtaining a public key from secret bytes. At all times, we should have
    /// &public_from_private(self.private()) == self.public()
    fn public_from_private(secret: &Self::Repr) -> Self::Repr;

    /// Check whether a public key is valid. This is meant to be applied on
    /// material provided through the network which fits the key
    /// representation (i.e. can be mapped to a curve point), but presents
    /// some risk - e.g. small subgroup check
    fn check_public_key(key: Self::Repr) -> Result<Self::Repr, InternalPakeError>;

    /// Computes the diffie hellman function on a public key and private key
    fn diffie_hellman(pk: Self::Repr, sk: Self::Repr) -> Vec<u8>;
}

#[cfg(test)]
trait KeyPairExt: KeyPair + Debug {
    /// Test-only strategy returning a proptest Strategy based on
    /// generate_random
    fn uniform_keypair_strategy() -> BoxedStrategy<Self> {
        // The no_shrink is because keypairs should be fixed -- shrinking would cause a different
        // keypair to be generated, which appears to not be very useful.
        any::<[u8; 32]>()
            .prop_filter_map("valid random keypair", |seed| {
                let mut rng = StdRng::from_seed(seed);
                Self::generate_random(&mut rng).ok()
            })
            .no_shrink()
            .boxed()
    }
}

// blanket implementation
#[cfg(test)]
impl<KP> KeyPairExt for KP where KP: KeyPair + Debug {}

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

/// A representation of an X25519 keypair according to RFC7748
#[derive(Debug, PartialEq, Eq, SizedBytes, TryFromForSizedBytes)]
#[ErrorType = "::generic_bytes::TryFromSizedBytesError"]
pub struct X25519KeyPair {
    pk: Key,
    sk: Key,
}

impl X25519KeyPair {
    fn gen<R: RngCore + CryptoRng>(rng: &mut R) -> (Vec<u8>, Vec<u8>) {
        let sk = StaticSecret::new(rng);
        let pk = PublicKey::from(&sk);
        (pk.as_bytes().to_vec(), sk.to_bytes().to_vec())
    }
}

impl KeyPair for X25519KeyPair {
    type Repr = Key;

    fn public(&self) -> &Self::Repr {
        &self.pk
    }

    fn private(&self) -> &Self::Repr {
        &self.sk
    }

    fn new(public: Self::Repr, private: Self::Repr) -> Result<Self, InternalPakeError> {
        Ok(X25519KeyPair {
            pk: public,
            sk: private,
        })
    }

    fn generate_random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, InternalPakeError> {
        let (public, private) = X25519KeyPair::gen(rng);
        Ok(X25519KeyPair {
            pk: Key(public),
            sk: Key(private),
        })
    }

    fn public_from_private(secret: &Self::Repr) -> Self::Repr {
        let secret_data: [u8; 32] = (&secret.0[..])
            .try_into()
            .expect("Keypair::Repr invariant broken");
        let base_data = ::x25519_dalek::X25519_BASEPOINT_BYTES;
        Key(::x25519_dalek::x25519(secret_data, base_data).to_vec())
    }

    fn check_public_key(key: Self::Repr) -> Result<Self::Repr, InternalPakeError> {
        let key_bytes: [u8; 32] = (&key[..]).try_into().expect("Key invariant broken");
        let point = ::curve25519_dalek::montgomery::MontgomeryPoint(key_bytes)
            .to_edwards(1)
            .ok_or(InternalPakeError::PointError)?;
        if !point.is_torsion_free() {
            Err(InternalPakeError::SubGroupError)
        } else {
            Ok(key)
        }
    }

    fn diffie_hellman(pk: Self::Repr, sk: Self::Repr) -> Vec<u8> {
        let mut pk_data = [0; 32];
        pk_data.copy_from_slice(&pk.0[..]);
        let mut sk_data = [0; 32];
        sk_data.copy_from_slice(&sk.0[..]);
        ::x25519_dalek::x25519(sk_data, pk_data).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest! {
        #[test]
        fn test_x25519_check(kp in X25519KeyPair::uniform_keypair_strategy()) {
            let pk = kp.public();
            prop_assert!(X25519KeyPair::check_public_key(pk.clone()).is_ok());
        }

        #[test]
        fn test_x25519_pub_from_priv(kp in X25519KeyPair::uniform_keypair_strategy()) {
            let pk = kp.public();
            let sk = kp.private();
            prop_assert_eq!(&X25519KeyPair::public_from_private(sk), pk);
        }


        #[test]
        fn test_x25519_dh(kp1 in X25519KeyPair::uniform_keypair_strategy(),
                          kp2 in X25519KeyPair::uniform_keypair_strategy()) {

            let dh1 = X25519KeyPair::diffie_hellman(kp1.public().clone(), kp2.private().clone());
            let dh2 = X25519KeyPair::diffie_hellman(kp2.public().clone(), kp1.private().clone());

            prop_assert_eq!(dh1,dh2);
        }
    }
}

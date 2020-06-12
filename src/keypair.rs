// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains the keypair types that must be supplied for the OPAQUE API

use crate::errors::{utils::check_slice_size, InternalPakeError};
use generic_array::{
    sequence::Concat,
    typenum::{Sum, Unsigned, U32},
    ArrayLength, GenericArray,
};
#[cfg(test)]
use proptest::prelude::*;
#[cfg(test)]
use rand::{rngs::StdRng, SeedableRng};
use rand_core::{CryptoRng, RngCore};
use std::fmt::Debug;
use x25519_dalek::{PublicKey, StaticSecret};

use std::convert::TryFrom;

use std::ops::{Add, Deref};

/// A trait for sized key material that can be represented within a fixed byte
/// array size, used to represent our DH key types
pub trait SizedBytes: Sized + PartialEq {
    /// The typed representation of the byte length
    type Len: ArrayLength<u8>;

    /// Converts this sized key material to a `GenericArray` of the same
    /// size. One can convert this to a `&[u8]` with `GenericArray::as_slice()`
    /// but the size information is then lost from the type.
    fn to_arr(&self) -> GenericArray<u8, Self::Len>;

    /// How to parse such sized material from a byte slice.
    fn from_bytes(key_bytes: &[u8]) -> Result<Self, InternalPakeError>;
}

/// A Keypair trait with public-private verification
pub trait KeyPair: Sized + Debug {
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

    /// Test-only strategy returning a proptest Strategy based on
    /// generate_random
    #[cfg(test)]
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

/// This is a blanket implementation of SizedBytes for any instance of KeyPair
/// with any length of keys. This encodes that we serialize the public key
/// first, followed by the private key in binary formats (and expect it in this
/// order upon decoding).
impl<T, KP> SizedBytes for KP
where
    T: SizedBytes + Clone,
    KP: KeyPair<Repr = T> + PartialEq,
    T::Len: Add<T::Len>,
    Sum<T::Len, T::Len>: ArrayLength<u8>,
{
    type Len = Sum<T::Len, T::Len>;

    fn to_arr(&self) -> GenericArray<u8, Self::Len> {
        let private = self.private().to_arr();
        let public = self.public().to_arr();
        public.concat(private)
    }

    fn from_bytes(key_bytes: &[u8]) -> Result<Self, InternalPakeError> {
        let checked_bytes =
            check_slice_size(key_bytes, <Self::Len as Unsigned>::to_usize(), "key_bytes")?;
        let single_key_len = <<KP::Repr as SizedBytes>::Len as Unsigned>::to_usize();
        let public = <T as SizedBytes>::from_bytes(&checked_bytes[..single_key_len])?;
        let private = <T as SizedBytes>::from_bytes(&checked_bytes[single_key_len..])?;
        KP::new(public, private)
    }
}

/// A minimalist key type built around [u8;32]
#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(transparent)]
pub struct Key(Vec<u8>);

impl Deref for Key {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for Key {
    type Error = InternalPakeError;

    fn try_from(key_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Key::from_bytes(&key_bytes[..])
    }
}

impl SizedBytes for Key {
    type Len = U32;

    fn to_arr(&self) -> GenericArray<u8, Self::Len> {
        GenericArray::clone_from_slice(&self.0[..])
    }

    fn from_bytes(key_bytes: &[u8]) -> Result<Self, InternalPakeError> {
        let checked_bytes =
            check_slice_size(key_bytes, <Self::Len as Unsigned>::to_usize(), "key_bytes")?;
        Ok(Key(checked_bytes.to_vec()))
    }
}

/// A representation of an X25519 keypair according to RFC7748
#[derive(Debug, PartialEq, Eq)]
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
        let mut secret_data = [0u8; 32];
        secret_data.copy_from_slice(&secret.0[..]);
        let base_data = ::x25519_dalek::X25519_BASEPOINT_BYTES;
        Key(::x25519_dalek::x25519(secret_data, base_data).to_vec())
    }

    fn check_public_key(key: Self::Repr) -> Result<Self::Repr, InternalPakeError> {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key);
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

/// A custom, minimalistic Key pair struct built on Key, aimed at reproducing the behavior of libsignal's keypairs
#[derive(Debug, PartialEq, Eq)]
pub struct SignalKeyPair {
    pk: Key,
    sk: Key,
}

impl SignalKeyPair {
    fn clamp_scalar(mut scalar: [u8; 32]) -> ::curve25519_dalek::scalar::Scalar {
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        ::curve25519_dalek::scalar::Scalar::from_bits(scalar)
    }

    fn gen<R: RngCore + CryptoRng>(rng: &mut R) -> (Vec<u8>, Vec<u8>) {
        let mut bits = [0u8; 32];
        rng.fill_bytes(&mut bits);

        // It's proper to sanitize the scalar here, and reproduces x25519::StaticSecret::new
        let sk = SignalKeyPair::clamp_scalar(bits);
        let pk = ::curve25519_dalek::constants::X25519_BASEPOINT * sk;

        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }
}

impl KeyPair for SignalKeyPair {
    type Repr = Key;

    fn public(&self) -> &Self::Repr {
        &self.pk
    }

    fn private(&self) -> &Self::Repr {
        &self.sk
    }

    fn new(public: Self::Repr, private: Self::Repr) -> Result<Self, InternalPakeError> {
        Ok(SignalKeyPair {
            pk: public,
            sk: private,
        })
    }

    fn generate_random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, InternalPakeError> {
        let (public, private) = SignalKeyPair::gen(rng);
        Ok(SignalKeyPair {
            pk: Key(public),
            sk: Key(private),
        })
    }

    fn public_from_private(secret: &Self::Repr) -> Self::Repr {
        let mut secret_data = [0u8; 32];
        secret_data.copy_from_slice(&secret.0[..]);
        let base_data = ::x25519_dalek::X25519_BASEPOINT_BYTES;
        Key(::x25519_dalek::x25519(secret_data, base_data).to_vec())
    }

    fn check_public_key(key: Self::Repr) -> Result<Self::Repr, InternalPakeError> {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key);
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
    use proptest::prelude::*;

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
        fn test_signal_check(kp in SignalKeyPair::uniform_keypair_strategy()) {
            let pk = kp.public();
            prop_assert!(SignalKeyPair::check_public_key(pk.clone()).is_ok());
        }

        #[test]
        fn test_signal_pub_from_priv(kp in SignalKeyPair::uniform_keypair_strategy()) {
            let pk = kp.public();
            let sk = kp.private();
            prop_assert_eq!(&SignalKeyPair::public_from_private(sk), pk);
        }

        #[test]
        fn test_signal_x25519_roundtrips(kp_signal in SignalKeyPair::uniform_keypair_strategy(),
                                         kp_x25519 in X25519KeyPair::uniform_keypair_strategy()) {
            let kp_signal_bytes: &[u8] = &kp_signal.to_arr();
            let kp_x25519_bytes: &[u8] = &kp_x25519.to_arr();

            let reinterpret_signal = X25519KeyPair::from_bytes(kp_signal_bytes).unwrap();
            let reinterpret_x25519 = SignalKeyPair::from_bytes(kp_x25519_bytes).unwrap();

            prop_assert_eq!(kp_signal_bytes, &reinterpret_signal.to_arr()[..]);
            prop_assert_eq!(kp_x25519_bytes, &reinterpret_x25519.to_arr()[..]);
        }

        #[test]
        fn test_signal_as_x25519(kp_signal in SignalKeyPair::uniform_keypair_strategy()) {
            let kp: X25519KeyPair = X25519KeyPair::from_bytes(&kp_signal.to_arr()).unwrap();
            let pk = kp.public();
            prop_assert!(X25519KeyPair::check_public_key(pk.clone()).is_ok());
            let sk = kp.private();
            prop_assert_eq!(&X25519KeyPair::public_from_private(sk), pk);

        }

        #[test]
        fn test_x25519_as_signal(kp_x25519 in X25519KeyPair::uniform_keypair_strategy()) {
            let kp: SignalKeyPair = SignalKeyPair::from_bytes(&kp_x25519.to_arr()).unwrap();
            let pk = kp.public();
            prop_assert!(SignalKeyPair::check_public_key(pk.clone()).is_ok());
            let sk = kp.private();
            prop_assert_eq!(&SignalKeyPair::public_from_private(sk), pk);

        }

    }
}

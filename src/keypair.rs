// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains the keypair types that must be supplied for the OPAQUE API

#![allow(unsafe_code)]

use crate::errors::{InternalError, ProtocolError};
use crate::group::Group;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::ops::Deref;
use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// A Keypair trait with public-private verification
#[cfg_attr(
    feature = "serialize",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "S: serde::Deserialize<'de>",
        serialize = "S: serde::Serialize"
    ))
)]
pub struct KeyPair<G: Group, S: SecretKey<G> = PrivateKey<G>> {
    pk: PublicKey<G>,
    sk: S,
}

impl<G: Group, S: SecretKey<G>> Clone for KeyPair<G, S> {
    fn clone(&self) -> Self {
        Self {
            pk: self.pk.clone(),
            sk: self.sk.clone(),
        }
    }
}

impl<G: Group, S: SecretKey<G> + Debug> Debug for KeyPair<G, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyPair")
            .field("pk", &self.pk)
            .field("sk", &self.sk)
            .finish()
    }
}

impl<G: Group, S: SecretKey<G> + PartialEq> PartialEq for KeyPair<G, S> {
    fn eq(&self, other: &Self) -> bool {
        self.pk.eq(&other.pk) && self.sk.eq(&other.sk)
    }
}

impl<G: Group, S: SecretKey<G> + Eq> Eq for KeyPair<G, S> {}

impl<G: Group, S: SecretKey<G> + core::hash::Hash> core::hash::Hash for KeyPair<G, S> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.pk.hash(state);
        self.sk.hash(state);
    }
}

// This can't be derived because of the use of a generic parameter
impl<G: Group, S: SecretKey<G>> Zeroize for KeyPair<G, S> {
    fn zeroize(&mut self) {
        self.pk.zeroize();
        self.sk.zeroize();
    }
}

impl<G: Group, S: SecretKey<G>> Drop for KeyPair<G, S> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<G: Group, S: SecretKey<G>> KeyPair<G, S> {
    /// The public key component
    pub fn public(&self) -> &PublicKey<G> {
        &self.pk
    }

    /// The private key component
    pub fn private(&self) -> &S {
        &self.sk
    }

    /// Check whether a public key is valid. This is meant to be applied on
    /// material provided through the network which fits the key
    /// representation (i.e. can be mapped to a curve point), but presents
    /// some risk - e.g. small subgroup check
    pub(crate) fn check_public_key(key: PublicKey<G>) -> Result<PublicKey<G>, InternalError> {
        G::from_element_slice(GenericArray::from_slice(&key.0)).map(|_| key)
    }

    /// Obtains a KeyPair from a slice representing the private key
    pub fn from_private_key_slice(input: &[u8]) -> Result<Self, ProtocolError<S::Error>> {
        Self::from_private_key(S::deserialize(input)?)
    }

    /// Obtains a KeyPair from a private key
    pub fn from_private_key(sk: S) -> Result<Self, ProtocolError<S::Error>> {
        let pk = sk.public_key()?;
        Ok(Self { pk, sk })
    }
}

impl<G: Group> KeyPair<G> {
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

    #[cfg(test)]
    pub fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        alloc::vec![
            (self.pk.as_ptr(), G::ElemLen::USIZE),
            (self.sk.as_ptr(), G::ScalarLen::USIZE),
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
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Key").field(&self.0).finish()
    }
}

impl<L: ArrayLength<u8>> Eq for Key<L> {}

impl<L: ArrayLength<u8>> PartialEq for Key<L> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<L: ArrayLength<u8>> core::hash::Hash for Key<L> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
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
    /// Convert to bytes
    pub fn to_arr(&self) -> GenericArray<u8, L> {
        self.0.clone()
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

impl<G: Group> PrivateKey<G> {
    /// Convert from bytes
    pub fn from_arr(key_bytes: GenericArray<u8, G::ScalarLen>) -> Self {
        PrivateKey(Key(key_bytes))
    }

    /// Convert from slice
    pub fn from_bytes(key_bytes: &[u8]) -> Result<Self, InternalError> {
        if key_bytes.len() == G::ScalarLen::USIZE {
            Ok(Self::from_arr(GenericArray::from_slice(key_bytes).clone()))
        } else {
            Err(InternalError::InvalidByteSequence)
        }
    }
}

/// A trait specifying the requirements for a private key container
pub trait SecretKey<G: Group>: Clone + Sized + Zeroize {
    /// Custom error type that can be passed down to `InternalError::Custom`
    type Error;

    /// Diffie-Hellman key exchange implementation
    fn diffie_hellman(&self, pk: PublicKey<G>) -> Result<Vec<u8>, InternalError<Self::Error>>;

    /// Returns public key from private key
    fn public_key(&self) -> Result<PublicKey<G>, InternalError<Self::Error>>;

    /// Serialization into bytes
    fn serialize(&self) -> Vec<u8>;

    /// Deserialization from bytes
    fn deserialize(input: &[u8]) -> Result<Self, InternalError<Self::Error>>;
}

impl<G: Group> SecretKey<G> for PrivateKey<G> {
    type Error = core::convert::Infallible;

    fn diffie_hellman(&self, pk: PublicKey<G>) -> Result<Vec<u8>, InternalError> {
        let pk_data = GenericArray::<u8, G::ElemLen>::from_slice(&pk.0[..]);
        let point = G::from_element_slice(pk_data)?;
        let secret_data = GenericArray::<u8, G::ScalarLen>::from_slice(&self.0[..]);
        Ok(G::mult_by_slice(&point, secret_data).to_arr().to_vec())
    }

    fn public_key(&self) -> Result<PublicKey<G>, InternalError> {
        let bytes_data = GenericArray::<u8, G::ScalarLen>::from_slice(&self.0[..]);
        Ok(PublicKey(Key(G::base_point()
            .mult_by_slice(bytes_data)
            .to_arr())))
    }

    fn serialize(&self) -> Vec<u8> {
        self.to_vec()
    }

    fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        PrivateKey::from_bytes(input).map_err(InternalError::from)
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

impl<G: Group> PublicKey<G> {
    /// Convert from bytes
    pub fn from_arr(key_bytes: GenericArray<u8, G::ElemLen>) -> Self {
        Self(Key(key_bytes))
    }

    /// Convert from slice
    pub fn from_bytes(key_bytes: &[u8]) -> Result<Self, InternalError> {
        if key_bytes.len() == G::ElemLen::USIZE {
            Ok(Self::from_arr(GenericArray::from_slice(key_bytes).clone()))
        } else {
            Err(InternalError::InvalidByteSequence)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::*;
    use core::slice::from_raw_parts;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use generic_array::typenum::Unsigned;
    use proptest::prelude::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_zeroize_key() -> Result<(), ProtocolError> {
        let key_len = <RistrettoPoint as Group>::ElemLen::USIZE;
        let mut key = Key::<<RistrettoPoint as Group>::ElemLen>(GenericArray::clone_from_slice(
            &alloc::vec![
                1u8;
                key_len
            ],
        ));
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
            prop_assert_eq!(&sk.public_key()?, pk);
        }

        #[test]
        fn test_ristretto_dh(kp1 in KeyPair::<RistrettoPoint>::uniform_keypair_strategy(),
                          kp2 in KeyPair::<RistrettoPoint>::uniform_keypair_strategy()) {

            let dh1 = kp2.private().diffie_hellman(kp1.public().clone())?;
            let dh2 = kp1.private().diffie_hellman(kp2.public().clone())?;

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

    #[test]
    fn remote_key() {
        use crate::{
            CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult,
            ClientLoginStartResult, ClientRegistration, ClientRegistrationFinishParameters,
            ClientRegistrationFinishResult, ClientRegistrationStartResult, ServerLogin,
            ServerLoginStartParameters, ServerLoginStartResult, ServerRegistration,
            ServerRegistrationStartResult, ServerSetup,
        };
        use curve25519_dalek::ristretto::RistrettoPoint;
        use rand::rngs::OsRng;

        struct Default;

        impl CipherSuite for Default {
            type OprfGroup = RistrettoPoint;
            type KeGroup = RistrettoPoint;
            type KeyExchange = crate::key_exchange::tripledh::TripleDH;
            type Hash = sha2::Sha512;
            type SlowHash = crate::slow_hash::NoOpHash;
        }

        #[derive(Clone, Zeroize)]
        struct RemoteKey(PrivateKey<RistrettoPoint>);

        impl SecretKey<RistrettoPoint> for RemoteKey {
            type Error = core::convert::Infallible;

            fn diffie_hellman(
                &self,
                pk: PublicKey<RistrettoPoint>,
            ) -> Result<Vec<u8>, InternalError<Self::Error>> {
                self.0.diffie_hellman(pk)
            }

            fn public_key(&self) -> Result<PublicKey<RistrettoPoint>, InternalError<Self::Error>> {
                self.0.public_key()
            }

            fn serialize(&self) -> Vec<u8> {
                self.0.serialize()
            }

            fn deserialize(input: &[u8]) -> Result<Self, InternalError<Self::Error>> {
                PrivateKey::deserialize(input).map(Self)
            }
        }

        const PASSWORD: &str = "password";

        let sk = RistrettoPoint::random_nonzero_scalar(&mut OsRng);
        let sk_bytes = RistrettoPoint::scalar_as_bytes(sk);
        let sk = RemoteKey(PrivateKey::from_arr(sk_bytes));
        let keypair = KeyPair::from_private_key(sk).unwrap();

        let server_setup = ServerSetup::<Default, RemoteKey>::new_with_key(&mut OsRng, keypair);

        let ClientRegistrationStartResult {
            message,
            state: client,
        } = ClientRegistration::<Default>::start(&mut OsRng, PASSWORD.as_bytes()).unwrap();
        let ServerRegistrationStartResult { message, .. } =
            ServerRegistration::start(&server_setup, message, &[]).unwrap();
        let ClientRegistrationFinishResult { message, .. } = client
            .finish(
                &mut OsRng,
                message,
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();
        let file = ServerRegistration::finish(message);

        let ClientLoginStartResult {
            message,
            state: client,
        } = ClientLogin::<Default>::start(&mut OsRng, PASSWORD.as_bytes()).unwrap();
        let ServerLoginStartResult {
            message,
            state: server,
            ..
        } = ServerLogin::start(
            &mut OsRng,
            &server_setup,
            Some(file),
            message,
            &[],
            ServerLoginStartParameters::default(),
        )
        .unwrap();
        let ClientLoginFinishResult { message, .. } = client
            .finish(message, ClientLoginFinishParameters::default())
            .unwrap();
        server.finish(message).unwrap();
    }
}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the keypair types that must be supplied for the OPAQUE API

#![allow(unsafe_code)]

use crate::errors::{InternalError, ProtocolError};
use crate::key_exchange::group::KeGroup;
use core::ops::Deref;
use derive_where::DeriveWhere;
use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// A Keypair trait with public-private verification
#[cfg_attr(
    feature = "serde",
    derive(serde_::Deserialize, serde_::Serialize),
    serde(
        bound(
            deserialize = "S: serde_::Deserialize<'de>",
            serialize = "S: serde_::Serialize"
        ),
        crate = "serde_"
    )
)]
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; S)]
pub struct KeyPair<KG: KeGroup, S: SecretKey<KG> = PrivateKey<KG>> {
    pk: PublicKey<KG>,
    sk: S,
}

impl<KG: KeGroup, S: SecretKey<KG>> KeyPair<KG, S> {
    /// The public key component
    pub fn public(&self) -> &PublicKey<KG> {
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
    pub(crate) fn check_public_key(key: PublicKey<KG>) -> Result<PublicKey<KG>, InternalError> {
        KG::from_pk_slice(GenericArray::from_slice(&key.0)).map(|_| key)
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

impl<KG: KeGroup> KeyPair<KG> {
    /// Generating a random key pair given a cryptographic rng
    pub(crate) fn generate_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sk = KG::random_sk(rng);
        let pk = KG::public_key(&sk);
        Self {
            pk: PublicKey(Key(pk.to_arr())),
            sk: PrivateKey(Key(sk)),
        }
    }
}

#[cfg(test)]
impl<KG: KeGroup> KeyPair<KG> {
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
    feature = "serde",
    derive(serde_::Deserialize, serde_::Serialize),
    serde(bound = "", crate = "serde_")
)]
#[derive(DeriveWhere)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Zeroize(drop))]
pub struct Key<L: ArrayLength<u8>>(GenericArray<u8, L>);

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
#[cfg_attr(
    feature = "serde",
    derive(serde_::Deserialize, serde_::Serialize),
    serde(bound = "", crate = "serde_")
)]
#[derive(DeriveWhere)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Zeroize(drop))]
pub struct PrivateKey<KG: KeGroup>(Key<KG::SkLen>);

// This can't be derived because of the use of a generic parameter
impl<KG: KeGroup> Deref for PrivateKey<KG> {
    type Target = Key<KG::SkLen>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<KG: KeGroup> PrivateKey<KG> {
    /// Convert from bytes
    pub fn from_arr(key_bytes: GenericArray<u8, KG::SkLen>) -> Self {
        PrivateKey(Key(key_bytes))
    }

    /// Convert from slice
    pub fn from_bytes(key_bytes: &[u8]) -> Result<Self, InternalError> {
        if key_bytes.len() == KG::SkLen::USIZE {
            Ok(Self::from_arr(GenericArray::from_slice(key_bytes).clone()))
        } else {
            Err(InternalError::InvalidByteSequence)
        }
    }
}

/// A trait specifying the requirements for a private key container
pub trait SecretKey<KG: KeGroup>: Clone + Sized + Zeroize {
    /// Custom error type that can be passed down to `InternalError::Custom`
    type Error;
    /// Serialization size in bytes.
    type Len: ArrayLength<u8>;

    /// Diffie-Hellman key exchange implementation
    fn diffie_hellman(
        &self,
        pk: PublicKey<KG>,
    ) -> Result<GenericArray<u8, KG::PkLen>, InternalError<Self::Error>>;

    /// Returns public key from private key
    fn public_key(&self) -> Result<PublicKey<KG>, InternalError<Self::Error>>;

    /// Serialization into bytes
    fn serialize(&self) -> GenericArray<u8, Self::Len>;

    /// Deserialization from bytes
    fn deserialize(input: &[u8]) -> Result<Self, InternalError<Self::Error>>;
}

impl<KG: KeGroup> SecretKey<KG> for PrivateKey<KG> {
    type Error = core::convert::Infallible;
    type Len = KG::SkLen;

    fn diffie_hellman(
        &self,
        pk: PublicKey<KG>,
    ) -> Result<GenericArray<u8, KG::PkLen>, InternalError> {
        let pk = KG::from_pk_slice(&pk)?;
        Ok(pk.diffie_hellman(self))
    }

    fn public_key(&self) -> Result<PublicKey<KG>, InternalError> {
        Ok(PublicKey(Key(KG::public_key(&self.0).to_arr())))
    }

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.to_arr()
    }

    fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        PrivateKey::from_bytes(input).map_err(InternalError::from)
    }
}

/// Wrapper around a Key to enforce that it's a public one.
#[cfg_attr(
    feature = "serde",
    derive(serde_::Deserialize, serde_::Serialize),
    serde(bound = "", crate = "serde_")
)]
#[derive(DeriveWhere)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Zeroize(drop))]
pub struct PublicKey<KG: KeGroup>(Key<KG::PkLen>);

impl<KG: KeGroup> Deref for PublicKey<KG> {
    type Target = Key<KG::PkLen>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<KG: KeGroup> PublicKey<KG> {
    /// Convert from bytes
    pub fn from_arr(key_bytes: GenericArray<u8, KG::PkLen>) -> Self {
        Self(Key(key_bytes))
    }

    /// Convert from slice
    pub fn from_bytes(key_bytes: &[u8]) -> Result<Self, InternalError> {
        if key_bytes.len() == KG::PkLen::USIZE {
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
    use generic_array::typenum::Unsigned;
    use rand::rngs::OsRng;

    #[test]
    fn test_zeroize_key() -> Result<(), ProtocolError> {
        fn inner<G: KeGroup>() -> Result<(), ProtocolError> {
            let key_len = G::PkLen::USIZE;
            let mut key = Key::<G::PkLen>(GenericArray::clone_from_slice(&alloc::vec![
                1u8;
                key_len
            ]));
            let ptr = key.as_ptr();

            Zeroize::zeroize(&mut key);

            let bytes = unsafe { from_raw_parts(ptr, key_len) };
            assert!(bytes.iter().all(|&x| x == 0));

            Ok(())
        }

        #[cfg(feature = "ristretto255")]
        inner::<curve25519_dalek::ristretto::RistrettoPoint>()?;
        #[cfg(feature = "p256")]
        inner::<p256_::PublicKey>()?;

        Ok(())
    }

    #[test]
    fn test_zeroize_keypair() {
        fn inner<G: KeGroup>() {
            let mut rng = OsRng;
            let mut keypair = KeyPair::<G>::generate_random(&mut rng);
            let pk_ptr = keypair.pk.as_ptr();
            let sk_ptr = keypair.sk.as_ptr();
            let pk_len = G::PkLen::USIZE;
            let sk_len = G::SkLen::USIZE;

            Zeroize::zeroize(&mut keypair);

            let pk_bytes = unsafe { from_raw_parts(pk_ptr, pk_len) };
            let sk_bytes = unsafe { from_raw_parts(sk_ptr, sk_len) };

            assert!(pk_bytes.iter().all(|&x| x == 0));
            assert!(sk_bytes.iter().all(|&x| x == 0));
        }

        #[cfg(feature = "ristretto255")]
        inner::<curve25519_dalek::ristretto::RistrettoPoint>();
        #[cfg(feature = "p256")]
        inner::<p256_::PublicKey>();
    }

    macro_rules! test {
        ($mod:ident, $point:ty) => {
            mod $mod {
                use super::*;
                use proptest::prelude::*;

                proptest! {
                    #[test]
                    fn check(kp in KeyPair::<$point>::uniform_keypair_strategy()) {
                        let pk = kp.public();
                        prop_assert!(KeyPair::<$point>::check_public_key(pk.clone()).is_ok());
                    }

                    #[test]
                    fn pub_from_priv(kp in KeyPair::<$point>::uniform_keypair_strategy()) {
                        let pk = kp.public();
                        let sk = kp.private();
                        prop_assert_eq!(&sk.public_key()?, pk);
                    }

                    #[test]
                    fn dh(kp1 in KeyPair::<$point>::uniform_keypair_strategy(),
                                      kp2 in KeyPair::<$point>::uniform_keypair_strategy()) {

                        let dh1 = kp2.private().diffie_hellman(kp1.public().clone())?;
                        let dh2 = kp1.private().diffie_hellman(kp2.public().clone())?;

                        prop_assert_eq!(dh1, dh2);
                    }

                    #[test]
                    fn private_key_slice(kp in KeyPair::<$point>::uniform_keypair_strategy()) {
                        let sk_bytes = kp.private().to_vec();

                        let kp2 = KeyPair::<$point>::from_private_key_slice(&sk_bytes)?;
                        let kp2_private_bytes = kp2.private().to_vec();

                        prop_assert_eq!(sk_bytes, kp2_private_bytes);
                    }
                }
            }
        };
    }

    #[cfg(feature = "ristretto255")]
    test!(ristretto, curve25519_dalek::ristretto::RistrettoPoint);
    #[cfg(feature = "p256")]
    test!(p256, p256_::PublicKey);

    #[test]
    fn remote_key() {
        use crate::{
            CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult,
            ClientLoginStartResult, ClientRegistration, ClientRegistrationFinishParameters,
            ClientRegistrationFinishResult, ClientRegistrationStartResult, ServerLogin,
            ServerLoginStartParameters, ServerLoginStartResult, ServerRegistration,
            ServerRegistrationStartResult, ServerSetup,
        };
        #[cfg(feature = "ristretto255")]
        use curve25519_dalek::ristretto::RistrettoPoint as KeCurve;
        #[cfg(not(feature = "ristretto255"))]
        use p256_::PublicKey as KeCurve;
        use rand::rngs::OsRng;

        struct Default;

        impl CipherSuite for Default {
            #[cfg(feature = "ristretto255")]
            type OprfGroup = KeCurve;
            #[cfg(not(feature = "ristretto255"))]
            type OprfGroup = p256_::ProjectivePoint;
            type KeGroup = KeCurve;
            type KeyExchange = crate::key_exchange::tripledh::TripleDH;
            #[cfg(feature = "ristretto255")]
            type Hash = sha2::Sha512;
            #[cfg(not(feature = "ristretto255"))]
            type Hash = sha2::Sha256;
            type SlowHash = crate::slow_hash::NoOpHash;
        }

        #[derive(Clone, Zeroize)]
        struct RemoteKey(PrivateKey<KeCurve>);

        impl SecretKey<KeCurve> for RemoteKey {
            type Error = core::convert::Infallible;
            type Len = <KeCurve as KeGroup>::SkLen;

            fn diffie_hellman(
                &self,
                pk: PublicKey<KeCurve>,
            ) -> Result<GenericArray<u8, <KeCurve as KeGroup>::PkLen>, InternalError<Self::Error>>
            {
                self.0.diffie_hellman(pk)
            }

            fn public_key(&self) -> Result<PublicKey<KeCurve>, InternalError<Self::Error>> {
                self.0.public_key()
            }

            fn serialize(&self) -> GenericArray<u8, Self::Len> {
                self.0.serialize()
            }

            fn deserialize(input: &[u8]) -> Result<Self, InternalError<Self::Error>> {
                PrivateKey::deserialize(input).map(Self)
            }
        }

        const PASSWORD: &str = "password";

        let sk = KeCurve::random_sk(&mut OsRng);
        let sk = RemoteKey(PrivateKey(Key(sk)));
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

// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Contains the keypair types that must be supplied for the OPAQUE API

#![allow(unsafe_code)]

use derive_where::derive_where;
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};

use crate::errors::ProtocolError;
use crate::key_exchange::group::Group;
use crate::key_exchange::tripledh::DiffieHellman;

/// A Keypair trait with public-private verification
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "SK: serde::Deserialize<'de>",
        serialize = "SK: serde::Serialize"
    ))
)]
#[derive_where(Clone)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; KG::Pk, SK)]
pub struct KeyPair<KG: Group, SK: Clone = PrivateKey<KG>> {
    pk: PublicKey<KG>,
    sk: SK,
}

impl<KG: Group, SK: Clone> KeyPair<KG, SK> {
    /// Creates a new [`KeyPair`] from the given keys.
    pub fn new(sk: SK, pk: PublicKey<KG>) -> Self {
        Self { pk, sk }
    }

    /// The public key component
    pub fn public(&self) -> &PublicKey<KG> {
        &self.pk
    }

    /// The private key component
    pub fn private(&self) -> &SK {
        &self.sk
    }
}

impl<KG: Group> KeyPair<KG> {
    pub(crate) fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sk = KG::random_sk(rng);
        let pk = KG::public_key(sk);
        Self {
            pk: PublicKey(pk),
            sk: PrivateKey(sk),
        }
    }

    /// Generating a random key pair given a cryptographic rng
    pub(crate) fn derive_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut scalar_bytes = GenericArray::<_, <KG as Group>::SkLen>::default();
        rng.fill_bytes(&mut scalar_bytes);
        let sk = KG::derive_scalar(scalar_bytes).unwrap();
        let pk = KG::public_key(sk);
        Self {
            pk: PublicKey(pk),
            sk: PrivateKey(sk),
        }
    }
}

#[cfg(test)]
impl<KG: Group> KeyPair<KG>
where
    KG::Pk: std::fmt::Debug,
    KG::Sk: std::fmt::Debug,
{
    /// Test-only strategy returning a proptest Strategy based on
    /// [`Self::derive_random`]
    fn uniform_keypair_strategy() -> proptest::prelude::BoxedStrategy<Self> {
        use proptest::prelude::*;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        // The no_shrink is because keypairs should be fixed -- shrinking would cause a
        // different keypair to be generated, which appears to not be very useful.
        any::<[u8; 32]>()
            .prop_filter_map("valid random keypair", |seed| {
                let mut rng = StdRng::from_seed(seed);
                Some(Self::derive_random(&mut rng))
            })
            .no_shrink()
            .boxed()
    }
}

/// Wrapper around a Key to enforce that it's a private one.
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; KG::Sk)]
pub struct PrivateKey<KG: Group>(KG::Sk);

impl<KG: Group> PrivateKey<KG> {
    /// Returns public key from private key
    pub fn public_key(&self) -> PublicKey<KG> {
        PublicKey(KG::public_key(self.0))
    }

    pub(crate) fn serialize(&self) -> GenericArray<u8, KG::SkLen> {
        KG::serialize_sk(self.0)
    }

    /// Creates a [`PrivateKey`] from the given bytes.
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        KG::deserialize_sk(input).map(Self)
    }
}

impl<KG: Group> PrivateKey<KG>
where
    KG::Sk: DiffieHellman<KG>,
{
    /// Diffie-Hellman key exchange implementation
    pub(crate) fn ke_diffie_hellman(&self, pk: &PublicKey<KG>) -> GenericArray<u8, KG::PkLen> {
        self.0.diffie_hellman(pk.0)
    }
}

/// A trait to facilitate
/// [`ServerSetup::de/serialize`](crate::ServerSetup::serialize).
pub trait PrivateKeySerialization<KG: Group>: Clone {
    /// Custom error type that can be passed down to `ProtocolError::Custom`
    type Error;
    /// Serialization size in bytes.
    type Len: ArrayLength<u8>;

    /// Serialization into bytes
    fn serialize_key_pair(key_pair: &KeyPair<KG, Self>) -> GenericArray<u8, Self::Len>;

    /// Deserialization from bytes
    fn deserialize_key_pair(input: &[u8]) -> Result<KeyPair<KG, Self>, ProtocolError<Self::Error>>;
}

impl<KG: Group> PrivateKeySerialization<KG> for PrivateKey<KG> {
    type Error = core::convert::Infallible;
    type Len = KG::SkLen;

    fn serialize_key_pair(key_pair: &KeyPair<KG, Self>) -> GenericArray<u8, Self::Len> {
        key_pair.private().serialize()
    }

    fn deserialize_key_pair(input: &[u8]) -> Result<KeyPair<KG, Self>, ProtocolError> {
        let sk = PrivateKey::deserialize(input)?;
        let pk = sk.public_key();

        Ok(KeyPair::new(sk, pk))
    }
}

#[cfg(feature = "serde")]
impl<'de, KG: Group> serde::Deserialize<'de> for PrivateKey<KG> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        KG::deserialize_sk(&GenericArray::<_, KG::SkLen>::deserialize(deserializer)?)
            .map(Self)
            .map_err(D::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl<KG: Group> serde::Serialize for PrivateKey<KG> {
    fn serialize<SK>(&self, serializer: SK) -> Result<SK::Ok, SK::Error>
    where
        SK: serde::Serializer,
    {
        KG::serialize_sk(self.0).serialize(serializer)
    }
}

/// Wrapper around a Key to enforce that it's a public one.
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; KG::Pk)]
pub struct PublicKey<KG: Group>(KG::Pk);

impl<KG: Group> PublicKey<KG> {
    /// Convert from bytes
    pub fn deserialize(key_bytes: &[u8]) -> Result<Self, ProtocolError> {
        KG::deserialize_pk(key_bytes).map(Self)
    }

    /// Convert to bytes
    pub fn serialize(&self) -> GenericArray<u8, KG::PkLen> {
        KG::serialize_pk(self.0)
    }

    /// Returns the inner [`Group::Pk`].
    pub fn to_group_type(&self) -> KG::Pk {
        self.0
    }
}

#[cfg(feature = "serde")]
impl<'de, KG: Group> serde::Deserialize<'de> for PublicKey<KG> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        KG::deserialize_pk(&GenericArray::<_, KG::PkLen>::deserialize(deserializer)?)
            .map(Self)
            .map_err(D::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl<KG: Group> serde::Serialize for PublicKey<KG> {
    fn serialize<SK>(&self, serializer: SK) -> Result<SK::Ok, SK::Error>
    where
        SK: serde::Serializer,
    {
        KG::serialize_pk(self.0).serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;
    use crate::ciphersuite::KeGroup;
    use crate::util;

    #[test]
    fn test_zeroize_key() {
        fn inner<G: Group>() {
            let mut rng = OsRng;
            let mut key = PrivateKey::<G>(G::random_sk(&mut rng));
            util::test_zeroize_on_drop(&mut key);
        }

        #[cfg(feature = "ristretto255")]
        inner::<crate::Ristretto255>();
        inner::<::p256::NistP256>();
        inner::<::p384::NistP384>();
        inner::<::p521::NistP521>();
    }

    macro_rules! test {
        ($mod:ident, $point:ty) => {
            mod $mod {
                use std::format;

                use proptest::prelude::*;

                use super::*;

                proptest! {
                    #[test]
                    fn pub_from_priv(kp in KeyPair::<$point>::uniform_keypair_strategy()) {
                        let pk = kp.public();
                        let sk = kp.private();
                        prop_assert_eq!(&sk.public_key(), pk);
                    }

                    #[test]
                    fn dh(kp1 in KeyPair::<$point>::uniform_keypair_strategy(),
                                      kp2 in KeyPair::<$point>::uniform_keypair_strategy()) {

                        let dh1 = kp2.private().ke_diffie_hellman(&kp1.public());
                        let dh2 = kp1.private().ke_diffie_hellman(kp2.public());

                        prop_assert_eq!(dh1, dh2);
                    }

                    #[test]
                    fn private_key_slice(kp in KeyPair::<$point>::uniform_keypair_strategy()) {
                        let sk_bytes = kp.private().serialize().to_vec();

                        let kp2 = PrivateKey::<$point>::deserialize_key_pair(&sk_bytes)?;
                        let kp2_private_bytes = kp2.private().serialize().to_vec();

                        prop_assert_eq!(sk_bytes, kp2_private_bytes);
                    }
                }
            }
        };
    }

    #[cfg(feature = "ristretto255")]
    test!(ristretto, crate::Ristretto255);
    test!(p256, ::p256::NistP256);
    test!(p384, ::p384::NistP384);
    test!(p521, ::p521::NistP521);

    #[test]
    fn remote_key() {
        use rand::rngs::OsRng;

        use crate::{
            CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult,
            ClientLoginStartResult, ClientRegistration, ClientRegistrationFinishParameters,
            ClientRegistrationFinishResult, ClientRegistrationStartResult, ServerLogin,
            ServerLoginStartParameters, ServerLoginStartResult, ServerRegistration,
            ServerRegistrationStartResult, ServerSetup,
        };

        struct Default;

        impl CipherSuite for Default {
            #[cfg(feature = "ristretto255")]
            type OprfCs = crate::Ristretto255;
            #[cfg(not(feature = "ristretto255"))]
            type OprfCs = ::p256::NistP256;
            #[cfg(feature = "ristretto255")]
            type KeyExchange =
                crate::key_exchange::tripledh::TripleDh<crate::Ristretto255, sha2::Sha512>;
            #[cfg(not(feature = "ristretto255"))]
            type KeyExchange =
                crate::key_exchange::tripledh::TripleDh<::p256::NistP256, sha2::Sha256>;
            type Ksf = crate::ksf::Identity;
        }

        #[derive(Clone)]
        struct RemoteKey(PrivateKey<KeGroup<Default>>);

        const PASSWORD: &str = "password";

        let sk = PrivateKey(KeGroup::<Default>::random_sk(&mut OsRng));
        let pk = sk.public_key();
        let sk = RemoteKey(sk);
        let keypair = KeyPair::new(sk, pk);

        let server_setup =
            ServerSetup::<Default, RemoteKey>::new_with_key_pair(&mut OsRng, keypair);

        let ClientRegistrationStartResult {
            message,
            state: client,
        } = ClientRegistration::<Default>::start(&mut OsRng, PASSWORD.as_bytes()).unwrap();
        let ServerRegistrationStartResult { message, .. } =
            ServerRegistration::start(&server_setup, message, &[]).unwrap();
        let ClientRegistrationFinishResult { message, .. } = client
            .finish(
                &mut OsRng,
                PASSWORD.as_bytes(),
                message,
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();
        let file = ServerRegistration::finish(message);

        let ClientLoginStartResult {
            message,
            state: client,
        } = ClientLogin::<Default>::start(&mut OsRng, PASSWORD.as_bytes()).unwrap();
        let builder = ServerLogin::builder(
            &mut OsRng,
            &server_setup,
            Some(file),
            message,
            &[],
            ServerLoginStartParameters::default(),
        )
        .unwrap();
        let shared_secret = builder.private_key().0.ke_diffie_hellman(builder.data());
        let ServerLoginStartResult {
            message,
            state: server,
            ..
        } = builder.build(shared_secret).unwrap();
        let ClientLoginFinishResult { message, .. } = client
            .finish(
                PASSWORD.as_bytes(),
                message,
                ClientLoginFinishParameters::default(),
            )
            .unwrap();
        server.finish(message).unwrap();
    }
}

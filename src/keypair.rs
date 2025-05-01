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
use digest::{Output, OutputSizeUser};
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};

use crate::ciphersuite::CipherSuite;
use crate::errors::ProtocolError;
use crate::key_exchange::group::Group;
use crate::key_exchange::sigma_i::{Message, MessageBuilder, SharedSecret, SignatureProtocol};
use crate::key_exchange::tripledh::DiffieHellman;
use crate::serialization::SliceExt;

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
#[derive_where(Eq, Hash, Ord, PartialEq, PartialOrd; G::Pk, SK)]
#[cfg_attr(not(test), derive_where(Debug; G::Pk, SK))]
#[cfg_attr(test, derive_where(Debug), derive_where(skip_inner(Debug)))]
pub struct KeyPair<G: Group, SK: Clone = PrivateKey<G>> {
    pk: PublicKey<G>,
    sk: SK,
}

impl<G: Group, SK: Clone> KeyPair<G, SK> {
    /// Creates a new [`KeyPair`] from the given keys.
    pub fn new(sk: SK, pk: PublicKey<G>) -> Self {
        Self { pk, sk }
    }

    /// The public key component
    pub fn public(&self) -> &PublicKey<G> {
        &self.pk
    }

    /// The private key component
    pub fn private(&self) -> &SK {
        &self.sk
    }
}

impl<G: Group> KeyPair<G> {
    pub(crate) fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sk = G::random_sk(rng);
        let pk = G::public_key(sk);
        Self {
            pk: PublicKey(pk),
            sk: PrivateKey(sk),
        }
    }

    /// Generating a random key pair given a cryptographic rng
    pub(crate) fn derive_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut scalar_bytes = GenericArray::<_, <G as Group>::SkLen>::default();
        rng.fill_bytes(&mut scalar_bytes);
        let sk = G::derive_scalar(scalar_bytes).unwrap();
        let pk = G::public_key(sk);
        Self {
            pk: PublicKey(pk),
            sk: PrivateKey(sk),
        }
    }
}

/// Wrapper around a Key to enforce that it's a private one.
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Sk)]
pub struct PrivateKey<G: Group>(G::Sk);

impl<G: Group> PrivateKey<G> {
    pub(crate) fn new(key: G::Sk) -> Self {
        Self(key)
    }

    /// Returns public key from private key
    pub fn public_key(&self) -> PublicKey<G> {
        PublicKey(G::public_key(self.0))
    }

    pub(crate) fn serialize(&self) -> GenericArray<u8, G::SkLen> {
        G::serialize_sk(self.0)
    }

    /// Creates a [`PrivateKey`] from the given bytes.
    pub fn deserialize(mut input: &[u8]) -> Result<Self, ProtocolError> {
        Self::deserialize_take(&mut input)
    }

    pub(crate) fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        G::deserialize_take_sk(input).map(Self)
    }
}

impl<G: Group> PrivateKey<G>
where
    G::Sk: DiffieHellman<G>,
{
    /// Diffie-Hellman key exchange implementation
    pub(crate) fn ke_diffie_hellman(&self, pk: &PublicKey<G>) -> GenericArray<u8, G::PkLen> {
        self.0.diffie_hellman(pk.0)
    }
}

impl<G: Group> PrivateKey<G>
where
    G::Sk: SharedSecret<G>,
{
    /// Key-exchange implementation
    pub(crate) fn ke_shared_secret(
        &self,
        pk: &PublicKey<G>,
    ) -> GenericArray<u8, <G::Sk as SharedSecret<G>>::Len> {
        self.0.shared_secret(pk.0)
    }
}

impl<G: Group> PrivateKey<G> {
    /// Private-key signing implementation
    pub(crate) fn sign<
        R: CryptoRng + RngCore,
        CS: CipherSuite,
        SIG: SignatureProtocol<Group = G>,
        KE: Group,
    >(
        &self,
        rng: &mut R,
        message: &Message<CS, KE>,
    ) -> (SIG::Signature, SIG::VerifyState<CS, KE>) {
        SIG::sign(&self.0, rng, message)
    }
}

/// A trait to facilitate
/// [`ServerSetup::de/serialize`](crate::ServerSetup::serialize).
pub trait PrivateKeySerialization<G: Group>: Clone {
    /// Custom error type that can be passed down to `ProtocolError::Custom`
    type Error;
    /// Serialization size in bytes.
    type Len: ArrayLength<u8>;

    /// Serialization into bytes
    fn serialize_key_pair(key_pair: &KeyPair<G, Self>) -> GenericArray<u8, Self::Len>;

    /// Deserialization from bytes
    fn deserialize_key_pair(
        input: &mut &[u8],
    ) -> Result<KeyPair<G, Self>, ProtocolError<Self::Error>>;
}

impl<G: Group> PrivateKeySerialization<G> for PrivateKey<G> {
    type Error = core::convert::Infallible;
    type Len = G::SkLen;

    fn serialize_key_pair(key_pair: &KeyPair<G, Self>) -> GenericArray<u8, Self::Len> {
        key_pair.private().serialize()
    }

    fn deserialize_key_pair(input: &mut &[u8]) -> Result<KeyPair<G, Self>, ProtocolError> {
        let sk = PrivateKey::deserialize_take(input)?;
        let pk = sk.public_key();

        Ok(KeyPair::new(sk, pk))
    }
}

#[cfg(feature = "serde")]
impl<'de, G: Group> serde::Deserialize<'de> for PrivateKey<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        G::deserialize_take_sk(
            &mut (GenericArray::<_, G::SkLen>::deserialize(deserializer)?.as_slice()),
        )
        .map(Self)
        .map_err(D::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl<G: Group> serde::Serialize for PrivateKey<G> {
    fn serialize<SK>(&self, serializer: SK) -> Result<SK::Ok, SK::Error>
    where
        SK: serde::Serializer,
    {
        G::serialize_sk(self.0).serialize(serializer)
    }
}

/// Wrapper around a Key to enforce that it's a public one.
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Pk)]
pub struct PublicKey<G: Group>(G::Pk);

impl<G: Group> PublicKey<G> {
    /// Convert from bytes
    pub fn deserialize(mut key_bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::deserialize_take(&mut key_bytes)
    }

    pub(crate) fn deserialize_take(key_bytes: &mut &[u8]) -> Result<Self, ProtocolError> {
        G::deserialize_take_pk(key_bytes).map(Self)
    }

    /// Convert to bytes
    pub fn serialize(&self) -> GenericArray<u8, G::PkLen> {
        G::serialize_pk(self.0)
    }

    /// Returns the inner [`Group::Pk`].
    pub fn to_group_type(&self) -> G::Pk {
        self.0
    }
}

impl<G: Group> PublicKey<G> {
    /// Public-key verifying implementation
    pub(crate) fn verify<CS: CipherSuite, SIG: SignatureProtocol<Group = G>, KE: Group>(
        &self,
        message_builder: MessageBuilder<'_, CS>,
        state: SIG::VerifyState<CS, KE>,
        signature: &SIG::Signature,
    ) -> Result<(), ProtocolError> {
        SIG::verify(&self.0, message_builder, state, signature)
    }
}

#[cfg(feature = "serde")]
impl<'de, G: Group> serde::Deserialize<'de> for PublicKey<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        G::deserialize_take_pk(
            &mut (GenericArray::<_, G::PkLen>::deserialize(deserializer)?.as_slice()),
        )
        .map(Self)
        .map_err(D::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl<G: Group> serde::Serialize for PublicKey<G> {
    fn serialize<SK>(&self, serializer: SK) -> Result<SK::Ok, SK::Error>
    where
        SK: serde::Serializer,
    {
        G::serialize_pk(self.0).serialize(serializer)
    }
}

/// Default OPRF seed container.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, ZeroizeOnDrop)]
pub struct OprfSeed<H: OutputSizeUser>(pub(crate) Output<H>);

/// A trait to facilitate
/// [`ServerSetup::de/serialize`](crate::ServerSetup::serialize).
///
/// Will be called with `E` being [`PrivateKeySerialization::Error`].
pub trait OprfSeedSerialization<H, E>: Sized {
    /// Serialization size in bytes.
    type Len: ArrayLength<u8>;

    /// Serialization into bytes
    fn serialize(&self) -> GenericArray<u8, Self::Len>;

    /// Deserialization from bytes
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError<E>>;
}

impl<H: OutputSizeUser, E> OprfSeedSerialization<H, E> for OprfSeed<H> {
    type Len = H::OutputSize;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.0.clone()
    }

    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError<E>> {
        Ok(Self(
            input
                .take_array("OPRF seed")
                .map_err(ProtocolError::into_custom)?,
        ))
    }
}

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl<G: Group> KeyPair<G> {
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

#[cfg(test)]
impl<G: Group> AssertZeroized for PublicKey<G>
where
    G::Pk: AssertZeroized,
{
    fn assert_zeroized(&self) {
        self.0.assert_zeroized();
    }
}

#[cfg(test)]
impl<G: Group> AssertZeroized for PrivateKey<G>
where
    G::Sk: AssertZeroized,
{
    fn assert_zeroized(&self) {
        self.0.assert_zeroized();
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use rand::rngs::OsRng;

    use super::*;
    use crate::ciphersuite::KeGroup;
    use crate::serialization::AssertZeroized;

    #[test]
    fn test_zeroize_key() {
        fn inner<G: Group>()
        where
            G::Sk: AssertZeroized,
        {
            let mut rng = OsRng;
            let mut key = PrivateKey::<G>(G::random_sk(&mut rng));
            unsafe { ptr::drop_in_place(&mut key) };
            key.0.assert_zeroized();
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

                        let kp2 = PrivateKey::<$point>::deserialize_key_pair(&mut (sk_bytes.as_slice()))?;
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
            ServerLoginParameters, ServerLoginStartResult, ServerRegistration,
            ServerRegistrationStartResult, ServerSetup,
        };

        struct Default;

        impl CipherSuite for Default {
            #[cfg(feature = "ristretto255")]
            type OprfCs = crate::Ristretto255;
            #[cfg(not(feature = "ristretto255"))]
            type OprfCs = ::p256::NistP256;
            #[cfg(feature = "ristretto255")]
            type KeyExchange = crate::TripleDh<crate::Ristretto255, sha2::Sha512>;
            #[cfg(not(feature = "ristretto255"))]
            type KeyExchange = crate::TripleDh<::p256::NistP256, sha2::Sha256>;
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
            ServerLoginParameters::default(),
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
                &mut OsRng,
                PASSWORD.as_bytes(),
                message,
                ClientLoginFinishParameters::default(),
            )
            .unwrap();
        server
            .finish(message, ServerLoginParameters::default())
            .unwrap();
    }
}

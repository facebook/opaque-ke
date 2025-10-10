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
use crate::key_exchange::shared::DiffieHellman;
use crate::key_exchange::sigma_i::{Message, MessageBuilder, SignatureProtocol};
use crate::serialization::SliceExt;

/// A Keypair trait with public-private verification
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G::Pk: serde::Deserialize<'de>, SK: serde::Deserialize<'de>",
        serialize = "G::Pk: serde::Serialize, SK: serde::Serialize"
    ))
)]
#[derive_where(Clone)]
#[derive_where(Eq, Hash, Ord, PartialEq, PartialOrd; G::Pk, SK)]
// `NonZeroScalar` doesn't implement `Debug`.
// TODO: remove after `elliptic-curve` bump to v0.14.
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
        let pk = G::public_key(&sk);
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
        let pk = G::public_key(&sk);
        Self {
            pk: PublicKey(pk),
            sk: PrivateKey(sk),
        }
    }
}

/// Wrapper around a Key to enforce that it's a private one.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G::Sk: serde::Deserialize<'de>",
        serialize = "G::Sk: serde::Serialize"
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Sk)]
pub struct PrivateKey<G: Group>(G::Sk);

impl<G: Group> PrivateKey<G> {
    pub(crate) fn new(key: G::Sk) -> Self {
        Self(key)
    }

    /// Returns public key from private key
    pub fn public_key(&self) -> PublicKey<G> {
        PublicKey(G::public_key(&self.0))
    }

    /// Serializes this private key to a fixed-length byte array.
    pub fn serialize(&self) -> GenericArray<u8, G::SkLen> {
        G::serialize_sk(&self.0)
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
        self.0.diffie_hellman(&pk.0)
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
    ///
    /// The deserialized bytes must be taken from `bytes`.
    fn deserialize_take_key_pair(
        bytes: &mut &[u8],
    ) -> Result<KeyPair<G, Self>, ProtocolError<Self::Error>>;
}

impl<G: Group> PrivateKeySerialization<G> for PrivateKey<G> {
    type Error = core::convert::Infallible;
    type Len = G::SkLen;

    fn serialize_key_pair(key_pair: &KeyPair<G, Self>) -> GenericArray<u8, Self::Len> {
        key_pair.private().serialize()
    }

    fn deserialize_take_key_pair(input: &mut &[u8]) -> Result<KeyPair<G, Self>, ProtocolError> {
        let sk = PrivateKey::deserialize_take(input)?;
        let pk = sk.public_key();

        Ok(KeyPair::new(sk, pk))
    }
}

/// Wrapper around a Key to enforce that it's a public one.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G::Pk: serde::Deserialize<'de>",
        serialize = "G::Pk: serde::Serialize"
    ))
)]
#[derive_where(Clone)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Pk)]
pub struct PublicKey<G: Group + ?Sized>(G::Pk);

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
        G::serialize_pk(&self.0)
    }

    /// Returns the inner [`Group::Pk`].
    pub fn to_group_type(&self) -> &G::Pk {
        &self.0
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
    ///
    /// The deserialized bytes must be taken from `bytes`.
    fn deserialize_take(bytes: &mut &[u8]) -> Result<Self, ProtocolError<E>>;
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
impl<G: Group> KeyPair<G> {
    /// Test-only strategy returning a proptest Strategy based on
    /// [`Self::derive_random`]
    fn uniform_keypair_strategy() -> proptest::prelude::BoxedStrategy<Self> {
        use proptest::prelude::*;
        use rand::SeedableRng;
        use rand::rngs::StdRng;

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
mod tests {
    use hkdf::Hkdf;
    use rand::rngs::OsRng;

    use super::*;
    use crate::ciphersuite::{KeGroup, OprfHash};
    use crate::{
        CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult,
        ClientLoginStartResult, ClientRegistration, ClientRegistrationFinishParameters,
        ClientRegistrationFinishResult, ClientRegistrationStartResult, ServerLogin,
        ServerLoginParameters, ServerLoginStartResult, ServerRegistration,
        ServerRegistrationStartResult, ServerSetup,
    };

    macro_rules! test {
        ($mod:ident, $point:ty) => {
            mod $mod {

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

                        let kp2 = PrivateKey::<$point>::deserialize_take_key_pair(&mut (sk_bytes.as_slice()))?;
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
    struct RemoteSeed<H: OutputSizeUser>(Output<H>);

    #[derive(Clone)]
    struct RemoteKey(PrivateKey<KeGroup<Default>>);

    const PASSWORD: &str = "password";

    #[test]
    fn remote_key() {
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

    #[test]
    fn remote_seed() {
        let mut oprf_seed = RemoteSeed::<OprfHash<Default>>(GenericArray::default());
        OsRng.fill_bytes(&mut oprf_seed.0);

        let sk = PrivateKey(KeGroup::<Default>::random_sk(&mut OsRng));
        let pk = sk.public_key();
        let sk = RemoteKey(sk);
        let keypair = KeyPair::new(sk, pk);

        let server_setup = ServerSetup::<Default, _, _>::new_with_key_pair_and_seed(
            &mut OsRng, keypair, oprf_seed,
        );

        let ClientRegistrationStartResult {
            message,
            state: client,
        } = ClientRegistration::<Default>::start(&mut OsRng, PASSWORD.as_bytes()).unwrap();
        let km = server_setup.key_material_info(&[]);
        let mut ikm = GenericArray::default();
        Hkdf::<OprfHash<Default>>::from_prk(&km.ikm.0)
            .unwrap()
            .expand_multi_info(&km.info, &mut ikm)
            .unwrap();
        let ServerRegistrationStartResult { message, .. } =
            ServerRegistration::start_with_key_material(&server_setup, ikm, message).unwrap();
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
        let km = server_setup.key_material_info(&[]);
        let mut ikm = GenericArray::default();
        Hkdf::<OprfHash<Default>>::from_prk(&km.ikm.0)
            .unwrap()
            .expand_multi_info(&km.info, &mut ikm)
            .unwrap();
        let builder = ServerLogin::builder_with_key_material(
            &mut OsRng,
            &server_setup,
            ikm,
            Some(file),
            message,
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

// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! TripleDH-KEM is a variant of the OPAQUE Triple Diffie-Hellman handshake in
//! which the client supplies a KEM public key in KE1 and the server performs a
//! KEM encapsulation in KE2 instead of relying solely on the final Diffie-
//! Hellman hop. The server bundles the KEM ciphertext alongside the classic
//! `TripleDH` payload, both parties absorb the ciphertext into the transcript
//! and mix the encapsulated shared secret with the three Diffie-Hellman
//! products when deriving handshake keys, and the client decapsulates during
//! KE3 to recover that shared secret before validating the server MAC. This
//! file contains the data model and trait glue that layer
//! the generic `ml-kem` abstractions into the existing OPAQUE key-exchange
//! pipeline.

use core::convert::TryFrom;
use core::fmt::Debug;
use core::marker::PhantomData;
use core::ops::Add;

use derive_where::derive_where;
use digest::core_api::BlockSizeUser;
use digest::{Digest, Output};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, Le, NonZero, Sum, U256};
use generic_array::{ArrayLength, GenericArray};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{
    Ciphertext as MlKemCiphertext, Encoded, EncodedSizeUser, KemCore, SharedKey as MlKemSharedKey,
};
use rand::{CryptoRng, RngCore};
use subtle::{ConstantTimeEq, CtOption};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::shared::{self, Ke1Message, Ke1State, NonceLen};
use super::{
    Deserialize, GenerateKe1Result, GenerateKe2Result, GenerateKe3Result, KeyExchange, Serialize,
    SerializedContext, SerializedCredentialRequest, SerializedCredentialResponse,
    SerializedIdentifiers,
};
use crate::ciphersuite::{CipherSuite, KeGroup};
use crate::errors::{InternalError, ProtocolError};
use crate::hash::{Hash, OutputSize, ProxyHash};
use crate::key_exchange::group::Group;
use crate::keypair::{PrivateKey, PublicKey};
use crate::opaque::Identifiers;
use crate::serialization::SliceExt;

/// Adapter trait that augments the `ml-kem` core traits with the metadata
/// required by OPAQUE (e.g. fixed lengths and serialization hooks).
pub trait KemCoreWrapper {
    /// Public key type used for encapsulation operations.
    type EncapsulationKey: Clone;

    /// Secret key type used for decapsulation operations.
    type DecapsulationKey: Clone + ZeroizeOnDrop;

    /// Length (in bytes) of the serialized public key.
    type EncapsulationKeyLen: ArrayLength<u8>;
    /// Length (in bytes) of the serialized secret key.
    type DecapsulationKeyLen: ArrayLength<u8>;
    /// Length (in bytes) of the encapsulated ciphertext.
    type CiphertextLen: ArrayLength<u8>;
    /// Length (in bytes) of the shared secret output by the KEM.
    type SharedSecretLen: ArrayLength<u8>;

    /// Generates a fresh KEM key pair.
    fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), ProtocolError>;

    /// Serializes the public encapsulation key.
    fn serialize_encapsulation_key(
        key: &Self::EncapsulationKey,
    ) -> GenericArray<u8, Self::EncapsulationKeyLen>;

    /// Deserializes the public encapsulation key, advancing the input slice.
    fn deserialize_encapsulation_key(
        input: &mut &[u8],
    ) -> Result<Self::EncapsulationKey, ProtocolError>;

    /// Serializes the secret decapsulation key.
    fn serialize_decapsulation_key(
        key: &Self::DecapsulationKey,
    ) -> GenericArray<u8, Self::DecapsulationKeyLen>;

    /// Deserializes the secret decapsulation key, advancing the input slice.
    fn deserialize_decapsulation_key(
        input: &mut &[u8],
    ) -> Result<Self::DecapsulationKey, ProtocolError>;

    /// Encapsulates to the given public key, returning the ciphertext and
    /// shared secret.
    #[allow(clippy::type_complexity)]
    fn encapsulate<R: RngCore + CryptoRng>(
        key: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> Result<
        (
            GenericArray<u8, Self::CiphertextLen>,
            GenericArray<u8, Self::SharedSecretLen>,
        ),
        ProtocolError,
    >;

    /// Decapsulates the shared secret from the provided ciphertext.
    fn decapsulate(
        key: &Self::DecapsulationKey,
        encapsulated_key: &GenericArray<u8, Self::CiphertextLen>,
    ) -> Result<GenericArray<u8, Self::SharedSecretLen>, ProtocolError>;
}

type RcEncapsulationKeyLen<K> = <<K as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
type RcDecapsulationKeyLen<K> = <<K as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize;
type RcCiphertextLen<K> = <K as KemCore>::CiphertextSize;
type RcSharedSecretLen<K> = <K as KemCore>::SharedKeySize;

impl<K> KemCoreWrapper for K
where
    K: KemCore,
    K::EncapsulationKey: Encapsulate<MlKemCiphertext<K>, MlKemSharedKey<K>> + Clone,
    K::DecapsulationKey: Decapsulate<MlKemCiphertext<K>, MlKemSharedKey<K>> + Clone + ZeroizeOnDrop,
    RcEncapsulationKeyLen<K>: ArrayLength<u8>,
    RcDecapsulationKeyLen<K>: ArrayLength<u8>,
    RcCiphertextLen<K>: ArrayLength<u8>,
    RcSharedSecretLen<K>: ArrayLength<u8>,
{
    type EncapsulationKey = K::EncapsulationKey;
    type DecapsulationKey = K::DecapsulationKey;
    type EncapsulationKeyLen = RcEncapsulationKeyLen<K>;
    type DecapsulationKeyLen = RcDecapsulationKeyLen<K>;
    type CiphertextLen = RcCiphertextLen<K>;
    type SharedSecretLen = RcSharedSecretLen<K>;

    fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), ProtocolError> {
        Ok(K::generate(rng))
    }

    fn serialize_encapsulation_key(
        key: &Self::EncapsulationKey,
    ) -> GenericArray<u8, Self::EncapsulationKeyLen> {
        GenericArray::clone_from_slice(key.as_bytes().as_slice())
    }

    fn deserialize_encapsulation_key(
        input: &mut &[u8],
    ) -> Result<Self::EncapsulationKey, ProtocolError> {
        let bytes: GenericArray<u8, RcEncapsulationKeyLen<K>> =
            input.take_array("kem encapsulation key")?;
        let encoded = Encoded::<K::EncapsulationKey>::try_from(bytes.as_slice())
            .map_err(|_| ProtocolError::SerializationError)?;
        Ok(K::EncapsulationKey::from_bytes(&encoded))
    }

    fn serialize_decapsulation_key(
        key: &Self::DecapsulationKey,
    ) -> GenericArray<u8, Self::DecapsulationKeyLen> {
        GenericArray::clone_from_slice(key.as_bytes().as_slice())
    }

    fn deserialize_decapsulation_key(
        input: &mut &[u8],
    ) -> Result<Self::DecapsulationKey, ProtocolError> {
        let bytes: GenericArray<u8, RcDecapsulationKeyLen<K>> =
            input.take_array("kem decapsulation key")?;
        let encoded = Encoded::<K::DecapsulationKey>::try_from(bytes.as_slice())
            .map_err(|_| ProtocolError::SerializationError)?;
        Ok(K::DecapsulationKey::from_bytes(&encoded))
    }

    fn encapsulate<R: RngCore + CryptoRng>(
        key: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> Result<
        (
            GenericArray<u8, Self::CiphertextLen>,
            GenericArray<u8, Self::SharedSecretLen>,
        ),
        ProtocolError,
    > {
        key.encapsulate(rng)
            .map(|(ciphertext, shared)| {
                (
                    GenericArray::clone_from_slice(ciphertext.as_slice()),
                    GenericArray::clone_from_slice(shared.as_slice()),
                )
            })
            .map_err(|_| ProtocolError::LibraryError(InternalError::KemError))
    }

    fn decapsulate(
        key: &Self::DecapsulationKey,
        encapsulated_key: &GenericArray<u8, Self::CiphertextLen>,
    ) -> Result<GenericArray<u8, Self::SharedSecretLen>, ProtocolError> {
        let ciphertext = MlKemCiphertext::<K>::try_from(encapsulated_key.as_slice())
            .map_err(|_| ProtocolError::SerializationError)?;
        key.decapsulate(&ciphertext)
            .map(|shared| GenericArray::clone_from_slice(shared.as_slice()))
            .map_err(|_| ProtocolError::LibraryError(InternalError::KemError))
    }
}
/// Triple Diffie-Hellman-style key exchange that offloads the second hop to a
/// generic KEM.
#[derive(Clone, Debug)]
pub struct TripleDhKem<G, H, K>(PhantomData<(G, H, K)>);

/// Client state combining the classic `TripleDH` state with a KEM secret key.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "Ke1State<G>: serde::Deserialize<'de>, K::DecapsulationKey: \
                       serde::Deserialize<'de>",
        serialize = "Ke1State<G>: serde::Serialize, K::DecapsulationKey: serde::Serialize",
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; Ke1State<G>, K::DecapsulationKey)]
pub struct KemKe1State<G: Group, K: KemCoreWrapper> {
    dh_state: Ke1State<G>,
    kem_decapsulation_key: K::DecapsulationKey,
}

/// Client message including the ephemeral Diffie-Hellman component alongside a
/// serialized KEM public key.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "Ke1Message<G>: serde::Deserialize<'de>",
        serialize = "Ke1Message<G>: serde::Serialize",
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; Ke1Message<G>)]
pub struct KemKe1Message<G: Group, K: KemCoreWrapper> {
    dh_message: Ke1Message<G>,
    kem_encapsulation_key: GenericArray<u8, K::EncapsulationKeyLen>,
}

/// Server state mirrors the `TripleDH` state and carries the client’s KEM
/// public key for later use.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KemKe2State<K: KemCoreWrapper, H: Hash>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    base_state: super::tripledh::Ke2State<H>,
    kem_encapsulation_key: GenericArray<u8, K::EncapsulationKeyLen>,
    server_kem_ciphertext: GenericArray<u8, K::CiphertextLen>,
}

/// Server builder placeholder capturing the data needed to finish the KEM
/// exchange.
#[derive_where(Clone)]
pub struct KemKe2Builder<G: Group, H: Hash, K: KemCoreWrapper>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    server_nonce: GenericArray<u8, NonceLen>,
    transcript_hasher: H,
    client_e_pk: PublicKey<G>,
    server_e_pk: PublicKey<G>,
    shared_secret_1: GenericArray<u8, G::PkLen>,
    shared_secret_3: GenericArray<u8, G::PkLen>,
    kem_encapsulation_key: GenericArray<u8, K::EncapsulationKeyLen>,
    kem_ciphertext: GenericArray<u8, K::CiphertextLen>,
    kem_shared_secret: GenericArray<u8, K::SharedSecretLen>,
}

/// Server message bundles the `TripleDH` payload with the KEM encapsulation.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "super::tripledh::Ke2Message<G, H>: serde::Deserialize<'de>",
        serialize = "super::tripledh::Ke2Message<G, H>: serde::Serialize",
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; super::tripledh::Ke2Message<G, H>)]
pub struct KemKe2Message<G: Group, H: Hash, K: KemCoreWrapper>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    dh_message: super::tripledh::Ke2Message<G, H>,
    kem_ciphertext: GenericArray<u8, K::CiphertextLen>,
}

/// Third message remains the same as `TripleDH`.
pub type KemKe3Message<H> = super::tripledh::Ke3Message<H>;

impl<G, H, K> Drop for KemKe2Builder<G, H, K>
where
    G: Group,
    H: Hash,
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    K: KemCoreWrapper,
{
    fn drop(&mut self) {
        self.server_nonce.zeroize();
        self.transcript_hasher.reset();
        self.shared_secret_1.zeroize();
        self.shared_secret_3.zeroize();
        self.kem_shared_secret.zeroize();
        self.kem_ciphertext.zeroize();
    }
}

impl<G, H, K> ZeroizeOnDrop for KemKe2Builder<G, H, K>
where
    G: Group,
    H: Hash,
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    K: KemCoreWrapper,
{
}

impl<G, H, K> KeyExchange for TripleDhKem<G, H, K>
where
    G: Group + 'static,
    G::Sk: shared::DiffieHellman<G>,
    H: Hash,
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    K: KemCoreWrapper,
    NonceLen: Add<K::EncapsulationKeyLen>,
    Sum<NonceLen, K::EncapsulationKeyLen>: ArrayLength<u8>,
{
    type Group = G;
    type Hash = H;

    type KE1State = KemKe1State<G, K>;
    type KE2State<CS: CipherSuite> = KemKe2State<K, H>;
    type KE1Message = KemKe1Message<G, K>;
    type KE2Builder<'a, CS: CipherSuite<KeyExchange = Self>> = KemKe2Builder<G, H, K>;
    type KE2BuilderData<'a, CS: 'static + CipherSuite> = (
        &'a PublicKey<G>,
        &'a GenericArray<u8, K::EncapsulationKeyLen>,
    );
    type KE2BuilderInput<CS: CipherSuite> = GenericArray<u8, G::PkLen>;
    type KE2Message = KemKe2Message<G, H, K>;
    type KE3Message = KemKe3Message<H>;

    fn generate_ke1<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<GenerateKe1Result<Self>, ProtocolError> {
        let base = super::tripledh::TripleDh::<G, H>::generate_ke1(rng)?;
        let (kem_secret, kem_public) = K::generate(rng)?;
        let kem_encapsulation_key = K::serialize_encapsulation_key(&kem_public);

        Ok(GenerateKe1Result {
            state: KemKe1State {
                dh_state: base.state,
                kem_decapsulation_key: kem_secret,
            },
            message: KemKe1Message {
                dh_message: base.message,
                kem_encapsulation_key,
            },
        })
    }

    fn ke2_builder<'a, CS: CipherSuite<KeyExchange = Self>, R: RngCore + CryptoRng>(
        rng: &mut R,
        credential_request: SerializedCredentialRequest<CS>,
        ke1_message: Self::KE1Message,
        credential_response: SerializedCredentialResponse<CS>,
        client_s_pk: PublicKey<G>,
        identifiers: SerializedIdentifiers<'_, KeGroup<CS>>,
        context: SerializedContext<'a>,
    ) -> Result<Self::KE2Builder<'a, CS>, ProtocolError> {
        let shared::Ke2BuilderCommon {
            server_nonce,
            transcript_hasher,
            client_e_pk,
            server_e_pk,
            shared_secret_1,
            shared_secret_3,
        } = shared::ke2_builder_common::<G, H, CS, R>(
            rng,
            credential_request,
            ke1_message.dh_message.clone(),
            credential_response,
            client_s_pk,
            identifiers,
            context,
        )?;

        let mut kem_bytes_slice: &[u8] = ke1_message.kem_encapsulation_key.as_slice();
        let encapsulation_key = K::deserialize_encapsulation_key(&mut kem_bytes_slice)?;
        let (kem_ciphertext, kem_shared_secret) = K::encapsulate(&encapsulation_key, rng)?;

        let mut transcript_hasher = transcript_hasher;
        transcript_hasher.update(ke1_message.kem_encapsulation_key.as_slice());
        transcript_hasher.update(kem_ciphertext.as_slice());

        Ok(KemKe2Builder {
            server_nonce,
            transcript_hasher,
            client_e_pk,
            server_e_pk,
            shared_secret_1,
            shared_secret_3,
            kem_encapsulation_key: ke1_message.kem_encapsulation_key.clone(),
            kem_ciphertext,
            kem_shared_secret,
        })
    }

    fn ke2_builder_data<'a, CS: 'static + CipherSuite<KeyExchange = Self>>(
        builder: &'a Self::KE2Builder<'_, CS>,
    ) -> Self::KE2BuilderData<'a, CS> {
        (&builder.client_e_pk, &builder.kem_encapsulation_key)
    }

    fn generate_ke2_input<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + RngCore>(
        builder: &Self::KE2Builder<'_, CS>,
        _: &mut R,
        server_s_sk: &PrivateKey<G>,
    ) -> Self::KE2BuilderInput<CS> {
        server_s_sk.ke_diffie_hellman(&builder.client_e_pk)
    }

    fn build_ke2<CS: CipherSuite<KeyExchange = Self>>(
        mut builder: Self::KE2Builder<'_, CS>,
        shared_secret_2: Self::KE2BuilderInput<CS>,
    ) -> Result<GenerateKe2Result<CS>, ProtocolError> {
        let transcript_digest = builder.transcript_hasher.clone().finalize();
        let derived_keys = shared::derive_keys::<H>(
            [
                builder.shared_secret_1.as_slice(),
                shared_secret_2.as_slice(),
                builder.shared_secret_3.as_slice(),
                builder.kem_shared_secret.as_slice(),
            ]
            .into_iter(),
            &transcript_digest,
        )?;

        let (mac, expected_mac) = shared::compute_ke2_macs(
            &mut builder.transcript_hasher,
            &derived_keys,
            &transcript_digest,
        )?;

        Ok(GenerateKe2Result {
            state: KemKe2State {
                base_state: super::tripledh::Ke2State {
                    session_key: derived_keys.session_key.clone(),
                    expected_mac,
                },
                kem_encapsulation_key: builder.kem_encapsulation_key.clone(),
                server_kem_ciphertext: builder.kem_ciphertext.clone(),
            },
            message: KemKe2Message {
                dh_message: super::tripledh::Ke2Message {
                    server_nonce: builder.server_nonce,
                    server_e_pk: builder.server_e_pk.clone(),
                    mac,
                },
                kem_ciphertext: builder.kem_ciphertext.clone(),
            },
            #[cfg(test)]
            handshake_secret: derived_keys.handshake_secret,
            #[cfg(test)]
            km2: derived_keys.km2,
        })
    }

    fn generate_ke3<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + RngCore>(
        _rng: &mut R,
        credential_request: SerializedCredentialRequest<CS>,
        ke1_message: Self::KE1Message,
        credential_response: SerializedCredentialResponse<CS>,
        ke1_state: &Self::KE1State,
        ke2_message: Self::KE2Message,
        server_s_pk: PublicKey<G>,
        client_s_sk: PrivateKey<G>,
        identifiers: SerializedIdentifiers<'_, KeGroup<CS>>,
        context: SerializedContext<'_>,
    ) -> Result<GenerateKe3Result<Self>, ProtocolError> {
        let mut transcript_hasher = shared::transcript(
            &context,
            &identifiers,
            &credential_request,
            &ke1_message.dh_message.to_iter(),
            &credential_response,
            ke2_message.dh_message.server_nonce,
            &ke2_message.dh_message.server_e_pk.serialize(),
        );
        transcript_hasher.update(ke1_message.kem_encapsulation_key.as_slice());
        transcript_hasher.update(ke2_message.kem_ciphertext.as_slice());

        let shared_secret_1 = ke1_state
            .dh_state
            .client_e_sk
            .ke_diffie_hellman(&ke2_message.dh_message.server_e_pk);
        let shared_secret_2 = ke1_state
            .dh_state
            .client_e_sk
            .ke_diffie_hellman(&server_s_pk);
        let shared_secret_3 = client_s_sk.ke_diffie_hellman(&ke2_message.dh_message.server_e_pk);
        let kem_shared_secret = K::decapsulate(
            &ke1_state.kem_decapsulation_key,
            &ke2_message.kem_ciphertext,
        )?;

        let (derived_keys, client_mac) = shared::finalize_ke3_transcript(
            &mut transcript_hasher,
            [
                shared_secret_1.as_slice(),
                shared_secret_2.as_slice(),
                shared_secret_3.as_slice(),
                kem_shared_secret.as_slice(),
            ]
            .into_iter(),
            &ke2_message.dh_message.mac,
        )?;

        Ok(GenerateKe3Result {
            session_key: derived_keys.session_key,
            message: super::tripledh::Ke3Message { mac: client_mac },
            #[cfg(test)]
            handshake_secret: derived_keys.handshake_secret,
            #[cfg(test)]
            km3: derived_keys.km3,
        })
    }

    fn finish_ke<CS: CipherSuite>(
        ke2_state: &Self::KE2State<CS>,
        ke3_message: Self::KE3Message,
        _identifiers: Identifiers<'_>,
        _context: SerializedContext<'_>,
    ) -> Result<Output<Self::Hash>, ProtocolError> {
        CtOption::new(
            ke2_state.base_state.session_key.clone(),
            ke2_state.base_state.expected_mac.ct_eq(&ke3_message.mac),
        )
        .into_option()
        .ok_or(ProtocolError::InvalidLoginError)
    }
}

/// Serialization logic will be implemented once the concrete KEM wiring is in
/// place.
impl<G: Group, K: KemCoreWrapper> Deserialize for KemKe1State<G, K> {
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            dh_state: Ke1State::<G>::deserialize_take(input)?,
            kem_decapsulation_key: K::deserialize_decapsulation_key(input)?,
        })
    }
}

impl<G: Group, K: KemCoreWrapper> Serialize for KemKe1State<G, K>
where
    Ke1State<G>: Serialize,
    <Ke1State<G> as Serialize>::Len: Add<K::DecapsulationKeyLen>,
    Sum<<Ke1State<G> as Serialize>::Len, K::DecapsulationKeyLen>: ArrayLength<u8>,
{
    type Len = Sum<<Ke1State<G> as Serialize>::Len, K::DecapsulationKeyLen>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.dh_state
            .serialize()
            .concat(K::serialize_decapsulation_key(&self.kem_decapsulation_key))
    }
}

impl<G: Group, K: KemCoreWrapper> Deserialize for KemKe1Message<G, K> {
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            dh_message: Ke1Message::<G>::deserialize_take(input)?,
            kem_encapsulation_key: input.take_array("kem encapsulation key")?,
        })
    }
}

impl<G: Group, K: KemCoreWrapper> Serialize for KemKe1Message<G, K>
where
    Ke1Message<G>: Serialize,
    <Ke1Message<G> as Serialize>::Len: Add<K::EncapsulationKeyLen>,
    Sum<<Ke1Message<G> as Serialize>::Len, K::EncapsulationKeyLen>: ArrayLength<u8>,
{
    type Len = Sum<<Ke1Message<G> as Serialize>::Len, K::EncapsulationKeyLen>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.dh_message
            .serialize()
            .concat(self.kem_encapsulation_key.clone())
    }
}

impl<K: KemCoreWrapper, H: Hash> Deserialize for KemKe2State<K, H>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            base_state: super::tripledh::Ke2State::<H>::deserialize_take(input)?,
            kem_encapsulation_key: input.take_array("kem encapsulation key")?,
            server_kem_ciphertext: input.take_array("kem ciphertext")?,
        })
    }
}

impl<K: KemCoreWrapper, H: Hash> Serialize for KemKe2State<K, H>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    super::tripledh::Ke2State<H>: Serialize,
    <super::tripledh::Ke2State<H> as Serialize>::Len: Add<K::EncapsulationKeyLen>,
    Sum<<super::tripledh::Ke2State<H> as Serialize>::Len, K::EncapsulationKeyLen>:
        ArrayLength<u8> + Add<K::CiphertextLen>,
    Sum<
        Sum<<super::tripledh::Ke2State<H> as Serialize>::Len, K::EncapsulationKeyLen>,
        K::CiphertextLen,
    >: ArrayLength<u8>,
{
    type Len = Sum<
        Sum<<super::tripledh::Ke2State<H> as Serialize>::Len, K::EncapsulationKeyLen>,
        K::CiphertextLen,
    >;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.base_state
            .serialize()
            .concat(self.kem_encapsulation_key.clone())
            .concat(self.server_kem_ciphertext.clone())
    }
}

impl<G: Group, H: Hash, K: KemCoreWrapper> Deserialize for KemKe2Message<G, H, K>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            dh_message: super::tripledh::Ke2Message::<G, H>::deserialize_take(input)?,
            kem_ciphertext: input.take_array("kem ciphertext")?,
        })
    }
}

impl<G: Group, H: Hash, K: KemCoreWrapper> Serialize for KemKe2Message<G, H, K>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    NonceLen: Add<G::PkLen>,
    Sum<NonceLen, G::PkLen>: ArrayLength<u8> + Add<OutputSize<H>>,
    Sum<Sum<NonceLen, G::PkLen>, OutputSize<H>>: ArrayLength<u8>,
    super::tripledh::Ke2Message<G, H>: Serialize,
    <super::tripledh::Ke2Message<G, H> as Serialize>::Len: Add<K::CiphertextLen>,
    <<super::tripledh::Ke2Message<G, H> as Serialize>::Len as Add<K::CiphertextLen>>::Output:
        ArrayLength<u8>,
{
    type Len = Sum<<super::tripledh::Ke2Message<G, H> as Serialize>::Len, K::CiphertextLen>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.dh_message
            .serialize()
            .concat(self.kem_ciphertext.clone())
    }
}

// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! An implementation of the SIGMA-I key exchange protocol

#[cfg(feature = "ecdsa")]
pub mod ecdsa;
pub mod hash_eddsa;
mod message;
pub mod pure_eddsa;
pub(super) mod shared;

use core::iter;
use core::marker::PhantomData;
use core::ops::Add;

use derive_where::derive_where;
use digest::core_api::BlockSizeUser;
use digest::{Digest, Mac, Output, OutputSizeUser};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, Le, NonZero, Sum, U256};
use generic_array::{ArrayLength, GenericArray};
use hmac::Hmac;
use rand::{CryptoRng, RngCore};
use subtle::{ConstantTimeEq, CtOption};
use zeroize::Zeroize;

use self::message::Role;
pub use self::message::{CachedMessage, HashOutput, Message, MessageBuilder, VerifyMessage};
use crate::ciphersuite::{CipherSuite, KeGroup, KeHash};
use crate::envelope::NonceLen;
use crate::errors::{InternalError, ProtocolError};
use crate::hash::{Hash, OutputSize, ProxyHash};
use crate::key_exchange::group::Group;
use crate::key_exchange::shared::{derive_keys, generate_ke1, generate_nonce, transcript};
pub use crate::key_exchange::shared::{DiffieHellman, Ke1Message, Ke1State};
use crate::key_exchange::traits::{
    CredentialRequestParts, CredentialResponseParts, Deserialize, GenerateKe2Result,
    GenerateKe3Result, KeyExchange, Sealed, Serialize, SerializedContext, SerializedIdentifier,
    SerializedIdentifiers,
};
use crate::keypair::{KeyPair, PrivateKey, PublicKey};
use crate::opaque::Identifiers;
use crate::serialization::{SliceExt, UpdateExt};

/// The SIGMA-I key exchange implementation
///
/// `SIG` determines the algorithm used for the signature. `KE` determines the
/// algorithm used for establishing the shared secret. `KEH` determines the hash
/// used for the key exchange.
///
/// # Remote Key
///
/// [`ServerLoginBuilder::data()`](crate::ServerLoginBuilder::data()) will
/// return [`Message`].
///
/// [`ServerLoginBuilder::build()`](crate::ServerLoginBuilder::build()) expects
/// a signature from signing the [message](Message::sign_message) with the
/// servers private key, and a ["verification
/// state"](SignatureProtocol::VerifyState).
///
/// To understand what kind of "verification state" is expected here exactly,
/// refer to the documentation of your chosen [`SignatureProtocol`] `SIG`. E.g.
/// [`Ecdsa`](ecdsa::Ecdsa), [`PureEddsa`](pure_eddsa::PureEddsa) or
/// [`HashEddsa`](hash_eddsa::HashEddsa).
pub struct SigmaI<SIG, KE, KEH>(PhantomData<(SIG, KE, KEH)>);

/// Trait to implement for `SIG` used in [`SigmaI`].
///
/// The [`sign()`] and [`verify()`] methods do not function independent of each
/// other. [`sign()`] is always called first and receives a [Message] containing
/// the message for both signing and verifying. A ["verification
/// state"](Self::VerifyState) is created by [`sign()`] and then passed onto
/// [`verify()`].
///
/// The most straightforward implementation would simply store the message for
/// verifying in [`VerifyState`](Self::VerifyState). However, protocols that
/// allow for pre-hashing don't need to store the whole message and can
/// preemptively hash the verification message and only store that instead,
/// getting rid of the much larger message.
///
/// [`sign()`]: Self::sign
/// [`verify()`]: Self::verify
pub trait SignatureProtocol {
    /// The [`Group`] used to generate and derive keys.
    type Group: Group;
    /// The signature.
    type Signature: Clone + Deserialize + Serialize + Zeroize;
    /// The state required to run the verification. This is used to cache the
    /// pre-hash for curves that support that, otherwise the [`Message`] to
    /// verify is stored via [`CachedMessage`].
    type VerifyState<CS: CipherSuite, KE: Group>: Clone + Zeroize;

    /// Returns a signature from the given message signed by the given private
    /// key.
    ///
    /// [`Message`] contains both signature messages for signing and
    /// verification. If you need it again during verification, consider
    /// using [`CachedMessage`].
    ///
    /// The returned [`VerifyState`](Self::VerifyState) will be passed to
    /// [`verify()`](Self::verify) and must contain the necessary
    /// information to verify the incoming signature.
    fn sign<R: CryptoRng + RngCore, CS: CipherSuite, KE: Group>(
        sk: &<Self::Group as Group>::Sk,
        rng: &mut R,
        message: &Message<CS, KE>,
    ) -> (Self::Signature, Self::VerifyState<CS, KE>);

    /// Validates that the signature was created by signing the message with the
    /// corresponding private key.
    ///
    /// The [`MessageBuilder`] can be used with [`CachedMessage`] to create
    /// [`VerifyMessage`] which contains the message of the given `signature`.
    ///
    /// The `state` is created by [`sign()`](Self::sign()).
    fn verify<CS: CipherSuite, KE: Group>(
        pk: &<Self::Group as Group>::Pk,
        message_builder: MessageBuilder<'_, CS>,
        state: Self::VerifyState<CS, KE>,
        signature: &Self::Signature,
    ) -> Result<(), ProtocolError>;
}

/// Builder for the second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(deserialize = "'de: 'a", serialize = ""))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, PartialEq; PublicKey<KeGroup<CS>>, PublicKey<KE>)]
pub struct Ke2Builder<'a, CS: CipherSuite, KE: Group> {
    transcript: Message<'a, CS, KE>,
    server_nonce: GenericArray<u8, NonceLen>,
    client_s_pk: PublicKey<KeGroup<CS>>,
    server_e_pk: PublicKey<KE>,
    expected_mac: Output<KeHash<CS>>,
    session_key: Output<KeHash<CS>>,
    #[cfg(test)]
    km3: Output<KeHash<CS>>,
    #[cfg(test)]
    handshake_secret: Output<KeHash<CS>>,
}

/// The server state produced after the second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "SIG::VerifyState<CS, KE>: serde::Deserialize<'de>",
        serialize = "SIG::VerifyState<CS, KE>: serde::Serialize"
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, PartialEq; <SIG::Group as Group>::Pk, SIG::VerifyState<CS, KE>)]
pub struct Ke2State<CS: CipherSuite, SIG: SignatureProtocol, KE: Group> {
    client_s_pk: PublicKey<SIG::Group>,
    session_key: Output<KeHash<CS>>,
    verify_state: SIG::VerifyState<CS, KE>,
    expected_mac: Output<KeHash<CS>>,
}

/// The second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "SIG::Signature: serde::Deserialize<'de>",
        serialize = "SIG::Signature: serde::Serialize"
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; KE::Pk, SIG::Signature)]
pub struct Ke2Message<SIG: SignatureProtocol, KE: Group, KEH: Hash>
where
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: PublicKey<KE>,
    signature: SIG::Signature,
    mac: Output<KEH>,
}

/// The third key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "SIG::Signature: serde::Deserialize<'de>",
        serialize = "SIG::Signature: serde::Serialize"
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; SIG::Signature)]
pub struct Ke3Message<SIG: SignatureProtocol, KEH: OutputSizeUser> {
    signature: SIG::Signature,
    mac: Output<KEH>,
}

impl<SIG: SignatureProtocol, KE: 'static + Group, KEH: Hash> KeyExchange for SigmaI<SIG, KE, KEH>
where
    KE::Sk: DiffieHellman<KE>,
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    type Group = SIG::Group;
    type Hash = KEH;

    type KE1State = Ke1State<KE>;
    type KE1Message = Ke1Message<KE>;
    type KE2Builder<'a, CS: CipherSuite<KeyExchange = Self>> = Ke2Builder<'a, CS, KE>;
    type KE2BuilderData<'a, CS: 'static + CipherSuite> = &'a Message<'a, CS, KE>;
    type KE2BuilderInput<CS: CipherSuite> = (SIG::Signature, SIG::VerifyState<CS, KE>);
    type KE2State<CS: CipherSuite> = Ke2State<CS, SIG, KE>;
    type KE2Message = Ke2Message<SIG, KE, KEH>;
    type KE3Message = Ke3Message<SIG, KEH>;

    fn generate_ke1<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError> {
        generate_ke1(rng)
    }

    fn ke2_builder<'a, CS: CipherSuite<KeyExchange = Self>, R: RngCore + CryptoRng>(
        rng: &mut R,
        credential_request: CredentialRequestParts<CS>,
        ke1_message: Self::KE1Message,
        credential_response: CredentialResponseParts<CS>,
        client_s_pk: PublicKey<Self::Group>,
        identifiers: SerializedIdentifiers<'a, KeGroup<CS>>,
        context: SerializedContext<'a>,
    ) -> Result<Self::KE2Builder<'a, CS>, ProtocolError> {
        let server_e = KeyPair::<KE>::derive_random(rng);
        let server_nonce = generate_nonce::<R>(rng);

        let ke1_message_iter = ke1_message.to_iter();
        let server_e_pk = server_e.public().serialize();

        let transcript_hasher = transcript(
            &context,
            &identifiers,
            &credential_request,
            &ke1_message_iter,
            &credential_response,
            server_nonce,
            &server_e_pk,
        );

        let shared_secret = server_e
            .private()
            .ke_diffie_hellman(&ke1_message.client_e_pk);

        let derived_keys = derive_keys::<KEH>(
            iter::once(shared_secret.as_slice()),
            &transcript_hasher.finalize(),
        )?;

        let mut server_mac =
            Hmac::<KEH>::new_from_slice(&derived_keys.km2).map_err(|_| InternalError::HmacError)?;
        server_mac.update_iter(identifiers.server.iter());
        let server_mac = server_mac.finalize().into_bytes();

        let mut client_mac =
            Hmac::<KEH>::new_from_slice(&derived_keys.km3).map_err(|_| InternalError::HmacError)?;
        client_mac.update_iter(identifiers.client.iter());
        let client_mac = client_mac.finalize().into_bytes();

        let message = Message {
            role: Role::Server,
            context,
            identifiers,
            cache: CachedMessage {
                credential_request,
                ke1_message: ke1_message_iter,
                credential_response,
                server_nonce,
                server_e_pk,
                server_mac,
            },
        };

        Ok(Ke2Builder {
            transcript: message,
            server_nonce,
            client_s_pk,
            server_e_pk: server_e.public().clone(),
            expected_mac: client_mac,
            session_key: derived_keys.session_key,
            #[cfg(test)]
            km3: derived_keys.km3,
            #[cfg(test)]
            handshake_secret: derived_keys.handshake_secret,
        })
    }

    fn ke2_builder_data<'a, CS: 'static + CipherSuite<KeyExchange = Self>>(
        builder: &'a Self::KE2Builder<'_, CS>,
    ) -> Self::KE2BuilderData<'a, CS> {
        &builder.transcript
    }

    fn generate_ke2_input<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + RngCore>(
        builder: &Self::KE2Builder<'_, CS>,
        rng: &mut R,
        server_s_sk: &PrivateKey<Self::Group>,
    ) -> Self::KE2BuilderInput<CS> {
        server_s_sk.sign::<_, CS, SIG, KE>(rng, &builder.transcript)
    }

    fn build_ke2<CS: CipherSuite<KeyExchange = Self>>(
        builder: Self::KE2Builder<'_, CS>,
        input: Self::KE2BuilderInput<CS>,
    ) -> Result<GenerateKe2Result<CS>, ProtocolError> {
        Ok((
            Ke2State {
                client_s_pk: builder.client_s_pk.clone(),
                session_key: builder.session_key.clone(),
                verify_state: input.1,
                expected_mac: builder.expected_mac.clone(),
            },
            Ke2Message {
                server_nonce: builder.server_nonce,
                server_e_pk: builder.server_e_pk.clone(),
                signature: input.0,
                mac: builder.transcript.cache.server_mac.clone(),
            },
            #[cfg(test)]
            builder.handshake_secret.clone(),
            #[cfg(test)]
            builder.km3.clone(),
        ))
    }

    fn generate_ke3<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + RngCore>(
        rng: &mut R,
        credential_request: CredentialRequestParts<CS>,
        ke1_message: Self::KE1Message,
        credential_response: CredentialResponseParts<CS>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        server_s_pk: PublicKey<Self::Group>,
        client_s_sk: PrivateKey<Self::Group>,
        identifiers: SerializedIdentifiers<'_, KeGroup<CS>>,
        context: SerializedContext<'_>,
    ) -> Result<GenerateKe3Result<Self>, ProtocolError> {
        let ke1_message_iter = ke1_message.to_iter();
        let server_e_pk = ke2_message.server_e_pk.serialize();

        let transcript_hasher = transcript(
            &context,
            &identifiers,
            &credential_request,
            &ke1_message_iter,
            &credential_response,
            ke2_message.server_nonce,
            &server_e_pk,
        );

        let shared_secret = ke1_state
            .client_e_sk
            .ke_diffie_hellman(&ke2_message.server_e_pk);

        let derived_keys = derive_keys::<KEH>(
            iter::once(shared_secret.as_slice()),
            &transcript_hasher.finalize(),
        )?;

        let mut server_mac =
            Hmac::<KEH>::new_from_slice(&derived_keys.km2).map_err(|_| InternalError::HmacError)?;
        server_mac.update_iter(identifiers.server.iter());
        let server_mac = server_mac.finalize().into_bytes();

        bool::from(server_mac.ct_eq(&ke2_message.mac))
            .then_some(())
            .ok_or(ProtocolError::InvalidLoginError)?;

        let mut client_mac =
            Hmac::<KEH>::new_from_slice(&derived_keys.km3).map_err(|_| InternalError::HmacError)?;
        client_mac.update_iter(identifiers.client.iter());
        let client_mac = client_mac.finalize().into_bytes();

        let message = Message {
            role: Role::Client,
            context: context.clone(),
            identifiers: identifiers.clone(),
            cache: CachedMessage {
                credential_request,
                ke1_message: ke1_message_iter,
                credential_response,
                server_nonce: ke2_message.server_nonce,
                server_e_pk,
                server_mac,
            },
        };

        let (signature, state) = client_s_sk.sign::<_, CS, SIG, KE>(rng, &message);

        server_s_pk.verify::<CS, SIG, KE>(
            MessageBuilder {
                role: Role::Client,
                context,
                identifier: identifiers.server,
            },
            state,
            &ke2_message.signature,
        )?;

        Ok((
            derived_keys.session_key,
            Ke3Message {
                signature,
                mac: client_mac,
            },
            #[cfg(test)]
            derived_keys.handshake_secret,
            #[cfg(test)]
            derived_keys.km3,
        ))
    }

    fn finish_ke<CS: CipherSuite<KeyExchange = Self>>(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State<CS>,
        identifiers: Identifiers<'_>,
        context: SerializedContext<'_>,
    ) -> Result<Output<KEH>, ProtocolError> {
        ke2_state.client_s_pk.verify::<CS, SIG, KE>(
            MessageBuilder {
                role: Role::Server,
                context,
                identifier: SerializedIdentifier::from_identifier(
                    identifiers.client,
                    ke2_state.client_s_pk.serialize(),
                )?,
            },
            ke2_state.verify_state.clone(),
            &ke3_message.signature,
        )?;

        CtOption::new(
            ke2_state.session_key.clone(),
            ke2_state.expected_mac.ct_eq(&ke3_message.mac),
        )
        .into_option()
        .ok_or(ProtocolError::InvalidLoginError)
    }
}

impl<SIG: SignatureProtocol, KE: 'static + Group, KEH: Hash> Sealed for SigmaI<SIG, KE, KEH>
where
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
}

impl<CS: CipherSuite, SIG: SignatureProtocol, KE: Group> Deserialize for Ke2State<CS, SIG, KE>
where
    SIG::VerifyState<CS, KE>: Deserialize,
{
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            client_s_pk: PublicKey::deserialize_take(input)?,
            session_key: input.take_array("session key")?,
            verify_state: SIG::VerifyState::deserialize_take(input)?,
            expected_mac: input.take_array("expected mac")?,
        })
    }
}

type Ke2StateLen<CS, SIG: SignatureProtocol, KE> = Sum<
    Sum<Sum<<SIG::Group as Group>::PkLen, OutputSize<KeHash<CS>>>, VerifyStateLen<CS, SIG, KE>>,
    OutputSize<KeHash<CS>>,
>;

type VerifyStateLen<CS, SIG: SignatureProtocol, KE> = <SIG::VerifyState<CS, KE> as Serialize>::Len;

impl<CS: CipherSuite, SIG: SignatureProtocol, KE: Group> Serialize for Ke2State<CS, SIG, KE>
where
    SIG::VerifyState<CS, KE>: Serialize,
    // Ke2State: ((SigPk + Hash) + VerifyState) + Hash
    <SIG::Group as Group>::PkLen: Add<OutputSize<KeHash<CS>>>,
    Sum<<SIG::Group as Group>::PkLen, OutputSize<KeHash<CS>>>:
        ArrayLength<u8> + Add<VerifyStateLen<CS, SIG, KE>>,
    Sum<Sum<<SIG::Group as Group>::PkLen, OutputSize<KeHash<CS>>>, VerifyStateLen<CS, SIG, KE>>:
        ArrayLength<u8> + Add<OutputSize<KeHash<CS>>>,
    Ke2StateLen<CS, SIG, KE>: ArrayLength<u8>,
{
    type Len = Ke2StateLen<CS, SIG, KE>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.client_s_pk
            .serialize()
            .concat(self.session_key.clone())
            .concat(self.verify_state.serialize())
            .concat(self.expected_mac.clone())
    }
}

impl<SIG: SignatureProtocol, KE: Group, KEH: Hash> Deserialize for Ke2Message<SIG, KE, KEH>
where
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            server_nonce: input.take_array("server nonce")?,
            server_e_pk: PublicKey::deserialize_take(input)?,
            signature: SIG::Signature::deserialize_take(input)?,
            mac: input.take_array("mac")?,
        })
    }
}

impl<SIG: SignatureProtocol, KE: Group, KEH: Hash> Serialize for Ke2Message<SIG, KE, KEH>
where
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Ke2Message: ((Nonce + KePk) + Signature) + Hash
    NonceLen: Add<KE::PkLen>,
    Sum<NonceLen, KE::PkLen>: ArrayLength<u8> + Add<<SIG::Signature as Serialize>::Len>,
    Sum<Sum<NonceLen, KE::PkLen>, <SIG::Signature as Serialize>::Len>:
        ArrayLength<u8> + Add<OutputSize<KEH>>,
    Sum<Sum<Sum<NonceLen, KE::PkLen>, <SIG::Signature as Serialize>::Len>, OutputSize<KEH>>:
        ArrayLength<u8>,
{
    type Len =
        Sum<Sum<Sum<NonceLen, KE::PkLen>, <SIG::Signature as Serialize>::Len>, OutputSize<KEH>>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.server_nonce
            .concat(self.server_e_pk.serialize())
            .concat(self.signature.serialize())
            .concat(self.mac.clone())
    }
}

impl<SIG: SignatureProtocol, KEH: Hash> Deserialize for Ke3Message<SIG, KEH>
where
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            signature: SIG::Signature::deserialize_take(input)?,
            mac: input.take_array("mac")?,
        })
    }
}

impl<SIG: SignatureProtocol, KEH: Hash> Serialize for Ke3Message<SIG, KEH>
where
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Ke2Message: Signature + Hash
    <SIG::Signature as Serialize>::Len: Add<OutputSize<KEH>>,
    Sum<<SIG::Signature as Serialize>::Len, OutputSize<KEH>>: ArrayLength<u8>,
{
    type Len = Sum<<SIG::Signature as Serialize>::Len, OutputSize<KEH>>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.signature.serialize().concat(self.mac.clone())
    }
}

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::key_exchange::shared::Ke1MessageIter;
#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl<CS: CipherSuite, KE: Group> AssertZeroized for CachedMessage<CS, KE>
where
    Ke1MessageIter<KE>: AssertZeroized,
{
    fn assert_zeroized(&self) {
        let Self {
            credential_request,
            ke1_message,
            credential_response,
            server_nonce,
            server_e_pk,
            server_mac,
        } = self;

        credential_request.assert_zeroized();
        ke1_message.assert_zeroized();
        credential_response.assert_zeroized();

        for byte in server_nonce.iter().chain(server_e_pk).chain(server_mac) {
            assert_eq!(byte, &0);
        }
    }
}

#[cfg(test)]
impl<CS: CipherSuite, SIG: SignatureProtocol, KE: Group> AssertZeroized for Ke2State<CS, SIG, KE>
where
    <SIG::Group as Group>::Pk: AssertZeroized,
    SIG::VerifyState<CS, KE>: AssertZeroized,
{
    fn assert_zeroized(&self) {
        let Self {
            client_s_pk,
            session_key,
            verify_state,
            expected_mac,
        } = self;

        client_s_pk.assert_zeroized();
        verify_state.assert_zeroized();

        for byte in session_key.iter().chain(expected_mac) {
            assert_eq!(byte, &0);
        }
    }
}

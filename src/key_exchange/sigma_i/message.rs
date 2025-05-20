// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use core::ops::Add;

use derive_where::derive_where;
use digest::{FixedOutput, Output, Update};
use generic_array::sequence::Concat;
use generic_array::typenum::Sum;
use generic_array::{ArrayLength, GenericArray};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{CipherSuite, KeGroup, KeHash, OprfGroup};
use crate::errors::ProtocolError;
use crate::hash::OutputSize;
use crate::key_exchange::group::Group;
use crate::key_exchange::shared::{Ke1MessageIter, Ke1MessageIterLen, NonceLen};
use crate::key_exchange::{
    Deserialize, Serialize, SerializedContext, SerializedCredentialRequest,
    SerializedCredentialRequestLen, SerializedCredentialResponse, SerializedCredentialResponseLen,
    SerializedIdentifier, SerializedIdentifiers,
};
use crate::opaque::MaskedResponseLen;
use crate::serialization::{SliceExt, UpdateExt};

/// This holds the message to be signed and the message to be verified.
///
/// If your signature protocol requires pre-hashes, you can call [`hash()`].
///
/// If you require the actual message, call [`sign_message()`]. To get the
/// message to verify, call [`to_cached()`] to create a [`CachedMessage`] and
/// save it in [`SignatureProtocol::VerifyState`], which you can then use in
/// [`SignatureProtocol::verify()`] with [`MessageBuilder`] to create
/// [`VerifyMessage`].
///
/// [`hash()`]: super::Message::hash
/// [`sign_message()`]: super::Message::sign_message
/// [`to_cached()`]: super::Message::to_cached
/// [`SignatureProtocol::sign()`]: super::SignatureProtocol::sign
/// [`SignatureProtocol::verify()`]: super::SignatureProtocol::verify
/// [`SignatureProtocol::VerifyState`]: super::SignatureProtocol::VerifyState
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(deserialize = "'de: 'a", serialize = ""))
)]
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, ZeroizeOnDrop)]
pub struct Message<'a, CS: CipherSuite, KE: Group> {
    pub(super) role: Role,
    pub(super) context: SerializedContext<'a>,
    pub(super) identifiers: SerializedIdentifiers<'a, KeGroup<CS>>,
    pub(super) cache: CachedMessage<CS, KE>,
}

/// This holds the message to be verified.
///
/// Create it by using [`MessageBuilder::build()`] with [`CachedMessage`].
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(deserialize = "'de: 'a", serialize = ""))
)]
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, ZeroizeOnDrop)]
pub struct VerifyMessage<'a, CS: CipherSuite, KE: Group> {
    role: Role,
    context: SerializedContext<'a>,
    identifier: SerializedIdentifier<'a, KeGroup<CS>>,
    pub(super) cache: CachedMessage<CS, KE>,
}

/// Used to build [`VerifyMessage`]. It is only available in
/// [`SignatureProtocol::verify()`].
///
/// [`SignatureProtocol::verify()`]: super::SignatureProtocol::verify
#[derive(Debug, Eq, Hash, PartialEq, ZeroizeOnDrop)]
pub struct MessageBuilder<'a, CS: CipherSuite> {
    pub(super) role: Role,
    pub(super) context: SerializedContext<'a>,
    pub(super) identifier: SerializedIdentifier<'a, KeGroup<CS>>,
}

/// Created by [`Message::to_cached()`]. This is used to save the message to be
/// verified in [`SignatureProtocol::VerifyState`].
///
/// Use [`MessageBuilder::build()`] to create [`VerifyMessage`] in
/// [`SignatureProtocol::verify()`].
///
/// [`SignatureProtocol::verify()`]: super::SignatureProtocol::verify
/// [`SignatureProtocol::VerifyState`]: super::SignatureProtocol::VerifyState
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct CachedMessage<CS: CipherSuite, KE: Group> {
    pub(super) credential_request: SerializedCredentialRequest<CS>,
    pub(super) ke1_message: Ke1MessageIter<KE>,
    pub(super) credential_response: SerializedCredentialResponse<CS>,
    pub(super) server_nonce: GenericArray<u8, NonceLen>,
    pub(super) server_e_pk: GenericArray<u8, KE::PkLen>,
    pub(super) server_mac: Output<KeHash<CS>>,
}

impl<CS: CipherSuite, KE: Group> Message<'_, CS, KE> {
    /// Returns the message to be signed.
    pub fn sign_message(&self) -> impl Clone + Iterator<Item = &[u8]> {
        self.context.iter().chain(self.post_message(Stage::Sign))
    }

    /// Returns the hash of both messages.
    pub fn hash<KEH: Default + Clone + FixedOutput + Update>(&self) -> HashOutput<KEH> {
        let mut context = KEH::default();
        context.update_iter(self.context.iter());

        let sign = context.clone().chain_iter(self.post_message(Stage::Sign));
        let verify = context.chain_iter(self.post_message(Stage::Verify));

        HashOutput { sign, verify }
    }

    fn post_message(&self, stage: Stage) -> impl Clone + Iterator<Item = &[u8]> {
        let transcript = match (self.role, stage) {
            (Role::Server, Stage::Sign) => Role::Server,
            (Role::Server, Stage::Verify) => Role::Client,
            (Role::Client, Stage::Sign) => Role::Client,
            (Role::Client, Stage::Verify) => Role::Server,
        };
        let identifier = match transcript {
            Role::Server => &self.identifiers.server,
            Role::Client => &self.identifiers.client,
        };

        self.cache.post_message(transcript, identifier)
    }

    /// Create a [`CachedMessage`], which can be saved in
    /// [`SignatureProtocol::VerifyState`] and create a [`VerifyMessage`] with
    /// [`MessageBuilder::build()`].
    ///
    /// [`SignatureProtocol::VerifyState`]: super::SignatureProtocol::VerifyState
    pub fn to_cached(&self) -> CachedMessage<CS, KE> {
        self.cache.clone()
    }
}

impl<CS: CipherSuite, KE: Group> VerifyMessage<'_, CS, KE> {
    /// Returns the message to be verified.
    pub fn verify_message(&self) -> impl Clone + Iterator<Item = &[u8]> {
        let transcript = match self.role {
            Role::Server => Role::Client,
            Role::Client => Role::Server,
        };

        self.context
            .iter()
            .chain(self.cache.post_message(transcript, &self.identifier))
    }
}

impl<CS: CipherSuite, KE: Group> CachedMessage<CS, KE> {
    fn post_message<'a>(
        &'a self,
        transcript: Role,
        identifier: &'a SerializedIdentifier<'_, KeGroup<CS>>,
    ) -> impl Clone + Iterator<Item = &'a [u8]> {
        Some(identifier.iter())
            .filter(|_| matches!(transcript, Role::Client))
            .into_iter()
            .flatten()
            .chain(self.credential_request.iter())
            .chain(self.ke1_message.iter())
            .chain(
                Some(identifier.iter())
                    .filter(|_| matches!(transcript, Role::Server))
                    .into_iter()
                    .flatten(),
            )
            .chain(self.credential_response.iter())
            .chain([self.server_nonce.as_slice(), &self.server_e_pk])
            .chain(Some(self.server_mac.as_slice()).filter(|_| matches!(transcript, Role::Client)))
    }
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Zeroize)]
pub(super) enum Role {
    Server,
    Client,
}

enum Stage {
    Sign,
    Verify,
}

/// Returned by [`Message::hash()`] containing the hash of the message to be
/// signed and the message to be verified.
pub struct HashOutput<H> {
    /// The hash of the message to be signed.
    pub sign: H,
    /// The hash of the message to be verified.
    pub verify: H,
}

impl<'a, CS: CipherSuite> MessageBuilder<'a, CS> {
    /// Creates a [`VerifyMessage`]. [`CachedMessage`] can be created by
    /// [`Message::to_cached()`] and stored in
    /// [`SignatureProtocol::VerifyState`].
    ///
    /// [`SignatureProtocol::VerifyState`]: super::SignatureProtocol::VerifyState
    pub fn build<KE: Group>(self, cache: CachedMessage<CS, KE>) -> VerifyMessage<'a, CS, KE> {
        VerifyMessage {
            role: self.role,
            context: self.context.clone(),
            identifier: self.identifier.clone(),
            cache,
        }
    }
}

impl<CS: CipherSuite, KE: Group> Deserialize for CachedMessage<CS, KE> {
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            credential_request: SerializedCredentialRequest::deserialize_take(input)?,
            ke1_message: Ke1MessageIter::deserialize_take(input)?,
            credential_response: SerializedCredentialResponse::deserialize_take(input)?,
            server_nonce: input.take_array("server nonce")?,
            server_e_pk: input.take_array("serialized server ephemeral key")?,
            server_mac: input.take_array("server mac")?,
        })
    }
}

/// Length of [`CachedMessage`].
type CachedMessageLen<CS: CipherSuite, KE: Group> = Sum<
    Sum<
        Sum<
            Sum<
                Sum<SerializedCredentialRequestLen<CS>, Ke1MessageIterLen<KE>>,
                SerializedCredentialResponseLen<CS>,
            >,
            NonceLen,
        >,
        KE::PkLen,
    >,
    OutputSize<KeHash<CS>>,
>;

impl<CS: CipherSuite, KE: Group> Serialize for CachedMessage<CS, KE>
where
    SerializedCredentialRequestLen<CS>: ArrayLength<u8> + Add<Ke1MessageIterLen<KE>>,
    Sum<SerializedCredentialRequestLen<CS>, Ke1MessageIterLen<KE>>:
        ArrayLength<u8> + Add<SerializedCredentialResponseLen<CS>>,
    Sum<
        Sum<SerializedCredentialRequestLen<CS>, Ke1MessageIterLen<KE>>,
        SerializedCredentialResponseLen<CS>,
    >: ArrayLength<u8> + Add<NonceLen>,
    Sum<
        Sum<
            Sum<SerializedCredentialRequestLen<CS>, Ke1MessageIterLen<KE>>,
            SerializedCredentialResponseLen<CS>,
        >,
        NonceLen,
    >: ArrayLength<u8> + Add<KE::PkLen>,
    Sum<
        Sum<
            Sum<
                Sum<SerializedCredentialRequestLen<CS>, Ke1MessageIterLen<KE>>,
                SerializedCredentialResponseLen<CS>,
            >,
            NonceLen,
        >,
        KE::PkLen,
    >: ArrayLength<u8> + Add<OutputSize<KeHash<CS>>>,
    CachedMessageLen<CS, KE>: ArrayLength<u8>,
    // Ke1MessageIter
    NonceLen: Add<KE::PkLen>,
    Ke1MessageIterLen<KE>: ArrayLength<u8>,
    // CredentialResponseParts
    <OprfGroup<CS> as voprf::Group>::ElemLen: Add<NonceLen>,
    Sum<<OprfGroup<CS> as voprf::Group>::ElemLen, NonceLen>:
        ArrayLength<u8> + Add<MaskedResponseLen<CS>>,
    SerializedCredentialResponseLen<CS>: ArrayLength<u8>,
{
    type Len = CachedMessageLen<CS, KE>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.credential_request
            .serialize()
            .concat(self.ke1_message.serialize())
            .concat(self.credential_response.serialize())
            .concat(self.server_nonce)
            .concat(self.server_e_pk.clone())
            .concat(self.server_mac.clone())
    }
}

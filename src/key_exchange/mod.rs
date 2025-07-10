// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Includes instantiations of key exchange protocols used in the login step for
//! OPAQUE

pub mod group;
pub(crate) mod shared;
pub mod sigma_i;
pub mod tripledh;

use core::iter;
use core::ops::Add;

use derive_where::derive_where;
use digest::Output;
use digest::core_api::{BlockSizeUser, CoreProxy};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, Le, NonZero, Sum, U2, U256};
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use voprf::{BlindedElement, EvaluationElement};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(test)]
use crate::ciphersuite::KeHash;
use crate::ciphersuite::{CipherSuite, OprfGroup};
use crate::errors::ProtocolError;
use crate::hash::{Hash, ProxyHash};
use crate::key_exchange::group::Group;
use crate::key_exchange::shared::{NonceLen, STR_CONTEXT};
use crate::keypair::{PrivateKey, PublicKey};
use crate::opaque::{Identifiers, MaskedResponse, MaskedResponseLen};
use crate::serialization::{SliceExt, i2osp};

/// The key exchange trait.
pub trait KeyExchange
where
    <Self::Hash as CoreProxy>::Core: ProxyHash,
    <<Self::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<Self::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// The group used for the key exchange.
    type Group: Group;
    /// The hash used for the key exchange.
    type Hash: Hash;

    /// Client state.
    type KE1State: ZeroizeOnDrop + Clone;
    /// Server state.
    type KE2State<CS: CipherSuite>: ZeroizeOnDrop + Clone;
    /// First message sent by the client.
    type KE1Message: ZeroizeOnDrop + Clone;
    /// Server state builder.
    type KE2Builder<'a, CS: CipherSuite<KeyExchange = Self>>: ZeroizeOnDrop + Clone;
    /// Server data for the remote key interaction.
    type KE2BuilderData<'a, CS: 'static + CipherSuite>;
    /// Server remote key input.
    type KE2BuilderInput<CS: CipherSuite>;
    /// Message sent by the server.
    type KE2Message: ZeroizeOnDrop + Clone;
    /// Second message sent by the client.
    type KE3Message: ZeroizeOnDrop + Clone;

    /// Client generates [`KE1Message`](Self::KE1Message) and
    /// [`KE1State`](Self::KE1State).
    fn generate_ke1<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<GenerateKe1Result<Self>, ProtocolError>;

    /// Server generates [`KE2Builder`](Self::KE2Builder).
    fn ke2_builder<'a, CS: CipherSuite<KeyExchange = Self>, R: RngCore + CryptoRng>(
        rng: &mut R,
        credential_request: SerializedCredentialRequest<CS>,
        ke1_message: Self::KE1Message,
        credential_response: SerializedCredentialResponse<CS>,
        client_s_pk: PublicKey<Self::Group>,
        identifiers: SerializedIdentifiers<'a, Self::Group>,
        context: SerializedContext<'a>,
    ) -> Result<Self::KE2Builder<'a, CS>, ProtocolError>;

    /// Server returns the data for the remote key interaction.
    fn ke2_builder_data<'a, CS: CipherSuite<KeyExchange = Self>>(
        builder: &'a Self::KE2Builder<'_, CS>,
    ) -> Self::KE2BuilderData<'a, CS>;

    /// Server generates the input without a remote key.
    fn generate_ke2_input<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + RngCore>(
        builder: &Self::KE2Builder<'_, CS>,
        rng: &mut R,
        server_s_sk: &PrivateKey<Self::Group>,
    ) -> Self::KE2BuilderInput<CS>;

    /// Server generates [`KE2Message`](Self::KE2Message) and
    /// [`KE2State`](Self::KE2State).
    fn build_ke2<CS: CipherSuite<KeyExchange = Self>>(
        builder: Self::KE2Builder<'_, CS>,
        input: Self::KE2BuilderInput<CS>,
    ) -> Result<GenerateKe2Result<CS>, ProtocolError>;

    /// Client generates [`KE3Message`](Self::KE3Message) and the session key.
    #[allow(clippy::too_many_arguments)]
    fn generate_ke3<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + RngCore>(
        rng: &mut R,
        credential_request: SerializedCredentialRequest<CS>,
        ke1_message: Self::KE1Message,
        credential_response: SerializedCredentialResponse<CS>,
        ke1_state: &Self::KE1State,
        ke2_message: Self::KE2Message,
        server_s_pk: PublicKey<Self::Group>,
        client_s_sk: PrivateKey<Self::Group>,
        identifiers: SerializedIdentifiers<'_, Self::Group>,
        context: SerializedContext<'_>,
    ) -> Result<GenerateKe3Result<Self>, ProtocolError>;

    /// Server generates the session key.
    fn finish_ke<CS: CipherSuite<KeyExchange = Self>>(
        ke2_state: &Self::KE2State<CS>,
        ke3_message: Self::KE3Message,
        identifiers: Identifiers<'_>,
        context: SerializedContext<'_>,
    ) -> Result<Output<Self::Hash>, ProtocolError>;
}

/// Serialized form of [`CredentialRequest`](crate::CredentialRequest).
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Zeroize)]
pub struct SerializedCredentialRequest<CS: CipherSuite>(
    GenericArray<u8, <OprfGroup<CS> as voprf::Group>::ElemLen>,
);

impl<CS: CipherSuite> SerializedCredentialRequest<CS> {
    pub(crate) fn new(blinded_element: &BlindedElement<CS::OprfCs>) -> Self {
        Self(blinded_element.serialize())
    }

    /// Returns the serialized form of
    /// [`CredentialRequest`](crate::CredentialRequest) in multiple byte slices.
    pub fn iter(&self) -> impl Clone + Iterator<Item = &[u8]> {
        iter::once(self.0.as_slice())
    }

    /// Returns a [`SerializedCredentialRequest`] deserialized from the given
    /// `bytes`.
    pub fn deserialize_take(bytes: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self(bytes.take_array("blinded element")?))
    }
}

type SerializedCredentialRequestLen<CS: CipherSuite> = <OprfGroup<CS> as voprf::Group>::ElemLen;

impl<CS: CipherSuite> Serialize for SerializedCredentialRequest<CS> {
    type Len = SerializedCredentialRequestLen<CS>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.0.clone()
    }
}

/// Serialized form of [`CredentialResponse`](crate::CredentialResponse).
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, Zeroize)]
pub struct SerializedCredentialResponse<CS: CipherSuite> {
    evaluation_element: GenericArray<u8, <OprfGroup<CS> as voprf::Group>::ElemLen>,
    masking_nonce: GenericArray<u8, NonceLen>,
    masked_response: MaskedResponse<CS>,
}

impl<CS: CipherSuite> SerializedCredentialResponse<CS> {
    pub(crate) fn new(
        evaluation_element: &EvaluationElement<CS::OprfCs>,
        masking_nonce: GenericArray<u8, NonceLen>,
        masked_response: MaskedResponse<CS>,
    ) -> Self {
        Self {
            evaluation_element: evaluation_element.serialize(),
            masking_nonce,
            masked_response,
        }
    }

    /// Returns the serialized form of
    /// [`CredentialResponse`](crate::CredentialResponse) in multiple byte
    /// slices.
    pub fn iter(&self) -> impl Clone + Iterator<Item = &[u8]> {
        [self.evaluation_element.as_slice(), &self.masking_nonce]
            .into_iter()
            .chain(self.masked_response.iter())
    }

    /// Returns a [`SerializedCredentialRequest`] deserialized from the given
    /// `bytes`.
    pub fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            evaluation_element: input.take_array("evaluation element")?,
            masking_nonce: input.take_array("masking nonce")?,
            masked_response: MaskedResponse::deserialize_take(input)?,
        })
    }
}

type SerializedCredentialResponseLen<CS: CipherSuite> =
    Sum<Sum<<OprfGroup<CS> as voprf::Group>::ElemLen, NonceLen>, MaskedResponseLen<CS>>;

impl<CS: CipherSuite> Serialize for SerializedCredentialResponse<CS>
where
    <OprfGroup<CS> as voprf::Group>::ElemLen: Add<NonceLen>,
    Sum<<OprfGroup<CS> as voprf::Group>::ElemLen, NonceLen>:
        ArrayLength<u8> + Add<MaskedResponseLen<CS>>,
    SerializedCredentialResponseLen<CS>: ArrayLength<u8>,
{
    type Len = SerializedCredentialResponseLen<CS>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.evaluation_element
            .clone()
            .concat(self.masking_nonce)
            .concat(self.masked_response.serialize())
    }
}

/// Serialized form of a `context` given in
/// [`ClientLoginFinishParameters`](crate::ClientLoginFinishParameters) or
/// [`ServerLoginParameters`](crate::ServerLoginParameters).
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Zeroize)]
pub struct SerializedContext<'a> {
    length: GenericArray<u8, U2>,
    #[zeroize(skip)]
    context: &'a [u8],
}

impl<'a> SerializedContext<'a> {
    pub(crate) fn from(context: Option<&'a [u8]>) -> Result<Self, ProtocolError> {
        let context = context.unwrap_or(&[]);

        Ok(Self {
            length: i2osp::<U2>(context.len())?,
            context,
        })
    }

    /// Returns the serialized form of `context` in multiple byte slices.
    pub fn iter(&self) -> impl Clone + Iterator<Item = &[u8]> {
        iter::once(STR_CONTEXT).chain([self.length.as_slice(), self.context])
    }
}

/// Serialized form of [`Identifiers`](crate::Identifiers).
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(deserialize = "'de: 'a", serialize = ""))
)]
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, Zeroize)]
pub struct SerializedIdentifiers<'a, G: Group> {
    /// Client identifiers.
    pub client: SerializedIdentifier<'a, G>,
    /// Server identifiers.
    pub server: SerializedIdentifier<'a, G>,
}

/// Serialized form of a single identifier from
/// [`Identifiers`](crate::Identifiers).
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(deserialize = "'de: 'a", serialize = ""))
)]
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, Zeroize)]
pub struct SerializedIdentifier<'a, G: Group> {
    length: GenericArray<u8, U2>,
    identifier: Identifier<'a, G>,
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, Zeroize)]
enum Identifier<'a, G: Group> {
    Owned(GenericArray<u8, G::PkLen>),
    #[derive_where(skip_inner(Zeroize))]
    Borrowed(&'a [u8]),
}

impl<'a, G: Group> SerializedIdentifiers<'a, G> {
    pub(crate) fn from_identifiers(
        ids: Identifiers<'a>,
        client_s_pk: GenericArray<u8, G::PkLen>,
        server_s_pk: GenericArray<u8, G::PkLen>,
    ) -> Result<Self, ProtocolError> {
        let client = SerializedIdentifier::from_identifier(ids.client, client_s_pk)?;
        let server = SerializedIdentifier::from_identifier(ids.server, server_s_pk)?;

        Ok(Self { client, server })
    }
}

impl<'a, G: Group> SerializedIdentifier<'a, G> {
    /// Creates a [`SerializedIdentifier`] an identifier or the corresponding
    /// static public key.
    pub fn from_identifier(
        id: Option<&'a [u8]>,
        s_pk: GenericArray<u8, G::PkLen>,
    ) -> Result<Self, ProtocolError> {
        if let Some(id) = id {
            Ok(SerializedIdentifier {
                length: i2osp::<U2>(id.len())?,
                identifier: Identifier::Borrowed(id),
            })
        } else {
            Ok(SerializedIdentifier {
                length: i2osp::<U2>(s_pk.len())?,
                identifier: Identifier::Owned(s_pk),
            })
        }
    }

    /// Returns the serialized form of an identifier in multiple byte slices.
    pub fn iter(&self) -> impl Clone + Iterator<Item = &[u8]> {
        [self.length.as_slice()]
            .into_iter()
            .chain(match &self.identifier {
                Identifier::Owned(bytes) => [bytes.as_slice()],
                Identifier::Borrowed(bytes) => [*bytes],
            })
    }
}

/// Deserialization trait for key exchange types.
pub trait Deserialize: Sized {
    /// Deserialize [`Self`] from the given `bytes`.
    ///
    /// The deserialized bytes must be taken from `bytes`.
    fn deserialize_take(bytes: &mut &[u8]) -> Result<Self, ProtocolError>;
}

/// Serialization trait for key exchange types.
pub trait Serialize {
    /// The length of the serialized types.
    type Len: ArrayLength<u8>;

    /// Serialize [`Self`] to a fixed-length byte array.
    fn serialize(&self) -> GenericArray<u8, Self::Len>;
}

/// Result type of [`KeyExchange::generate_ke1()`].
pub struct GenerateKe1Result<KE: KeyExchange + ?Sized> {
    /// The client state.
    pub state: KE::KE1State,
    /// The first client message.
    pub message: KE::KE1Message,
}

/// Result type of [`KeyExchange::build_ke2()`].
pub struct GenerateKe2Result<CS: CipherSuite> {
    /// The server state.
    pub state: <CS::KeyExchange as KeyExchange>::KE2State<CS>,
    /// The server message.
    pub message: <CS::KeyExchange as KeyExchange>::KE2Message,
    #[cfg(test)]
    pub(crate) handshake_secret: Output<KeHash<CS>>,
    #[cfg(test)]
    pub(crate) km2: Output<KeHash<CS>>,
}

/// Result type of [`KeyExchange::generate_ke3()`].
pub struct GenerateKe3Result<KE: KeyExchange + ?Sized> {
    /// The session key.
    pub session_key: Output<KE::Hash>,
    /// The second client message.
    pub message: KE::KE3Message,
    #[cfg(test)]
    pub(crate) handshake_secret: Output<KE::Hash>,
    #[cfg(test)]
    pub(crate) km3: Output<KE::Hash>,
}

pub(crate) type Ke1StateLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE1State as Serialize>::Len;
pub(crate) type Ke1MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE1Message as Serialize>::Len;
pub(crate) type Ke2StateLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE2State<CS> as Serialize>::Len;
pub(crate) type Ke2MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE2Message as Serialize>::Len;
pub(crate) type Ke3MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE3Message as Serialize>::Len;

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl<CS: CipherSuite> AssertZeroized for SerializedCredentialRequest<CS> {
    fn assert_zeroized(&self) {
        let Self(blinded_element) = self;

        for byte in blinded_element.iter() {
            assert_eq!(byte, &0);
        }
    }
}

#[cfg(test)]
impl<CS: CipherSuite> AssertZeroized for SerializedCredentialResponse<CS> {
    fn assert_zeroized(&self) {
        let Self {
            evaluation_element,
            masking_nonce,
            masked_response,
        } = self;

        for byte in evaluation_element
            .iter()
            .chain(masking_nonce)
            .chain(masked_response.iter().flatten())
        {
            assert_eq!(byte, &0);
        }
    }
}

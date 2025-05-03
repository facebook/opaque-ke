// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use core::iter;
use core::ops::Add;

use derive_where::derive_where;
use digest::core_api::{BlockSizeUser, CoreProxy};
use digest::Output;
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
use crate::serialization::{i2osp, SliceExt};

/// The key exchange trait. This is only exposed so users can use it in generics
/// and qualified bounds.
#[allow(private_bounds)]
pub trait KeyExchange: Sealed
where
    <Self::Hash as CoreProxy>::Core: ProxyHash,
    <<Self::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<Self::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// The group used for the key exchange.
    type Group: Group;
    /// The has used for the key exchange.
    type Hash: Hash;

    #[doc(hidden)]
    type KE1State: ZeroizeOnDrop + Clone;
    #[doc(hidden)]
    type KE2State<CS: CipherSuite>: ZeroizeOnDrop + Clone;
    #[doc(hidden)]
    type KE1Message: ZeroizeOnDrop + Clone;
    #[doc(hidden)]
    type KE2Builder<'a, CS: CipherSuite<KeyExchange = Self>>: ZeroizeOnDrop + Clone;
    #[doc(hidden)]
    type KE2BuilderData<'a, CS: 'static + CipherSuite>;
    #[doc(hidden)]
    type KE2BuilderInput<CS: CipherSuite>;
    #[doc(hidden)]
    type KE2Message: ZeroizeOnDrop + Clone;
    #[doc(hidden)]
    type KE3Message: ZeroizeOnDrop + Clone;

    #[doc(hidden)]
    fn generate_ke1<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError>;

    #[doc(hidden)]
    fn ke2_builder<'a, CS: CipherSuite<KeyExchange = Self>, R: RngCore + CryptoRng>(
        rng: &mut R,
        credential_request: CredentialRequestParts<CS>,
        ke1_message: Self::KE1Message,
        credential_response: CredentialResponseParts<CS>,
        client_s_pk: PublicKey<Self::Group>,
        identifiers: SerializedIdentifiers<'a, Self::Group>,
        context: SerializedContext<'a>,
    ) -> Result<Self::KE2Builder<'a, CS>, ProtocolError>;

    #[doc(hidden)]
    fn ke2_builder_data<'a, CS: CipherSuite<KeyExchange = Self>>(
        builder: &'a Self::KE2Builder<'_, CS>,
    ) -> Self::KE2BuilderData<'a, CS>;

    #[doc(hidden)]
    fn generate_ke2_input<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + RngCore>(
        builder: &Self::KE2Builder<'_, CS>,
        rng: &mut R,
        server_s_sk: &PrivateKey<Self::Group>,
    ) -> Self::KE2BuilderInput<CS>;

    #[doc(hidden)]
    fn build_ke2<CS: CipherSuite<KeyExchange = Self>>(
        builder: Self::KE2Builder<'_, CS>,
        input: Self::KE2BuilderInput<CS>,
    ) -> Result<GenerateKe2Result<CS>, ProtocolError>;

    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    fn generate_ke3<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + RngCore>(
        rng: &mut R,
        credential_request: CredentialRequestParts<CS>,
        ke1_message: Self::KE1Message,
        credential_response: CredentialResponseParts<CS>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        server_s_pk: PublicKey<Self::Group>,
        client_s_sk: PrivateKey<Self::Group>,
        identifiers: SerializedIdentifiers<'_, Self::Group>,
        context: SerializedContext<'_>,
    ) -> Result<GenerateKe3Result<Self>, ProtocolError>;

    #[doc(hidden)]
    fn finish_ke<CS: CipherSuite<KeyExchange = Self>>(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State<CS>,
        identifiers: Identifiers<'_>,
        context: SerializedContext<'_>,
    ) -> Result<Output<Self::Hash>, ProtocolError>;
}

pub(super) trait Sealed {}

#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Zeroize)]
pub struct CredentialRequestParts<CS: CipherSuite>(
    GenericArray<u8, <OprfGroup<CS> as voprf::Group>::ElemLen>,
);

impl<CS: CipherSuite> CredentialRequestParts<CS> {
    pub(crate) fn new(blinded_element: &BlindedElement<CS::OprfCs>) -> Self {
        Self(blinded_element.serialize())
    }

    pub fn iter(&self) -> impl Clone + Iterator<Item = &[u8]> {
        iter::once(self.0.as_slice())
    }

    pub fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self(input.take_array("blinded element")?))
    }
}

pub type CredentialRequestPartsLen<CS: CipherSuite> = <OprfGroup<CS> as voprf::Group>::ElemLen;

impl<CS: CipherSuite> Serialize for CredentialRequestParts<CS> {
    type Len = CredentialRequestPartsLen<CS>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.0.clone()
    }
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, Zeroize)]
pub struct CredentialResponseParts<CS: CipherSuite> {
    evaluation_element: GenericArray<u8, <OprfGroup<CS> as voprf::Group>::ElemLen>,
    masking_nonce: GenericArray<u8, NonceLen>,
    masked_response: MaskedResponse<CS>,
}

impl<CS: CipherSuite> CredentialResponseParts<CS> {
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

    pub fn iter(&self) -> impl Clone + Iterator<Item = &[u8]> {
        [self.evaluation_element.as_slice(), &self.masking_nonce]
            .into_iter()
            .chain(self.masked_response.iter())
    }

    pub fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            evaluation_element: input.take_array("evaluation element")?,
            masking_nonce: input.take_array("masking nonce")?,
            masked_response: MaskedResponse::deserialize_take(input)?,
        })
    }
}

pub type CredentialResponsePartsLen<CS: CipherSuite> =
    Sum<Sum<<OprfGroup<CS> as voprf::Group>::ElemLen, NonceLen>, MaskedResponseLen<CS>>;

impl<CS: CipherSuite> Serialize for CredentialResponseParts<CS>
where
    <OprfGroup<CS> as voprf::Group>::ElemLen: Add<NonceLen>,
    Sum<<OprfGroup<CS> as voprf::Group>::ElemLen, NonceLen>:
        ArrayLength<u8> + Add<MaskedResponseLen<CS>>,
    CredentialResponsePartsLen<CS>: ArrayLength<u8>,
{
    type Len = CredentialResponsePartsLen<CS>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.evaluation_element
            .clone()
            .concat(self.masking_nonce)
            .concat(self.masked_response.serialize())
    }
}

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

    pub fn iter(&self) -> impl Clone + Iterator<Item = &[u8]> {
        iter::once(STR_CONTEXT).chain([self.length.as_slice(), self.context])
    }
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(deserialize = "'de: 'a", serialize = ""))
)]
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, Zeroize)]
pub struct SerializedIdentifiers<'a, G: Group> {
    pub client: SerializedIdentifier<'a, G>,
    pub server: SerializedIdentifier<'a, G>,
}

/// Computes `I2OSP(len(input), max_bytes) || input` and helps hold output
/// without allocation.
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

    pub(crate) fn iter(&self) -> impl Clone + Iterator<Item = &[u8]> {
        // Some magic to make it output the same type in all branches.
        [self.length.as_slice()]
            .into_iter()
            .chain(match &self.identifier {
                Identifier::Owned(bytes) => [bytes.as_slice()],
                Identifier::Borrowed(bytes) => [*bytes],
            })
    }
}

pub trait Deserialize: Sized {
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError>;
}

pub trait Serialize {
    type Len: ArrayLength<u8>;

    fn serialize(&self) -> GenericArray<u8, Self::Len>;
}

#[cfg(not(test))]
pub type GenerateKe2Result<CS: CipherSuite> = (
    <CS::KeyExchange as KeyExchange>::KE2State<CS>,
    <CS::KeyExchange as KeyExchange>::KE2Message,
);
#[cfg(test)]
pub type GenerateKe2Result<CS: CipherSuite> = (
    <CS::KeyExchange as KeyExchange>::KE2State<CS>,
    <CS::KeyExchange as KeyExchange>::KE2Message,
    Output<KeHash<CS>>,
    Output<KeHash<CS>>,
);
#[cfg(not(test))]
pub type GenerateKe3Result<K: KeyExchange> = (Output<K::Hash>, K::KE3Message);
#[cfg(test)]
pub type GenerateKe3Result<K: KeyExchange> = (
    Output<K::Hash>,
    K::KE3Message,
    Output<K::Hash>,
    Output<K::Hash>,
);

pub type Ke1StateLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE1State as Serialize>::Len;
pub type Ke1MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE1Message as Serialize>::Len;
pub type Ke2StateLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE2State<CS> as Serialize>::Len;
pub type Ke2MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE2Message as Serialize>::Len;
pub type Ke3MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE3Message as Serialize>::Len;

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl<CS: CipherSuite> AssertZeroized for CredentialRequestParts<CS> {
    fn assert_zeroized(&self) {
        let Self(blinded_element) = self;

        for byte in blinded_element.iter() {
            assert_eq!(byte, &0);
        }
    }
}

#[cfg(test)]
impl<CS: CipherSuite> AssertZeroized for CredentialResponseParts<CS> {
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

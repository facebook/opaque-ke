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
use zeroize::ZeroizeOnDrop;

use crate::ciphersuite::{CipherSuite, KeGroup, OprfGroup, OprfHash};
use crate::errors::ProtocolError;
use crate::hash::{Hash, OutputSize, ProxyHash};
use crate::key_exchange::group::Group;
use crate::key_exchange::shared::NonceLen;
use crate::keypair::{PrivateKey, PublicKey};
use crate::opaque::{Identifiers, MaskedResponse, MaskedResponseLen};
use crate::serialization::{i2osp, SliceExt};

pub trait KeyExchange
where
    <Self::Hash as CoreProxy>::Core: ProxyHash,
    <<Self::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<Self::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    type Group: Group;
    type Hash: Hash;

    type KE1State: ZeroizeOnDrop + Clone;
    type KE2State: ZeroizeOnDrop + Clone;
    type KE1Message: ZeroizeOnDrop + Clone;
    type KE2Builder<CS: CipherSuite<KeyExchange = Self>>: ZeroizeOnDrop + Clone;
    type KE2BuilderData<'a, CS: 'static + CipherSuite>;
    type KE2BuilderInput;
    type KE2Message: ZeroizeOnDrop + Clone;
    type KE3Message: ZeroizeOnDrop + Clone;

    fn generate_ke1<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError>;

    fn ke2_builder<CS: CipherSuite<KeyExchange = Self>, R: RngCore + CryptoRng>(
        rng: &mut R,
        credential_request: CredentialRequestParts<CS>,
        ke1_message: Self::KE1Message,
        credential_response: CredentialResponseParts<CS>,
        client_s_pk: PublicKey<Self::Group>,
        identifiers: SerializedIdentifiers<'_, KeGroup<CS>>,
        context: &[u8],
    ) -> Result<Self::KE2Builder<CS>, ProtocolError>;

    fn ke2_builder_data<CS: CipherSuite<KeyExchange = Self>>(
        builder: &Self::KE2Builder<CS>,
    ) -> Self::KE2BuilderData<'_, CS>;

    fn generate_ke2_input<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + RngCore>(
        builder: &Self::KE2Builder<CS>,
        rng: &mut R,
        server_s_sk: &PrivateKey<Self::Group>,
    ) -> Self::KE2BuilderInput;

    fn build_ke2<CS: CipherSuite<KeyExchange = Self>>(
        builder: Self::KE2Builder<CS>,
        input: Self::KE2BuilderInput,
    ) -> Result<GenerateKe2Result<Self>, ProtocolError>;

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
        identifiers: SerializedIdentifiers<'_, KeGroup<CS>>,
        context: &[u8],
    ) -> Result<GenerateKe3Result<Self>, ProtocolError>;

    fn finish_ke(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State,
    ) -> Result<Output<Self::Hash>, ProtocolError>;
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub struct CredentialRequestParts<CS: CipherSuite>(
    GenericArray<u8, <OprfGroup<CS> as voprf::Group>::ElemLen>,
);

impl<CS: CipherSuite> CredentialRequestParts<CS> {
    pub(crate) fn new(blinded_element: &BlindedElement<CS::OprfCs>) -> Self {
        Self(blinded_element.serialize())
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
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
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, ZeroizeOnDrop)]
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

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
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
    // MaskedResponse: (Nonce + Hash) + KePk
    NonceLen: Add<OutputSize<OprfHash<CS>>>,
    Sum<NonceLen, OutputSize<OprfHash<CS>>>: ArrayLength<u8> + Add<<KeGroup<CS> as Group>::PkLen>,
    MaskedResponseLen<CS>: ArrayLength<u8>,
{
    type Len = CredentialResponsePartsLen<CS>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.evaluation_element
            .clone()
            .concat(self.masking_nonce)
            .concat(self.masked_response.serialize())
    }
}

pub struct SerializedIdentifiers<'a, G: Group> {
    pub client: SerializedIdentifier<'a, G>,
    pub server: SerializedIdentifier<'a, G>,
}

/// Computes `I2OSP(len(input), max_bytes) || input` and helps hold output
/// without allocation.
pub struct SerializedIdentifier<'a, G: Group> {
    length: GenericArray<u8, U2>,
    identifier: Identifier<'a, G>,
}

enum Identifier<'a, G: Group> {
    Owned(GenericArray<u8, G::PkLen>),
    Borrowed(&'a [u8]),
}

impl<'a, G: Group> SerializedIdentifiers<'a, G> {
    pub(crate) fn from_identifiers(
        ids: Identifiers<'a>,
        client_s_pk: GenericArray<u8, G::PkLen>,
        server_s_pk: GenericArray<u8, G::PkLen>,
    ) -> Result<Self, ProtocolError> {
        let client = if let Some(client) = ids.client {
            SerializedIdentifier::from(client)?
        } else {
            SerializedIdentifier::from_owned(client_s_pk)?
        };
        let server = if let Some(server) = ids.server {
            SerializedIdentifier::from(server)?
        } else {
            SerializedIdentifier::from_owned(server_s_pk)?
        };

        Ok(Self { client, server })
    }
}

impl<'a, G: Group> SerializedIdentifier<'a, G> {
    // Variation of `serialize` that takes a borrowed `input
    fn from(input: &'a [u8]) -> Result<Self, ProtocolError> {
        Ok(SerializedIdentifier {
            length: i2osp::<U2>(input.len())?,
            identifier: Identifier::Borrowed(input),
        })
    }

    // Variation of `serialize` that takes an owned `input`
    fn from_owned(input: GenericArray<u8, G::PkLen>) -> Result<Self, ProtocolError> {
        Ok(SerializedIdentifier {
            length: i2osp::<U2>(input.len())?,
            identifier: Identifier::Owned(input),
        })
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
pub type GenerateKe2Result<K: KeyExchange> = (K::KE2State, K::KE2Message);
#[cfg(test)]
pub type GenerateKe2Result<K: KeyExchange> =
    (K::KE2State, K::KE2Message, Output<K::Hash>, Output<K::Hash>);
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
    <<CS::KeyExchange as KeyExchange>::KE2State as Serialize>::Len;
pub type Ke2MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE2Message as Serialize>::Len;
pub type Ke3MessageLen<CS: CipherSuite> =
    <<CS::KeyExchange as KeyExchange>::KE3Message as Serialize>::Len;

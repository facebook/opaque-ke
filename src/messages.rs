// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains the messages used for OPAQUE

use crate::{
    ciphersuite::CipherSuite,
    envelope::{Envelope, EnvelopeCredentialsFormat},
    errors::{
        utils::{check_slice_size, check_slice_size_atleast},
        PakeError, ProtocolError,
    },
    group::Group,
    hash::Hash,
    key_exchange::traits::{KeyExchange, ToBytes},
    keypair::{KeyPair, SizedBytesExt},
    serialization::{serialize, tokenize, u8_to_credential_type, CredentialType},
};
use generic_array::{typenum::Unsigned, GenericArray};
use generic_bytes::SizedBytes;
use std::convert::TryFrom;

// Messages
// =========

/// The message sent by the client to the server, to initiate registration
pub struct RegistrationRequest<Grp> {
    /// blinded password information
    pub(crate) alpha: Grp,
}

impl<Grp: Group> TryFrom<&[u8]> for RegistrationRequest<Grp> {
    type Error = ProtocolError;
    fn try_from(first_message_bytes: &[u8]) -> Result<Self, Self::Error> {
        let elem_len = Grp::ElemLen::to_usize();
        let checked_slice = check_slice_size(first_message_bytes, elem_len, "first_message_bytes")?;

        // Check that the message is actually containing an element of the
        // correct subgroup
        let arr = GenericArray::from_slice(&checked_slice[checked_slice.len() - elem_len..]);
        let alpha = Grp::from_element_slice(arr)?;
        Ok(Self { alpha })
    }
}

impl<Grp: Group> RegistrationRequest<Grp> {
    /// Byte representation for the registration request
    pub fn to_bytes(&self) -> Vec<u8> {
        self.alpha.to_arr().to_vec()
    }

    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        serialize(&self.alpha.to_arr(), 2)
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let (alpha_bytes, remainder) = tokenize(&input, 2)?;

        if !remainder.is_empty() {
            return Err(PakeError::SerializationError.into());
        }

        let checked_slice = check_slice_size(
            &alpha_bytes,
            Grp::ElemLen::to_usize(),
            "first_message_bytes",
        )?;
        // Check that the message is actually containing an element of the
        // correct subgroup
        let arr = GenericArray::from_slice(checked_slice);
        let alpha = Grp::from_element_slice(arr)?;
        Ok(Self { alpha })
    }
}

/// The answer sent by the server to the user, upon reception of the
/// registration attempt
pub struct RegistrationResponse<Grp> {
    /// The server's oprf output
    pub(crate) beta: Grp,
    /// Server's static public key
    pub(crate) server_s_pk: Vec<u8>,
    /// Envelope credentials format
    pub(crate) ecf: EnvelopeCredentialsFormat,
}

impl<Grp> TryFrom<&[u8]> for RegistrationResponse<Grp>
where
    Grp: Group,
{
    type Error = ProtocolError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let elem_len = Grp::ElemLen::to_usize();
        let checked_slice = check_slice_size_atleast(bytes, elem_len, "second_message_bytes")?;

        // Check that the message is actually containing an element of the
        // correct subgroup
        let arr = GenericArray::from_slice(&checked_slice[..elem_len]);
        let beta = Grp::from_element_slice(arr)?;

        let server_s_pk = checked_slice[elem_len..].to_vec();

        // Note that we use a default envelope credentials format here, since it
        // is not included in the byte representation
        let ecf = EnvelopeCredentialsFormat::default()?;
        Ok(Self {
            beta,
            server_s_pk,
            ecf,
        })
    }
}

impl<Grp> RegistrationResponse<Grp>
where
    Grp: Group,
{
    /// Byte representation for the registration response message. This does not
    /// include the envelope credentials format
    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.beta.to_arr().to_vec()[..], &self.server_s_pk[..]].concat()
    }

    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut registration_response: Vec<u8> = Vec::new();
        registration_response.extend_from_slice(&serialize(&self.beta.to_arr(), 2));
        registration_response.extend_from_slice(&serialize(&self.server_s_pk, 2));

        // Handle ecf serialization
        let secret_credentials: Vec<u8> = self
            .ecf
            .secret_credentials
            .iter()
            .map(|&x| x as u8 + 1)
            .collect();
        let cleartext_credentials: Vec<u8> = self
            .ecf
            .cleartext_credentials
            .iter()
            .map(|&x| x as u8 + 1)
            .collect();
        let ecf_serialized = [
            serialize(&secret_credentials, 1),
            serialize(&cleartext_credentials, 1),
        ]
        .concat();
        registration_response.extend_from_slice(&ecf_serialized);

        registration_response
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let (beta_bytes, remainder) = tokenize(&input, 2)?;
        let (server_s_pk, remainder) = tokenize(&remainder, 2)?;

        // Handle ecf deserialization
        let (secret_credentials, remainder) = tokenize(&remainder, 1)?;
        let (cleartext_credentials, remainder) = tokenize(&remainder, 1)?;
        let sc = secret_credentials
            .iter()
            .map(|x| u8_to_credential_type(*x).ok_or(PakeError::SerializationError))
            .collect::<Result<Vec<CredentialType>, _>>()?;
        let cc = cleartext_credentials
            .iter()
            .map(|x| u8_to_credential_type(*x).ok_or(PakeError::SerializationError))
            .collect::<Result<Vec<CredentialType>, _>>()?;
        let ecf = EnvelopeCredentialsFormat::new(sc, cc)?;

        if !remainder.is_empty() {
            return Err(PakeError::SerializationError.into());
        }

        let checked_slice = check_slice_size(
            &beta_bytes,
            Grp::ElemLen::to_usize(),
            "second_message_bytes",
        )?;
        // Check that the message is actually containing an element of the
        // correct subgroup
        let arr = GenericArray::from_slice(&checked_slice);
        let beta = Grp::from_element_slice(arr)?;
        Ok(Self {
            ecf,
            server_s_pk,
            beta,
        })
    }
}

/// The final message from the client, containing sealed cryptographic
/// identifiers
pub struct RegistrationUpload<KeyFormat: KeyPair, D: Hash> {
    /// The "envelope" generated by the user, containing sealed
    /// cryptographic identifiers
    pub(crate) envelope: Envelope<D>,
    /// The user's public key
    pub(crate) client_s_pk: KeyFormat::Repr,
}

impl<KeyFormat, D> TryFrom<&[u8]> for RegistrationUpload<KeyFormat, D>
where
    KeyFormat: KeyPair,
    D: Hash,
{
    type Error = ProtocolError;

    fn try_from(third_message_bytes: &[u8]) -> Result<Self, Self::Error> {
        let key_len = <KeyFormat::Repr as SizedBytes>::Len::to_usize();
        let envelope_size = key_len + Envelope::<D>::additional_size();
        let checked_bytes = check_slice_size(
            third_message_bytes,
            envelope_size + key_len,
            "third_message",
        )?;
        let unchecked_client_s_pk = KeyFormat::Repr::from_bytes(&checked_bytes[envelope_size..])?;
        let client_s_pk = KeyFormat::check_public_key(unchecked_client_s_pk)?;

        Ok(Self {
            envelope: Envelope::<D>::from_bytes(&checked_bytes[..envelope_size])?,
            client_s_pk,
        })
    }
}

impl<KeyFormat, D> RegistrationUpload<KeyFormat, D>
where
    KeyFormat: KeyPair,
    D: Hash,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut message: Vec<u8> = Vec::new();
        message.extend_from_slice(&self.envelope.serialize());
        message.extend_from_slice(&serialize(&self.client_s_pk.to_arr(), 2));
        message
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let (envelope, remainder) = Envelope::<D>::deserialize(&input)?;
        let (client_s_pk, remainder) = tokenize(&remainder, 2)?;

        if !remainder.is_empty() {
            return Err(PakeError::SerializationError.into());
        }

        Ok(Self {
            envelope,
            client_s_pk: KeyFormat::check_public_key(KeyFormat::Repr::from_bytes(&client_s_pk)?)?,
        })
    }
}

/// The message sent by the user to the server, to initiate registration
pub struct CredentialRequest<CS: CipherSuite> {
    /// blinded password information
    pub(crate) alpha: CS::Group,
    pub(crate) ke1_message: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE1Message,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for CredentialRequest<CS> {
    type Error = ProtocolError;
    fn try_from(first_message_bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::deserialize(first_message_bytes)
    }
}

impl<CS: CipherSuite> CredentialRequest<CS> {
    /// byte representation for the login request
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        [&self.alpha.to_arr()[..], &self.ke1_message.to_bytes()].concat()
    }

    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut credential_request: Vec<u8> = Vec::new();
        credential_request.extend_from_slice(&serialize(&self.alpha.to_arr(), 2));
        credential_request.extend_from_slice(&self.ke1_message.to_bytes());
        credential_request
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let (alpha_bytes, ke1m) = tokenize(&input, 2)?;

        let elem_len = <CS::Group as Group>::ElemLen::to_usize();
        let checked_slice = check_slice_size(&alpha_bytes, elem_len, "login_first_message_bytes")?;
        let arr = GenericArray::from_slice(&checked_slice[..elem_len]);
        let alpha = <CS::Group as Group>::from_element_slice(arr)?;

        let ke1_message =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE1Message::try_from(
                &ke1m[..],
            )?;

        Ok(Self { alpha, ke1_message })
    }
}

/// The answer sent by the server to the user, upon reception of the
/// login attempt
pub struct CredentialResponse<CS: CipherSuite> {
    /// the server's oprf output
    pub(crate) beta: CS::Group,
    /// the user's sealed information,
    pub(crate) envelope: Envelope<CS::Hash>,
    pub(crate) ke2_message: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE2Message,
}

impl<CS: CipherSuite> CredentialResponse<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut credential_response: Vec<u8> = Vec::new();
        credential_response.extend_from_slice(&serialize(&self.beta.to_arr(), 2));
        credential_response.extend_from_slice(&self.envelope.to_bytes());
        credential_response.extend_from_slice(&self.ke2_message.to_bytes());
        credential_response
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let (beta_bytes, envelope_and_ke2m_bytes) = tokenize(&input, 2)?;
        let concatenated = [&beta_bytes[..], &envelope_and_ke2m_bytes[..]].concat();
        Self::try_from(&concatenated[..])
    }
}

impl<CS: CipherSuite> TryFrom<&[u8]> for CredentialResponse<CS> {
    type Error = ProtocolError;
    fn try_from(second_message_bytes: &[u8]) -> Result<Self, Self::Error> {
        let elem_len = <CS::Group as Group>::ElemLen::to_usize();
        let checked_slice =
            check_slice_size_atleast(second_message_bytes, elem_len, "login_second_message_bytes")?;

        // Check that the message is actually containing an element of the
        // correct subgroup
        let beta_bytes = &checked_slice[..elem_len];
        let arr = GenericArray::from_slice(beta_bytes);
        let beta = CS::Group::from_element_slice(arr)?;

        let (envelope, remainder) = Envelope::<CS::Hash>::deserialize(&checked_slice[elem_len..])?;

        let ke2_message_size = CS::KeyExchange::ke2_message_size();
        let checked_remainder =
            check_slice_size_atleast(&remainder, ke2_message_size, "login_second_message_bytes")?;
        let ke2_message =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE2Message::try_from(
                &checked_remainder,
            )?;

        Ok(Self {
            beta,
            envelope,
            ke2_message,
        })
    }
}

/// The answer sent by the client to the server, upon reception of the
/// sealed envelope
pub struct CredentialFinalization<CS: CipherSuite> {
    pub(crate) ke3_message: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE3Message,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for CredentialFinalization<CS> {
    type Error = ProtocolError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let ke3_message =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE3Message::try_from(bytes)?;
        Ok(Self { ke3_message })
    }
}

impl<CS: CipherSuite> CredentialFinalization<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        self.ke3_message.to_bytes()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        Self::try_from(&input[..])
    }

    /// byte representation for the login finalization
    pub fn to_bytes(&self) -> Vec<u8> {
        self.ke3_message.to_bytes()
    }
}

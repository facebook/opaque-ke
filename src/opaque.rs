// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Provides the main OPAQUE API

use crate::{
    ciphersuite::CipherSuite,
    envelope::{Envelope, EnvelopeCredentialsFormat, ExportKeySize},
    errors::{
        utils::{check_slice_size, check_slice_size_atleast},
        InternalPakeError, PakeError, ProtocolError,
    },
    group::Group,
    hash::Hash,
    key_exchange::traits::{KeyExchange, ToBytes},
    keypair::{KeyPair, SizedBytes},
    oprf,
    serialization::{
        serialize, tokenize, u8_to_credential_type, CredentialType, ProtocolMessageType,
    },
    slow_hash::SlowHash,
};
use generic_array::{typenum::Unsigned, GenericArray};
use rand_core::{CryptoRng, RngCore};
use std::collections::HashMap;
use std::{convert::TryFrom, marker::PhantomData};
use zeroize::Zeroize;

// Messages
// =========

/// The message sent by the client to the server, to initiate registration
pub struct RegisterFirstMessage<Grp> {
    /// User identity
    id_u: Vec<u8>,
    /// blinded password information
    alpha: Grp,
}

impl<Grp: Group> TryFrom<&[u8]> for RegisterFirstMessage<Grp> {
    type Error = ProtocolError;
    fn try_from(first_message_bytes: &[u8]) -> Result<Self, Self::Error> {
        let elem_len = Grp::ElemLen::to_usize();
        let checked_slice =
            check_slice_size_atleast(first_message_bytes, elem_len, "first_message_bytes")?;

        let id_u = checked_slice[..checked_slice.len() - elem_len].to_vec();

        // Check that the message is actually containing an element of the
        // correct subgroup
        let arr = GenericArray::from_slice(&checked_slice[checked_slice.len() - elem_len..]);
        let alpha = Grp::from_element_slice(arr)?;
        Ok(Self { id_u, alpha })
    }
}

impl<Grp: Group> RegisterFirstMessage<Grp> {
    /// Byte representation for the registration request
    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.id_u[..], &self.alpha.to_arr().to_vec()[..]].concat()
    }

    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut registration_request: Vec<u8> = Vec::new();
        registration_request.extend_from_slice(&serialize(&self.id_u, 2));
        registration_request.extend_from_slice(&serialize(&self.alpha.to_arr(), 2));

        let mut output: Vec<u8> = Vec::new();
        output.push(ProtocolMessageType::from(self) as u8 + 1);
        output.extend_from_slice(&serialize(&registration_request, 3));
        output
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.is_empty()
            || input.is_empty()
            || input[0] != ProtocolMessageType::RegistrationRequest as u8 + 1
        {
            return Err(PakeError::SerializationError.into());
        }

        let (data, remainder) = tokenize(input[1..].to_vec(), 3)?;
        if !remainder.is_empty() {
            return Err(PakeError::SerializationError.into());
        }

        let (id_u, remainder) = tokenize(data, 2)?;
        let (alpha_bytes, remainder) = tokenize(remainder, 2)?;

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
        Ok(Self { id_u, alpha })
    }
}

/// The answer sent by the server to the user, upon reception of the
/// registration attempt
pub struct RegisterSecondMessage<Grp> {
    /// The server's oprf output
    beta: Grp,
    /// Server's static public key
    server_s_pk: Vec<u8>,
    /// Envelope credentials format
    ecf: EnvelopeCredentialsFormat,
}

impl<Grp> TryFrom<&[u8]> for RegisterSecondMessage<Grp>
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

impl<Grp> RegisterSecondMessage<Grp>
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

        let mut output: Vec<u8> = Vec::new();
        output.push(ProtocolMessageType::from(self) as u8 + 1);
        output.extend_from_slice(&serialize(&registration_response, 3));
        output
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.is_empty() || input[0] != ProtocolMessageType::RegistrationResponse as u8 + 1 {
            return Err(PakeError::SerializationError.into());
        }

        let (data, remainder) = tokenize(input[1..].to_vec(), 3)?;
        if !remainder.is_empty() {
            return Err(PakeError::SerializationError.into());
        }

        let (beta_bytes, remainder) = tokenize(data, 2)?;
        let (server_s_pk, remainder) = tokenize(remainder, 2)?;

        // Handle ecf deserialization
        let (secret_credentials, remainder) = tokenize(remainder, 1)?;
        let (cleartext_credentials, remainder) = tokenize(remainder, 1)?;
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
pub struct RegisterThirdMessage<KeyFormat: KeyPair, D: Hash> {
    /// The "envelope" generated by the user, containing sealed
    /// cryptographic identifiers
    envelope: Envelope<D>,
    /// The user's public key
    client_s_pk: KeyFormat::Repr,
}

impl<KeyFormat, D> TryFrom<&[u8]> for RegisterThirdMessage<KeyFormat, D>
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

impl<KeyFormat, D> RegisterThirdMessage<KeyFormat, D>
where
    KeyFormat: KeyPair,
    D: Hash,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut registration_upload: Vec<u8> = Vec::new();
        registration_upload.extend_from_slice(&self.envelope.serialize());
        registration_upload.extend_from_slice(&serialize(&self.client_s_pk.to_arr(), 2));

        let mut output: Vec<u8> = Vec::new();
        output.push(ProtocolMessageType::from(self) as u8 + 1);
        output.extend_from_slice(&serialize(&registration_upload, 3));
        output
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.is_empty() || input[0] != ProtocolMessageType::RegistrationUpload as u8 + 1 {
            return Err(PakeError::SerializationError.into());
        }

        let (data, remainder) = tokenize(input[1..].to_vec(), 3)?;
        if !remainder.is_empty() {
            return Err(PakeError::SerializationError.into());
        }

        let (envelope, remainder) = Envelope::<D>::deserialize(&data)?;
        let (client_s_pk, remainder) = tokenize(remainder, 2)?;

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
pub struct LoginFirstMessage<CS: CipherSuite> {
    /// User identity
    id_u: Vec<u8>,
    /// blinded password information
    alpha: CS::Group,
    ke1_message: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE1Message,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for LoginFirstMessage<CS> {
    type Error = ProtocolError;
    fn try_from(first_message_bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::deserialize(first_message_bytes)
    }
}

impl<CS: CipherSuite> LoginFirstMessage<CS> {
    /// byte representation for the login request
    fn to_bytes(&self) -> Vec<u8> {
        [&self.alpha.to_arr()[..], &self.ke1_message.to_bytes()].concat()
    }

    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut credential_request: Vec<u8> = Vec::new();
        credential_request.extend_from_slice(&serialize(&self.id_u, 2));
        credential_request.extend_from_slice(&serialize(&self.alpha.to_arr(), 2));

        let mut output: Vec<u8> = Vec::new();
        output.push(ProtocolMessageType::from(self) as u8 + 1);
        output.extend_from_slice(&serialize(&credential_request, 3));
        output.extend_from_slice(&self.ke1_message.to_bytes());
        output
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.is_empty() || input[0] != ProtocolMessageType::CredentialRequest as u8 + 1 {
            return Err(PakeError::SerializationError.into());
        }

        let (data, ke1m) = tokenize(input[1..].to_vec(), 3)?;

        let (id_u, remainder) = tokenize(data, 2)?;
        let (alpha_bytes, remainder) = tokenize(remainder, 2)?;

        if !remainder.is_empty() {
            return Err(PakeError::SerializationError.into());
        }

        let elem_len = <CS::Group as Group>::ElemLen::to_usize();
        let checked_slice = check_slice_size(&alpha_bytes, elem_len, "login_first_message_bytes")?;
        let arr = GenericArray::from_slice(&checked_slice[..elem_len]);
        let alpha = <CS::Group as Group>::from_element_slice(arr)?;

        let ke1_message =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE1Message::try_from(
                &ke1m[..],
            )?;

        Ok(Self {
            id_u,
            alpha,
            ke1_message,
        })
    }
}

/// The answer sent by the server to the user, upon reception of the
/// login attempt.
pub struct LoginSecondMessage<CS: CipherSuite> {
    /// the server's oprf output
    beta: CS::Group,
    /// the user's sealed information,
    envelope: Envelope<CS::Hash>,
    ke2_message: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE2Message,
}

impl<CS: CipherSuite> LoginSecondMessage<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut credential_response: Vec<u8> = Vec::new();
        credential_response.extend_from_slice(&serialize(&self.beta.to_arr(), 2));
        credential_response.extend_from_slice(&self.envelope.to_bytes());

        let mut output: Vec<u8> = Vec::new();
        output.push(ProtocolMessageType::from(self) as u8 + 1);
        output.extend_from_slice(&serialize(&credential_response, 3));
        output.extend_from_slice(&self.ke2_message.to_bytes());
        output
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.is_empty() || input[0] != ProtocolMessageType::CredentialResponse as u8 + 1 {
            return Err(PakeError::SerializationError.into());
        }

        let (data, ke2m) = tokenize(input[1..].to_vec(), 3)?;
        let (beta_bytes, envelope_bytes) = tokenize(data, 2)?;

        let concatenated = [&beta_bytes[..], &envelope_bytes[..], &ke2m[..]].concat();
        Self::try_from(&concatenated[..])
    }
}

impl<CS: CipherSuite> TryFrom<&[u8]> for LoginSecondMessage<CS> {
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
pub struct LoginThirdMessage<CS: CipherSuite> {
    ke3_message: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE3Message,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for LoginThirdMessage<CS> {
    type Error = ProtocolError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let ke3_message =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE3Message::try_from(bytes)?;
        Ok(Self { ke3_message })
    }
}

impl<CS: CipherSuite> LoginThirdMessage<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::new();
        output.push(ProtocolMessageType::from(self) as u8 + 1);
        output.extend_from_slice(&self.ke3_message.to_bytes());
        output
    }

    /// byte representation for the login finalization
    pub fn to_bytes(&self) -> Vec<u8> {
        self.ke3_message.to_bytes()
    }
}

// Registration
// ============

/// The state elements the client holds to register itself
pub struct ClientRegistration<CS: CipherSuite> {
    /// User identity
    id_u: Vec<u8>,
    /// Server identity
    id_s: Vec<u8>,
    /// token containing the client's password and the blinding factor
    pub(crate) token: oprf::Token<CS::Group>,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for ClientRegistration<CS> {
    type Error = ProtocolError;
    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let (id_u, bytes) = tokenize(input.to_vec(), 2)?;
        let (id_s, bytes) = tokenize(bytes.to_vec(), 2)?;

        let min_expected_len = <CS::Group as Group>::ScalarLen::to_usize();
        let checked_slice = (if bytes.len() <= min_expected_len {
            Err(InternalPakeError::SizeError {
                name: "client_registration_bytes",
                len: min_expected_len,
                actual_len: bytes.len(),
            })
        } else {
            Ok(bytes)
        })?;

        // Check that the message is actually containing an element of the
        // correct subgroup
        let scalar_len = min_expected_len;
        let blinding_factor_bytes = GenericArray::from_slice(&checked_slice[..scalar_len]);
        let blinding_factor = CS::Group::from_scalar_slice(blinding_factor_bytes)?;
        let password = checked_slice[scalar_len..].to_vec();
        Ok(Self {
            id_u,
            id_s,
            token: oprf::Token {
                data: password,
                blind: blinding_factor,
            },
        })
    }
}

impl<CS: CipherSuite> ClientRegistration<CS> {
    /// byte representation for the client's registration state
    pub fn to_bytes(&self) -> Vec<u8> {
        let output: Vec<u8> = [
            &serialize(&self.id_u, 2),
            &serialize(&self.id_s, 2),
            &CS::Group::scalar_as_bytes(&self.token.blind)[..],
            &self.token.data,
        ]
        .concat();
        output
    }
}

impl<CS: CipherSuite> ClientRegistration<CS> {
    /// Returns an initial "blinded" request to send to the server, as well as a ClientRegistration
    ///
    /// # Arguments
    /// * `password` - A user password
    ///
    /// # Example
    ///
    /// ```
    /// use opaque_ke::opaque::ClientRegistration;
    /// # use opaque_ke::errors::ProtocolError;
    /// use rand_core::{OsRng, RngCore};
    /// use opaque_ke::ciphersuite::CipherSuite;
    /// struct Default;
    /// impl CipherSuite for Default {
    ///     type Group = curve25519_dalek::ristretto::RistrettoPoint;
    ///     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
    ///     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    ///     type Hash = sha2::Sha256;
    ///     type SlowHash = opaque_ke::slow_hash::NoOpHash;
    /// }
    /// let mut rng = OsRng;
    /// let (register_m1, registration_state) = ClientRegistration::<Default>::start(b"hunter2", &mut rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        password: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<(RegisterFirstMessage<CS::Group>, Self), ProtocolError> {
        Self::start_with_user_and_server_name(
            &Vec::new(),
            &Vec::new(),
            password,
            blinding_factor_rng,
        )
    }

    /// Same as ClientRegistration::start, but also accepts a username and server name as input
    pub fn start_with_user_and_server_name<R: RngCore + CryptoRng>(
        user_name: &[u8],
        server_name: &[u8],
        password: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<(RegisterFirstMessage<CS::Group>, Self), ProtocolError> {
        Self::start_with_user_and_server_name_and_postprocessing(
            user_name,
            server_name,
            password,
            blinding_factor_rng,
            std::convert::identity,
        )
    }

    /// Same as ClientRegistration::start, but also accepts a username and server name as input as well as
    /// an optional postprocessing function for the blinding factor
    pub fn start_with_user_and_server_name_and_postprocessing<R: RngCore + CryptoRng>(
        user_name: &[u8],
        server_name: &[u8],
        password: &[u8],
        blinding_factor_rng: &mut R,
        postprocess: fn(<CS::Group as Group>::Scalar) -> <CS::Group as Group>::Scalar,
    ) -> Result<(RegisterFirstMessage<CS::Group>, Self), ProtocolError> {
        let (token, alpha) = oprf::blind_with_postprocessing::<R, CS::Group>(
            &password,
            blinding_factor_rng,
            postprocess,
        )?;

        Ok((
            RegisterFirstMessage::<CS::Group> {
                id_u: user_name.to_vec(),
                alpha,
            },
            Self {
                id_u: user_name.to_vec(),
                id_s: server_name.to_vec(),
                token,
            },
        ))
    }
}

type ClientRegistrationFinishResult<KeyFormat, D> = (
    RegisterThirdMessage<KeyFormat, D>,
    GenericArray<u8, ExportKeySize>,
);

impl<CS: CipherSuite> ClientRegistration<CS> {
    /// "Unblinds" the server's answer and returns a final message containing
    /// cryptographic identifiers, to be sent to the server on setup finalization
    ///
    /// # Arguments
    /// * `message` - the server's answer to the initial registration attempt
    ///
    /// # Example
    ///
    /// ```
    /// use opaque_ke::{opaque::{ClientRegistration, ServerRegistration}, keypair::{X25519KeyPair, SizedBytes}};
    /// # use opaque_ke::errors::ProtocolError;
    /// # use opaque_ke::keypair::KeyPair;
    /// use rand_core::{OsRng, RngCore};
    /// use opaque_ke::ciphersuite::CipherSuite;
    /// struct Default;
    /// impl CipherSuite for Default {
    ///     type Group = curve25519_dalek::ristretto::RistrettoPoint;
    ///     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
    ///     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    ///     type Hash = sha2::Sha256;
    ///     type SlowHash = opaque_ke::slow_hash::NoOpHash;
    /// }
    /// let mut client_rng = OsRng;
    /// let mut server_rng = OsRng;
    /// let server_kp = X25519KeyPair::generate_random(&mut server_rng)?;
    /// let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", &mut client_rng)?;
    /// let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, &mut server_rng)?;
    /// let mut client_rng = OsRng;
    /// let register_m3 = client_state.finish(register_m2, server_kp.public(), &mut client_rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn finish<R: CryptoRng + RngCore>(
        self,
        r2: RegisterSecondMessage<CS::Group>,
        server_s_pk: &<CS::KeyFormat as KeyPair>::Repr,
        rng: &mut R,
    ) -> Result<ClientRegistrationFinishResult<CS::KeyFormat, CS::Hash>, ProtocolError> {
        let mut r2_cloned = r2;
        r2_cloned.server_s_pk = server_s_pk.to_arr().to_vec();
        self.finish_using_transmitted_server_public_key(r2_cloned, rng)
    }

    /// Same as finish, but without the server public key check
    pub fn finish_using_transmitted_server_public_key<R: CryptoRng + RngCore>(
        self,
        r2: RegisterSecondMessage<CS::Group>,
        rng: &mut R,
    ) -> Result<ClientRegistrationFinishResult<CS::KeyFormat, CS::Hash>, ProtocolError> {
        let client_static_keypair = CS::KeyFormat::generate_random(rng)?;

        let password_derived_key =
            get_password_derived_key::<CS::Group, CS::SlowHash, CS::Hash>(&self.token, r2.beta)?;

        let mut credentials_map: HashMap<CredentialType, Vec<u8>> = HashMap::new();
        credentials_map.insert(
            CredentialType::SkU,
            client_static_keypair.private().to_arr().to_vec(),
        );
        credentials_map.insert(
            CredentialType::PkU,
            client_static_keypair.public().to_arr().to_vec(),
        );
        credentials_map.insert(CredentialType::PkS, r2.server_s_pk);
        credentials_map.insert(CredentialType::IdU, self.id_u.clone());
        credentials_map.insert(CredentialType::IdS, self.id_s.clone());

        let (envelope, export_key) =
            Envelope::<CS::Hash>::seal(&password_derived_key, r2.ecf, credentials_map, rng)?;

        Ok((
            RegisterThirdMessage {
                envelope,
                client_s_pk: client_static_keypair.public().clone(),
            },
            export_key,
        ))
    }
}

// This can't be derived because of the use of a phantom parameter
impl<CS: CipherSuite> Zeroize for ClientRegistration<CS> {
    fn zeroize(&mut self) {
        self.token.data.zeroize();
        self.token.blind.zeroize();
    }
}

impl<CS: CipherSuite> Drop for ClientRegistration<CS> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// This can't be derived because of the use of a phantom parameter
impl<CS: CipherSuite> Zeroize for ClientLogin<CS> {
    fn zeroize(&mut self) {
        self.token.data.zeroize();
        self.token.blind.zeroize();
    }
}

impl<CS: CipherSuite> Drop for ClientLogin<CS> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The state elements the server holds to record a registration
pub struct ServerRegistration<CS: CipherSuite> {
    envelope: Option<Envelope<CS::Hash>>,
    client_s_pk: Option<<CS::KeyFormat as KeyPair>::Repr>,
    pub(crate) oprf_key: <CS::Group as Group>::Scalar,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for ServerRegistration<CS>
where
    <<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len:
        std::ops::Add<<<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len>,
    generic_array::typenum::Sum<
        <<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len,
        <<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len,
    >: generic_array::ArrayLength<u8>,
{
    type Error = ProtocolError;

    /// The format of a serialized ServerRegistration object:
    /// oprf_key | client_s_pk | envelope
    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let scalar_len = <CS::Group as Group>::ScalarLen::to_usize();
        if input.len() == scalar_len {
            return Ok(Self {
                oprf_key: CS::Group::from_scalar_slice(GenericArray::from_slice(input))?,
                client_s_pk: None,
                envelope: None,
            });
        }

        // Need to do this check manually because envelope is variable-size
        let key_len = <<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len::to_usize();

        let checked_bytes =
            check_slice_size_atleast(&input, scalar_len + key_len, "server_registration_bytes")?;

        let oprf_key_bytes = GenericArray::from_slice(&checked_bytes[..scalar_len]);
        let oprf_key = CS::Group::from_scalar_slice(oprf_key_bytes)?;
        let unchecked_client_s_pk = <CS::KeyFormat as KeyPair>::Repr::from_bytes(
            &checked_bytes[scalar_len..scalar_len + key_len],
        )?;
        let client_s_pk = CS::KeyFormat::check_public_key(unchecked_client_s_pk)?;

        let envelope = Envelope::<CS::Hash>::from_bytes(&checked_bytes[scalar_len + key_len..])?;

        Ok(Self {
            envelope: Some(envelope),
            client_s_pk: Some(client_s_pk),
            oprf_key,
        })
    }
}

impl<CS: CipherSuite> ServerRegistration<CS>
where
    <<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len:
        std::ops::Add<<<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len>,
    generic_array::typenum::Sum<
        <<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len,
        <<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len,
    >: generic_array::ArrayLength<u8>,
{
    /// byte representation for the server's registration state
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output: Vec<u8> = CS::Group::scalar_as_bytes(&self.oprf_key).to_vec();
        self.client_s_pk
            .iter()
            .for_each(|v| output.extend_from_slice(&v.to_arr()));
        self.envelope
            .iter()
            .for_each(|v| output.extend_from_slice(&v.to_bytes()));
        output
    }

    /// From the client's "blinded" password, returns a response to be
    /// sent back to the client, as well as a ServerRegistration
    ///
    /// # Arguments
    /// * `message`   - the initial registration message
    ///
    /// # Example
    ///
    /// ```
    /// use opaque_ke::{opaque::*, keypair::{X25519KeyPair, SizedBytes}};
    /// # use opaque_ke::errors::ProtocolError;
    /// use rand_core::{OsRng, RngCore};
    /// use opaque_ke::ciphersuite::CipherSuite;
    /// struct Default;
    /// impl CipherSuite for Default {
    ///     type Group = curve25519_dalek::ristretto::RistrettoPoint;
    ///     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
    ///     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    ///     type Hash = sha2::Sha256;
    ///     type SlowHash = opaque_ke::slow_hash::NoOpHash;
    /// }
    /// let mut client_rng = OsRng;
    /// let mut server_rng = OsRng;
    /// let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", &mut client_rng)?;
    /// let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, &mut server_rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        message: RegisterFirstMessage<CS::Group>,
        rng: &mut R,
    ) -> Result<(RegisterSecondMessage<CS::Group>, Self), ProtocolError> {
        Self::start_with_server_pk(message, &Vec::new(), rng)
    }

    /// Same as start, but with the ability to supply a server_s_pk as input
    pub fn start_with_server_pk<R: RngCore + CryptoRng>(
        message: RegisterFirstMessage<CS::Group>,
        server_s_pk: &[u8],
        rng: &mut R,
    ) -> Result<(RegisterSecondMessage<CS::Group>, Self), ProtocolError> {
        Self::start_with_server_pk_and_ecf(
            message,
            server_s_pk,
            EnvelopeCredentialsFormat::default()?,
            rng,
        )
    }

    /// Same as start, but with the ability to supply a server_s_pk as input and envelope credentials format
    pub fn start_with_server_pk_and_ecf<R: RngCore + CryptoRng>(
        message: RegisterFirstMessage<CS::Group>,
        server_s_pk: &[u8],
        ecf: EnvelopeCredentialsFormat,
        rng: &mut R,
    ) -> Result<(RegisterSecondMessage<CS::Group>, Self), ProtocolError> {
        // RFC: generate oprf_key (salt) and v_u = g^oprf_key
        let oprf_key = CS::Group::random_scalar(rng);

        // Compute beta = alpha^oprf_key
        let beta = oprf::evaluate::<CS::Group>(message.alpha, &oprf_key)?;

        Ok((
            RegisterSecondMessage {
                beta,
                server_s_pk: server_s_pk.to_vec(),
                ecf,
            },
            Self {
                envelope: None,
                client_s_pk: None,
                oprf_key,
            },
        ))
    }

    /// From the client's cryptographic identifiers, fully populates and
    /// returns a ServerRegistration
    ///
    /// # Arguments
    /// * `message` - the final client message
    ///
    /// # Example
    ///
    /// ```
    /// use opaque_ke::{opaque::*, keypair::{KeyPair, X25519KeyPair, SizedBytes}};
    /// # use opaque_ke::errors::ProtocolError;
    /// use rand_core::{OsRng, RngCore};
    /// use opaque_ke::ciphersuite::CipherSuite;
    /// struct Default;
    /// impl CipherSuite for Default {
    ///     type Group = curve25519_dalek::ristretto::RistrettoPoint;
    ///     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
    ///     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    ///     type Hash = sha2::Sha256;
    ///     type SlowHash = opaque_ke::slow_hash::NoOpHash;
    /// }
    /// let mut client_rng = OsRng;
    /// let mut server_rng = OsRng;
    /// let server_kp = X25519KeyPair::generate_random(&mut server_rng)?;
    /// let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", &mut client_rng)?;
    /// let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, &mut server_rng)?;
    /// let mut client_rng = OsRng;
    /// let (register_m3, _export_key) = client_state.finish(register_m2, server_kp.public(), &mut client_rng)?;
    /// let client_record = server_state.finish(register_m3)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn finish(
        self,
        message: RegisterThirdMessage<CS::KeyFormat, CS::Hash>,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            envelope: Some(message.envelope),
            client_s_pk: Some(message.client_s_pk),
            oprf_key: self.oprf_key,
        })
    }
}

// Login
// =====

/// The state elements the client holds to perform a login
pub struct ClientLogin<CS: CipherSuite> {
    /// User identity
    id_u: Vec<u8>,
    /// Server identity
    id_s: Vec<u8>,
    /// token containing the client's password and the blinding factor
    token: oprf::Token<CS::Group>,
    ke1_state: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE1State,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for ClientLogin<CS> {
    type Error = ProtocolError;
    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let (id_u, bytes) = tokenize(input.to_vec(), 2)?;
        let (id_s, bytes) = tokenize(bytes.to_vec(), 2)?;

        let scalar_len = <CS::Group as Group>::ScalarLen::to_usize();
        let ke1_state_size =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::ke1_state_size();

        let min_expected_len = scalar_len + ke1_state_size;
        let checked_slice = (if bytes.len() <= min_expected_len {
            Err(InternalPakeError::SizeError {
                name: "client_login_bytes",
                len: min_expected_len,
                actual_len: bytes.len(),
            })
        } else {
            Ok(bytes.clone())
        })?;

        let blinding_factor_bytes = GenericArray::from_slice(&checked_slice[..scalar_len]);
        let blinding_factor = CS::Group::from_scalar_slice(blinding_factor_bytes)?;
        let ke1_state =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE1State::try_from(
                &checked_slice[scalar_len..scalar_len + ke1_state_size],
            )?;
        let password = bytes[scalar_len + ke1_state_size..].to_vec();
        Ok(Self {
            id_u,
            id_s,
            token: oprf::Token {
                data: password,
                blind: blinding_factor,
            },
            ke1_state,
        })
    }
}

impl<CS: CipherSuite> ClientLogin<CS> {
    /// byte representation for the client's login state
    pub fn to_bytes(&self) -> Vec<u8> {
        let output: Vec<u8> = [
            &serialize(&self.id_u, 2),
            &serialize(&self.id_s, 2),
            &CS::Group::scalar_as_bytes(&self.token.blind)[..],
            &self.ke1_state.to_bytes(),
            &self.token.data,
        ]
        .concat();
        output
    }
}

type ClientLoginFinishResult<CS> = (
    LoginThirdMessage<CS>,
    Vec<u8>,
    GenericArray<u8, ExportKeySize>,
);

impl<CS: CipherSuite> ClientLogin<CS> {
    /// Returns an initial "blinded" password request to send to the server, as well as a ClientLogin
    ///
    /// # Arguments
    /// * `password` - A user password
    ///
    /// # Example
    ///
    /// ```
    /// use opaque_ke::opaque::ClientLogin;
    /// # use opaque_ke::errors::ProtocolError;
    /// use rand_core::{OsRng, RngCore};
    /// use opaque_ke::ciphersuite::CipherSuite;
    /// struct Default;
    /// impl CipherSuite for Default {
    ///     type Group = curve25519_dalek::ristretto::RistrettoPoint;
    ///     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
    ///     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    ///     type Hash = sha2::Sha256;
    ///     type SlowHash = opaque_ke::slow_hash::NoOpHash;
    /// }
    /// let mut client_rng = OsRng;
    /// let (login_m1, client_login_state) = ClientLogin::<Default>::start(b"hunter2", &mut client_rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        password: &[u8],
        rng: &mut R,
    ) -> Result<(LoginFirstMessage<CS>, Self), ProtocolError> {
        Self::start_with_user_and_server_name(&Vec::new(), &Vec::new(), password, rng)
    }

    /// Same as start, but allows the user to supply a username and server name
    pub fn start_with_user_and_server_name<R: RngCore + CryptoRng>(
        user_name: &[u8],
        server_name: &[u8],
        password: &[u8],
        rng: &mut R,
    ) -> Result<(LoginFirstMessage<CS>, Self), ProtocolError> {
        Self::start_with_user_and_server_name_and_postprocessing(
            user_name,
            server_name,
            password,
            rng,
            std::convert::identity,
        )
    }

    /// Same as start, but allows the user to supply a username and server name and postprocessing function
    pub fn start_with_user_and_server_name_and_postprocessing<R: RngCore + CryptoRng>(
        user_name: &[u8],
        server_name: &[u8],
        password: &[u8],
        rng: &mut R,
        postprocess: fn(<CS::Group as Group>::Scalar) -> <CS::Group as Group>::Scalar,
    ) -> Result<(LoginFirstMessage<CS>, Self), ProtocolError> {
        let (token, alpha) =
            oprf::blind_with_postprocessing::<R, CS::Group>(&password, rng, postprocess)?;

        let (ke1_state, ke1_message) = CS::KeyExchange::generate_ke1(alpha.to_arr().to_vec(), rng)?;

        let l1 = LoginFirstMessage {
            id_u: user_name.to_vec(),
            alpha,
            ke1_message,
        };

        Ok((
            l1,
            Self {
                id_u: user_name.to_vec(),
                id_s: server_name.to_vec(),
                token,
                ke1_state,
            },
        ))
    }

    /// "Unblinds" the server's answer and returns the opened assets from
    /// the server
    ///
    /// # Arguments
    /// * `message` - the server's answer to the initial login attempt
    ///
    /// # Example
    ///
    /// ```
    /// use opaque_ke::opaque::{ClientLogin, ServerLogin};
    /// # use opaque_ke::opaque::{ClientRegistration, ServerRegistration};
    /// # use opaque_ke::errors::ProtocolError;
    /// # use opaque_ke::keypair::{X25519KeyPair, KeyPair};
    /// use rand_core::{OsRng, RngCore};
    /// use opaque_ke::ciphersuite::CipherSuite;
    /// struct Default;
    /// impl CipherSuite for Default {
    ///     type Group = curve25519_dalek::ristretto::RistrettoPoint;
    ///     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
    ///     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    ///     type Hash = sha2::Sha256;
    ///     type SlowHash = opaque_ke::slow_hash::NoOpHash;
    /// }
    /// let mut client_rng = OsRng;
    /// # let mut server_rng = OsRng;
    /// # let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", &mut client_rng)?;
    /// # let server_kp = X25519KeyPair::generate_random(&mut server_rng)?;
    /// # let (register_m2, server_state) = ServerRegistration::<Default>::start(register_m1, &mut server_rng)?;
    /// # let (register_m3, _export_key) = client_state.finish(register_m2, server_kp.public(), &mut client_rng)?;
    /// # let p_file = server_state.finish(register_m3)?;
    /// let (login_m1, client_login_state) = ClientLogin::<Default>::start(b"hunter2", &mut client_rng)?;
    /// let (login_m2, server_login_state) = ServerLogin::start(p_file, &server_kp.private(), login_m1, &mut server_rng)?;
    /// let (login_m3, client_transport, _export_key) = client_login_state.finish(login_m2, &server_kp.public(), &mut client_rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn finish<R: RngCore + CryptoRng>(
        self,
        l2: LoginSecondMessage<CS>,
        _server_s_pk: &<<CS as CipherSuite>::KeyFormat as KeyPair>::Repr,
        _client_e_sk_rng: &mut R,
    ) -> Result<ClientLoginFinishResult<CS>, ProtocolError> {
        let l2_bytes: Vec<u8> = [&l2.beta.to_arr()[..], &l2.envelope.to_bytes()].concat();

        let password_derived_key =
            get_password_derived_key::<CS::Group, CS::SlowHash, CS::Hash>(&self.token, l2.beta)?;

        let opened_envelope = &l2
            .envelope
            .open(&password_derived_key)
            .map_err(|e| match e {
                InternalPakeError::SealOpenHmacError => PakeError::InvalidLoginError,
                err => PakeError::from(err),
            })?;

        let (shared_secret, ke3_message) = CS::KeyExchange::generate_ke3(
            l2_bytes,
            l2.ke2_message,
            &self.ke1_state,
            <CS::KeyFormat as KeyPair>::Repr::from_bytes(
                &opened_envelope.credentials_map[&CredentialType::PkS],
            )?,
            <CS::KeyFormat as KeyPair>::Repr::from_bytes(
                &opened_envelope.credentials_map[&CredentialType::SkU],
            )?,
        )?;

        Ok((
            LoginThirdMessage { ke3_message },
            shared_secret,
            opened_envelope.export_key,
        ))
    }
}

/// The state elements the server holds to record a login
pub struct ServerLogin<CS: CipherSuite> {
    ke2_state: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE2State,
    _cs: PhantomData<CS>,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for ServerLogin<CS> {
    type Error = ProtocolError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            _cs: PhantomData,
            ke2_state:
                <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE2State::try_from(
                    bytes,
                )?,
        })
    }
}

type ServerLoginStartResult<CS> = (LoginSecondMessage<CS>, ServerLogin<CS>);

impl<CS: CipherSuite> ServerLogin<CS> {
    /// byte representation for the server's login state
    pub fn to_bytes(&self) -> Vec<u8> {
        self.ke2_state.to_bytes()
    }

    /// From the client's "blinded"" password, returns a challenge to be
    /// sent back to the client, as well as a ServerLogin
    ///
    /// # Arguments
    /// * `message`   - the initial registration message
    ///
    /// # Example
    ///
    /// ```
    /// use opaque_ke::opaque::{ClientLogin, ServerLogin};
    /// # use opaque_ke::opaque::{ClientRegistration,  ServerRegistration};
    /// # use opaque_ke::errors::ProtocolError;
    /// # use opaque_ke::keypair::{KeyPair, X25519KeyPair};
    /// use rand_core::{OsRng, RngCore};
    /// use opaque_ke::ciphersuite::CipherSuite;
    /// struct Default;
    /// impl CipherSuite for Default {
    ///     type Group = curve25519_dalek::ristretto::RistrettoPoint;
    ///     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
    ///     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    ///     type Hash = sha2::Sha256;
    ///     type SlowHash = opaque_ke::slow_hash::NoOpHash;
    /// }
    /// let mut client_rng = OsRng;
    /// let mut server_rng = OsRng;
    /// let server_kp = X25519KeyPair::generate_random(&mut server_rng)?;
    /// # let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", &mut client_rng)?;
    /// # let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, &mut server_rng)?;
    /// # let (register_m3, _export_key) = client_state.finish(register_m2, server_kp.public(), &mut client_rng)?;
    /// # let p_file = server_state.finish(register_m3)?;
    /// let (login_m1, client_login_state) = ClientLogin::<Default>::start(b"hunter2", &mut client_rng)?;
    /// let (login_m2, server_login_state) = ServerLogin::start(p_file, &server_kp.private(), login_m1, &mut server_rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        password_file: ServerRegistration<CS>,
        server_s_sk: &<CS::KeyFormat as KeyPair>::Repr,
        l1: LoginFirstMessage<CS>,
        rng: &mut R,
    ) -> Result<ServerLoginStartResult<CS>, ProtocolError> {
        let l1_bytes = &l1.to_bytes();
        let beta = oprf::evaluate(l1.alpha, &password_file.oprf_key)?;

        let client_s_pk = password_file
            .client_s_pk
            .ok_or(InternalPakeError::SealError)?;
        let envelope = password_file.envelope.ok_or(InternalPakeError::SealError)?;

        let l2_component: Vec<u8> = [&beta.to_arr()[..], &envelope.to_bytes()].concat();

        let (ke2_state, ke2_message) = CS::KeyExchange::generate_ke2(
            rng,
            l1_bytes.to_vec(),
            l2_component,
            l1.ke1_message,
            client_s_pk,
            server_s_sk.clone(),
        )?;

        let l2 = LoginSecondMessage {
            beta,
            envelope,
            ke2_message,
        };

        Ok((
            l2,
            Self {
                _cs: PhantomData,
                ke2_state,
            },
        ))
    }

    /// From the client's second & final message, check the client's
    /// authentication & produce a message transport
    ///
    /// # Arguments
    /// * `message` - the client's second login message
    ///
    /// # Example
    ///
    /// ```
    /// use opaque_ke::opaque::{ClientLogin, ServerLogin};
    /// # use opaque_ke::opaque::{ClientRegistration,  ServerRegistration};
    /// # use opaque_ke::errors::ProtocolError;
    /// # use opaque_ke::keypair::{KeyPair, X25519KeyPair};
    /// use rand_core::{OsRng, RngCore};
    /// use opaque_ke::ciphersuite::CipherSuite;
    /// struct Default;
    /// impl CipherSuite for Default {
    ///     type Group = curve25519_dalek::ristretto::RistrettoPoint;
    ///     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
    ///     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    ///     type Hash = sha2::Sha256;
    ///     type SlowHash = opaque_ke::slow_hash::NoOpHash;
    /// }
    /// let mut client_rng = OsRng;
    /// let mut server_rng = OsRng;
    /// let server_kp = X25519KeyPair::generate_random(&mut server_rng)?;
    /// # let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", &mut client_rng)?;
    /// # let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, &mut server_rng)?;
    /// # let (register_m3, _export_key) = client_state.finish(register_m2, server_kp.public(), &mut client_rng)?;
    /// # let p_file = server_state.finish(register_m3)?;
    /// let (login_m1, client_login_state) = ClientLogin::<Default>::start(b"hunter2", &mut client_rng)?;
    /// let (login_m2, server_login_state) = ServerLogin::start(p_file, &server_kp.private(), login_m1, &mut server_rng)?;
    /// let (login_m3, client_transport, _export_key) = client_login_state.finish(login_m2, &server_kp.public(), &mut client_rng)?;
    /// let mut server_transport = server_login_state.finish(login_m3)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn finish(&self, message: LoginThirdMessage<CS>) -> Result<Vec<u8>, ProtocolError> {
        <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::finish_ke(
            message.ke3_message,
            &self.ke2_state,
        )
        .map_err(|e| match e {
            ProtocolError::VerificationError(PakeError::KeyExchangeMacValidationError) => {
                ProtocolError::VerificationError(PakeError::InvalidLoginError)
            }
            err => err,
        })
    }
}

// Helper functions
fn get_password_derived_key<G: Group, SH: SlowHash<D>, D: Hash>(
    token: &oprf::Token<G>,
    beta: G,
) -> Result<Vec<u8>, InternalPakeError> {
    let oprf_output = oprf::unblind_and_finalize::<G, D>(token, beta)?;
    SH::hash(oprf_output)
}

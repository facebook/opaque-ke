// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Provides the main OPAQUE API

use crate::{
    ciphersuite::CipherSuite,
    envelope::{Envelope, ExportKeySize},
    errors::{utils::check_slice_size, InternalPakeError, PakeError, ProtocolError},
    group::Group,
    hash::Hash,
    key_exchange::traits::{KeyExchange, ToBytes},
    keypair::{Key, KeyPair, SizedBytes},
    oprf,
    oprf::OprfClientBytes,
    serialization::{serialize, tokenize},
    slow_hash::SlowHash,
};
use generic_array::{typenum::Unsigned, GenericArray};
use rand_core::{CryptoRng, RngCore};
use std::{convert::TryFrom, marker::PhantomData};
use zeroize::Zeroize;

const REGISTRATION_REQUEST: u8 = 0x01;
const REGISTRATION_RESPONSE: u8 = 0x02;
const REGISTRATION_UPLOAD: u8 = 0x03;
const CREDENTIAL_REQUEST: u8 = 0x04;
const CREDENTIAL_RESPONSE: u8 = 0x05;

const CREDENTIAL_TYPE_SKU: u8 = 0x01;
const CREDENTIAL_TYPE_PKS: u8 = 0x03;

// Messages
// =========

/// The message sent by the client to the server, to initiate registration
pub struct RegisterFirstMessage<Grp> {
    /// blinded password information
    alpha: Grp,
}

impl<Grp: Group> TryFrom<&[u8]> for RegisterFirstMessage<Grp> {
    type Error = ProtocolError;
    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        // Check that the message is actually containing an element of the
        // correct subgroup
        let arr = GenericArray::from_slice(&input);
        let alpha = Grp::from_element_slice(arr)?;
        Ok(Self { alpha })
    }
}

impl<Grp: Group> RegisterFirstMessage<Grp> {
    /// byte representation for the registration request
    fn to_bytes(&self) -> GenericArray<u8, Grp::ElemLen> {
        self.alpha.to_arr()
    }
}

impl<Grp: Group> RegisterFirstMessage<Grp> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut registration_request: Vec<u8> = Vec::new();
        registration_request.extend_from_slice(&serialize(Vec::new(), 2));
        registration_request.extend_from_slice(&serialize((&self.to_bytes()).to_vec(), 2));

        let mut output: Vec<u8> = Vec::new();
        output.push(REGISTRATION_REQUEST);
        output.extend_from_slice(&serialize(registration_request, 3));
        output
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        if input[0] != REGISTRATION_REQUEST {
            return Err(PakeError::SerializationError.into());
        }

        let (data, remainder) = tokenize(input[1..].to_vec(), 3)?;
        if !remainder.is_empty() {
            return Err(PakeError::SerializationError.into());
        }

        let (_, remainder) = tokenize(data, 2)?;
        let (alpha_bytes, remainder) = tokenize(remainder, 2)?;

        if !remainder.is_empty() {
            return Err(PakeError::SerializationError.into());
        }

        Self::try_from(&alpha_bytes[..])
    }
}

/// The answer sent by the server to the user, upon reception of the
/// registration attempt
pub struct RegisterSecondMessage<Grp> {
    /// The server's oprf output
    beta: Grp,
}

impl<Grp> TryFrom<&[u8]> for RegisterSecondMessage<Grp>
where
    Grp: Group,
{
    type Error = ProtocolError;

    fn try_from(second_message_bytes: &[u8]) -> Result<Self, Self::Error> {
        let checked_slice = check_slice_size(
            second_message_bytes,
            Grp::ElemLen::to_usize(),
            "second_message_bytes",
        )?;
        // Check that the message is actually containing an element of the
        // correct subgroup
        let arr = GenericArray::from_slice(&checked_slice);
        let beta = Grp::from_element_slice(arr)?;
        Ok(Self { beta })
    }
}

impl<Grp> RegisterSecondMessage<Grp>
where
    Grp: Group,
{
    /// byte representation for the registration response message
    fn to_bytes(&self) -> Vec<u8> {
        self.beta.to_arr().to_vec()
    }

    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut registration_response: Vec<u8> = Vec::new();
        registration_response.extend_from_slice(&serialize((&self.to_bytes()).to_vec(), 2));
        registration_response.extend_from_slice(&serialize(Vec::new(), 2));

        // TODO: The following should not be hardcoded, but instead be customizable
        registration_response.extend_from_slice(&serialize(vec![CREDENTIAL_TYPE_SKU], 1));
        registration_response.extend_from_slice(&serialize(vec![CREDENTIAL_TYPE_PKS], 1));

        let mut output: Vec<u8> = Vec::new();
        output.push(REGISTRATION_RESPONSE);
        output.extend_from_slice(&serialize(registration_response, 3));
        output
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        if input[0] != REGISTRATION_RESPONSE {
            return Err(PakeError::SerializationError.into());
        }

        let (data, remainder) = tokenize(input[1..].to_vec(), 3)?;
        if !remainder.is_empty() {
            return Err(PakeError::SerializationError.into());
        }

        let (beta_bytes, remainder) = tokenize(data, 2)?;
        let (_, remainder) = tokenize(remainder, 2)?;

        // TODO: The following should affect what is placed in the envelope rather than
        // being ignored
        let (_, remainder) = tokenize(remainder, 1)?;
        let (_, remainder) = tokenize(remainder, 1)?;

        if !remainder.is_empty() {
            return Err(PakeError::SerializationError.into());
        }

        Self::try_from(&beta_bytes[..])
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
        registration_upload.extend_from_slice(&serialize(self.client_s_pk.to_arr().to_vec(), 2));

        let mut output: Vec<u8> = Vec::new();
        output.push(REGISTRATION_UPLOAD);
        output.extend_from_slice(&serialize(registration_upload, 3));
        output
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        if input[0] != REGISTRATION_UPLOAD {
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
    /// blinded password information
    alpha: CS::Group,
    ke1_message: <CS::KeyExchange as KeyExchange<CS::Hash>>::KE1Message,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for LoginFirstMessage<CS> {
    type Error = ProtocolError;
    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        // Check that the message is actually containing an element of the
        // correct subgroup
        let elem_len = <CS::Group as Group>::ElemLen::to_usize();
        let arr = GenericArray::from_slice(&input[..elem_len]);
        let alpha = CS::Group::from_element_slice(arr)?;

        let ke1_message = <CS::KeyExchange as KeyExchange<CS::Hash>>::KE1Message::try_from(
            input[elem_len..].to_vec(),
        )?;
        Ok(Self { alpha, ke1_message })
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
        credential_request.extend_from_slice(&serialize(Vec::new(), 2));
        credential_request.extend_from_slice(&serialize((&self.alpha.to_arr()).to_vec(), 2));

        let mut output: Vec<u8> = Vec::new();
        output.push(CREDENTIAL_REQUEST);
        output.extend_from_slice(&serialize(credential_request, 3));
        output.extend_from_slice(&self.ke1_message.to_bytes());
        output
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        if input[0] != CREDENTIAL_REQUEST {
            return Err(PakeError::SerializationError.into());
        }

        let (data, ke1m) = tokenize(input[1..].to_vec(), 3)?;

        let (_, remainder) = tokenize(data, 2)?;
        let (alpha_bytes, remainder) = tokenize(remainder, 2)?;

        if !remainder.is_empty() {
            return Err(PakeError::SerializationError.into());
        }

        let concatenated = [&alpha_bytes[..], &ke1m[..]].concat();
        Self::try_from(&concatenated[..])
    }
}

/// The answer sent by the server to the user, upon reception of the
/// login attempt.
pub struct LoginSecondMessage<Grp, KeyFormat, KE, D>
where
    KeyFormat: KeyPair,
    KE: KeyExchange<D>,
    D: Hash,
{
    _key_format: PhantomData<KeyFormat>,
    _key_exchange: PhantomData<KE>,
    /// the server's oprf output
    beta: Grp,
    /// the user's sealed information,
    envelope: Envelope<D>,
    ke2_message: KE::KE2Message,
}

impl<Grp, KeyFormat, KE, D> LoginSecondMessage<Grp, KeyFormat, KE, D>
where
    Grp: Group,
    KeyFormat: KeyPair,
    KE: KeyExchange<D>,
    D: Hash,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut credential_response: Vec<u8> = Vec::new();
        credential_response.extend_from_slice(&serialize((&self.beta.to_arr()).to_vec(), 2));
        credential_response.extend_from_slice(&serialize((&self.envelope.to_bytes()).to_vec(), 2));
        credential_response.extend_from_slice(&serialize(Vec::new(), 2));

        let mut output: Vec<u8> = Vec::new();
        output.push(CREDENTIAL_RESPONSE);
        output.extend_from_slice(&serialize(credential_response, 3));
        output.extend_from_slice(&self.ke2_message.to_bytes());
        output
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        if input[0] != CREDENTIAL_RESPONSE {
            return Err(PakeError::SerializationError.into());
        }

        let (data, ke2m) = tokenize(input[1..].to_vec(), 3)?;

        let (beta_bytes, remainder) = tokenize(data, 2)?;
        let (envelope_bytes, remainder) = tokenize(remainder, 2)?;
        let (_, remainder) = tokenize(remainder, 2)?;

        if !remainder.is_empty() {
            return Err(PakeError::SerializationError.into());
        }

        let concatenated = [&beta_bytes[..], &envelope_bytes[..], &ke2m[..]].concat();
        Self::try_from(&concatenated[..])
    }
}

impl<Grp, KeyFormat, KE, D> TryFrom<&[u8]> for LoginSecondMessage<Grp, KeyFormat, KE, D>
where
    Grp: Group,
    KeyFormat: KeyPair,
    KE: KeyExchange<D>,
    D: Hash,
{
    type Error = ProtocolError;
    fn try_from(second_message_bytes: &[u8]) -> Result<Self, Self::Error> {
        let key_len = <KeyFormat::Repr as SizedBytes>::Len::to_usize();
        let envelope_size = key_len + Envelope::<D>::additional_size();
        let elem_len = Grp::ElemLen::to_usize();
        let ke2_message_size = KE::ke2_message_size();
        let checked_slice = check_slice_size(
            second_message_bytes,
            elem_len + envelope_size + ke2_message_size,
            "login_second_message_bytes",
        )?;

        // Check that the message is actually containing an element of the
        // correct subgroup
        let beta_bytes = &checked_slice[..elem_len];
        let arr = GenericArray::from_slice(beta_bytes);
        let beta = Grp::from_element_slice(arr)?;

        let envelope =
            Envelope::<D>::from_bytes(&checked_slice[elem_len..elem_len + envelope_size])?;

        let ke2_message =
            KE::KE2Message::try_from(checked_slice[elem_len + envelope_size..].to_vec())?;

        Ok(Self {
            _key_format: PhantomData,
            _key_exchange: PhantomData,
            beta,
            envelope,
            ke2_message,
        })
    }
}

/// The answer sent by the client to the server, upon reception of the
/// sealed envelope
pub struct LoginThirdMessage<CS: CipherSuite> {
    ke3_message: <CS::KeyExchange as KeyExchange<CS::Hash>>::KE3Message,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for LoginThirdMessage<CS> {
    type Error = ProtocolError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let ke3_message =
            <CS::KeyExchange as KeyExchange<CS::Hash>>::KE3Message::try_from(bytes.to_vec())?;
        Ok(Self { ke3_message })
    }
}

impl<CS: CipherSuite> LoginThirdMessage<CS> {
    /// byte representation for the login finalization
    pub fn to_bytes(&self) -> Vec<u8> {
        self.ke3_message.to_bytes()
    }
}

// Registration
// ============

/// The state elements the client holds to register itself
pub struct ClientRegistration<CS: CipherSuite> {
    /// a blinding factor
    pub(crate) blinding_factor: <CS::Group as Group>::Scalar,
    /// the client's password
    password: Vec<u8>,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for ClientRegistration<CS> {
    type Error = ProtocolError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // Check that the message is actually containing an element of the
        // correct subgroup
        let scalar_len = <CS::Group as Group>::ScalarLen::to_usize();
        let blinding_factor_bytes = GenericArray::from_slice(&bytes[..scalar_len]);
        let blinding_factor = CS::Group::from_scalar_slice(blinding_factor_bytes)?;
        let password = bytes[scalar_len..].to_vec();
        Ok(Self {
            blinding_factor,
            password,
        })
    }
}

impl<CS: CipherSuite> ClientRegistration<CS> {
    /// byte representation for the client's registration state
    pub fn to_bytes(&self) -> Vec<u8> {
        let output: Vec<u8> = [
            &CS::Group::scalar_as_bytes(&self.blinding_factor)[..],
            &self.password,
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
    /// let (register_m1, registration_state) = ClientRegistration::<Default>::start(b"hunter2", None, &mut rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        password: &[u8],
        pepper: Option<&[u8]>,
        blinding_factor_rng: &mut R,
    ) -> Result<(RegisterFirstMessage<CS::Group>, Self), ProtocolError> {
        let OprfClientBytes {
            alpha,
            blinding_factor,
        } = oprf::generate_oprf1::<R, CS::Group>(&password, pepper, blinding_factor_rng)?;

        Ok((
            RegisterFirstMessage::<CS::Group> { alpha },
            Self {
                blinding_factor,
                password: password.to_vec(),
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
    /// let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", None, &mut client_rng)?;
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
        let client_static_keypair = CS::KeyFormat::generate_random(rng)?;

        let password_derived_key = get_password_derived_key::<CS::Group, CS::SlowHash, CS::Hash>(
            self.password.clone(),
            r2.beta,
            &self.blinding_factor,
        )?;

        let (envelope, export_key) = Envelope::<CS::Hash>::seal(
            &password_derived_key,
            &client_static_keypair.private().to_arr(),
            &server_s_pk.to_arr(),
            rng,
        )?;

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
        self.password.zeroize();
        self.blinding_factor.zeroize();
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
        self.password.zeroize();
        self.blinding_factor.zeroize();
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
    fn try_from(server_registration_bytes: &[u8]) -> Result<Self, Self::Error> {
        let key_len = <<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len::to_usize();
        let scalar_len = <CS::Group as Group>::ScalarLen::to_usize();
        let envelope_size = key_len + Envelope::<CS::Hash>::additional_size();

        if server_registration_bytes.len() == scalar_len {
            return Ok(Self {
                oprf_key: CS::Group::from_scalar_slice(GenericArray::from_slice(
                    server_registration_bytes,
                ))?,
                client_s_pk: None,
                envelope: None,
            });
        }

        let checked_bytes = check_slice_size(
            server_registration_bytes,
            envelope_size + key_len + scalar_len,
            "server_registration_bytes",
        )?;
        let oprf_key_bytes = GenericArray::from_slice(&checked_bytes[..scalar_len]);
        let oprf_key = CS::Group::from_scalar_slice(oprf_key_bytes)?;
        let unchecked_client_s_pk = <CS::KeyFormat as KeyPair>::Repr::from_bytes(
            &checked_bytes[scalar_len..scalar_len + key_len],
        )?;
        let client_s_pk = CS::KeyFormat::check_public_key(unchecked_client_s_pk)?;
        Ok(Self {
            envelope: Some(Envelope::<CS::Hash>::from_bytes(
                &checked_bytes[checked_bytes.len() - envelope_size..],
            )?),
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
        match &self.client_s_pk {
            Some(v) => output.extend_from_slice(&v.to_arr()),
            None => {}
        };
        match &self.envelope {
            Some(v) => output.extend_from_slice(&v.to_bytes()),
            None => {}
        };
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
    /// let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", None, &mut client_rng)?;
    /// let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, &mut server_rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        message: RegisterFirstMessage<CS::Group>,
        rng: &mut R,
    ) -> Result<(RegisterSecondMessage<CS::Group>, Self), ProtocolError> {
        // RFC: generate oprf_key (salt) and v_u = g^oprf_key
        let oprf_key = CS::Group::random_scalar(rng);

        // Compute beta = alpha^oprf_key
        let beta = oprf::generate_oprf2::<CS::Group>(message.alpha, &oprf_key)?;

        Ok((
            RegisterSecondMessage { beta },
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
    /// let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", None, &mut client_rng)?;
    /// let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, &mut server_rng)?;
    /// let mut client_rng = OsRng;
    /// let (register_m3, _opaque_key) = client_state.finish(register_m2, server_kp.public(), &mut client_rng)?;
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
    /// A choice of the keypair type
    _key_format: PhantomData<CS::KeyFormat>,
    /// A blinding factor, which is used to mask (and unmask) secret
    /// information before transmission
    blinding_factor: <CS::Group as Group>::Scalar,
    /// The user's password
    password: Vec<u8>,
    ke1_state: <CS::KeyExchange as KeyExchange<CS::Hash>>::KE1State,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for ClientLogin<CS> {
    type Error = ProtocolError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let scalar_len = <CS::Group as Group>::ScalarLen::to_usize();
        let blinding_factor_bytes = GenericArray::from_slice(&bytes[..scalar_len]);
        let blinding_factor = CS::Group::from_scalar_slice(blinding_factor_bytes)?;
        let ke1_state_size = <CS::KeyExchange as KeyExchange<CS::Hash>>::ke1_state_size();
        let ke1_state = <CS::KeyExchange as KeyExchange<CS::Hash>>::KE1State::try_from(
            bytes[scalar_len..scalar_len + ke1_state_size].to_vec(),
        )?;
        let password = bytes[scalar_len + ke1_state_size..].to_vec();
        Ok(Self {
            _key_format: PhantomData,
            blinding_factor,
            password,
            ke1_state,
        })
    }
}

impl<CS: CipherSuite> ClientLogin<CS> {
    /// byte representation for the client's login state
    pub fn to_bytes(&self) -> Vec<u8> {
        let output: Vec<u8> = [
            &CS::Group::scalar_as_bytes(&self.blinding_factor)[..],
            &self.ke1_state.to_bytes(),
            &self.password,
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
    /// let (login_m1, client_login_state) = ClientLogin::<Default>::start(b"hunter2", None, &mut client_rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        password: &[u8],
        pepper: Option<&[u8]>,
        rng: &mut R,
    ) -> Result<(LoginFirstMessage<CS>, Self), ProtocolError> {
        let OprfClientBytes {
            alpha,
            blinding_factor,
        } = oprf::generate_oprf1::<R, CS::Group>(&password, pepper, rng)?;

        let (ke1_state, ke1_message) =
            CS::KeyExchange::generate_ke1::<_, CS::KeyFormat>(alpha.to_arr().to_vec(), rng)?;

        let l1 = LoginFirstMessage { alpha, ke1_message };

        Ok((
            l1,
            Self {
                _key_format: PhantomData,
                blinding_factor,
                password: password.to_vec(),
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
    /// # let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", None, &mut client_rng)?;
    /// # let server_kp = X25519KeyPair::generate_random(&mut server_rng)?;
    /// # let (register_m2, server_state) = ServerRegistration::<Default>::start(register_m1, &mut server_rng)?;
    /// # let (register_m3, _opaque_key) = client_state.finish(register_m2, server_kp.public(), &mut client_rng)?;
    /// # let p_file = server_state.finish(register_m3)?;
    /// let (login_m1, client_login_state) = ClientLogin::<Default>::start(b"hunter2", None, &mut client_rng)?;
    /// let (login_m2, server_login_state) = ServerLogin::start(p_file, &server_kp.private(), login_m1, &mut server_rng)?;
    /// let (login_m3, client_transport, _opaque_key) = client_login_state.finish(login_m2, &server_kp.public(), &mut client_rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn finish<R: RngCore + CryptoRng>(
        self,
        l2: LoginSecondMessage<CS::Group, CS::KeyFormat, CS::KeyExchange, CS::Hash>,
        server_s_pk: &<<CS as CipherSuite>::KeyFormat as KeyPair>::Repr,
        _client_e_sk_rng: &mut R,
    ) -> Result<ClientLoginFinishResult<CS>, ProtocolError> {
        let l2_bytes: Vec<u8> = [&l2.beta.to_arr()[..], &l2.envelope.to_bytes()].concat();

        let password_derived_key = get_password_derived_key::<CS::Group, CS::SlowHash, CS::Hash>(
            self.password.clone(),
            l2.beta,
            &self.blinding_factor,
        )?;

        let opened_envelope = &l2
            .envelope
            .open(&password_derived_key, &server_s_pk.to_arr())
            .map_err(|e| match e {
                InternalPakeError::SealOpenHmacError => PakeError::InvalidLoginError,
                err => PakeError::from(err),
            })?;

        let (shared_secret, ke3_message) = CS::KeyExchange::generate_ke3::<CS::KeyFormat>(
            l2_bytes,
            l2.ke2_message,
            &self.ke1_state,
            server_s_pk.clone(),
            Key::from_bytes(&opened_envelope.plaintext)?,
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
    ke2_state: <CS::KeyExchange as KeyExchange<CS::Hash>>::KE2State,
    _cs: PhantomData<CS>,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for ServerLogin<CS> {
    type Error = ProtocolError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            _cs: PhantomData,
            ke2_state: <CS::KeyExchange as KeyExchange<CS::Hash>>::KE2State::try_from(
                bytes.to_vec(),
            )?,
        })
    }
}

type ServerLoginStartResult<CS> = (
    LoginSecondMessage<
        <CS as CipherSuite>::Group,
        <CS as CipherSuite>::KeyFormat,
        <CS as CipherSuite>::KeyExchange,
        <CS as CipherSuite>::Hash,
    >,
    ServerLogin<CS>,
);

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
    /// # let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", None, &mut client_rng)?;
    /// # let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, &mut server_rng)?;
    /// # let (register_m3, _opaque_key) = client_state.finish(register_m2, server_kp.public(), &mut client_rng)?;
    /// # let p_file = server_state.finish(register_m3)?;
    /// let (login_m1, client_login_state) = ClientLogin::<Default>::start(b"hunter2", None, &mut client_rng)?;
    /// let (login_m2, server_login_state) = ServerLogin::start(p_file, &server_kp.private(), login_m1, &mut server_rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        password_file: ServerRegistration<CS>,
        server_s_sk: &Key,
        l1: LoginFirstMessage<CS>,
        rng: &mut R,
    ) -> Result<ServerLoginStartResult<CS>, ProtocolError> {
        let l1_bytes = &l1.to_bytes();
        let beta = oprf::generate_oprf2(l1.alpha, &password_file.oprf_key)?;

        let client_s_pk = password_file
            .client_s_pk
            .ok_or(InternalPakeError::SealError)?;
        let envelope = password_file.envelope.ok_or(InternalPakeError::SealError)?;

        let l2_component: Vec<u8> = [&beta.to_arr()[..], &envelope.to_bytes()].concat();

        let (ke2_state, ke2_message) = CS::KeyExchange::generate_ke2::<_, CS::KeyFormat>(
            rng,
            l1_bytes.to_vec(),
            l2_component,
            l1.ke1_message,
            client_s_pk,
            server_s_sk.clone(),
        )?;

        let l2 = LoginSecondMessage {
            _key_format: PhantomData,
            _key_exchange: PhantomData,
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
    /// # let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", None, &mut client_rng)?;
    /// # let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, &mut server_rng)?;
    /// # let (register_m3, _opaque_key) = client_state.finish(register_m2, server_kp.public(), &mut client_rng)?;
    /// # let p_file = server_state.finish(register_m3)?;
    /// let (login_m1, client_login_state) = ClientLogin::<Default>::start(b"hunter2", None, &mut client_rng)?;
    /// let (login_m2, server_login_state) = ServerLogin::start(p_file, &server_kp.private(), login_m1, &mut server_rng)?;
    /// let (login_m3, client_transport, _opaque_key) = client_login_state.finish(login_m2, &server_kp.public(), &mut client_rng)?;
    /// let mut server_transport = server_login_state.finish(login_m3)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn finish(&self, message: LoginThirdMessage<CS>) -> Result<Vec<u8>, ProtocolError> {
        <CS::KeyExchange as KeyExchange<CS::Hash>>::finish_ke(message.ke3_message, &self.ke2_state)
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
    password: Vec<u8>,
    beta: G,
    blinding_factor: &G::Scalar,
) -> Result<Vec<u8>, InternalPakeError> {
    let oprf_output = oprf::generate_oprf3::<G, D>(&password, beta, blinding_factor)?;
    SH::hash(oprf_output)
}

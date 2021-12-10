// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Provides the main OPAQUE API

use crate::{
    ciphersuite::CipherSuite,
    envelope::Envelope,
    errors::{utils::check_slice_size, InternalError, ProtocolError},
    hash::Hash,
    key_exchange::{
        group::KeGroup,
        traits::{FromBytes, KeyExchange, ToBytes},
        tripledh::NonceLen,
    },
    keypair::{KeyPair, PrivateKey, PublicKey, SecretKey},
    serialization::{serialize, tokenize},
    slow_hash::SlowHash,
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    RegistrationResponse, RegistrationUpload,
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::{Add, Shl};
use derive_where::DeriveWhere;
use digest::{Digest, FixedOutput};
use generic_array::{
    typenum::{Double, Sum, Unsigned, B1},
    ArrayLength, GenericArray,
};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use voprf::group::Group;

///////////////
// Constants //
// ========= //
///////////////

const STR_CREDENTIAL_RESPONSE_PAD: &[u8; 21] = b"CredentialResponsePad";
const STR_MASKING_KEY: &[u8; 10] = b"MaskingKey";
const STR_OPRF_KEY: &[u8; 7] = b"OprfKey";
const STR_OPAQUE_DERIVE_KEY_PAIR: &[u8; 20] = b"OPAQUE-DeriveKeyPair";

////////////////////////////
// High-level API Structs //
// ====================== //
////////////////////////////

/// The state elements the server holds upon setup
#[cfg_attr(
    feature = "serialize",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "KeyPair<CS::KeGroup, S>: serde::Deserialize<'de>",
        serialize = "KeyPair<CS::KeGroup, S>: serde::Serialize"
    ))
)]
#[derive(DeriveWhere)]
#[derive_where(Clone)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; S)]
pub struct ServerSetup<
    CS: CipherSuite,
    S: SecretKey<CS::KeGroup> = PrivateKey<<CS as CipherSuite>::KeGroup>,
> {
    oprf_seed: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
    keypair: KeyPair<CS::KeGroup, S>,
    pub(crate) fake_keypair: KeyPair<CS::KeGroup>,
}

/// The state elements the client holds to register itself
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(
    Debug, Eq, Hash, PartialEq;
    voprf::NonVerifiableClient<CS::OprfGroup, CS::Hash>,
    voprf::BlindedElement<CS::OprfGroup, CS::Hash>,
)]
pub struct ClientRegistration<CS: CipherSuite> {
    pub(crate) oprf_client: voprf::NonVerifiableClient<CS::OprfGroup, CS::Hash>,
    pub(crate) blinded_element: voprf::BlindedElement<CS::OprfGroup, CS::Hash>,
}

impl_serialize_and_deserialize_for!(ClientRegistration);

/// The state elements the server holds to record a registration
#[derive(DeriveWhere)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Zeroize(drop))]
pub struct ServerRegistration<CS: CipherSuite>(RegistrationUpload<CS>);

impl_serialize_and_deserialize_for!(ServerRegistration);

/// The state elements the client holds to perform a login
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(
    Debug, Eq, Hash, PartialEq;
    voprf::NonVerifiableClient<CS::OprfGroup, CS::Hash>,
    <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1State,
)]
pub struct ClientLogin<CS: CipherSuite> {
    oprf_client: voprf::NonVerifiableClient<CS::OprfGroup, CS::Hash>,
    ke1_state: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1State,
    serialized_credential_request: Vec<u8>,
}

impl_serialize_and_deserialize_for!(ClientLogin);

/// The state elements the server holds to record a login
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(
    Debug, Eq, Hash, PartialEq;
    <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE2State,
)]
pub struct ServerLogin<CS: CipherSuite> {
    ke2_state: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE2State,
    #[derive_where(skip(Zeroize))]
    _cs: PhantomData<CS>,
}

impl_serialize_and_deserialize_for!(ServerLogin);

////////////////////////////////
// High-level Implementations //
// ========================== //
////////////////////////////////

// Server Setup
// ============

impl<CS: CipherSuite> ServerSetup<CS, PrivateKey<CS::KeGroup>> {
    /// Generate a new instance of server setup
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let keypair = KeyPair::generate_random(rng);
        Self::new_with_key(rng, keypair)
    }
}

impl<CS: CipherSuite, S: SecretKey<CS::KeGroup>> ServerSetup<CS, S> {
    /// Create [`ServerSetup`] with the given keypair
    pub fn new_with_key<R: CryptoRng + RngCore>(
        rng: &mut R,
        keypair: KeyPair<CS::KeGroup, S>,
    ) -> Self {
        let mut oprf_seed = GenericArray::default();
        rng.fill_bytes(&mut oprf_seed);

        Self {
            oprf_seed,
            keypair,
            fake_keypair: KeyPair::<CS::KeGroup>::generate_random(rng),
        }
    }

    /// Serialization into bytes
    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        Ok([
            self.oprf_seed.to_vec(),
            self.keypair.private().serialize(),
            self.fake_keypair.private().serialize(),
        ]
        .concat())
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError<S::Error>> {
        let seed_len = <CS::Hash as Digest>::OutputSize::USIZE;
        let key_len = <CS::KeGroup as KeGroup>::SkLen::USIZE;
        let checked_slice = check_slice_size(input, seed_len + key_len + key_len, "server_setup")?;

        Ok(Self {
            oprf_seed: GenericArray::clone_from_slice(&checked_slice[..seed_len]),
            keypair: KeyPair::from_private_key_slice(&checked_slice[seed_len..seed_len + key_len])?,
            fake_keypair: KeyPair::from_private_key_slice(&checked_slice[seed_len + key_len..])
                .map_err(ProtocolError::into_custom)?,
        })
    }

    /// Returns the keypair
    pub fn keypair(&self) -> &KeyPair<CS::KeGroup, S> {
        &self.keypair
    }
}

// Registration
// ============

impl<CS: CipherSuite> ClientRegistration<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        Ok([
            serialize(&self.oprf_client.serialize(), 2)?,
            serialize(&self.blinded_element.serialize(), 2)?,
        ]
        .concat())
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let (serialized_oprf_client, remainder) = tokenize(input, 2)?;
        let (serialized_blinded_element, remainder) = tokenize(&remainder, 2)?;

        if !remainder.is_empty() {
            return Err(ProtocolError::SerializationError);
        }

        Ok(Self {
            oprf_client: voprf::NonVerifiableClient::deserialize(&serialized_oprf_client)?,
            blinded_element: voprf::BlindedElement::deserialize(&serialized_blinded_element)?,
        })
    }

    /// Only used for testing zeroize
    #[cfg(test)]
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        [
            self.oprf_client.serialize(),
            self.blinded_element.serialize(),
        ]
        .concat()
    }

    /// Returns an initial "blinded" request to send to the server, as well as a ClientRegistration
    pub fn start<R: RngCore + CryptoRng>(
        blinding_factor_rng: &mut R,
        password: &[u8],
    ) -> Result<ClientRegistrationStartResult<CS>, ProtocolError> {
        let blind_result = blind::<CS, _>(blinding_factor_rng, password)?;

        Ok(ClientRegistrationStartResult {
            message: RegistrationRequest {
                blinded_element: blind_result.message.clone(),
            },
            state: Self {
                oprf_client: blind_result.state,
                blinded_element: blind_result.message,
            },
        })
    }

    /// "Unblinds" the server's answer and returns a final message containing
    /// cryptographic identifiers, to be sent to the server on setup finalization
    pub fn finish<R: CryptoRng + RngCore>(
        self,
        rng: &mut R,
        registration_response: RegistrationResponse<CS>,
        params: ClientRegistrationFinishParameters<CS>,
    ) -> Result<ClientRegistrationFinishResult<CS>, ProtocolError>
    where
        <CS::Hash as FixedOutput>::OutputSize: Shl<B1>,
        Double<<CS::Hash as FixedOutput>::OutputSize>: ArrayLength<u8>,
    {
        // Check for reflected value from server and halt if detected
        if self
            .blinded_element
            .value()
            .ct_eq(&registration_response.evaluation_element.value())
            .into()
        {
            return Err(ProtocolError::ReflectedValueError);
        }

        #[cfg_attr(not(test), allow(unused_variables))]
        let (randomized_pwd, randomized_pwd_hasher) = get_password_derived_key::<CS>(
            self.oprf_client.clone(),
            registration_response.evaluation_element,
            params.slow_hash,
        )?;

        let mut masking_key = GenericArray::<_, <CS::Hash as Digest>::OutputSize>::default();
        randomized_pwd_hasher
            .expand(STR_MASKING_KEY, &mut masking_key)
            .map_err(|_| InternalError::HkdfError)?;

        let result = Envelope::<CS>::seal(
            rng,
            randomized_pwd_hasher,
            &registration_response.server_s_pk,
            params.identifiers,
        )?;

        Ok(ClientRegistrationFinishResult {
            message: RegistrationUpload {
                envelope: result.0,
                masking_key,
                client_s_pk: result.1,
            },
            export_key: result.2,
            server_s_pk: registration_response.server_s_pk,
            #[cfg(test)]
            state: self,
            #[cfg(test)]
            auth_key: result.3,
            #[cfg(test)]
            randomized_pwd,
        })
    }
}

impl<CS: CipherSuite> ServerRegistration<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        self.0.serialize()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self(RegistrationUpload::deserialize(input)?))
    }

    /// From the client's "blinded" password, returns a response to be
    /// sent back to the client, as well as a ServerRegistration
    pub fn start<S: SecretKey<CS::KeGroup>>(
        server_setup: &ServerSetup<CS, S>,
        message: RegistrationRequest<CS>,
        credential_identifier: &[u8],
    ) -> Result<ServerRegistrationStartResult<CS>, ProtocolError> {
        let oprf_key = oprf_key_from_seed::<CS::OprfGroup, CS::Hash>(
            &server_setup.oprf_seed,
            credential_identifier,
        )?;

        let server = voprf::NonVerifiableServer::new_with_key(&oprf_key)?;
        let evaluate_result = server.evaluate(message.blinded_element, None)?;

        Ok(ServerRegistrationStartResult {
            message: RegistrationResponse {
                evaluation_element: evaluate_result.message,
                server_s_pk: server_setup.keypair.public().clone(),
            },
            #[cfg(test)]
            oprf_key,
        })
    }

    /// From the client's cryptographic identifiers, fully populates and
    /// returns a ServerRegistration
    pub fn finish(message: RegistrationUpload<CS>) -> Self {
        Self(message)
    }

    // Creates a dummy instance used for faking a [CredentialResponse]
    pub(crate) fn dummy<R: RngCore + CryptoRng, S: SecretKey<CS::KeGroup>>(
        rng: &mut R,
        server_setup: &ServerSetup<CS, S>,
    ) -> Self {
        Self(RegistrationUpload::dummy(rng, server_setup))
    }
}

// Login
// =====

impl<CS: CipherSuite> ClientLogin<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        let output: Vec<u8> = [
            serialize(&self.oprf_client.serialize(), 2)?,
            serialize(&self.serialized_credential_request, 2)?,
            serialize(&self.ke1_state.to_bytes(), 2)?,
        ]
        .concat();
        Ok(output)
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let (serialized_oprf_client, remainder) = tokenize(input, 2)?;
        let (serialized_credential_request, remainder) = tokenize(&remainder, 2)?;
        let (ke1_state_bytes, remainder) = tokenize(&remainder, 2)?;

        if !remainder.is_empty() {
            return Err(ProtocolError::SerializationError);
        }

        let ke1_state =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1State::from_bytes::<CS>(
                &ke1_state_bytes,
            )?;
        Ok(Self {
            oprf_client: voprf::NonVerifiableClient::deserialize(&serialized_oprf_client)?,
            ke1_state,
            serialized_credential_request,
        })
    }

    /// Only used for testing zeroize
    #[cfg(test)]
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        [
            self.oprf_client.serialize(),
            self.serialized_credential_request.clone(),
            self.ke1_state.to_bytes(),
        ]
        .concat()
    }
}

impl<CS: CipherSuite> ClientLogin<CS> {
    /// Returns an initial "blinded" password request to send to the server, as well as a ClientLogin
    pub fn start<R: RngCore + CryptoRng>(
        rng: &mut R,
        password: &[u8],
    ) -> Result<ClientLoginStartResult<CS>, ProtocolError> {
        let blind_result = blind::<CS, _>(rng, password)?;
        let (ke1_state, ke1_message) = CS::KeyExchange::generate_ke1(rng)?;

        let credential_request = CredentialRequest {
            blinded_element: blind_result.message,
            ke1_message,
        };
        let serialized_credential_request = credential_request.serialize()?;

        Ok(ClientLoginStartResult {
            message: credential_request,
            state: Self {
                oprf_client: blind_result.state,
                ke1_state,
                serialized_credential_request,
            },
        })
    }

    /// "Unblinds" the server's answer and returns the opened assets from
    /// the server
    pub fn finish(
        self,
        credential_response: CredentialResponse<CS>,
        params: ClientLoginFinishParameters<CS>,
    ) -> Result<ClientLoginFinishResult<CS>, ProtocolError>
    where
        <CS::Hash as FixedOutput>::OutputSize: Shl<B1>,
        Double<<CS::Hash as FixedOutput>::OutputSize>: ArrayLength<u8>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, NonceLen>: Add<<CS::Hash as FixedOutput>::OutputSize>,
        Sum<Sum<<CS::KeGroup as KeGroup>::PkLen, NonceLen>, <CS::Hash as FixedOutput>::OutputSize>:
            ArrayLength<u8>,
    {
        // Check if beta value from server is equal to alpha value from client
        let credential_request =
            CredentialRequest::<CS>::deserialize(&self.serialized_credential_request)?;
        if credential_request
            .blinded_element
            .value()
            .ct_eq(&credential_response.evaluation_element.value())
            .into()
        {
            return Err(ProtocolError::ReflectedValueError);
        }

        let (_, randomized_pwd_hasher) = get_password_derived_key::<CS>(
            self.oprf_client.clone(),
            credential_response.evaluation_element.clone(),
            params.slow_hash,
        )?;

        let mut masking_key = GenericArray::<_, <CS::Hash as Digest>::OutputSize>::default();
        randomized_pwd_hasher
            .expand(STR_MASKING_KEY, &mut masking_key)
            .map_err(|_| InternalError::HkdfError)?;

        let (server_s_pk, envelope) = unmask_response::<CS>(
            &masking_key,
            &credential_response.masking_nonce,
            &credential_response.masked_response,
        )
        .map_err(|e| match e {
            ProtocolError::SerializationError => ProtocolError::InvalidLoginError,
            err => err,
        })?;
        let server_s_pk_bytes = server_s_pk.to_arr();

        let opened_envelope = &envelope
            .open(
                randomized_pwd_hasher,
                &server_s_pk_bytes,
                params.identifiers,
            )
            .map_err(|e| match e {
                ProtocolError::LibraryError(InternalError::SealOpenHmacError) => {
                    ProtocolError::InvalidLoginError
                }
                err => err,
            })?;

        let credential_response_component = CredentialResponse::<CS>::serialize_without_ke(
            &credential_response.evaluation_element.value(),
            &credential_response.masking_nonce,
            &credential_response.masked_response,
        );

        let result = CS::KeyExchange::generate_ke3(
            credential_response_component,
            credential_response.ke2_message,
            &self.ke1_state,
            &self.serialized_credential_request,
            server_s_pk.clone(),
            opened_envelope.client_static_keypair.private().clone(),
            opened_envelope.id_u.clone(),
            opened_envelope.id_s.clone(),
            params.context.unwrap_or(&[]),
        )?;

        Ok(ClientLoginFinishResult {
            message: CredentialFinalization {
                ke3_message: result.1,
            },
            session_key: result.0,
            export_key: opened_envelope.export_key.clone(),
            server_s_pk,
            #[cfg(test)]
            state: self,
            #[cfg(test)]
            handshake_secret: result.2,
            #[cfg(test)]
            client_mac_key: result.3,
        })
    }
}

impl<CS: CipherSuite> ServerLogin<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        Ok(self.ke2_state.to_bytes())
    }

    /// Deserialization from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            _cs: PhantomData,
            ke2_state:
                <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE2State::from_bytes::<CS>(
                    bytes,
                )?,
        })
    }

    /// From the client's "blinded" password, returns a challenge to be
    /// sent back to the client, as well as a ServerLogin
    pub fn start<R: RngCore + CryptoRng, S: SecretKey<CS::KeGroup>>(
        rng: &mut R,
        server_setup: &ServerSetup<CS, S>,
        password_file: Option<ServerRegistration<CS>>,
        credential_request: CredentialRequest<CS>,
        credential_identifier: &[u8],
        ServerLoginStartParameters {
            context,
            identifiers,
        }: ServerLoginStartParameters,
    ) -> Result<ServerLoginStartResult<CS>, ProtocolError<S::Error>>
    where
        Sum<<CS::KeGroup as KeGroup>::PkLen, NonceLen>: Add<<CS::Hash as FixedOutput>::OutputSize>,
        Sum<Sum<<CS::KeGroup as KeGroup>::PkLen, NonceLen>, <CS::Hash as FixedOutput>::OutputSize>:
            ArrayLength<u8>,
    {
        let record = match password_file {
            Some(x) => x,
            None => ServerRegistration::dummy(rng, server_setup),
        };

        let client_s_pk = record.0.client_s_pk.clone();

        let context = if let Some(context) = context {
            context
        } else {
            &[]
        };

        let server_s_sk = server_setup.keypair.private();
        let server_s_pk = server_s_sk.public_key()?;

        let mut masking_nonce = GenericArray::<_, NonceLen>::default();
        rng.fill_bytes(&mut masking_nonce);

        let masked_response = mask_response(
            &record.0.masking_key,
            &masking_nonce,
            &server_s_pk,
            &record.0.envelope,
        )
        .map_err(ProtocolError::into_custom)?;

        let (id_u, id_s) =
            bytestrings_from_identifiers(identifiers, &client_s_pk.to_arr(), &server_s_pk.to_arr())
                .map_err(ProtocolError::into_custom)?;

        let credential_request_bytes = credential_request
            .serialize()
            .map_err(ProtocolError::into_custom)?;

        let oprf_key = oprf_key_from_seed::<CS::OprfGroup, CS::Hash>(
            &server_setup.oprf_seed,
            credential_identifier,
        )
        .map_err(ProtocolError::into_custom)?;
        let server = voprf::NonVerifiableServer::new_with_key(&oprf_key)
            .map_err(|e| ProtocolError::into_custom(e.into()))?;
        let evaluate_result = server
            .evaluate(credential_request.blinded_element, None)
            .map_err(|e| ProtocolError::into_custom(e.into()))?;
        let evaluation_element = evaluate_result.message;

        let credential_response_component = CredentialResponse::<CS>::serialize_without_ke(
            &evaluation_element.value(),
            &masking_nonce,
            &masked_response,
        );

        let result = CS::KeyExchange::generate_ke2(
            rng,
            credential_request_bytes,
            credential_response_component,
            credential_request.ke1_message,
            client_s_pk,
            server_s_sk.clone(),
            id_u,
            id_s,
            context,
        )?;

        let credential_response = CredentialResponse {
            evaluation_element,
            masking_nonce,
            masked_response,
            ke2_message: result.1,
        };

        Ok(ServerLoginStartResult {
            message: credential_response,
            state: Self {
                _cs: PhantomData,
                ke2_state: result.0,
            },
            #[cfg(test)]
            handshake_secret: result.2,
            #[cfg(test)]
            server_mac_key: result.3,
            #[cfg(test)]
            oprf_key: GenericArray::clone_from_slice(&oprf_key),
        })
    }

    /// From the client's second and final message, check the client's
    /// authentication and produce a message transport
    pub fn finish(
        self,
        message: CredentialFinalization<CS>,
    ) -> Result<ServerLoginFinishResult<CS>, ProtocolError> {
        let session_key = <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::finish_ke(
            message.ke3_message,
            &self.ke2_state,
        )?;

        Ok(ServerLoginFinishResult {
            session_key,
            _cs: PhantomData,
            #[cfg(test)]
            state: self,
        })
    }
}

/////////////////////////
// Convenience Structs //
//==================== //
/////////////////////////

/// Options for specifying custom identifiers
#[derive(Clone, Copy, Debug, Default)]
pub struct Identifiers<'a> {
    /// Client identifier
    pub client: Option<&'a [u8]>,
    /// Server identifier
    pub server: Option<&'a [u8]>,
}

/// Optional parameters for client registration finish
#[derive(DeriveWhere)]
#[derive_where(Clone, Default)]
pub struct ClientRegistrationFinishParameters<'i, 'h, CS: CipherSuite> {
    /// Specifying the identifiers idU and idS
    pub identifiers: Identifiers<'i>,
    /// Specifying a configuration for the slow hash
    pub slow_hash: Option<&'h CS::SlowHash>,
}

impl<'i, 'h, CS: CipherSuite> ClientRegistrationFinishParameters<'i, 'h, CS> {
    /// Create a new [`ClientRegistrationFinishParameters`]
    pub fn new(identifiers: Identifiers<'i>, slow_hash: Option<&'h CS::SlowHash>) -> Self {
        Self {
            identifiers,
            slow_hash,
        }
    }
}

/// Contains the fields that are returned by a client registration start
#[derive(DeriveWhere)]
#[derive_where(Clone)]
pub struct ClientRegistrationStartResult<CS: CipherSuite> {
    /// The registration request message to be sent to the server
    pub message: RegistrationRequest<CS>,
    /// The client state that must be persisted in order to complete registration
    pub state: ClientRegistration<CS>,
}

/// Contains the fields that are returned by a client registration finish
#[derive(DeriveWhere)]
#[derive_where(Clone)]
pub struct ClientRegistrationFinishResult<CS: CipherSuite> {
    /// The registration upload message to be sent to the server
    pub message: RegistrationUpload<CS>,
    /// The export key output by client registration
    pub export_key: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
    /// The server's static public key
    pub server_s_pk: PublicKey<CS::KeGroup>,
    /// Instance of the ClientRegistration, only used in tests for checking zeroize
    #[cfg(test)]
    pub state: ClientRegistration<CS>,
    /// AuthKey, only used in tests
    #[cfg(test)]
    pub auth_key: Vec<u8>,
    /// Password derived key, only used in tests
    #[cfg(test)]
    pub randomized_pwd: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
}

/// Contains the fields that are returned by a server registration start.
/// Note that there is no state output in this step
#[derive(DeriveWhere)]
#[derive_where(Clone)]
pub struct ServerRegistrationStartResult<CS: CipherSuite> {
    /// The registration resposne message to send to the client
    pub message: RegistrationResponse<CS>,
    /// OPRF key, only used in tests
    #[cfg(test)]
    pub oprf_key: GenericArray<u8, <CS::OprfGroup as Group>::ScalarLen>,
}

/// Contains the fields that are returned by a client login start
#[derive(DeriveWhere)]
#[derive_where(Clone)]
pub struct ClientLoginStartResult<CS: CipherSuite> {
    /// The message to send to the server to begin the login protocol
    pub message: CredentialRequest<CS>,
    /// The state that the client must keep in order to complete the protocol
    pub state: ClientLogin<CS>,
}

/// Optional parameters for client login finish
#[derive(DeriveWhere)]
#[derive_where(Clone, Default)]
pub struct ClientLoginFinishParameters<'c, 'i, 'h, CS: CipherSuite> {
    /// Specifying a context field that the server must agree on
    pub context: Option<&'c [u8]>,
    /// Specifying a user identifier and server identifier that will be matched against the server
    pub identifiers: Identifiers<'i>,
    /// Specifying a configuration for the slow hash
    pub slow_hash: Option<&'h CS::SlowHash>,
}

impl<'c, 'i, 'h, CS: CipherSuite> ClientLoginFinishParameters<'c, 'i, 'h, CS> {
    /// Create a new [`ClientLoginFinishParameters`]
    pub fn new(
        context: Option<&'c [u8]>,
        identifiers: Identifiers<'i>,
        slow_hash: Option<&'h CS::SlowHash>,
    ) -> Self {
        Self {
            context,
            identifiers,
            slow_hash,
        }
    }
}

/// Contains the fields that are returned by a client login finish
#[derive(DeriveWhere)]
#[derive_where(Clone)]
pub struct ClientLoginFinishResult<CS: CipherSuite> {
    /// The message to send to the server to complete the protocol
    pub message: CredentialFinalization<CS>,
    /// The session key
    pub session_key: Vec<u8>,
    /// The client-side export key
    pub export_key: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
    /// The server's static public key
    pub server_s_pk: PublicKey<CS::KeGroup>,
    /// Instance of the ClientLogin, only used in tests for checking zeroize
    #[cfg(test)]
    pub state: ClientLogin<CS>,
    /// Handshake secret, only used in tests
    #[cfg(test)]
    pub handshake_secret: Vec<u8>,
    /// Client MAC key, only used in tests
    #[cfg(test)]
    pub client_mac_key: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
}

/// Contains the fields that are returned by a server login finish
#[derive(DeriveWhere)]
#[derive_where(Clone)]
#[cfg_attr(not(test), derive_where(Debug))]
#[cfg_attr(test, derive_where(Debug; ServerLogin<CS>))]
pub struct ServerLoginFinishResult<CS: CipherSuite> {
    /// The session key between client and server
    pub session_key: Vec<u8>,
    _cs: PhantomData<CS>,
    /// Instance of the ClientRegistration, only used in tests for checking zeroize
    #[cfg(test)]
    pub state: ServerLogin<CS>,
}

/// Optional parameters for server login start
#[derive(Clone, Debug, Default)]
pub struct ServerLoginStartParameters<'c, 'i> {
    /// Specifying a context field that the client must agree on
    pub context: Option<&'c [u8]>,
    /// Specifying a user identifier and server identifier that will be matched against the client
    pub identifiers: Identifiers<'i>,
}

/// Contains the fields that are returned by a server login start
#[derive(DeriveWhere)]
#[derive_where(Clone)]
#[derive_where(
    Debug;
    CS::OprfGroup,
    <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE2Message,
    <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE2State,
)]
pub struct ServerLoginStartResult<CS: CipherSuite>
where
    Sum<<CS::KeGroup as KeGroup>::PkLen, NonceLen>: Add<<CS::Hash as FixedOutput>::OutputSize>,
    Sum<Sum<<CS::KeGroup as KeGroup>::PkLen, NonceLen>, <CS::Hash as FixedOutput>::OutputSize>:
        ArrayLength<u8>,
{
    /// The message to send back to the client
    pub message: CredentialResponse<CS>,
    /// The state that the server must keep in order to finish the protocl
    pub state: ServerLogin<CS>,
    /// Handshake secret, only used in tests
    #[cfg(test)]
    pub handshake_secret: Vec<u8>,
    /// Server MAC key, only used in tests
    #[cfg(test)]
    pub server_mac_key: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
    /// OPRF key, only used in tests
    #[cfg(test)]
    pub oprf_key: GenericArray<u8, <CS::OprfGroup as Group>::ScalarLen>,
}

////////////////////////////////////////////////
// Helper functions and Trait Implementations //
// ========================================== //
////////////////////////////////////////////////

// Helper functions

#[allow(clippy::type_complexity)]
fn get_password_derived_key<CS: CipherSuite>(
    oprf_client: voprf::NonVerifiableClient<CS::OprfGroup, CS::Hash>,
    evaluation_element: voprf::EvaluationElement<CS::OprfGroup, CS::Hash>,
    slow_hash: Option<&CS::SlowHash>,
) -> Result<
    (
        GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
        Hkdf<CS::Hash>,
    ),
    ProtocolError,
>
where
    <CS::Hash as FixedOutput>::OutputSize: Shl<B1>,
    Double<<CS::Hash as FixedOutput>::OutputSize>: ArrayLength<u8>,
{
    let oprf_output = oprf_client.finalize(evaluation_element, None)?;

    let hardened_output = if let Some(slow_hash) = slow_hash {
        slow_hash.hash(oprf_output.clone())
    } else {
        CS::SlowHash::default().hash(oprf_output.clone())
    }
    .map_err(ProtocolError::from)?;

    Ok(Hkdf::<CS::Hash>::extract(
        None,
        &[oprf_output, hardened_output].concat(),
    ))
}

fn oprf_key_from_seed<G: Group, D: Hash>(
    oprf_seed: &GenericArray<u8, D::OutputSize>,
    credential_identifier: &[u8],
) -> Result<GenericArray<u8, G::ScalarLen>, ProtocolError> {
    let mut ikm = GenericArray::<_, G::ScalarLen>::default();
    Hkdf::<D>::from_prk(oprf_seed)
        .ok()
        .and_then(|hkdf| {
            hkdf.expand_multi_info(&[credential_identifier, STR_OPRF_KEY], &mut ikm)
                .ok()
        })
        .ok_or(InternalError::HkdfError)?;
    Ok(G::scalar_as_bytes(G::hash_to_scalar::<D, _, _>(
        Some(ikm.as_slice()),
        GenericArray::from(*STR_OPAQUE_DERIVE_KEY_PAIR),
    )?))
}

#[allow(type_alias_bounds)]
pub type MaskResponse<CS: CipherSuite> = GenericArray<
    u8,
    Sum<Sum<<CS::KeGroup as KeGroup>::PkLen, NonceLen>, <CS::Hash as FixedOutput>::OutputSize>,
>;

fn mask_response<CS: CipherSuite>(
    masking_key: &[u8],
    masking_nonce: &[u8],
    server_s_pk: &PublicKey<CS::KeGroup>,
    envelope: &Envelope<CS>,
) -> Result<MaskResponse<CS>, ProtocolError>
where
    Sum<<CS::KeGroup as KeGroup>::PkLen, NonceLen>: Add<<CS::Hash as FixedOutput>::OutputSize>,
    Sum<Sum<<CS::KeGroup as KeGroup>::PkLen, NonceLen>, <CS::Hash as FixedOutput>::OutputSize>:
        ArrayLength<u8>,
{
    let mut xor_pad = GenericArray::default();
    Hkdf::<CS::Hash>::from_prk(masking_key)
        .map_err(|_| InternalError::HkdfError)?
        .expand_multi_info(&[masking_nonce, STR_CREDENTIAL_RESPONSE_PAD], &mut xor_pad)
        .map_err(|_| InternalError::HkdfError)?;

    for (x1, x2) in xor_pad.iter_mut().zip(
        server_s_pk
            .to_arr()
            .as_slice()
            .iter()
            .chain(envelope.serialize().iter()),
    ) {
        *x1 ^= x2
    }

    Ok(xor_pad)
}

fn unmask_response<CS: CipherSuite>(
    masking_key: &[u8],
    masking_nonce: &[u8],
    masked_response: &[u8],
) -> Result<(PublicKey<CS::KeGroup>, Envelope<CS>), ProtocolError>
where
    Sum<<CS::KeGroup as KeGroup>::PkLen, NonceLen>: Add<<CS::Hash as FixedOutput>::OutputSize>,
    Sum<Sum<<CS::KeGroup as KeGroup>::PkLen, NonceLen>, <CS::Hash as FixedOutput>::OutputSize>:
        ArrayLength<u8>,
{
    let mut xor_pad = MaskResponse::<CS>::default();
    Hkdf::<CS::Hash>::from_prk(masking_key)
        .map_err(|_| InternalError::HkdfError)?
        .expand(
            &[masking_nonce, STR_CREDENTIAL_RESPONSE_PAD].concat(),
            &mut xor_pad,
        )
        .map_err(|_| InternalError::HkdfError)?;
    let plaintext: Vec<u8> = xor_pad
        .iter()
        .zip(masked_response.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    let key_len = <CS::KeGroup as KeGroup>::PkLen::USIZE;
    let unchecked_server_s_pk = PublicKey::from_bytes(&plaintext[..key_len])?;
    let envelope = Envelope::deserialize(&plaintext[key_len..])?;

    // Ensure that public key is valid
    let server_s_pk = KeyPair::<CS::KeGroup>::check_public_key(unchecked_server_s_pk)
        .map_err(|_| ProtocolError::SerializationError)?;

    Ok((server_s_pk, envelope))
}

pub(crate) fn bytestrings_from_identifiers(
    ids: Identifiers,
    client_s_pk: &[u8],
    server_s_pk: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let client_identity = ids.client.unwrap_or(client_s_pk);
    let server_identity = ids.server.unwrap_or(server_s_pk);
    Ok((
        serialize(client_identity, 2)?,
        serialize(server_identity, 2)?,
    ))
}

/// Internal function for computing the blind result by calling the
/// voprf library. Note that for tests, we use the deterministic blinding
/// in order to be able to set the blinding factor directly from the passed-in
/// rng.
fn blind<CS: CipherSuite, R: RngCore + CryptoRng>(
    rng: &mut R,
    password: &[u8],
) -> Result<
    voprf::NonVerifiableClientBlindResult<CS::OprfGroup, CS::Hash>,
    voprf::errors::InternalError,
> {
    #[cfg(not(test))]
    let result = voprf::NonVerifiableClient::blind(password.to_vec(), rng)?;

    #[cfg(test)]
    let result = {
        let mut blind_bytes = vec![0u8; <CS::OprfGroup as Group>::ScalarLen::USIZE];
        let blind = loop {
            rng.fill_bytes(&mut blind_bytes);
            let scalar = <CS::OprfGroup as Group>::from_scalar_slice_unchecked(
                &GenericArray::clone_from_slice(&blind_bytes),
            )?;
            match scalar
                .ct_eq(&<CS::OprfGroup as Group>::scalar_zero())
                .into()
            {
                false => break scalar,
                true => (),
            }
        };
        voprf::NonVerifiableClient::deterministic_blind_unchecked(password.to_vec(), blind)?
    };

    Ok(result)
}

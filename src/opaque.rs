// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Provides the main OPAQUE API

use crate::{
    ciphersuite::CipherSuite,
    envelope::Envelope,
    errors::{utils::check_slice_size, InternalPakeError, PakeError, ProtocolError},
    group::Group,
    hash::Hash,
    key_exchange::traits::{FromBytes, KeyExchange, ToBytesWithPointers},
    keypair::{KeyPair, PrivateKey, PublicKey},
    map_to_curve::GroupWithMapToCurve,
    oprf,
    serialization::{serialize, tokenize},
    slow_hash::SlowHash,
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    RegistrationResponse, RegistrationUpload,
};
use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};
use generic_bytes::SizedBytes;
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use std::marker::PhantomData;
use zeroize::Zeroize;

const STR_CREDENTIAL_RESPONSE_PAD: &[u8] = b"CredentialResponsePad";
const STR_MASKING_KEY: &[u8] = b"MaskingKey";
const STR_OPRF_KEY: &[u8] = b"OprfKey";

// Server Setup
// ============

/// The state elements the server holds upon setup
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
pub struct ServerSetup<CS: CipherSuite> {
    oprf_seed: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
    keypair: KeyPair<CS::Group>,
    pub(crate) fake_keypair: KeyPair<CS::Group>,
}

impl<CS: CipherSuite> ServerSetup<CS> {
    /// Generate a new instance of server setup
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut seed = vec![0u8; <CS::Hash as Digest>::OutputSize::to_usize()];
        rng.fill_bytes(&mut seed);

        Self {
            oprf_seed: GenericArray::clone_from_slice(&seed[..]),
            keypair: KeyPair::<CS::Group>::generate_random(rng),
            fake_keypair: KeyPair::<CS::Group>::generate_random(rng),
        }
    }

    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        [
            self.oprf_seed.to_vec(),
            self.keypair.private().to_arr().to_vec(),
            self.fake_keypair.private().to_arr().to_vec(),
        ]
        .concat()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let seed_len = <CS::Hash as Digest>::OutputSize::to_usize();
        let key_len = <PrivateKey as SizedBytes>::Len::to_usize();
        let checked_slice = check_slice_size(input, seed_len + key_len + key_len, "server_setup")?;

        Ok(Self {
            oprf_seed: GenericArray::clone_from_slice(&checked_slice[..seed_len]),
            keypair: KeyPair::from_private_key_slice(&checked_slice[seed_len..seed_len + key_len])?,
            fake_keypair: KeyPair::from_private_key_slice(&checked_slice[seed_len + key_len..])?,
        })
    }

    /// Returns the keypair
    pub fn keypair(&self) -> &KeyPair<CS::Group> {
        &self.keypair
    }
}

// Cannot be derived because it would require for CS to be bound.
impl_clone_for!(
    struct ServerSetup<CS: CipherSuite>,
    [oprf_seed, keypair, fake_keypair],
);
impl_debug_eq_hash_for!(
    struct ServerSetup<CS: CipherSuite>,
    [oprf_seed, oprf_seed, fake_keypair],
);

// Registration
// ============

/// The state elements the client holds to register itself
pub struct ClientRegistration<CS: CipherSuite> {
    /// token containing the client's password and the blinding factor
    pub(crate) token: oprf::Token<CS::Group>,
}

impl_clone_for!(struct ClientRegistration<CS: CipherSuite>, [token]);
impl_debug_eq_hash_for!(
    struct ClientRegistration<CS: CipherSuite>,
    [token],
    [oprf::Token<CS::Group>],
);

impl<CS: CipherSuite> ClientRegistration<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        [
            &CS::Group::scalar_as_bytes(&self.token.blind)[..],
            &self.token.data,
        ]
        .concat()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let min_expected_len = <CS::Group as Group>::ScalarLen::to_usize();
        let checked_slice = (if input.len() <= min_expected_len {
            Err(InternalPakeError::SizeError {
                name: "client_registration_bytes",
                len: min_expected_len,
                actual_len: input.len(),
            })
        } else {
            Ok(input)
        })?;

        // Check that the message is actually containing an element of the
        // correct subgroup
        let scalar_len = min_expected_len;
        let blinding_factor_bytes = GenericArray::from_slice(&checked_slice[..scalar_len]);
        let blinding_factor = CS::Group::from_scalar_slice(blinding_factor_bytes)?;
        let password = checked_slice[scalar_len..].to_vec();
        Ok(Self {
            token: oprf::Token {
                data: password,
                blind: blinding_factor,
            },
        })
    }

    #[cfg(test)]
    pub fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        vec![
            (self.token.data.as_ptr(), self.token.data.len()),
            /* cannot provide raw pointer to self.token.blind until this is exposed in curve25519_dalek::scalar::Scalar */
        ]
    }
}

impl_serialize_and_deserialize_for!(ClientRegistration);

/// Options for specifying custom identifiers
#[derive(Clone)]
pub enum Identifiers {
    /// Supply only a client identifier
    ClientIdentifier(Vec<u8>),
    /// Supply only a server identifier
    ServerIdentifier(Vec<u8>),
    /// Supply a client and server identifier
    ClientAndServerIdentifiers(Vec<u8>, Vec<u8>),
}

pub(crate) fn bytestrings_from_identifiers(
    ids: &Option<Identifiers>,
    client_s_pk: &[u8],
    server_s_pk: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let (client_identity, server_identity): (Vec<u8>, Vec<u8>) = match ids {
        None => (client_s_pk.to_vec(), server_s_pk.to_vec()),
        Some(Identifiers::ClientIdentifier(id_u)) => (id_u.clone(), server_s_pk.to_vec()),
        Some(Identifiers::ServerIdentifier(id_s)) => (client_s_pk.to_vec(), id_s.clone()),
        Some(Identifiers::ClientAndServerIdentifiers(id_u, id_s)) => (id_u.clone(), id_s.clone()),
    };
    (
        serialize(&client_identity, 2),
        serialize(&server_identity, 2),
    )
}

/// Optional parameters for client registration finish
#[derive(Clone)]
pub enum ClientRegistrationFinishParameters {
    /// Specifying the identifiers idU and idS
    WithIdentifiers(Identifiers),
    /// No identifiers or private key specified
    Default,
}

impl Default for ClientRegistrationFinishParameters {
    fn default() -> Self {
        Self::Default
    }
}

/// Contains the fields that are returned by a client registration start
pub struct ClientRegistrationStartResult<CS: CipherSuite> {
    /// The registration request message to be sent to the server
    pub message: RegistrationRequest<CS>,
    /// The client state that must be persisted in order to complete registration
    pub state: ClientRegistration<CS>,
}

// Cannot be derived because it would require for CS to be Clone.
impl<CS: CipherSuite> Clone for ClientRegistrationStartResult<CS> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
            state: self.state.clone(),
        }
    }
}

impl<CS: CipherSuite> ClientRegistration<CS> {
    /// Returns an initial "blinded" request to send to the server, as well as a ClientRegistration
    pub fn start<R: RngCore + CryptoRng>(
        blinding_factor_rng: &mut R,
        password: &[u8],
    ) -> Result<ClientRegistrationStartResult<CS>, ProtocolError> {
        let (token, alpha) = oprf::blind::<R, CS::Group, CS::Hash>(password, blinding_factor_rng)?;

        Ok(ClientRegistrationStartResult {
            message: RegistrationRequest::<CS> { alpha },
            state: Self { token },
        })
    }
}

/// Contains the fields that are returned by a client registration finish
pub struct ClientRegistrationFinishResult<CS: CipherSuite> {
    /// The registration upload message to be sent to the server
    pub message: RegistrationUpload<CS>,
    /// The export key output by client registration
    pub export_key: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
    /// The server's static public key
    pub server_s_pk: PublicKey,
    /// Instance of the ClientRegistration, only used in tests for checking zeroize
    #[cfg(test)]
    pub state: ClientRegistration<CS>,
}

// Cannot be derived because it would require for CS to be Clone.
impl<CS: CipherSuite> Clone for ClientRegistrationFinishResult<CS> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
            export_key: self.export_key.clone(),
            server_s_pk: self.server_s_pk.clone(),
            #[cfg(test)]
            state: self.state.clone(),
        }
    }
}

impl<CS: CipherSuite> ClientRegistration<CS> {
    /// "Unblinds" the server's answer and returns a final message containing
    /// cryptographic identifiers, to be sent to the server on setup finalization
    pub fn finish<R: CryptoRng + RngCore>(
        self,
        rng: &mut R,
        r2: RegistrationResponse<CS>,
        params: ClientRegistrationFinishParameters,
    ) -> Result<ClientRegistrationFinishResult<CS>, ProtocolError> {
        let optional_ids = match params {
            ClientRegistrationFinishParameters::WithIdentifiers(ids) => Some(ids),
            ClientRegistrationFinishParameters::Default => None,
        };

        let password_derived_key =
            get_password_derived_key::<CS::Group, CS::SlowHash, CS::Hash>(&self.token, r2.beta)?;

        let h = Hkdf::<CS::Hash>::new(None, &password_derived_key);
        let mut masking_key = vec![0u8; <CS::Hash as Digest>::OutputSize::to_usize()];
        h.expand(STR_MASKING_KEY, &mut masking_key)
            .map_err(|_| InternalPakeError::HkdfError)?;

        let (envelope, client_s_pk, export_key) =
            Envelope::<CS>::seal(rng, &password_derived_key, &r2.server_s_pk, optional_ids)?;

        Ok(ClientRegistrationFinishResult {
            message: RegistrationUpload {
                envelope,
                masking_key: GenericArray::clone_from_slice(&masking_key[..]),
                client_s_pk,
            },
            export_key,
            server_s_pk: r2.server_s_pk,
            #[cfg(test)]
            state: self,
        })
    }
}

/// Contains the fields that are returned by a server registration start.
/// Note that there is no state output in this step
pub struct ServerRegistrationStartResult<CS: CipherSuite> {
    /// The registration resposne message to send to the client
    pub message: RegistrationResponse<CS>,
}

// Cannot be derived because it would require for CS to be Clone.
impl<CS: CipherSuite> Clone for ServerRegistrationStartResult<CS> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
        }
    }
}

/// The state elements the server holds to record a registration
pub struct ServerRegistration<CS: CipherSuite>(RegistrationUpload<CS>);

impl_clone_for!(tuple ServerRegistration<CS: CipherSuite>, [0]);
impl_debug_eq_hash_for!(
    tuple ServerRegistration<CS: CipherSuite>,
    [0],
);

impl<CS: CipherSuite> ServerRegistration<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self(RegistrationUpload::deserialize(input)?))
    }

    #[cfg(test)]
    pub fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        [
            self.0.envelope.as_byte_ptrs(),
            vec![(self.0.client_s_pk.as_ptr(), self.0.client_s_pk.len())],
            /* cannot provide raw pointer to self.oprf_key until this is exposed in curve25519_dalek::scalar::Scalar */
        ].concat()
    }

    /// From the client's "blinded" password, returns a response to be
    /// sent back to the client, as well as a ServerRegistration
    pub fn start(
        server_setup: &ServerSetup<CS>,
        message: RegistrationRequest<CS>,
        credential_identifier: &[u8],
    ) -> Result<ServerRegistrationStartResult<CS>, ProtocolError> {
        let oprf_key = oprf_key_from_seed::<CS::Group, CS::Hash>(
            &server_setup.oprf_seed,
            credential_identifier,
        )?;

        // Compute beta = alpha^oprf_key
        let beta = oprf::evaluate::<CS::Group>(message.alpha, &oprf_key);

        Ok(ServerRegistrationStartResult {
            message: RegistrationResponse {
                beta,
                server_s_pk: server_setup.keypair.public().clone(),
            },
        })
    }

    /// From the client's cryptographic identifiers, fully populates and
    /// returns a ServerRegistration
    pub fn finish(message: RegistrationUpload<CS>) -> Self {
        Self(message)
    }

    // Creates a dummy instance used for faking a [CredentialResponse]
    pub(crate) fn dummy<R: RngCore + CryptoRng>(
        rng: &mut R,
        server_setup: &ServerSetup<CS>,
    ) -> Self {
        Self(RegistrationUpload::dummy(rng, server_setup))
    }
}

impl_serialize_and_deserialize_for!(ServerRegistration);

// Login
// =====

/// The state elements the client holds to perform a login
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(
    feature = "serialize",
    serde(bound(
        deserialize = "oprf::Token<CS::Group>: serde::Deserialize<'de>, <CS::KeyExchange as KeyExchange<CS::Hash, CS::Group>>::KE1State: serde::Deserialize<'de>",
        serialize = "oprf::Token<CS::Group>: serde::Serialize, <CS::KeyExchange as KeyExchange<CS::Hash, CS::Group>>::KE1State: serde::Serialize"
    ))
)]
pub struct ClientLogin<CS: CipherSuite> {
    /// token containing the client's password and the blinding factor
    token: oprf::Token<CS::Group>,
    ke1_state: <CS::KeyExchange as KeyExchange<CS::Hash, CS::Group>>::KE1State,
    serialized_credential_request: Vec<u8>,
}

impl_clone_for!(struct ClientLogin<CS: CipherSuite>, [token, ke1_state, serialized_credential_request]);
impl_debug_eq_hash_for!(
    struct ClientLogin<CS: CipherSuite>,
    [token, ke1_state, serialized_credential_request],
    [oprf::Token<CS::Group>, <CS::KeyExchange as KeyExchange<CS::Hash, CS::Group>>::KE1State],
);

impl<CS: CipherSuite> ClientLogin<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let output: Vec<u8> = [
            &CS::Group::scalar_as_bytes(&self.token.blind)[..],
            &serialize(&self.serialized_credential_request, 2),
            &serialize(&self.ke1_state.to_bytes(), 2),
            &self.token.data,
        ]
        .concat();
        output
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let scalar_len = <CS::Group as Group>::ScalarLen::to_usize();
        let checked_slice = (if input.len() <= scalar_len {
            Err(InternalPakeError::SizeError {
                name: "client_login_bytes",
                len: scalar_len,
                actual_len: input.len(),
            })
        } else {
            Ok(input)
        })?;

        let blinding_factor_bytes = GenericArray::from_slice(&checked_slice[..scalar_len]);
        let blinding_factor = CS::Group::from_scalar_slice(blinding_factor_bytes)?;

        let (serialized_credential_request, remainder) = tokenize(&checked_slice[scalar_len..], 2)?;
        let (ke1_state_bytes, password) = tokenize(&remainder, 2)?;

        let ke1_state =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::Group>>::KE1State::from_bytes::<CS>(
                &ke1_state_bytes[..],
            )?;
        Ok(Self {
            token: oprf::Token {
                data: password,
                blind: blinding_factor,
            },
            ke1_state,
            serialized_credential_request,
        })
    }

    #[cfg(test)]
    pub fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        [
            vec![
                (self.token.data.as_ptr(), self.token.data.len()),
                /* cannot provide raw pointer to self.token.blind until this is exposed in curve25519_dalek::scalar::Scalar */
            ],
            self.ke1_state.as_byte_ptrs(),
            vec![ (self.serialized_credential_request.as_ptr(), self.serialized_credential_request.len()) ],
        ].concat()
    }
}

/// Contains the fields that are returned by a client login start
pub struct ClientLoginStartResult<CS: CipherSuite> {
    /// The message to send to the server to begin the login protocol
    pub message: CredentialRequest<CS>,
    /// The state that the client must keep in order to complete the protocol
    pub state: ClientLogin<CS>,
}

// Cannot be derived because it would require for CS to be Clone.
impl<CS: CipherSuite> Clone for ClientLoginStartResult<CS> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
            state: self.state.clone(),
        }
    }
}

/// Optional parameters for client login finish
#[derive(Clone)]
pub enum ClientLoginFinishParameters {
    /// Specifying a context field that the server must agree on
    WithContext(Vec<u8>),
    /// Specifying a user identifier and server identifier that will be matched against the server
    WithIdentifiers(Identifiers),
    /// Specifying a context field that the server must agree on,
    /// along with a user identifier and server identifier and context that will be matched against the server
    WithContextAndIdentifiers(Vec<u8>, Identifiers),
    /// No custom identifiers and no context
    Default,
}

impl Default for ClientLoginFinishParameters {
    fn default() -> Self {
        Self::Default
    }
}

/// Contains the fields that are returned by a client login finish
pub struct ClientLoginFinishResult<CS: CipherSuite> {
    /// The message to send to the server to complete the protocol
    pub message: CredentialFinalization<CS>,
    /// The session key
    pub session_key: Vec<u8>,
    /// The client-side export key
    pub export_key: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
    /// The server's static public key
    pub server_s_pk: PublicKey,
    /// Instance of the ClientLogin, only used in tests for checking zeroize
    #[cfg(test)]
    pub state: ClientLogin<CS>,
}

// Cannot be derived because it would require for CS to be Clone.
impl<CS: CipherSuite> Clone for ClientLoginFinishResult<CS> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
            session_key: self.session_key.clone(),
            export_key: self.export_key.clone(),
            server_s_pk: self.server_s_pk.clone(),
            #[cfg(test)]
            state: self.state.clone(),
        }
    }
}

impl<CS: CipherSuite> ClientLogin<CS> {
    /// Returns an initial "blinded" password request to send to the server, as well as a ClientLogin
    pub fn start<R: RngCore + CryptoRng>(
        rng: &mut R,
        password: &[u8],
    ) -> Result<ClientLoginStartResult<CS>, ProtocolError> {
        let (token, alpha) = oprf::blind::<R, CS::Group, CS::Hash>(password, rng)?;

        let (ke1_state, ke1_message) = CS::KeyExchange::generate_ke1(rng)?;

        let credential_request = CredentialRequest { alpha, ke1_message };
        let serialized_credential_request = credential_request.serialize();

        Ok(ClientLoginStartResult {
            message: credential_request,
            state: Self {
                token,
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
        params: ClientLoginFinishParameters,
    ) -> Result<ClientLoginFinishResult<CS>, ProtocolError> {
        let (context, optional_ids) = match params {
            ClientLoginFinishParameters::Default => (vec![], None),
            ClientLoginFinishParameters::WithContext(context) => (context, None),
            ClientLoginFinishParameters::WithIdentifiers(ids) => (vec![], Some(ids)),
            // add context
            ClientLoginFinishParameters::WithContextAndIdentifiers(context, ids) => {
                (context, Some(ids))
            }
        };

        let password_derived_key = get_password_derived_key::<CS::Group, CS::SlowHash, CS::Hash>(
            &self.token,
            credential_response.beta,
        )?;

        let h = Hkdf::<CS::Hash>::new(None, &password_derived_key);
        let mut masking_key = vec![0u8; <CS::Hash as Digest>::OutputSize::to_usize()];
        h.expand(STR_MASKING_KEY, &mut masking_key)
            .map_err(|_| InternalPakeError::HkdfError)?;

        let (server_s_pk, envelope) = unmask_response::<CS>(
            &masking_key,
            &credential_response.masking_nonce,
            &credential_response.masked_response,
        )
        .map_err(|e| match e {
            ProtocolError::InvalidInnerEnvelopeError => PakeError::InvalidLoginError.into(),
            ProtocolError::VerificationError(PakeError::SerializationError) => {
                PakeError::InvalidLoginError.into()
            }
            err => err,
        })?;
        let server_s_pk_bytes = server_s_pk.to_arr().to_vec();

        let opened_envelope = &envelope
            .open(&password_derived_key, &server_s_pk_bytes, &optional_ids)
            .map_err(|e| match e {
                InternalPakeError::SealOpenHmacError => PakeError::InvalidLoginError,
                err => PakeError::from(err),
            })?;

        let credential_response_component = CredentialResponse::<CS>::serialize_without_ke(
            &credential_response.beta,
            &credential_response.masking_nonce,
            &credential_response.masked_response,
        );

        let (session_key, ke3_message) = CS::KeyExchange::generate_ke3(
            credential_response_component,
            credential_response.ke2_message,
            &self.ke1_state,
            &self.serialized_credential_request,
            server_s_pk.clone(),
            opened_envelope.client_static_keypair.private().clone(),
            opened_envelope.id_u.clone(),
            opened_envelope.id_s.clone(),
            context,
        )?;

        Ok(ClientLoginFinishResult {
            message: CredentialFinalization { ke3_message },
            session_key,
            export_key: opened_envelope.export_key.clone(),
            server_s_pk,
            #[cfg(test)]
            state: self,
        })
    }
}

/// The state elements the server holds to record a login
pub struct ServerLogin<CS: CipherSuite> {
    ke2_state: <CS::KeyExchange as KeyExchange<CS::Hash, CS::Group>>::KE2State,
    _cs: PhantomData<CS>,
}

impl_clone_for!(struct ServerLogin<CS: CipherSuite>, [ke2_state, _cs]);
impl_debug_eq_hash_for!(
    struct ServerLogin<CS: CipherSuite>,
    [ke2_state, _cs],
    [<CS::KeyExchange as KeyExchange<CS::Hash, CS::Group>>::KE2State],
);

/// Optional parameters for server login start
#[derive(Clone)]
pub enum ServerLoginStartParameters {
    /// Specifying a context field that the client must agree on
    WithContext(Vec<u8>),
    /// Specifying a user identifier and server identifier that will be matched against the client
    WithIdentifiers(Identifiers),
    /// Specifying a context field that the client must agree on,
    /// along with a user identifier and and server identifier that will be matched against the client
    /// (in that order)
    WithContextAndIdentifiers(Vec<u8>, Identifiers),
}

impl Default for ServerLoginStartParameters {
    fn default() -> Self {
        Self::WithContext(Vec::new())
    }
}

/// Contains the fields that are returned by a server login start
pub struct ServerLoginStartResult<CS: CipherSuite> {
    /// The message to send back to the client
    pub message: CredentialResponse<CS>,
    /// The state that the server must keep in order to finish the protocl
    pub state: ServerLogin<CS>,
}

// Cannot be derived because it would require for CS to be Clone.
impl<CS: CipherSuite> Clone for ServerLoginStartResult<CS> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
            state: self.state.clone(),
        }
    }
}

/// Contains the fields that are returned by a server login finish
pub struct ServerLoginFinishResult<CS: CipherSuite> {
    /// The session key between client and server
    pub session_key: Vec<u8>,
    _cs: PhantomData<CS>,
    /// Instance of the ClientRegistration, only used in tests for checking zeroize
    #[cfg(test)]
    pub state: ServerLogin<CS>,
}

// Cannot be derived because it would require for CS to be Clone.
impl<CS: CipherSuite> Clone for ServerLoginFinishResult<CS> {
    fn clone(&self) -> Self {
        Self {
            session_key: self.session_key.clone(),
            _cs: PhantomData,
            #[cfg(test)]
            state: self.state.clone(),
        }
    }
}

impl<CS: CipherSuite> ServerLogin<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        self.ke2_state.to_bytes()
    }

    /// Deserialization from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            _cs: PhantomData,
            ke2_state: <CS::KeyExchange as KeyExchange<CS::Hash, CS::Group>>::KE2State::from_bytes::<
                CS,
            >(bytes)?,
        })
    }

    /// From the client's "blinded" password, returns a challenge to be
    /// sent back to the client, as well as a ServerLogin
    pub fn start<R: RngCore + CryptoRng>(
        rng: &mut R,
        server_setup: &ServerSetup<CS>,
        password_file: Option<ServerRegistration<CS>>,
        l1: CredentialRequest<CS>,
        credential_identifier: &[u8],
        params: ServerLoginStartParameters,
    ) -> Result<ServerLoginStartResult<CS>, ProtocolError> {
        let record = match password_file {
            Some(x) => x,
            None => ServerRegistration::dummy(rng, server_setup),
        };

        let client_s_pk = record.0.client_s_pk.clone();

        let (context, optional_ids) = match params {
            ServerLoginStartParameters::WithContext(context) => (context, None),
            ServerLoginStartParameters::WithIdentifiers(ids) => (Vec::new(), Some(ids)),
            ServerLoginStartParameters::WithContextAndIdentifiers(context, ids) => {
                (context, Some(ids))
            }
        };

        let server_s_sk = server_setup.keypair.private();
        let server_s_pk = KeyPair::<CS::Group>::public_from_private(server_s_sk);

        let mut masking_nonce = vec![0u8; 32];
        rng.fill_bytes(&mut masking_nonce);

        let masked_response = mask_response(
            &record.0.masking_key,
            &masking_nonce,
            &server_s_pk,
            &record.0.envelope,
        )?;

        let (id_u, id_s) = bytestrings_from_identifiers(
            &optional_ids,
            &client_s_pk.to_arr(),
            &server_s_pk.to_arr(),
        );

        let l1_bytes = &l1.serialize();

        let oprf_key = oprf_key_from_seed::<CS::Group, CS::Hash>(
            &server_setup.oprf_seed,
            credential_identifier,
        )?;
        let beta = oprf::evaluate(l1.alpha, &oprf_key);

        let credential_response_component =
            CredentialResponse::<CS>::serialize_without_ke(&beta, &masking_nonce, &masked_response);

        let (ke2_state, ke2_message) = CS::KeyExchange::generate_ke2(
            rng,
            l1_bytes.to_vec(),
            credential_response_component,
            l1.ke1_message,
            client_s_pk,
            server_s_sk.clone(),
            id_u,
            id_s,
            context,
        )?;

        let credential_response = CredentialResponse {
            beta,
            masking_nonce,
            masked_response,
            ke2_message,
        };

        Ok(ServerLoginStartResult {
            message: credential_response,
            state: Self {
                _cs: PhantomData,
                ke2_state,
            },
        })
    }

    /// From the client's second and final message, check the client's
    /// authentication and produce a message transport
    pub fn finish(
        self,
        message: CredentialFinalization<CS>,
    ) -> Result<ServerLoginFinishResult<CS>, ProtocolError> {
        let session_key = <CS::KeyExchange as KeyExchange<CS::Hash, CS::Group>>::finish_ke(
            message.ke3_message,
            &self.ke2_state,
        )
        .map_err(|e| match e {
            ProtocolError::VerificationError(PakeError::KeyExchangeMacValidationError) => {
                ProtocolError::VerificationError(PakeError::InvalidLoginError)
            }
            err => err,
        })?;

        Ok(ServerLoginFinishResult {
            session_key,
            _cs: PhantomData,
            #[cfg(test)]
            state: self,
        })
    }

    #[cfg(test)]
    pub fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        self.ke2_state.as_byte_ptrs()
    }
}

impl_serialize_and_deserialize_for!(ServerLogin);

// Zeroize on drop implementations

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
impl<CS: CipherSuite> Zeroize for ServerRegistration<CS> {
    fn zeroize(&mut self) {
        self.0.envelope.zeroize();
        self.0.masking_key.zeroize();
        self.0.client_s_pk.zeroize();
    }
}

impl<CS: CipherSuite> Drop for ServerRegistration<CS> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// This can't be derived because of the use of a phantom parameter
impl<CS: CipherSuite> Zeroize for ClientLogin<CS> {
    fn zeroize(&mut self) {
        self.token.data.zeroize();
        self.token.blind.zeroize();
        self.ke1_state.zeroize();
        self.serialized_credential_request.zeroize();
    }
}

impl<CS: CipherSuite> Drop for ClientLogin<CS> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// This can't be derived because of the use of a phantom parameter
impl<CS: CipherSuite> Zeroize for ServerLogin<CS> {
    fn zeroize(&mut self) {
        self.ke2_state.zeroize();
    }
}

impl<CS: CipherSuite> Drop for ServerLogin<CS> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Helper functions

fn get_password_derived_key<G: GroupWithMapToCurve, SH: SlowHash<D>, D: Hash>(
    token: &oprf::Token<G>,
    beta: G,
) -> Result<Vec<u8>, InternalPakeError> {
    let oprf_output = oprf::finalize::<G, D>(&token.data, &token.blind, beta);
    SH::hash(oprf_output)
}

fn oprf_key_from_seed<G: GroupWithMapToCurve, D: Hash>(
    oprf_seed: &GenericArray<u8, D::OutputSize>,
    credential_identifier: &[u8],
) -> Result<G::Scalar, InternalPakeError> {
    let mut oprf_key_bytes = vec![0u8; <PrivateKey as SizedBytes>::Len::to_usize()];
    Hkdf::<D>::from_prk(oprf_seed)
        .map_err(|_| InternalPakeError::HkdfError)?
        .expand(
            &[credential_identifier, STR_OPRF_KEY].concat(),
            &mut oprf_key_bytes,
        )
        .map_err(|_| InternalPakeError::HkdfError)?;
    G::hash_to_scalar::<D>(&oprf_key_bytes[..], b"")
}

fn mask_response<CS: CipherSuite>(
    masking_key: &[u8],
    masking_nonce: &[u8],
    server_s_pk: &PublicKey,
    envelope: &Envelope<CS>,
) -> Result<Vec<u8>, ProtocolError> {
    let mut xor_pad = vec![0u8; <PublicKey as SizedBytes>::Len::to_usize() + Envelope::<CS>::len()];
    Hkdf::<CS::Hash>::from_prk(masking_key)
        .map_err(|_| InternalPakeError::HkdfError)?
        .expand(
            &[masking_nonce, STR_CREDENTIAL_RESPONSE_PAD].concat(),
            &mut xor_pad,
        )
        .map_err(|_| InternalPakeError::HkdfError)?;

    let plaintext = [&server_s_pk.to_arr()[..], &envelope.serialize()].concat();

    Ok(xor_pad
        .iter()
        .zip(plaintext.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect())
}

fn unmask_response<CS: CipherSuite>(
    masking_key: &[u8],
    masking_nonce: &[u8],
    masked_response: &[u8],
) -> Result<(PublicKey, Envelope<CS>), ProtocolError> {
    let mut xor_pad = vec![0u8; <PublicKey as SizedBytes>::Len::to_usize() + Envelope::<CS>::len()];
    Hkdf::<CS::Hash>::from_prk(masking_key)
        .map_err(|_| InternalPakeError::HkdfError)?
        .expand(
            &[masking_nonce, STR_CREDENTIAL_RESPONSE_PAD].concat(),
            &mut xor_pad,
        )
        .map_err(|_| InternalPakeError::HkdfError)?;
    let plaintext: Vec<u8> = xor_pad
        .iter()
        .zip(masked_response.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    let key_len = <PublicKey as SizedBytes>::Len::to_usize();
    let unchecked_server_s_pk =
        PublicKey::from_arr(&GenericArray::clone_from_slice(&plaintext[..key_len]))?;
    let envelope = Envelope::deserialize(&plaintext[key_len..])?;

    // Ensure that public key is valid
    let server_s_pk = KeyPair::<CS::Group>::check_public_key(unchecked_server_s_pk)
        .map_err(|_| ProtocolError::VerificationError(PakeError::SerializationError))?;

    Ok((server_s_pk, envelope))
}

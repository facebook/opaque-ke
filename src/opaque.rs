// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Provides the main OPAQUE API

use crate::{
    ciphersuite::CipherSuite,
    envelope::Envelope,
    errors::{utils::check_slice_size, InternalError, ProtocolError},
    group::Group,
    hash::Hash,
    key_exchange::traits::{FromBytes, KeyExchange, ToBytesWithPointers},
    keypair::{KeyPair, PrivateKey, PublicKey, SecretKey},
    oprf,
    serialization::{serialize, tokenize},
    slow_hash::SlowHash,
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    RegistrationResponse, RegistrationUpload,
};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

///////////////
// Constants //
// ========= //
///////////////

const STR_CREDENTIAL_RESPONSE_PAD: &[u8] = b"CredentialResponsePad";
const STR_MASKING_KEY: &[u8] = b"MaskingKey";
const STR_OPRF_KEY: &[u8] = b"OprfKey";
const STR_OPAQUE_DERIVE_KEY_PAIR: &[u8] = b"OPAQUE-DeriveKeyPair";

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
pub struct ServerSetup<
    CS: CipherSuite,
    S: SecretKey<CS::KeGroup> = PrivateKey<<CS as CipherSuite>::KeGroup>,
> {
    oprf_seed: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
    keypair: KeyPair<CS::KeGroup, S>,
    pub(crate) fake_keypair: KeyPair<CS::KeGroup>,
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

/// The state elements the client holds to register itself
pub struct ClientRegistration<CS: CipherSuite> {
    alpha: CS::OprfGroup,
    /// token containing the client's password and the blinding factor
    pub(crate) token: oprf::Token<CS::OprfGroup>,
}

impl_clone_for!(struct ClientRegistration<CS: CipherSuite>, [token, alpha]);
impl_debug_eq_hash_for!(
    struct ClientRegistration<CS: CipherSuite>,
    [token],
    [oprf::Token<CS::OprfGroup>],
);
impl_serialize_and_deserialize_for!(ClientRegistration);

/// The state elements the server holds to record a registration
pub struct ServerRegistration<CS: CipherSuite>(RegistrationUpload<CS>);

impl_clone_for!(tuple ServerRegistration<CS: CipherSuite>, [0]);
impl_debug_eq_hash_for!(
    tuple ServerRegistration<CS: CipherSuite>,
    [0],
);
impl_serialize_and_deserialize_for!(ServerRegistration);

/// The state elements the client holds to perform a login
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(
    feature = "serialize",
    serde(bound(
        deserialize = "oprf::Token<CS::OprfGroup>: serde::Deserialize<'de>, <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1State: serde::Deserialize<'de>",
        serialize = "oprf::Token<CS::OprfGroup>: serde::Serialize, <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1State: serde::Serialize"
    ))
)]
pub struct ClientLogin<CS: CipherSuite> {
    /// token containing the client's password and the blinding factor
    token: oprf::Token<CS::OprfGroup>,
    ke1_state: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1State,
    serialized_credential_request: Vec<u8>,
}

impl_clone_for!(struct ClientLogin<CS: CipherSuite>, [token, ke1_state, serialized_credential_request]);
impl_debug_eq_hash_for!(
    struct ClientLogin<CS: CipherSuite>,
    [token, ke1_state, serialized_credential_request],
    [oprf::Token<CS::OprfGroup>, <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1State],
);

/// The state elements the server holds to record a login
pub struct ServerLogin<CS: CipherSuite> {
    ke2_state: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE2State,
    _cs: PhantomData<CS>,
}

impl_clone_for!(struct ServerLogin<CS: CipherSuite>, [ke2_state, _cs]);
impl_debug_eq_hash_for!(
    struct ServerLogin<CS: CipherSuite>,
    [ke2_state, _cs],
    [<CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE2State],
);
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
        let keypair = KeyPair::<CS::KeGroup>::generate_random(rng);
        Self::new_with_key(rng, keypair)
    }
}

impl<CS: CipherSuite, S: SecretKey<CS::KeGroup>> ServerSetup<CS, S> {
    /// Create [`ServerSetup`] with the given keypair
    pub fn new_with_key<R: CryptoRng + RngCore>(
        rng: &mut R,
        keypair: KeyPair<CS::KeGroup, S>,
    ) -> Self {
        let mut seed = vec![0u8; <CS::Hash as Digest>::OutputSize::USIZE];
        rng.fill_bytes(&mut seed);

        Self {
            oprf_seed: GenericArray::clone_from_slice(&seed[..]),
            keypair,
            fake_keypair: KeyPair::<CS::KeGroup>::generate_random(rng),
        }
    }

    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        [
            self.oprf_seed.to_vec(),
            self.keypair.private().serialize(),
            self.fake_keypair.private().serialize(),
        ]
        .concat()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError<S::Error>> {
        let seed_len = <CS::Hash as Digest>::OutputSize::USIZE;
        let key_len = <CS::KeGroup as Group>::ScalarLen::USIZE;
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
    pub fn serialize(&self) -> Vec<u8> {
        [
            &self.alpha.to_arr().to_vec(),
            &CS::OprfGroup::scalar_as_bytes(self.token.blind)[..],
            &self.token.data,
        ]
        .concat()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let elem_len = <CS::OprfGroup as Group>::ElemLen::USIZE;
        let scalar_len = <CS::OprfGroup as Group>::ScalarLen::USIZE;
        let min_expected_len = elem_len + scalar_len;
        let checked_slice = (if input.len() <= min_expected_len {
            Err(InternalError::SizeError {
                name: "client_registration_bytes",
                len: min_expected_len,
                actual_len: input.len(),
            })
        } else {
            Ok(input)
        })?;

        let alpha = CS::OprfGroup::from_element_slice(GenericArray::from_slice(
            &checked_slice[..elem_len],
        ))?;

        // Check that the message is actually containing an element of the
        // correct subgroup
        let blinding_factor_bytes =
            GenericArray::from_slice(&checked_slice[elem_len..elem_len + scalar_len]);
        let blinding_factor = CS::OprfGroup::from_scalar_slice(blinding_factor_bytes)?;

        let password = checked_slice[elem_len + scalar_len..].to_vec();
        Ok(Self {
            alpha,
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

    /// Returns an initial "blinded" request to send to the server, as well as a ClientRegistration
    pub fn start<R: RngCore + CryptoRng>(
        blinding_factor_rng: &mut R,
        password: &[u8],
    ) -> Result<ClientRegistrationStartResult<CS>, ProtocolError> {
        let (token, alpha) =
            oprf::blind::<R, CS::OprfGroup, CS::Hash>(password, blinding_factor_rng)?;

        Ok(ClientRegistrationStartResult {
            message: RegistrationRequest::<CS> { alpha },
            state: Self { alpha, token },
        })
    }

    /// "Unblinds" the server's answer and returns a final message containing
    /// cryptographic identifiers, to be sent to the server on setup finalization
    pub fn finish<R: CryptoRng + RngCore>(
        self,
        rng: &mut R,
        r2: RegistrationResponse<CS>,
        params: ClientRegistrationFinishParameters<CS>,
    ) -> Result<ClientRegistrationFinishResult<CS>, ProtocolError> {
        // Check for reflected value from server and halt if detected
        if self.alpha.ct_equal(&r2.beta) {
            return Err(ProtocolError::ReflectedValueError);
        }

        let password_derived_key =
            get_password_derived_key::<CS>(&self.token, r2.beta, params.slow_hash)?;

        #[cfg_attr(not(test), allow(unused_variables))]
        let (randomized_pwd, h) = Hkdf::<CS::Hash>::extract(None, &password_derived_key);
        let mut masking_key = vec![0u8; <CS::Hash as Digest>::OutputSize::USIZE];
        h.expand(STR_MASKING_KEY, &mut masking_key)
            .map_err(|_| InternalError::HkdfError)?;

        let result = Envelope::<CS>::seal(
            rng,
            &password_derived_key,
            &r2.server_s_pk,
            params.identifiers,
        )?;

        Ok(ClientRegistrationFinishResult {
            message: RegistrationUpload {
                envelope: result.0,
                masking_key: GenericArray::clone_from_slice(&masking_key[..]),
                client_s_pk: result.1,
            },
            export_key: result.2,
            server_s_pk: r2.server_s_pk,
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
    pub fn start<S: SecretKey<CS::KeGroup>>(
        server_setup: &ServerSetup<CS, S>,
        message: RegistrationRequest<CS>,
        credential_identifier: &[u8],
    ) -> Result<ServerRegistrationStartResult<CS>, ProtocolError> {
        let oprf_key = oprf_key_from_seed::<CS::OprfGroup, CS::Hash>(
            &server_setup.oprf_seed,
            credential_identifier,
        )?;

        // Compute beta = alpha^oprf_key
        let beta = oprf::evaluate::<CS::OprfGroup>(message.alpha, &oprf_key);

        Ok(ServerRegistrationStartResult {
            message: RegistrationResponse {
                beta,
                server_s_pk: server_setup.keypair.public().clone(),
            },
            #[cfg(test)]
            oprf_key: CS::OprfGroup::scalar_as_bytes(oprf_key),
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
            &CS::OprfGroup::scalar_as_bytes(self.token.blind)[..],
            &serialize(&self.serialized_credential_request, 2)?,
            &serialize(&self.ke1_state.to_bytes(), 2)?,
            &self.token.data,
        ]
        .concat();
        Ok(output)
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let scalar_len = <CS::OprfGroup as Group>::ScalarLen::USIZE;
        let checked_slice = (if input.len() <= scalar_len {
            Err(InternalError::SizeError {
                name: "client_login_bytes",
                len: scalar_len,
                actual_len: input.len(),
            })
        } else {
            Ok(input)
        })?;

        let blinding_factor_bytes = GenericArray::from_slice(&checked_slice[..scalar_len]);
        let blinding_factor = CS::OprfGroup::from_scalar_slice(blinding_factor_bytes)?;

        let (serialized_credential_request, remainder) = tokenize(&checked_slice[scalar_len..], 2)?;
        let (ke1_state_bytes, password) = tokenize(&remainder, 2)?;

        let ke1_state =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1State::from_bytes::<CS>(
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

impl<CS: CipherSuite> ClientLogin<CS> {
    /// Returns an initial "blinded" password request to send to the server, as well as a ClientLogin
    pub fn start<R: RngCore + CryptoRng>(
        rng: &mut R,
        password: &[u8],
    ) -> Result<ClientLoginStartResult<CS>, ProtocolError> {
        let (token, alpha) = oprf::blind::<R, CS::OprfGroup, CS::Hash>(password, rng)?;

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
        params: ClientLoginFinishParameters<CS>,
    ) -> Result<ClientLoginFinishResult<CS>, ProtocolError> {
        // Check if beta value from server is equal to alpha value from client
        let credential_request =
            CredentialRequest::<CS>::deserialize(&self.serialized_credential_request[..])?;
        if credential_request.alpha.ct_equal(&credential_response.beta) {
            return Err(ProtocolError::ReflectedValueError);
        }

        let password_derived_key = get_password_derived_key::<CS>(
            &self.token,
            credential_response.beta,
            params.slow_hash,
        )?;

        let h = Hkdf::<CS::Hash>::new(None, &password_derived_key);
        let mut masking_key = vec![0u8; <CS::Hash as Digest>::OutputSize::USIZE];
        h.expand(STR_MASKING_KEY, &mut masking_key)
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
        let server_s_pk_bytes = server_s_pk.to_arr().to_vec();

        let opened_envelope = &envelope
            .open(
                &password_derived_key,
                &server_s_pk_bytes,
                &params.identifiers,
            )
            .map_err(|e| match e {
                ProtocolError::LibraryError(InternalError::SealOpenHmacError) => {
                    ProtocolError::InvalidLoginError
                }
                err => err,
            })?;

        let credential_response_component = CredentialResponse::<CS>::serialize_without_ke(
            &credential_response.beta,
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
            params.context.unwrap_or_default(),
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
    pub fn serialize(&self) -> Vec<u8> {
        self.ke2_state.to_bytes()
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
        l1: CredentialRequest<CS>,
        credential_identifier: &[u8],
        params: ServerLoginStartParameters,
    ) -> Result<ServerLoginStartResult<CS>, ProtocolError<S::Error>> {
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
        let server_s_pk = server_s_sk.public_key()?;

        let mut masking_nonce = vec![0u8; 32];
        rng.fill_bytes(&mut masking_nonce);

        let masked_response = mask_response(
            &record.0.masking_key,
            &masking_nonce,
            &server_s_pk,
            &record.0.envelope,
        )
        .map_err(ProtocolError::into_custom)?;

        let (id_u, id_s) = bytestrings_from_identifiers(
            &optional_ids,
            &client_s_pk.to_arr(),
            &server_s_pk.to_arr(),
        )
        .map_err(ProtocolError::into_custom)?;

        let l1_bytes = &l1.serialize();

        let oprf_key = oprf_key_from_seed::<CS::OprfGroup, CS::Hash>(
            &server_setup.oprf_seed,
            credential_identifier,
        )
        .map_err(ProtocolError::into_custom)?;
        let beta = oprf::evaluate(l1.alpha, &oprf_key);

        let credential_response_component =
            CredentialResponse::<CS>::serialize_without_ke(&beta, &masking_nonce, &masked_response);

        let result = CS::KeyExchange::generate_ke2(
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
            oprf_key: CS::OprfGroup::scalar_as_bytes(oprf_key),
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

    #[cfg(test)]
    pub fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        self.ke2_state.as_byte_ptrs()
    }
}

/////////////////////////
// Convenience Structs //
//==================== //
/////////////////////////

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

/// Optional parameters for client registration finish
#[derive(Clone)]
pub struct ClientRegistrationFinishParameters<'h, CS: CipherSuite> {
    /// Specifying the identifiers idU and idS
    pub identifiers: Option<Identifiers>,
    /// Specifying a configuration for the slow hash
    pub slow_hash: Option<&'h CS::SlowHash>,
}

impl<'h, CS: CipherSuite> Default for ClientRegistrationFinishParameters<'h, CS> {
    fn default() -> Self {
        Self {
            identifiers: None,
            slow_hash: None,
        }
    }
}

impl<'h, CS: CipherSuite> ClientRegistrationFinishParameters<'h, CS> {
    /// Create a new [`ClientRegistrationFinishParameters`]
    pub fn new(identifiers: Option<Identifiers>, slow_hash: Option<&'h CS::SlowHash>) -> Self {
        Self {
            identifiers,
            slow_hash,
        }
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

/// Contains the fields that are returned by a client registration finish
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

// Cannot be derived because it would require for CS to be Clone.
impl<CS: CipherSuite> Clone for ClientRegistrationFinishResult<CS> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
            export_key: self.export_key.clone(),
            server_s_pk: self.server_s_pk.clone(),
            #[cfg(test)]
            state: self.state.clone(),
            #[cfg(test)]
            auth_key: self.auth_key.clone(),
            #[cfg(test)]
            randomized_pwd: self.randomized_pwd.clone(),
        }
    }
}

/// Contains the fields that are returned by a server registration start.
/// Note that there is no state output in this step
pub struct ServerRegistrationStartResult<CS: CipherSuite> {
    /// The registration resposne message to send to the client
    pub message: RegistrationResponse<CS>,
    /// OPRF key, only used in tests
    #[cfg(test)]
    pub oprf_key: GenericArray<u8, <CS::OprfGroup as Group>::ScalarLen>,
}

// Cannot be derived because it would require for CS to be Clone.
impl<CS: CipherSuite> Clone for ServerRegistrationStartResult<CS> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
            #[cfg(test)]
            oprf_key: self.oprf_key.clone(),
        }
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
pub struct ClientLoginFinishParameters<'h, CS: CipherSuite> {
    /// Specifying a context field that the server must agree on
    pub context: Option<Vec<u8>>,
    /// Specifying a user identifier and server identifier that will be matched against the server
    pub identifiers: Option<Identifiers>,
    /// Specifying a configuration for the slow hash
    pub slow_hash: Option<&'h CS::SlowHash>,
}

impl<'h, CS: CipherSuite> Default for ClientLoginFinishParameters<'h, CS> {
    fn default() -> Self {
        Self {
            context: None,
            identifiers: None,
            slow_hash: None,
        }
    }
}

impl<'h, CS: CipherSuite> ClientLoginFinishParameters<'h, CS> {
    /// Create a new [`ClientLoginFinishParameters`]
    pub fn new(
        context: Option<Vec<u8>>,
        identifiers: Option<Identifiers>,
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
            #[cfg(test)]
            handshake_secret: self.handshake_secret.clone(),
            #[cfg(test)]
            client_mac_key: self.client_mac_key.clone(),
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

// Cannot be derived because it would require for CS to be Clone.
impl<CS: CipherSuite> Clone for ServerLoginStartResult<CS> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
            state: self.state.clone(),
            #[cfg(test)]
            handshake_secret: self.handshake_secret.clone(),
            #[cfg(test)]
            server_mac_key: self.server_mac_key.clone(),
            #[cfg(test)]
            oprf_key: self.oprf_key.clone(),
        }
    }
}

////////////////////////////////////////////////
// Helper functions and Trait Implementations //
// ========================================== //
////////////////////////////////////////////////

// Helper functions

fn get_password_derived_key<CS: CipherSuite>(
    token: &oprf::Token<CS::OprfGroup>,
    beta: CS::OprfGroup,
    slow_hash: Option<&CS::SlowHash>,
) -> Result<Vec<u8>, ProtocolError> {
    let oprf_output = oprf::finalize::<CS::OprfGroup, CS::Hash>(&token.data, &token.blind, beta)?;

    if let Some(slow_hash) = slow_hash {
        slow_hash.hash(oprf_output)
    } else {
        CS::SlowHash::default().hash(oprf_output)
    }
    .map_err(ProtocolError::from)
}

fn oprf_key_from_seed<G: Group, D: Hash>(
    oprf_seed: &GenericArray<u8, D::OutputSize>,
    credential_identifier: &[u8],
) -> Result<G::Scalar, ProtocolError> {
    let mut ikm = vec![0u8; G::ScalarLen::USIZE];
    Hkdf::<D>::from_prk(oprf_seed)
        .map_err(|_| InternalError::HkdfError)?
        .expand(&[credential_identifier, STR_OPRF_KEY].concat(), &mut ikm)
        .map_err(|_| InternalError::HkdfError)?;
    G::hash_to_scalar::<D>(&ikm[..], STR_OPAQUE_DERIVE_KEY_PAIR)
}

fn mask_response<CS: CipherSuite>(
    masking_key: &[u8],
    masking_nonce: &[u8],
    server_s_pk: &PublicKey<CS::KeGroup>,
    envelope: &Envelope<CS>,
) -> Result<Vec<u8>, ProtocolError> {
    let mut xor_pad = vec![0u8; <CS::KeGroup as Group>::ElemLen::USIZE + Envelope::<CS>::len()];
    Hkdf::<CS::Hash>::from_prk(masking_key)
        .map_err(|_| InternalError::HkdfError)?
        .expand(
            &[masking_nonce, STR_CREDENTIAL_RESPONSE_PAD].concat(),
            &mut xor_pad,
        )
        .map_err(|_| InternalError::HkdfError)?;

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
) -> Result<(PublicKey<CS::KeGroup>, Envelope<CS>), ProtocolError> {
    let mut xor_pad = vec![0u8; <CS::KeGroup as Group>::ElemLen::USIZE + Envelope::<CS>::len()];
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
    let key_len = <CS::KeGroup as Group>::ElemLen::USIZE;
    let unchecked_server_s_pk = PublicKey::from_bytes(&plaintext[..key_len])?;
    let envelope = Envelope::deserialize(&plaintext[key_len..])?;

    // Ensure that public key is valid
    let server_s_pk = KeyPair::<CS::KeGroup>::check_public_key(unchecked_server_s_pk)
        .map_err(|_| ProtocolError::SerializationError)?;

    Ok((server_s_pk, envelope))
}

pub(crate) fn bytestrings_from_identifiers(
    ids: &Option<Identifiers>,
    client_s_pk: &[u8],
    server_s_pk: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let (client_identity, server_identity): (Vec<u8>, Vec<u8>) = match ids {
        None => (client_s_pk.to_vec(), server_s_pk.to_vec()),
        Some(Identifiers::ClientIdentifier(id_u)) => (id_u.clone(), server_s_pk.to_vec()),
        Some(Identifiers::ServerIdentifier(id_s)) => (client_s_pk.to_vec(), id_s.clone()),
        Some(Identifiers::ClientAndServerIdentifiers(id_u, id_s)) => (id_u.clone(), id_s.clone()),
    };
    Ok((
        serialize(&client_identity, 2)?,
        serialize(&server_identity, 2)?,
    ))
}

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

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Provides the main OPAQUE API

use crate::{
    ciphersuite::CipherSuite,
    envelope::{Envelope, EnvelopeCredentialsFormat, ExportKeySize},
    errors::{utils::check_slice_size_atleast, InternalPakeError, PakeError, ProtocolError},
    group::Group,
    hash::Hash,
    key_exchange::traits::{KeyExchange, ToBytes},
    keypair::{KeyPair, SizedBytesExt},
    map_to_curve::GroupWithMapToCurve,
    oprf,
    serialization::CredentialType,
    slow_hash::SlowHash,
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    RegistrationResponse, RegistrationUpload,
};
use generic_array::{typenum::Unsigned, GenericArray};
use generic_bytes::SizedBytes;
use rand_core::{CryptoRng, RngCore};
use std::collections::HashMap;
use std::{convert::TryFrom, marker::PhantomData};
use zeroize::Zeroize;

static STR_OPAQUE_VERSION: &[u8] = b"OPAQUE00";

// Registration
// ============

/// The state elements the client holds to register itself
pub struct ClientRegistration<CS: CipherSuite> {
    /// token containing the client's password and the blinding factor
    pub(crate) token: oprf::Token<CS::Group>,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for ClientRegistration<CS> {
    type Error = ProtocolError;
    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
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
}

impl<CS: CipherSuite> ClientRegistration<CS> {
    /// byte representation for the client's registration state
    pub fn to_bytes(&self) -> Vec<u8> {
        let output: Vec<u8> = [
            &CS::Group::scalar_as_bytes(&self.token.blind)[..],
            &self.token.data,
        ]
        .concat();
        output
    }
}

/// Optional parameters for client registration finish
pub enum ClientRegistrationFinishParameters {
    /// Specifying the identifiers idU and idS
    WithIdentifiers(Vec<u8>, Vec<u8>),
}

impl Default for ClientRegistrationFinishParameters {
    fn default() -> Self {
        Self::WithIdentifiers(Vec::new(), Vec::new())
    }
}

/// Contains the fields that are returned by a client registration start
pub struct ClientRegistrationStartResult<CS: CipherSuite> {
    /// The registration request message to be sent to the server
    pub message: RegistrationRequest<CS::Group>,
    /// The client state that must be persisted in order to complete registration
    pub state: ClientRegistration<CS>,
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
    /// use opaque_ke::ClientRegistration;
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
    /// let client_registration_start_result = ClientRegistration::<Default>::start(&mut client_rng, b"hunter2")?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        blinding_factor_rng: &mut R,
        password: &[u8],
        #[cfg(test)] postprocess: fn(<CS::Group as Group>::Scalar) -> <CS::Group as Group>::Scalar,
    ) -> Result<ClientRegistrationStartResult<CS>, ProtocolError> {
        let (token, alpha) = oprf::blind::<R, CS::Group, CS::Hash>(
            &password,
            blinding_factor_rng,
            #[cfg(test)]
            postprocess,
        )?;

        Ok(ClientRegistrationStartResult {
            message: RegistrationRequest::<CS::Group> { alpha },
            state: Self { token },
        })
    }
}

/// Contains the fields that are returned by a client registration finish
pub struct ClientRegistrationFinishResult<KeyFormat: KeyPair, D: Hash> {
    /// The registration upload message to be sent to the server
    pub message: RegistrationUpload<KeyFormat, D>,
    /// The export key output by client registration
    pub export_key: GenericArray<u8, ExportKeySize>,
}

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
    /// use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, keypair::X25519KeyPair};
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
    /// let client_registration_start_result = ClientRegistration::<Default>::start(&mut client_rng, b"hunter2")?;
    /// let server_registration_start_result =
    /// ServerRegistration::<Default>::start(&mut server_rng, client_registration_start_result.message, server_kp.public())?;
    /// let mut client_rng = OsRng;
    /// let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message, ClientRegistrationFinishParameters::default())?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn finish<R: CryptoRng + RngCore>(
        self,
        rng: &mut R,
        r2: RegistrationResponse<CS::Group>,
        params: ClientRegistrationFinishParameters,
    ) -> Result<ClientRegistrationFinishResult<CS::KeyFormat, CS::Hash>, ProtocolError> {
        let (id_u, id_s) = match params {
            ClientRegistrationFinishParameters::WithIdentifiers(id_u, id_s) => (id_u, id_s),
        };
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
        credentials_map.insert(CredentialType::IdU, id_u);
        credentials_map.insert(CredentialType::IdS, id_s);

        let (envelope, export_key) =
            Envelope::<CS::Hash>::seal(&password_derived_key, r2.ecf, credentials_map, rng)?;

        Ok(ClientRegistrationFinishResult {
            message: RegistrationUpload {
                envelope,
                client_s_pk: client_static_keypair.public().clone(),
            },
            export_key,
        })
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

/// Contains the fields that are returned by a server registration start
pub struct ServerRegistrationStartResult<CS: CipherSuite> {
    /// The registration resposne message to send to the client
    pub message: RegistrationResponse<CS::Group>,
    /// The state that the server must keep in order to complete registration
    pub state: ServerRegistration<CS>,
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
    /// use opaque_ke::{*, keypair::{KeyPair, X25519KeyPair}};
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
    /// let client_registration_start_result = ClientRegistration::<Default>::start(&mut client_rng, b"hunter2")?;
    /// let server_registration_start_result = ServerRegistration::<Default>::start(&mut server_rng, client_registration_start_result.message, server_kp.public())?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        rng: &mut R,
        message: RegistrationRequest<CS::Group>,
        server_s_pk: &<CS::KeyFormat as KeyPair>::Repr,
    ) -> Result<ServerRegistrationStartResult<CS>, ProtocolError> {
        // RFC: generate oprf_key (salt) and v_u = g^oprf_key
        let oprf_key = CS::Group::random_scalar(rng);

        // Compute beta = alpha^oprf_key
        let beta = oprf::evaluate::<CS::Group>(message.alpha, &oprf_key);

        Ok(ServerRegistrationStartResult {
            message: RegistrationResponse {
                beta,
                server_s_pk: server_s_pk.to_arr().to_vec(),
                ecf: EnvelopeCredentialsFormat::default()?,
            },
            state: Self {
                envelope: None,
                client_s_pk: None,
                oprf_key,
            },
        })
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
    /// use opaque_ke::{*, keypair::{KeyPair, X25519KeyPair}};
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
    /// let client_registration_start_result = ClientRegistration::<Default>::start(&mut client_rng, b"hunter2")?;
    /// let server_registration_start_result = ServerRegistration::<Default>::start(&mut server_rng, client_registration_start_result.message, server_kp.public())?;
    /// let mut client_rng = OsRng;
    /// let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message, ClientRegistrationFinishParameters::default())?;
    /// let client_record = server_registration_start_result.state.finish(client_registration_finish_result.message)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn finish(
        self,
        message: RegistrationUpload<CS::KeyFormat, CS::Hash>,
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
    /// token containing the client's password and the blinding factor
    token: oprf::Token<CS::Group>,
    ke1_state: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE1State,
}

impl<CS: CipherSuite> TryFrom<&[u8]> for ClientLogin<CS> {
    type Error = ProtocolError;
    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let scalar_len = <CS::Group as Group>::ScalarLen::to_usize();
        let ke1_state_size =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::ke1_state_size();

        let min_expected_len = scalar_len + ke1_state_size;
        let checked_slice = (if input.len() <= min_expected_len {
            Err(InternalPakeError::SizeError {
                name: "client_login_bytes",
                len: min_expected_len,
                actual_len: input.len(),
            })
        } else {
            Ok(input.clone())
        })?;

        let blinding_factor_bytes = GenericArray::from_slice(&checked_slice[..scalar_len]);
        let blinding_factor = CS::Group::from_scalar_slice(blinding_factor_bytes)?;
        let ke1_state =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::KE1State::try_from(
                &checked_slice[scalar_len..scalar_len + ke1_state_size],
            )?;
        let password = input[scalar_len + ke1_state_size..].to_vec();
        Ok(Self {
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
            &CS::Group::scalar_as_bytes(&self.token.blind)[..],
            &self.ke1_state.to_bytes(),
            &self.token.data,
        ]
        .concat();
        output
    }
}

/// Optional parameters for client login start
pub enum ClientLoginStartParameters {
    /// Specifying an info field that will be sent to the server
    WithInfo(Vec<u8>),
}

impl Default for ClientLoginStartParameters {
    fn default() -> Self {
        Self::WithInfo(Vec::new())
    }
}

/// Contains the fields that are returned by a client login start
pub struct ClientLoginStartResult<CS: CipherSuite> {
    /// The message to send to the server to begin the login protocol
    pub message: CredentialRequest<CS>,
    /// The state that the client must keep in order to complete the protocol
    pub state: ClientLogin<CS>,
}

/// Optional parameters for client login finish
pub enum ClientLoginFinishParameters {
    /// Specifying an info and confidential info field that will be sent to the server
    WithInfo(Vec<u8>, Vec<u8>),
    /// Specifying an info, confidential info that will be sent to the server,
    /// along with an id_u and id_s that will be matched against the server
    WithInfoAndIdentifiers(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
}

impl Default for ClientLoginFinishParameters {
    fn default() -> Self {
        Self::WithInfoAndIdentifiers(Vec::new(), Vec::new(), Vec::new(), Vec::new())
    }
}

/// Contains the fields that are returned by a client login finish
pub struct ClientLoginFinishResult<CS: CipherSuite> {
    /// The message to send to the server to complete the protocol
    pub message: CredentialFinalization<CS>,
    /// The shared session secret
    pub shared_secret: Vec<u8>,
    /// The client-side export key
    pub export_key: GenericArray<u8, ExportKeySize>,
    /// The server's static public key
    pub server_s_pk: Vec<u8>,
    /// An optional id_s if supplied by the server
    pub id_s: Option<Vec<u8>>,
    /// The plaintext info sent by the client
    pub plain_info: Vec<u8>,
    /// The confidential info sent by the client
    pub confidential_info: Vec<u8>,
}

impl<CS: CipherSuite> ClientLogin<CS> {
    /// Returns an initial "blinded" password request to send to the server, as well as a ClientLogin
    ///
    /// # Arguments
    /// * `password` - A user password
    ///
    /// # Example
    ///
    /// ```
    /// use opaque_ke::{ClientLogin, ClientLoginStartParameters};
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
    /// let client_login_start_result = ClientLogin::<Default>::start(&mut client_rng, b"hunter2", ClientLoginStartParameters::default())?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        rng: &mut R,
        password: &[u8],
        params: ClientLoginStartParameters,
        #[cfg(test)] postprocess: fn(<CS::Group as Group>::Scalar) -> <CS::Group as Group>::Scalar,
    ) -> Result<ClientLoginStartResult<CS>, ProtocolError> {
        let info = match params {
            ClientLoginStartParameters::WithInfo(info) => info,
        };

        let (token, alpha) = oprf::blind::<R, CS::Group, CS::Hash>(
            &password,
            rng,
            #[cfg(test)]
            postprocess,
        )?;

        let (ke1_state, ke1_message) =
            CS::KeyExchange::generate_ke1(alpha.to_arr().to_vec(), info, rng)?;

        let l1 = CredentialRequest { alpha, ke1_message };

        Ok(ClientLoginStartResult {
            message: l1,
            state: Self { token, ke1_state },
        })
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
    /// use opaque_ke::{ClientLogin, ClientLoginStartParameters, ClientLoginFinishParameters, ServerLogin, ServerLoginStartParameters};
    /// # use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration};
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
    /// # let client_registration_start_result = ClientRegistration::<Default>::start(&mut client_rng, b"hunter2")?;
    /// # let server_kp = X25519KeyPair::generate_random(&mut server_rng)?;
    /// # let server_registration_start_result = ServerRegistration::<Default>::start(&mut server_rng, client_registration_start_result.message, server_kp.public())?;
    /// # let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message, ClientRegistrationFinishParameters::default())?;
    /// # let p_file = server_registration_start_result.state.finish(client_registration_finish_result.message)?;
    /// let client_login_start_result = ClientLogin::<Default>::start(&mut client_rng, b"hunter2", ClientLoginStartParameters::default())?;
    /// let server_login_start_result = ServerLogin::start(&mut server_rng, p_file, &server_kp.private(), client_login_start_result.message, ServerLoginStartParameters::default())?;
    /// let client_login_finish_result = client_login_start_result.state.finish(server_login_start_result.message, ClientLoginFinishParameters::default())?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn finish(
        self,
        l2: CredentialResponse<CS>,
        params: ClientLoginFinishParameters,
    ) -> Result<ClientLoginFinishResult<CS>, ProtocolError> {
        let (info, e_info, _id_u, _id_s) = match params {
            ClientLoginFinishParameters::WithInfo(info, e_info) => {
                (info, e_info, Vec::new(), Vec::new())
            }
            ClientLoginFinishParameters::WithInfoAndIdentifiers(info, e_info, id_u, id_s) => {
                (info, e_info, id_u, id_s)
            }
        };

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

        let client_s_sk = <CS::KeyFormat as KeyPair>::Repr::from_bytes(
            &opened_envelope.credentials_map[&CredentialType::SkU],
        )?;
        let server_s_pk = <CS::KeyFormat as KeyPair>::Repr::from_bytes(
            &opened_envelope.credentials_map[&CredentialType::PkS],
        )?;

        let id_u = match opened_envelope.credentials_map.get(&CredentialType::IdU) {
            Some(id_u) => id_u.clone(),
            None => CS::KeyFormat::public_from_private(&client_s_sk)
                .to_arr()
                .to_vec(),
        };

        let (id_s, ret_id_s) = match opened_envelope.credentials_map.get(&CredentialType::IdS) {
            Some(id_s) => (id_s.clone(), Some(id_s.clone())),
            None => (server_s_pk.to_arr().to_vec(), None),
        };

        let (plain_info, confidential_info, shared_secret, ke3_message) =
            CS::KeyExchange::generate_ke3(
                l2_bytes,
                l2.ke2_message,
                &self.ke1_state,
                server_s_pk.clone(),
                client_s_sk,
                id_u,
                id_s,
                info,
                e_info,
            )?;

        Ok(ClientLoginFinishResult {
            plain_info,
            confidential_info,
            message: CredentialFinalization { ke3_message },
            shared_secret,
            export_key: opened_envelope.export_key,
            server_s_pk: server_s_pk.to_arr().to_vec(),
            id_s: ret_id_s,
        })
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

/// Optional parameters for server login start
pub enum ServerLoginStartParameters {
    /// Specifying an info and confidential info field that will be sent to the client
    WithInfo(Vec<u8>, Vec<u8>),
    /// Specifying an info, confidential info that will be sent to the client,
    /// along with an id_u and id_s that will be matched against the client
    WithInfoAndIdentifiers(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
}

impl Default for ServerLoginStartParameters {
    fn default() -> Self {
        Self::WithInfo(Vec::new(), Vec::new())
    }
}

/// Contains the fields that are returned by a server login start
pub struct ServerLoginStartResult<CS: CipherSuite> {
    /// The message to send back to the client
    pub message: CredentialResponse<CS>,
    /// The state that the server must keep in order to finish the protocl
    pub state: ServerLogin<CS>,
    /// The client's static public key
    pub client_s_pk: Vec<u8>,
    /// The plaintext info sent by the client
    pub plain_info: Vec<u8>,
}

/// Contains the fields that are returned by a server login finish
pub struct ServerLoginFinishResult {
    /// The shared session secret between client and server
    pub shared_secret: Vec<u8>,
    /// The plaintext info sent by the client
    pub plain_info: Vec<u8>,
    /// The confidential info sent by the client
    pub confidential_info: Vec<u8>,
}

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
    /// use opaque_ke::{ClientLogin, ClientLoginStartParameters, ServerLogin, ServerLoginStartParameters};
    /// # use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration};
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
    /// # let client_registration_start_result = ClientRegistration::<Default>::start(&mut client_rng, b"hunter2")?;
    /// # let server_registration_start_result = ServerRegistration::<Default>::start(&mut server_rng, client_registration_start_result.message, server_kp.public())?;
    /// # let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message, ClientRegistrationFinishParameters::default())?;
    /// # let p_file = server_registration_start_result.state.finish(client_registration_finish_result.message)?;
    /// let client_login_start_result = ClientLogin::<Default>::start(&mut client_rng, b"hunter2", ClientLoginStartParameters::default())?;
    /// let server_login_start_result = ServerLogin::start(&mut server_rng, p_file, &server_kp.private(), client_login_start_result.message, ServerLoginStartParameters::default())?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        rng: &mut R,
        password_file: ServerRegistration<CS>,
        server_s_sk: &<CS::KeyFormat as KeyPair>::Repr,
        l1: CredentialRequest<CS>,
        params: ServerLoginStartParameters,
    ) -> Result<ServerLoginStartResult<CS>, ProtocolError> {
        let client_s_pk = password_file
            .client_s_pk
            .ok_or(InternalPakeError::SealError)?;

        let (info, e_info, id_u, id_s) = match params {
            ServerLoginStartParameters::WithInfo(info, e_info) => (info, e_info, None, None),
            ServerLoginStartParameters::WithInfoAndIdentifiers(info, e_info, id_u, id_s) => {
                (info, e_info, Some(id_u), Some(id_s))
            }
        };

        let id_u = match id_u {
            Some(id_u) => id_u,
            None => client_s_pk.to_arr().to_vec(),
        };

        let id_s = match id_s {
            Some(id_s) => id_s,
            None => CS::KeyFormat::public_from_private(server_s_sk)
                .to_arr()
                .to_vec(),
        };

        let l1_bytes = &l1.to_bytes();
        let beta = oprf::evaluate(l1.alpha, &password_file.oprf_key);
        let envelope = password_file.envelope.ok_or(InternalPakeError::SealError)?;
        let l2_component: Vec<u8> = [&beta.to_arr()[..], &envelope.to_bytes()].concat();

        let (plain_info, ke2_state, ke2_message) = CS::KeyExchange::generate_ke2(
            rng,
            l1_bytes.to_vec(),
            l2_component,
            l1.ke1_message,
            client_s_pk.clone(),
            server_s_sk.clone(),
            id_u,
            id_s,
            info,
            e_info,
        )?;

        let l2 = CredentialResponse {
            beta,
            envelope,
            ke2_message,
        };

        Ok(ServerLoginStartResult {
            plain_info,
            message: l2,
            state: Self {
                _cs: PhantomData,
                ke2_state,
            },
            client_s_pk: client_s_pk.to_arr().to_vec(),
        })
    }

    /// From the client's second and final message, check the client's
    /// authentication and produce a message transport
    ///
    /// # Arguments
    /// * `message` - the client's second login message
    ///
    /// # Example
    ///
    /// ```
    /// use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientLoginStartParameters, ServerLogin, ServerLoginStartParameters};
    /// # use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration};
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
    /// # let client_registration_start_result = ClientRegistration::<Default>::start(&mut client_rng, b"hunter2")?;
    /// # let server_registration_start_result = ServerRegistration::<Default>::start(&mut server_rng, client_registration_start_result.message, server_kp.public())?;
    /// # let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message, ClientRegistrationFinishParameters::default())?;
    /// # let p_file = server_registration_start_result.state.finish(client_registration_finish_result.message)?;
    /// let client_login_start_result = ClientLogin::<Default>::start(&mut client_rng, b"hunter2", ClientLoginStartParameters::default())?;
    /// let server_login_start_result = ServerLogin::start(&mut server_rng, p_file, &server_kp.private(), client_login_start_result.message, ServerLoginStartParameters::default())?;
    /// let client_login_finish_result = client_login_start_result.state.finish(server_login_start_result.message, ClientLoginFinishParameters::default())?;
    /// let mut server_transport = server_login_start_result.state.finish(client_login_finish_result.message)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn finish(
        &self,
        message: CredentialFinalization<CS>,
    ) -> Result<ServerLoginFinishResult, ProtocolError> {
        let (plain_info, confidential_info, shared_secret) =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeyFormat>>::finish_ke(
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
            plain_info,
            confidential_info,
            shared_secret,
        })
    }
}

// Helper functions
fn get_password_derived_key<G: GroupWithMapToCurve, SH: SlowHash<D>, D: Hash>(
    token: &oprf::Token<G>,
    beta: G,
) -> Result<Vec<u8>, InternalPakeError> {
    let oprf_output = oprf::finalize::<G, D>(
        &token.data,
        &oprf::unblind::<G>(token, beta),
        STR_OPAQUE_VERSION,
    );
    SH::hash(oprf_output)
}

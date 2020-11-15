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
    serialization::{serialize, tokenize, CredentialType},
    slow_hash::SlowHash,
    LoginFirstMessage, LoginSecondMessage, LoginThirdMessage, RegisterFirstMessage,
    RegisterSecondMessage, RegisterThirdMessage,
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
        let (id_u, bytes) = tokenize(&input, 2)?;
        let (id_s, bytes) = tokenize(&bytes, 2)?;

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

/// Optional parameters for client registration start
pub enum ClientRegistrationStartParameters {
    /// Specifying the identifiers idU and idS
    WithIdentifiers(Vec<u8>, Vec<u8>),
}

impl Default for ClientRegistrationStartParameters {
    fn default() -> Self {
        Self::WithIdentifiers(Vec::new(), Vec::new())
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
    /// use opaque_ke::{ClientRegistration, ClientRegistrationStartParameters};
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
    /// let (register_m1, registration_state) = ClientRegistration::<Default>::start(b"hunter2", ClientRegistrationStartParameters::default(), &mut client_rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        password: &[u8],
        params: ClientRegistrationStartParameters,
        blinding_factor_rng: &mut R,
        #[cfg(test)] postprocess: fn(<CS::Group as Group>::Scalar) -> <CS::Group as Group>::Scalar,
    ) -> Result<(RegisterFirstMessage<CS::Group>, Self), ProtocolError> {
        let (id_u, id_s) = match params {
            ClientRegistrationStartParameters::WithIdentifiers(id_u, id_s) => (id_u, id_s),
        };

        let (token, alpha) = oprf::blind::<R, CS::Group>(
            &password,
            blinding_factor_rng,
            #[cfg(test)]
            postprocess,
        )?;

        Ok((
            RegisterFirstMessage::<CS::Group> { alpha },
            Self { id_u, id_s, token },
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
    /// use opaque_ke::{ClientRegistration, ClientRegistrationStartParameters, ServerRegistration, keypair::X25519KeyPair};
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
    /// let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", ClientRegistrationStartParameters::default(), &mut client_rng)?;
    /// let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, server_kp.public(), &mut server_rng)?;
    /// let mut client_rng = OsRng;
    /// let register_m3 = client_state.finish(register_m2, &mut client_rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn finish<R: CryptoRng + RngCore>(
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
    /// let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", ClientRegistrationStartParameters::default(), &mut client_rng)?;
    /// let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, server_kp.public(), &mut server_rng)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        message: RegisterFirstMessage<CS::Group>,
        server_s_pk: &<CS::KeyFormat as KeyPair>::Repr,
        rng: &mut R,
    ) -> Result<(RegisterSecondMessage<CS::Group>, Self), ProtocolError> {
        // RFC: generate oprf_key (salt) and v_u = g^oprf_key
        let oprf_key = CS::Group::random_scalar(rng);

        // Compute beta = alpha^oprf_key
        let beta = oprf::evaluate::<CS::Group>(message.alpha, &oprf_key)?;

        Ok((
            RegisterSecondMessage {
                beta,
                server_s_pk: server_s_pk.to_arr().to_vec(),
                ecf: EnvelopeCredentialsFormat::default()?,
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
    /// let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", ClientRegistrationStartParameters::default(), &mut client_rng)?;
    /// let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, server_kp.public(), &mut server_rng)?;
    /// let mut client_rng = OsRng;
    /// let (register_m3, _export_key) = client_state.finish(register_m2, &mut client_rng)?;
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
        let (id_u, bytes) = tokenize(&input, 2)?;
        let (id_s, bytes) = tokenize(&bytes, 2)?;

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

/// Optional parameters for client login start
pub enum ClientLoginStartParameters {
    /// Specifying an info field that will be sent to the server
    WithInfo(Vec<u8>),
    /// Specifying the info field along with idU and idS
    WithIdentifiersAndInfo(Vec<u8>, Vec<u8>, Vec<u8>),
}

impl Default for ClientLoginStartParameters {
    fn default() -> Self {
        Self::WithIdentifiersAndInfo(Vec::new(), Vec::new(), Vec::new())
    }
}

/// Contains the fields that are returned by a client login start
pub struct ClientLoginStartResult<CS: CipherSuite> {
    /// The message to send to the server to begin the login protocol
    pub credential_request: LoginFirstMessage<CS>,
    /// The state that the client must keep in order to complete the protocol
    pub client_login_state: ClientLogin<CS>,
}

/// Optional parameters for client login finish
pub enum ClientLoginFinishParameters {
    /// Specifying an info and confidential info field that will be sent to the server
    WithInfo(Vec<u8>, Vec<u8>),
}

impl Default for ClientLoginFinishParameters {
    fn default() -> Self {
        Self::WithInfo(Vec::new(), Vec::new())
    }
}

/// Contains the fields that are returned by a client login finish
pub struct ClientLoginFinishResult<CS: CipherSuite> {
    /// The plaintext info sent by the client
    pub plain_info: Vec<u8>,
    /// The message to send back to the client
    pub confidential_info: Vec<u8>,
    /// The message to send to the server to complete the protocol
    pub key_exchange: LoginThirdMessage<CS>,
    /// The shared session secret
    pub session_secret: Vec<u8>,
    /// The client-side export key
    pub export_key: GenericArray<u8, ExportKeySize>,
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
    /// let client_login_start_result = ClientLogin::<Default>::start(b"hunter2", &mut client_rng, ClientLoginStartParameters::default())?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        password: &[u8],
        rng: &mut R,
        params: ClientLoginStartParameters,
        #[cfg(test)] postprocess: fn(<CS::Group as Group>::Scalar) -> <CS::Group as Group>::Scalar,
    ) -> Result<ClientLoginStartResult<CS>, ProtocolError> {
        let (info, id_u, id_s) = match params {
            ClientLoginStartParameters::WithInfo(info) => (info, Vec::new(), Vec::new()),
            ClientLoginStartParameters::WithIdentifiersAndInfo(info, id_u, id_s) => {
                (info, id_u, id_s)
            }
        };

        let (token, alpha) = oprf::blind::<R, CS::Group>(
            &password,
            rng,
            #[cfg(test)]
            postprocess,
        )?;

        let (ke1_state, ke1_message) =
            CS::KeyExchange::generate_ke1(alpha.to_arr().to_vec(), info, rng)?;

        let l1 = LoginFirstMessage { alpha, ke1_message };

        Ok(ClientLoginStartResult {
            credential_request: l1,
            client_login_state: Self {
                id_u,
                id_s,
                token,
                ke1_state,
            },
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
    /// # use opaque_ke::{ClientRegistration, ClientRegistrationStartParameters, ServerRegistration};
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
    /// # let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", ClientRegistrationStartParameters::default(), &mut client_rng)?;
    /// # let server_kp = X25519KeyPair::generate_random(&mut server_rng)?;
    /// # let (register_m2, server_state) = ServerRegistration::<Default>::start(register_m1, server_kp.public(), &mut server_rng)?;
    /// # let (register_m3, _export_key) = client_state.finish(register_m2, &mut client_rng)?;
    /// # let p_file = server_state.finish(register_m3)?;
    /// let client_login_start_result = ClientLogin::<Default>::start(b"hunter2", &mut client_rng, ClientLoginStartParameters::default())?;
    /// let server_login_start_result = ServerLogin::start(p_file, &server_kp.private(), client_login_start_result.credential_request, &mut server_rng, ServerLoginStartParameters::default())?;
    /// let client_login_finish_result = client_login_start_result.client_login_state.finish(server_login_start_result.credential_response, ClientLoginFinishParameters::default())?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn finish(
        self,
        l2: LoginSecondMessage<CS>,
        params: ClientLoginFinishParameters,
    ) -> Result<ClientLoginFinishResult<CS>, ProtocolError> {
        let (info, e_info) = match params {
            ClientLoginFinishParameters::WithInfo(info, e_info) => (info, e_info),
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

        let id_s = match opened_envelope.credentials_map.get(&CredentialType::IdS) {
            Some(id_s) => id_s.clone(),
            None => server_s_pk.to_arr().to_vec(),
        };

        let (plain_info, confidential_info, session_secret, ke3_message) =
            CS::KeyExchange::generate_ke3(
                l2_bytes,
                l2.ke2_message,
                &self.ke1_state,
                server_s_pk,
                client_s_sk,
                id_u,
                id_s,
                info,
                e_info,
            )?;

        Ok(ClientLoginFinishResult {
            plain_info,
            confidential_info,
            key_exchange: LoginThirdMessage { ke3_message },
            session_secret,
            export_key: opened_envelope.export_key,
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
    /// The plaintext info sent by the client
    pub plain_info: Vec<u8>,
    /// The message to send back to the client
    pub credential_response: LoginSecondMessage<CS>,
    /// The state that the server must keep in order to finish the protocl
    pub server_login_state: ServerLogin<CS>,
}

/// Contains the fields that are returned by a server login finish
pub struct ServerLoginFinishResult {
    /// The plaintext info sent by the client
    pub plain_info: Vec<u8>,
    /// The confidential info sent by the client
    pub confidential_info: Vec<u8>,
    /// The shared session secret between client and server
    pub session_secret: Vec<u8>,
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
    /// # use opaque_ke::{ClientRegistration, ClientRegistrationStartParameters, ServerRegistration};
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
    /// # let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", ClientRegistrationStartParameters::default(), &mut client_rng)?;
    /// # let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, server_kp.public(), &mut server_rng)?;
    /// # let (register_m3, _export_key) = client_state.finish(register_m2, &mut client_rng)?;
    /// # let p_file = server_state.finish(register_m3)?;
    /// let client_login_start_result = ClientLogin::<Default>::start(b"hunter2", &mut client_rng, ClientLoginStartParameters::default())?;
    /// let server_login_start_result = ServerLogin::start(p_file, &server_kp.private(), client_login_start_result.credential_request, &mut server_rng, ServerLoginStartParameters::default())?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn start<R: RngCore + CryptoRng>(
        password_file: ServerRegistration<CS>,
        server_s_sk: &<CS::KeyFormat as KeyPair>::Repr,
        l1: LoginFirstMessage<CS>,
        rng: &mut R,
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
        let beta = oprf::evaluate(l1.alpha, &password_file.oprf_key)?;
        let envelope = password_file.envelope.ok_or(InternalPakeError::SealError)?;
        let l2_component: Vec<u8> = [&beta.to_arr()[..], &envelope.to_bytes()].concat();

        let (plain_info, ke2_state, ke2_message) = CS::KeyExchange::generate_ke2(
            rng,
            l1_bytes.to_vec(),
            l2_component,
            l1.ke1_message,
            client_s_pk,
            server_s_sk.clone(),
            id_u,
            id_s,
            info,
            e_info,
        )?;

        let l2 = LoginSecondMessage {
            beta,
            envelope,
            ke2_message,
        };

        Ok(ServerLoginStartResult {
            plain_info,
            credential_response: l2,
            server_login_state: Self {
                _cs: PhantomData,
                ke2_state,
            },
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
    /// # use opaque_ke::{ClientRegistration, ClientRegistrationStartParameters, ServerRegistration};
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
    /// # let (register_m1, client_state) = ClientRegistration::<Default>::start(b"hunter2", ClientRegistrationStartParameters::default(), &mut client_rng)?;
    /// # let (register_m2, server_state) =
    /// ServerRegistration::<Default>::start(register_m1, server_kp.public(), &mut server_rng)?;
    /// # let (register_m3, _export_key) = client_state.finish(register_m2, &mut client_rng)?;
    /// # let p_file = server_state.finish(register_m3)?;
    /// let client_login_start_result = ClientLogin::<Default>::start(b"hunter2", &mut client_rng, ClientLoginStartParameters::default())?;
    /// let server_login_start_result = ServerLogin::start(p_file, &server_kp.private(), client_login_start_result.credential_request, &mut server_rng, ServerLoginStartParameters::default())?;
    /// let client_login_finish_result = client_login_start_result.client_login_state.finish(server_login_start_result.credential_response, ClientLoginFinishParameters::default())?;
    /// let mut server_transport = server_login_start_result.server_login_state.finish(client_login_finish_result.key_exchange)?;
    /// # Ok::<(), ProtocolError>(())
    /// ```
    pub fn finish(
        &self,
        message: LoginThirdMessage<CS>,
    ) -> Result<ServerLoginFinishResult, ProtocolError> {
        let (plain_info, confidential_info, session_secret) =
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
            session_secret,
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

// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Provides the main OPAQUE API

use core::ops::{Add, Deref};

use derive_where::derive_where;
use digest::Output;
use generic_array::sequence::Concat;
use generic_array::typenum::{Sum, Unsigned};
use generic_array::{ArrayLength, GenericArray};
use hkdf::{Hkdf, HkdfExtract};
use rand::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq, CtOption};
use voprf::{BlindedElement, Group as _, OprfClient, OprfClientLen};
use zeroize::Zeroizing;

use crate::ciphersuite::{CipherSuite, KeGroup, KeHash, OprfGroup, OprfHash};
use crate::envelope::{Envelope, EnvelopeLen};
use crate::errors::{InternalError, ProtocolError};
use crate::hash::OutputSize;
use crate::key_exchange::group::Group;
use crate::key_exchange::shared::NonceLen;
use crate::key_exchange::{
    Deserialize, Ke1MessageLen, Ke1StateLen, Ke2StateLen, KeyExchange, Serialize,
    SerializedContext, SerializedCredentialResponse, SerializedIdentifiers,
};
use crate::keypair::{
    KeyPair, OprfSeed, OprfSeedSerialization, PrivateKey, PrivateKeySerialization, PublicKey,
};
use crate::ksf::Ksf;
use crate::messages::{CredentialRequestLen, RegistrationUploadLen};
use crate::serialization::{GenericArrayExt, SliceExt};
use crate::{
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    RegistrationResponse, RegistrationUpload, ServerLoginBuilder,
};

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
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "<KeGroup<CS> as Group>::Pk: serde::Deserialize<'de>, <KeGroup<CS> as \
                       Group>::Sk: serde::Deserialize<'de>, SK: serde::Deserialize<'de>, OS: \
                       serde::Deserialize<'de>",
        serialize = "<KeGroup<CS> as Group>::Pk: serde::Serialize, <KeGroup<CS> as Group>::Sk: \
                     serde::Serialize, SK: serde::Serialize, OS: serde::Serialize"
    ))
)]
#[derive_where(Clone)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <KeGroup<CS> as Group>::Pk, <KeGroup<CS> as Group>::Sk, SK, OS)]
pub struct ServerSetup<
    CS: CipherSuite,
    SK: Clone = PrivateKey<KeGroup<CS>>,
    OS: Clone = OprfSeed<OprfHash<CS>>,
> {
    oprf_seed: OS,
    keypair: KeyPair<KeGroup<CS>, SK>,
    pub(crate) dummy_pk: PublicKey<KeGroup<CS>>,
}

/// The state elements the client holds to register itself
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(
    Debug, Eq, Hash, PartialEq;
    voprf::OprfClient<CS::OprfCs>,
    voprf::BlindedElement<CS::OprfCs>,
)]
pub struct ClientRegistration<CS: CipherSuite> {
    pub(crate) oprf_client: voprf::OprfClient<CS::OprfCs>,
    pub(crate) blinded_element: voprf::BlindedElement<CS::OprfCs>,
}

/// The state elements the server holds to record a registration
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "<KeGroup<CS> as Group>::Pk: serde::Deserialize<'de>",
        serialize = "<KeGroup<CS> as Group>::Pk: serde::Serialize"
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <KeGroup<CS> as Group>::Pk)]
pub struct ServerRegistration<CS: CipherSuite>(pub(crate) RegistrationUpload<CS>);

/// The state elements the client holds to perform a login
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "<CS::KeyExchange as KeyExchange>::KE1Message: serde::Deserialize<'de>, \
                       <CS::KeyExchange as KeyExchange>::KE1State: serde::Deserialize<'de>",
        serialize = "<CS::KeyExchange as KeyExchange>::KE1Message: serde::Serialize, \
                     <CS::KeyExchange as KeyExchange>::KE1State: serde::Serialize"
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(
    Debug, Eq, Hash, PartialEq;
    voprf::OprfClient<CS::OprfCs>,
    <CS::KeyExchange as KeyExchange>::KE1State,
    CredentialRequest<CS>,
)]
pub struct ClientLogin<CS: CipherSuite> {
    pub(crate) oprf_client: voprf::OprfClient<CS::OprfCs>,
    pub(crate) ke1_state: <CS::KeyExchange as KeyExchange>::KE1State,
    pub(crate) credential_request: CredentialRequest<CS>,
}

/// The state elements the server holds to record a login
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "<CS::KeyExchange as KeyExchange>::KE2State<CS>: serde::Deserialize<'de>",
        serialize = "<CS::KeyExchange as KeyExchange>::KE2State<CS>: serde::Serialize"
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, PartialEq; <CS::KeyExchange as KeyExchange>::KE2State<CS>)]
pub struct ServerLogin<CS: CipherSuite> {
    ke2_state: <CS::KeyExchange as KeyExchange>::KE2State<CS>,
}

////////////////////////////////
// High-level Implementations //
// ========================== //
////////////////////////////////

// Server Setup
// ============

impl<CS: CipherSuite> ServerSetup<CS, PrivateKey<KeGroup<CS>>> {
    /// Generate a new instance of server setup
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let keypair = KeyPair::random(rng);
        Self::new_with_key_pair(rng, keypair)
    }
}

/// Length of [`ServerSetup`] in bytes for serialization.
pub type ServerSetupLen<
    CS: CipherSuite,
    SK: PrivateKeySerialization<KeGroup<CS>>,
    OS: OprfSeedSerialization<OprfHash<CS>, SK::Error>,
> = Sum<Sum<OS::Len, SK::Len>, <KeGroup<CS> as Group>::PkLen>;

impl<CS: CipherSuite, SK: Clone, OS: Clone> ServerSetup<CS, SK, OS> {
    /// Create [`ServerSetup`] with the given keypair and OPRF seed.
    ///
    /// This function should not be used to restore a previously-existing
    /// instance of [`ServerSetup`]. Instead, use [`ServerSetup::serialize`] and
    /// [`ServerSetup::deserialize`] for this purpose.
    pub fn new_with_key_pair_and_seed<R: CryptoRng + RngCore>(
        rng: &mut R,
        keypair: KeyPair<KeGroup<CS>, SK>,
        oprf_seed: OS,
    ) -> Self {
        Self {
            oprf_seed,
            keypair,
            dummy_pk: KeyPair::<KeGroup<CS>>::random(rng).public().clone(),
        }
    }

    /// The information required to generate the key material for
    /// [`ServerRegistration::start_with_key_material()`] and
    /// [`ServerLogin::builder_with_key_material()`].
    pub fn key_material_info<'ci>(
        &self,
        credential_identifier: &'ci [u8],
    ) -> KeyMaterialInfo<'ci, OS> {
        KeyMaterialInfo {
            ikm: self.oprf_seed.clone(),
            info: [credential_identifier, STR_OPRF_KEY],
        }
    }

    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, ServerSetupLen<CS, SK, OS>>
    where
        SK: PrivateKeySerialization<KeGroup<CS>>,
        OS: OprfSeedSerialization<OprfHash<CS>, SK::Error>,
        // ServerSetup: Hash + KeSk + KePk
        OS::Len: Add<SK::Len>,
        Sum<OS::Len, SK::Len>: ArrayLength<u8> + Add<<KeGroup<CS> as Group>::PkLen>,
        ServerSetupLen<CS, SK, OS>: ArrayLength<u8>,
    {
        self.oprf_seed
            .serialize()
            .concat(SK::serialize_key_pair(&self.keypair))
            .concat(self.dummy_pk.serialize())
    }

    /// Deserialization from bytes
    pub fn deserialize(mut input: &[u8]) -> Result<Self, ProtocolError<SK::Error>>
    where
        SK: PrivateKeySerialization<KeGroup<CS>>,
        OS: OprfSeedSerialization<OprfHash<CS>, SK::Error>,
    {
        Ok(Self {
            oprf_seed: OS::deserialize_take(&mut input)?,
            keypair: SK::deserialize_take_key_pair(&mut input)?,
            dummy_pk: PublicKey::deserialize_take(&mut input)
                .map_err(ProtocolError::into_custom)?,
        })
    }

    /// Returns the keypair
    pub fn keypair(&self) -> &KeyPair<KeGroup<CS>, SK> {
        &self.keypair
    }
}

impl<CS: CipherSuite, SK: Clone> ServerSetup<CS, SK> {
    /// Create [`ServerSetup`] with the given keypair
    ///
    /// This function should not be used to restore a previously-existing
    /// instance of [`ServerSetup`]. Instead, use [`ServerSetup::serialize`] and
    /// [`ServerSetup::deserialize`] for this purpose.
    pub fn new_with_key_pair<R: CryptoRng + RngCore>(
        rng: &mut R,
        keypair: KeyPair<KeGroup<CS>, SK>,
    ) -> Self {
        let mut oprf_seed = GenericArray::default();
        rng.fill_bytes(&mut oprf_seed);

        Self::new_with_key_pair_and_seed(rng, keypair, OprfSeed(oprf_seed))
    }
}

/// The information required to generate the key material for
/// [`ServerRegistration::start_with_key_material()`] and
/// [`ServerLogin::builder_with_key_material()`].
///
/// Use a HKDF, with the input key material [`ikm`](Self::ikm), expand operation
/// with [`info`](Self::info) with an output length
/// of [`CS::OprfCs::ScalarLen`](voprf::Group::ScalarLen).
pub struct KeyMaterialInfo<'ci, OS: Clone> {
    /// Input key material for the HKDF.
    pub ikm: OS,
    /// Info for the HKDF expand operation.
    pub info: [&'ci [u8]; 2],
}

// Registration
// ============

pub(crate) type ClientRegistrationLen<CS: CipherSuite> =
    Sum<<OprfGroup<CS> as voprf::Group>::ScalarLen, <OprfGroup<CS> as voprf::Group>::ElemLen>;

impl<CS: CipherSuite> ClientRegistration<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, ClientRegistrationLen<CS>>
    where
        // ClientRegistration: KgSk + KgPk
        <OprfGroup<CS> as voprf::Group>::ScalarLen: Add<<OprfGroup<CS> as voprf::Group>::ElemLen>,
        ClientRegistrationLen<CS>: ArrayLength<u8>,
    {
        self.oprf_client
            .serialize()
            .concat(self.blinded_element.serialize())
    }

    /// Deserialization from bytes
    pub fn deserialize(mut input: &[u8]) -> Result<Self, ProtocolError> {
        let oprf_client = OprfClient::deserialize(input)?;
        input = &input[OprfClientLen::<CS::OprfCs>::USIZE..];

        let blinded_element = BlindedElement::deserialize(input)?;

        Ok(Self {
            oprf_client,
            blinded_element,
        })
    }

    /// Returns an initial "blinded" request to send to the server, as well as a
    /// [`ClientRegistration`]
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
    /// cryptographic identifiers, to be sent to the server on setup
    /// finalization
    pub fn finish<R: CryptoRng + RngCore>(
        self,
        rng: &mut R,
        password: &[u8],
        registration_response: RegistrationResponse<CS>,
        params: ClientRegistrationFinishParameters<CS>,
    ) -> Result<ClientRegistrationFinishResult<CS>, ProtocolError> {
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
            password,
            self.oprf_client.clone(),
            registration_response.evaluation_element,
            params.ksf,
        )?;

        let mut masking_key = Output::<OprfHash<CS>>::default();
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

/// Length of [`ServerRegistration`] in bytes for serialization.
pub type ServerRegistrationLen<CS> = RegistrationUploadLen<CS>;

impl<CS: CipherSuite> ServerRegistration<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, ServerRegistrationLen<CS>>
    where
        // RegistrationUpload: (KePk + Hash) + Envelope
        <KeGroup<CS> as Group>::PkLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<<KeGroup<CS> as Group>::PkLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<EnvelopeLen<CS>>,
        RegistrationUploadLen<CS>: ArrayLength<u8>,
        // ServerRegistration = RegistrationUpload
    {
        self.0.serialize()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self(RegistrationUpload::deserialize(input)?))
    }

    /// Create a [`RegistrationResponse`] with a remote OPRF seed. To generate
    /// the `key_material` see [`ServerSetup::key_material_info()`].
    ///
    /// See [`ServerRegistration::start()`] for the regular path.
    pub fn start_with_key_material<SK: Clone, OS: Clone>(
        server_setup: &ServerSetup<CS, SK, OS>,
        key_material: GenericArray<u8, <OprfGroup<CS> as voprf::Group>::ScalarLen>,
        message: RegistrationRequest<CS>,
    ) -> Result<ServerRegistrationStartResult<CS>, ProtocolError> {
        let oprf_key = oprf_key_from_key_material::<CS>(key_material)?;

        let server = voprf::OprfServer::new_with_key(&oprf_key)?;
        let evaluation_element = server.blind_evaluate(&message.blinded_element);

        Ok(ServerRegistrationStartResult {
            message: RegistrationResponse {
                evaluation_element,
                server_s_pk: server_setup.keypair().public().clone(),
            },
            #[cfg(test)]
            oprf_key,
        })
    }

    /// From the client's "blinded" password, returns a response to be sent back
    /// to the client, as well as a [`ServerRegistration`]
    pub fn start<SK: Clone>(
        server_setup: &ServerSetup<CS, SK>,
        message: RegistrationRequest<CS>,
        credential_identifier: &[u8],
    ) -> Result<ServerRegistrationStartResult<CS>, ProtocolError> {
        let KeyMaterialInfo {
            ikm: oprf_seed,
            info,
        } = server_setup.key_material_info(credential_identifier);
        let key_material = oprf_key_material::<CS>(&oprf_seed.0, &info)?;

        Self::start_with_key_material(server_setup, key_material, message)
    }

    /// From the client's cryptographic identifiers, fully populates and returns
    /// a [`ServerRegistration`]
    pub fn finish(message: RegistrationUpload<CS>) -> Self {
        Self(message)
    }

    // Creates a dummy instance used for faking a [CredentialResponse]
    pub(crate) fn dummy<R: RngCore + CryptoRng, SK: Clone, S: Clone>(
        rng: &mut R,
        server_setup: &ServerSetup<CS, SK, S>,
    ) -> Self {
        Self(RegistrationUpload::dummy(rng, server_setup))
    }
}

// Login
// =====

pub(crate) type ClientLoginLen<CS: CipherSuite> =
    Sum<Sum<<OprfGroup<CS> as voprf::Group>::ScalarLen, CredentialRequestLen<CS>>, Ke1StateLen<CS>>;

impl<CS: CipherSuite> ClientLogin<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, ClientLoginLen<CS>>
    where
        // CredentialRequest: KgPk + Ke1Message
        <CS::KeyExchange as KeyExchange>::KE1Message: Serialize,
        <OprfGroup<CS> as voprf::Group>::ElemLen: Add<Ke1MessageLen<CS>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
        // ClientLogin: KgSk + CredentialRequest + Ke1State
        <OprfGroup<CS> as voprf::Group>::ScalarLen: Add<CredentialRequestLen<CS>>,
        <CS::KeyExchange as KeyExchange>::KE1State: Serialize,
        Sum<<OprfGroup<CS> as voprf::Group>::ScalarLen, CredentialRequestLen<CS>>:
            ArrayLength<u8> + Add<Ke1StateLen<CS>>,
        ClientLoginLen<CS>: ArrayLength<u8>,
    {
        self.oprf_client
            .serialize()
            .concat(self.credential_request.serialize())
            .concat(self.ke1_state.serialize())
    }

    /// Deserialization from bytes
    pub fn deserialize(mut input: &[u8]) -> Result<Self, ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE1Message: Deserialize + Serialize,
        <CS::KeyExchange as KeyExchange>::KE1State: Deserialize + Serialize,
    {
        let oprf_client = OprfClient::deserialize(input)?;
        input = &input[OprfClientLen::<CS::OprfCs>::USIZE..];

        Ok(Self {
            oprf_client,
            credential_request: CredentialRequest::deserialize_take(&mut input)?,
            ke1_state: <CS::KeyExchange as KeyExchange>::KE1State::deserialize_take(&mut input)?,
        })
    }
}

impl<CS: CipherSuite> ClientLogin<CS> {
    /// Returns an initial "blinded" password request to send to the server, as
    /// well as a [`ClientLogin`]
    pub fn start<R: RngCore + CryptoRng>(
        rng: &mut R,
        password: &[u8],
    ) -> Result<ClientLoginStartResult<CS>, ProtocolError> {
        let blind_result = blind::<CS, _>(rng, password)?;
        let ke1_result = CS::KeyExchange::generate_ke1(rng)?;

        let credential_request = CredentialRequest {
            blinded_element: blind_result.message,
            ke1_message: ke1_result.message,
        };

        Ok(ClientLoginStartResult {
            message: credential_request.clone(),
            state: Self {
                oprf_client: blind_result.state,
                ke1_state: ke1_result.state,
                credential_request,
            },
        })
    }

    /// "Unblinds" the server's answer and returns the opened assets from the
    /// server
    pub fn finish<R: CryptoRng + RngCore>(
        self,
        rng: &mut R,
        password: &[u8],
        credential_response: CredentialResponse<CS>,
        params: ClientLoginFinishParameters<CS>,
    ) -> Result<ClientLoginFinishResult<CS>, ProtocolError> {
        // Check if beta value from server is equal to alpha value from client
        if self
            .credential_request
            .blinded_element
            .value()
            .ct_eq(&credential_response.evaluation_element.value())
            .into()
        {
            return Err(ProtocolError::ReflectedValueError);
        }

        let (_, randomized_pwd_hasher) = get_password_derived_key::<CS>(
            password,
            self.oprf_client.clone(),
            credential_response.evaluation_element.clone(),
            params.ksf,
        )?;

        let mut masking_key = Output::<OprfHash<CS>>::default();
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

        let opened_envelope = envelope
            .open(
                randomized_pwd_hasher,
                server_s_pk.clone(),
                params.identifiers,
            )
            .map_err(|e| match e {
                ProtocolError::LibraryError(InternalError::SealOpenHmacError) => {
                    ProtocolError::InvalidLoginError
                }
                err => err,
            })?;

        let context = SerializedContext::from(params.context)?;

        let result = CS::KeyExchange::generate_ke3(
            rng,
            self.credential_request.to_parts(),
            self.credential_request.ke1_message.clone(),
            credential_response.to_parts(),
            &self.ke1_state,
            credential_response.ke2_message,
            server_s_pk.clone(),
            opened_envelope.client_static_keypair.private().clone(),
            opened_envelope.identifiers,
            context,
        )?;

        Ok(ClientLoginFinishResult {
            message: CredentialFinalization {
                ke3_message: result.message,
            },
            session_key: result.session_key,
            export_key: opened_envelope.export_key,
            server_s_pk,
            #[cfg(test)]
            state: self,
            #[cfg(test)]
            handshake_secret: result.handshake_secret,
            #[cfg(test)]
            client_mac_key: result.km3,
        })
    }
}

impl<CS: CipherSuite> ServerLogin<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, Ke2StateLen<CS>>
    where
        <CS::KeyExchange as KeyExchange>::KE2State<CS>: Serialize,
    {
        self.ke2_state.serialize()
    }

    /// Deserialization from bytes
    pub fn deserialize(mut bytes: &[u8]) -> Result<Self, ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE2State<CS>: Deserialize,
    {
        Ok(Self {
            ke2_state:
                <<CS::KeyExchange as KeyExchange>::KE2State<CS> as Deserialize>::deserialize_take(
                    &mut bytes,
                )?,
        })
    }

    /// Create a [`ServerLoginBuilder`] with a remote OPRF seed and private key.
    /// To generate the `key_material` see
    /// [`ServerSetup::key_material_info()`].
    ///
    /// See [`ServerLogin::start()`] for the regular path. Or
    /// [`ServerLogin::builder()`] with just a remote private key.
    pub fn builder_with_key_material<'a, R: RngCore + CryptoRng, SK: Clone, OS: Clone>(
        rng: &mut R,
        server_setup: &ServerSetup<CS, SK, OS>,
        key_material: GenericArray<u8, <OprfGroup<CS> as voprf::Group>::ScalarLen>,
        password_file: Option<ServerRegistration<CS>>,
        credential_request: CredentialRequest<CS>,
        ServerLoginParameters {
            context,
            identifiers,
        }: ServerLoginParameters<'a, 'a>,
    ) -> Result<ServerLoginBuilder<'a, CS, SK>, ProtocolError> {
        let record = CtOption::new(
            ServerRegistration::dummy(rng, server_setup),
            Choice::from(password_file.is_none() as u8),
        )
        .into_option()
        .unwrap_or_else(|| password_file.unwrap());

        let client_s_pk = record.0.client_s_pk.clone();
        let context = SerializedContext::from(context)?;
        let server_s_pk = server_setup.keypair.public();

        let mut masking_nonce = GenericArray::<_, NonceLen>::default();
        rng.fill_bytes(&mut masking_nonce);

        let masked_response = mask_response(
            &record.0.masking_key,
            masking_nonce.as_slice(),
            server_s_pk,
            &record.0.envelope,
        )?;

        let serialized_client_s_pk = client_s_pk.serialize();
        let serialized_server_s_pk = server_s_pk.serialize();
        let identifiers = SerializedIdentifiers::<KeGroup<CS>>::from_identifiers(
            identifiers,
            serialized_client_s_pk.clone(),
            serialized_server_s_pk.clone(),
        )?;

        let oprf_key = oprf_key_from_key_material::<CS>(key_material)?;
        let server = voprf::OprfServer::new_with_key(&oprf_key).map_err(ProtocolError::from)?;
        let evaluation_element = server.blind_evaluate(&credential_request.blinded_element);

        let credential_response = SerializedCredentialResponse::new(
            &evaluation_element,
            masking_nonce,
            masked_response.clone(),
        );

        let ke2_builder = CS::KeyExchange::ke2_builder(
            rng,
            credential_request.to_parts(),
            credential_request.ke1_message.clone(),
            credential_response,
            client_s_pk,
            identifiers,
            context,
        )?;

        Ok(ServerLoginBuilder {
            server_s_sk: server_setup.keypair().private().clone(),
            evaluation_element,
            masking_nonce: Zeroizing::new(masking_nonce),
            masked_response,
            #[cfg(test)]
            oprf_key: Zeroizing::new(oprf_key),
            ke2_builder,
        })
    }

    /// Create a [`ServerLoginBuilder`] to use with a remote private key.
    ///
    /// See [`ServerLogin::start()`] for the regular path.
    pub fn builder<'a, R: RngCore + CryptoRng, SK: Clone>(
        rng: &mut R,
        server_setup: &ServerSetup<CS, SK>,
        password_file: Option<ServerRegistration<CS>>,
        credential_request: CredentialRequest<CS>,
        credential_identifier: &[u8],
        params: ServerLoginParameters<'a, 'a>,
    ) -> Result<ServerLoginBuilder<'a, CS, SK>, ProtocolError> {
        let KeyMaterialInfo {
            ikm: oprf_seed,
            info,
        } = server_setup.key_material_info(credential_identifier);
        let key_material = oprf_key_material::<CS>(&oprf_seed.0, &info)?;

        Self::builder_with_key_material(
            rng,
            server_setup,
            key_material,
            password_file,
            credential_request,
            params,
        )
    }

    pub(crate) fn build<SK: Clone>(
        builder: ServerLoginBuilder<CS, SK>,
        input: <CS::KeyExchange as KeyExchange>::KE2BuilderInput<CS>,
    ) -> Result<ServerLoginStartResult<CS>, ProtocolError> {
        let result = CS::KeyExchange::build_ke2(builder.ke2_builder.clone(), input)?;

        let credential_response = CredentialResponse {
            evaluation_element: builder.evaluation_element.clone(),
            masking_nonce: *builder.masking_nonce.deref(),
            masked_response: builder.masked_response.clone(),
            ke2_message: result.message,
        };

        Ok(ServerLoginStartResult {
            message: credential_response,
            state: Self {
                ke2_state: result.state,
            },
            #[cfg(test)]
            handshake_secret: result.handshake_secret,
            #[cfg(test)]
            server_mac_key: result.km2,
            #[cfg(test)]
            oprf_key: builder.oprf_key.deref().clone(),
        })
    }

    /// From the client's "blinded" password, returns a challenge to be sent
    /// back to the client, as well as a [`ServerLogin`]
    pub fn start<R: RngCore + CryptoRng>(
        rng: &mut R,
        server_setup: &ServerSetup<CS>,
        password_file: Option<ServerRegistration<CS>>,
        credential_request: CredentialRequest<CS>,
        credential_identifier: &[u8],
        parameters: ServerLoginParameters,
    ) -> Result<ServerLoginStartResult<CS>, ProtocolError> {
        let builder = Self::builder(
            rng,
            server_setup,
            password_file,
            credential_request,
            credential_identifier,
            parameters,
        )?;
        let input = CS::KeyExchange::generate_ke2_input(
            &builder.ke2_builder,
            rng,
            server_setup.keypair.private(),
        );

        Self::build(builder, input)
    }

    /// From the client's second and final message, check the client's
    /// authentication and produce a message transport
    pub fn finish(
        self,
        message: CredentialFinalization<CS>,
        parameters: ServerLoginParameters,
    ) -> Result<ServerLoginFinishResult<CS>, ProtocolError> {
        let context = SerializedContext::from(parameters.context)?;

        let session_key = <CS::KeyExchange as KeyExchange>::finish_ke(
            &self.ke2_state,
            message.ke3_message,
            parameters.identifiers,
            context,
        )?;

        Ok(ServerLoginFinishResult {
            session_key,
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
#[derive_where(Clone, Default)]
pub struct ClientRegistrationFinishParameters<'i, 'h, CS: CipherSuite> {
    /// Specifying the identifiers idU and idS
    pub identifiers: Identifiers<'i>,
    /// Specifying a configuration for the key stretching function
    pub ksf: Option<&'h CS::Ksf>,
}

impl<'i, 'h, CS: CipherSuite> ClientRegistrationFinishParameters<'i, 'h, CS> {
    /// Create a new [`ClientRegistrationFinishParameters`]
    pub fn new(identifiers: Identifiers<'i>, ksf: Option<&'h CS::Ksf>) -> Self {
        Self { identifiers, ksf }
    }
}

/// Contains the fields that are returned by a client registration start
#[derive_where(Clone)]
pub struct ClientRegistrationStartResult<CS: CipherSuite> {
    /// The registration request message to be sent to the server
    pub message: RegistrationRequest<CS>,
    /// The client state that must be persisted in order to complete
    /// registration
    pub state: ClientRegistration<CS>,
}

/// Contains the fields that are returned by a client registration finish
#[derive_where(Clone)]
pub struct ClientRegistrationFinishResult<CS: CipherSuite> {
    /// The registration upload message to be sent to the server
    pub message: RegistrationUpload<CS>,
    /// The export key output by client registration
    pub export_key: Output<OprfHash<CS>>,
    /// The server's static public key
    pub server_s_pk: PublicKey<KeGroup<CS>>,
    /// Instance of the ClientRegistration, only used in tests for checking
    /// zeroize
    #[cfg(test)]
    pub state: ClientRegistration<CS>,
    /// AuthKey, only used in tests
    #[cfg(test)]
    pub auth_key: Output<OprfHash<CS>>,
    /// Password derived key, only used in tests
    #[cfg(test)]
    pub randomized_pwd: Output<OprfHash<CS>>,
}

/// Contains the fields that are returned by a server registration start. Note
/// that there is no state output in this step
#[derive_where(Clone)]
pub struct ServerRegistrationStartResult<CS: CipherSuite> {
    /// The registration resposne message to send to the client
    pub message: RegistrationResponse<CS>,
    /// OPRF key, only used in tests
    #[cfg(test)]
    pub oprf_key: GenericArray<u8, <OprfGroup<CS> as voprf::Group>::ScalarLen>,
}

/// Contains the fields that are returned by a client login start
#[derive_where(Clone)]
pub struct ClientLoginStartResult<CS: CipherSuite> {
    /// The message to send to the server to begin the login protocol
    pub message: CredentialRequest<CS>,
    /// The state that the client must keep in order to complete the protocol
    pub state: ClientLogin<CS>,
}

/// Optional parameters for client login finish
#[derive_where(Clone, Default)]
pub struct ClientLoginFinishParameters<'c, 'i, 'h, CS: CipherSuite> {
    /// Specifying a context field that the server must agree on
    pub context: Option<&'c [u8]>,
    /// Specifying a user identifier and server identifier that will be matched
    /// against the server
    pub identifiers: Identifiers<'i>,
    /// Specifying a configuration for the key stretching hash
    pub ksf: Option<&'h CS::Ksf>,
}

impl<'c, 'i, 'h, CS: CipherSuite> ClientLoginFinishParameters<'c, 'i, 'h, CS> {
    /// Create a new [`ClientLoginFinishParameters`]
    pub fn new(
        context: Option<&'c [u8]>,
        identifiers: Identifiers<'i>,
        ksf: Option<&'h CS::Ksf>,
    ) -> Self {
        Self {
            context,
            identifiers,
            ksf,
        }
    }
}

/// Contains the fields that are returned by a client login finish
#[derive_where(Clone)]
pub struct ClientLoginFinishResult<CS: CipherSuite> {
    /// The message to send to the server to complete the protocol
    pub message: CredentialFinalization<CS>,
    /// The session key
    pub session_key: Output<KeHash<CS>>,
    /// The client-side export key
    pub export_key: Output<OprfHash<CS>>,
    /// The server's static public key
    pub server_s_pk: PublicKey<KeGroup<CS>>,
    /// Instance of the ClientLogin, only used in tests for checking zeroize
    #[cfg(test)]
    pub state: ClientLogin<CS>,
    /// Handshake secret, only used in tests
    #[cfg(test)]
    pub handshake_secret: Output<KeHash<CS>>,
    /// Client MAC key, only used in tests
    #[cfg(test)]
    pub client_mac_key: Output<KeHash<CS>>,
}

/// Contains the fields that are returned by a server login finish
#[derive_where(Clone)]
#[cfg_attr(not(test), derive_where(Debug))]
#[cfg_attr(test, derive_where(Debug; ServerLogin<CS>))]
pub struct ServerLoginFinishResult<CS: CipherSuite> {
    /// The session key between client and server
    pub session_key: Output<KeHash<CS>>,
    /// Instance of the ClientRegistration, only used in tests for checking
    /// zeroize
    #[cfg(test)]
    pub state: ServerLogin<CS>,
}

/// Optional parameters for server login start and finish
#[derive(Clone, Debug, Default)]
pub struct ServerLoginParameters<'c, 'i> {
    /// Specifying a context field that the client must agree on
    pub context: Option<&'c [u8]>,
    /// Specifying a user identifier and server identifier that will be matched
    /// against the client
    pub identifiers: Identifiers<'i>,
}

/// Contains the fields that are returned by a server login start
#[derive_where(Clone)]
#[derive_where(
    Debug;
    <KeGroup<CS> as Group>::Pk,
    voprf::EvaluationElement<CS::OprfCs>,
    <CS::KeyExchange as KeyExchange>::KE2Message,
    <CS::KeyExchange as KeyExchange>::KE2State<CS>,
)]
pub struct ServerLoginStartResult<CS: CipherSuite> {
    /// The message to send back to the client
    pub message: CredentialResponse<CS>,
    /// The state that the server must keep in order to finish the protocl
    pub state: ServerLogin<CS>,
    /// Handshake secret, only used in tests
    #[cfg(test)]
    pub handshake_secret: Output<KeHash<CS>>,
    /// Server MAC key, only used in tests
    #[cfg(test)]
    pub server_mac_key: Output<KeHash<CS>>,
    /// OPRF key, only used in tests
    #[cfg(test)]
    pub oprf_key: GenericArray<u8, <OprfGroup<CS> as voprf::Group>::ScalarLen>,
}

////////////////////////////////////////////////
// Helper functions and Trait Implementations //
// ========================================== //
////////////////////////////////////////////////

// Helper functions
#[allow(clippy::type_complexity)]
fn get_password_derived_key<CS: CipherSuite>(
    input: &[u8],
    oprf_client: voprf::OprfClient<CS::OprfCs>,
    evaluation_element: voprf::EvaluationElement<CS::OprfCs>,
    ksf: Option<&CS::Ksf>,
) -> Result<(Output<OprfHash<CS>>, Hkdf<OprfHash<CS>>), ProtocolError> {
    let oprf_output = oprf_client.finalize(input, &evaluation_element)?;

    let hardened_output = if let Some(ksf) = ksf {
        ksf.hash(oprf_output.clone())
    } else {
        CS::Ksf::default().hash(oprf_output.clone())
    }
    .map_err(ProtocolError::from)?;

    let mut hkdf = HkdfExtract::<OprfHash<CS>>::new(None);
    hkdf.input_ikm(&oprf_output);
    hkdf.input_ikm(&hardened_output);
    Ok(hkdf.finalize())
}

fn oprf_key_material<CS: CipherSuite>(
    oprf_seed: &Output<OprfHash<CS>>,
    info: &[&[u8]],
) -> Result<GenericArray<u8, <OprfGroup<CS> as voprf::Group>::ScalarLen>, InternalError> {
    let mut ikm = GenericArray::<_, <OprfGroup<CS> as voprf::Group>::ScalarLen>::default();
    Hkdf::<OprfHash<CS>>::from_prk(oprf_seed)
        .ok()
        .and_then(|hkdf| hkdf.expand_multi_info(info, &mut ikm).ok())
        .ok_or(InternalError::HkdfError)?;

    Ok(ikm)
}

fn oprf_key_from_key_material<CS: CipherSuite>(
    input: GenericArray<u8, <OprfGroup<CS> as voprf::Group>::ScalarLen>,
) -> Result<GenericArray<u8, <OprfGroup<CS> as voprf::Group>::ScalarLen>, InternalError> {
    Ok(OprfGroup::<CS>::serialize_scalar(voprf::derive_key::<
        CS::OprfCs,
    >(
        input.as_slice(),
        &GenericArray::from(*STR_OPAQUE_DERIVE_KEY_PAIR),
        voprf::Mode::Oprf,
    )?))
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Zeroize)]
#[derive_where(Debug, Eq, Hash, PartialEq)]
pub(crate) struct MaskedResponse<CS: CipherSuite> {
    pub(crate) nonce: GenericArray<u8, NonceLen>,
    pub(crate) hash: Output<OprfHash<CS>>,
    pub(crate) pk: GenericArray<u8, <KeGroup<CS> as Group>::PkLen>,
}

pub(crate) type MaskedResponseLen<CS: CipherSuite> =
    Sum<Sum<OutputSize<OprfHash<CS>>, NonceLen>, <KeGroup<CS> as Group>::PkLen>;

impl<CS: CipherSuite> MaskedResponse<CS> {
    pub(crate) fn serialize(&self) -> GenericArray<u8, MaskedResponseLen<CS>> {
        self.nonce.concat_ext(&self.hash).concat(self.pk.clone())
    }

    pub(crate) fn deserialize_take(bytes: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            nonce: bytes.take_array("masked nonce")?,
            hash: bytes.take_array("masked hash")?,
            pk: bytes.take_array("masked public key")?,
        })
    }

    pub(crate) fn iter(&self) -> impl Clone + Iterator<Item = &[u8]> {
        [self.nonce.as_slice(), &self.hash, &self.pk].into_iter()
    }
}

fn mask_response<CS: CipherSuite>(
    masking_key: &[u8],
    masking_nonce: &[u8],
    server_s_pk: &PublicKey<KeGroup<CS>>,
    envelope: &Envelope<CS>,
) -> Result<MaskedResponse<CS>, ProtocolError> {
    let mut xor_pad = GenericArray::<_, MaskedResponseLen<CS>>::default();

    Hkdf::<OprfHash<CS>>::from_prk(masking_key)
        .map_err(|_| InternalError::HkdfError)?
        .expand_multi_info(&[masking_nonce, STR_CREDENTIAL_RESPONSE_PAD], &mut xor_pad)
        .map_err(|_| InternalError::HkdfError)?;

    for (x1, x2) in xor_pad.iter_mut().zip(
        server_s_pk
            .serialize()
            .as_slice()
            .iter()
            .chain(envelope.serialize().iter()),
    ) {
        *x1 ^= x2
    }

    MaskedResponse::deserialize_take(&mut (xor_pad.as_slice()))
}

fn unmask_response<CS: CipherSuite>(
    masking_key: &[u8],
    masking_nonce: &[u8],
    masked_response: &MaskedResponse<CS>,
) -> Result<(PublicKey<KeGroup<CS>>, Envelope<CS>), ProtocolError> {
    let mut xor_pad = GenericArray::<_, MaskedResponseLen<CS>>::default();

    Hkdf::<OprfHash<CS>>::from_prk(masking_key)
        .map_err(|_| InternalError::HkdfError)?
        .expand_multi_info(&[masking_nonce, STR_CREDENTIAL_RESPONSE_PAD], &mut xor_pad)
        .map_err(|_| InternalError::HkdfError)?;

    for (x1, x2) in xor_pad.iter_mut().zip(masked_response.iter().flatten()) {
        *x1 ^= x2
    }

    let mut xor_pad = xor_pad.as_slice();
    let server_s_pk =
        PublicKey::deserialize_take(&mut xor_pad).map_err(|_| ProtocolError::SerializationError)?;
    let envelope = Envelope::deserialize_take(&mut xor_pad)?;

    Ok((server_s_pk, envelope))
}

/// Internal function for computing the blind result by calling the voprf
/// library. Note that for tests, we use the deterministic blinding in order to
/// be able to set the blinding factor directly from the passed-in rng.
fn blind<CS: CipherSuite, R: RngCore + CryptoRng>(
    rng: &mut R,
    password: &[u8],
) -> Result<voprf::OprfClientBlindResult<CS::OprfCs>, voprf::Error> {
    #[cfg(not(test))]
    let result = voprf::OprfClient::blind(password, rng)?;

    #[cfg(test)]
    let result = {
        let mut blind_bytes =
            GenericArray::<_, <OprfGroup<CS> as voprf::Group>::ScalarLen>::default();
        let blind = loop {
            rng.fill_bytes(&mut blind_bytes);
            if let Ok(scalar) = <OprfGroup<CS> as voprf::Group>::deserialize_scalar(&blind_bytes) {
                break scalar;
            }
        };
        voprf::OprfClient::deterministic_blind_unchecked(password, blind)?
    };

    Ok(result)
}

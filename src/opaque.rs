// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Provides the main OPAQUE API

use crate::{
    ciphersuite::CipherSuite,
    envelope::{Envelope, EnvelopeLen},
    errors::{utils::check_slice_size, InternalError, ProtocolError},
    hash::{Hash, OutputSize, ProxyHash},
    key_exchange::{
        group::KeGroup,
        traits::{FromBytes, Ke1MessageLen, Ke1StateLen, Ke2StateLen, KeyExchange, ToBytes},
        tripledh::NonceLen,
    },
    keypair::{KeyPair, PrivateKey, PublicKey, SecretKey},
    messages::{CredentialRequestLen, RegistrationUploadLen},
    serialization::{tokenize, Serialize},
    slow_hash::SlowHash,
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    RegistrationResponse, RegistrationUpload,
};
use core::marker::PhantomData;
use core::ops::Add;
use derive_where::DeriveWhere;
use digest::core_api::{BlockSizeUser, CoreProxy};
use digest::Output;
use generic_array::sequence::Concat;
use generic_array::{
    typenum::{IsLess, Le, NonZero, Sum, Unsigned, U2, U256},
    ArrayLength, GenericArray,
};
use hkdf::{Hkdf, HkdfExtract};
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use voprf::Group;

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
    derive(serde_::Deserialize, serde_::Serialize),
    serde(
        bound(
            deserialize = "KeyPair<CS::KeGroup, S>: serde_::Deserialize<'de>",
            serialize = "KeyPair<CS::KeGroup, S>: serde_::Serialize"
        ),
        crate = "serde_"
    )
)]
#[derive(DeriveWhere)]
#[derive_where(Clone)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; S)]
pub struct ServerSetup<
    CS: CipherSuite,
    S: SecretKey<CS::KeGroup> = PrivateKey<<CS as CipherSuite>::KeGroup>,
> where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    oprf_seed: Output<CS::Hash>,
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
pub struct ClientRegistration<CS: CipherSuite>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    pub(crate) oprf_client: voprf::NonVerifiableClient<CS::OprfGroup, CS::Hash>,
    pub(crate) blinded_element: voprf::BlindedElement<CS::OprfGroup, CS::Hash>,
}

impl_serialize_and_deserialize_for!(
    ClientRegistration
    where
        // ClientRegistration: (2 + KgSk) + (2 + KgPk)
        U2: Add<<CS::OprfGroup as Group>::ScalarLen>,
        Sum<U2, <CS::OprfGroup as Group>::ScalarLen>:
            ArrayLength<u8> | Add<Sum<U2, <CS::OprfGroup as Group>::ElemLen>>,
        U2: Add<<CS::OprfGroup as Group>::ElemLen>,
        Sum<U2, <CS::OprfGroup as Group>::ElemLen>: ArrayLength<u8>,
        ClientRegistrationLen<CS>: ArrayLength<u8>;
    serde_::ser::Error::custom);

/// The state elements the server holds to record a registration
#[derive(DeriveWhere)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Zeroize(drop))]
pub struct ServerRegistration<CS: CipherSuite>(RegistrationUpload<CS>)
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero;

impl_serialize_and_deserialize_for!(
    ServerRegistration
    where
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<CS::Hash>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <CS::KeGroup as KeGroup>::PkLen: Add<OutputSize<CS::Hash>>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, OutputSize<CS::Hash>>:
            ArrayLength<u8> | Add<EnvelopeLen<CS>>,
        RegistrationUploadLen<CS>: ArrayLength<u8>,
        // ServerRegistration = RegistrationUpload
);

/// The state elements the client holds to perform a login
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(
    Debug, Eq, Hash, PartialEq;
    voprf::NonVerifiableClient<CS::OprfGroup, CS::Hash>,
    <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1State,
    CredentialRequest<CS>,
)]
pub struct ClientLogin<CS: CipherSuite>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    oprf_client: voprf::NonVerifiableClient<CS::OprfGroup, CS::Hash>,
    ke1_state: <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1State,
    credential_request: CredentialRequest<CS>,
}

impl_serialize_and_deserialize_for!(
    ClientLogin
    where
        // CredentialRequest: KgPk + Ke1Message
        <CS::OprfGroup as Group>::ElemLen: Add<Ke1MessageLen<CS>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
        // ClientLogin: (2 + KgSk) + (2 + CredentialRequest) + (2 + Ke1State)
        U2: Add<<CS::OprfGroup as Group>::ScalarLen>,
        Sum<U2, <CS::OprfGroup as Group>::ScalarLen>:
            ArrayLength<u8> | Add<Sum<U2, CredentialRequestLen<CS>>>,
        U2: Add<CredentialRequestLen<CS>>,
        Sum<U2, CredentialRequestLen<CS>>: ArrayLength<u8>,
        Sum<Sum<U2, <CS::OprfGroup as Group>::ScalarLen>, Sum<U2, CredentialRequestLen<CS>>>:
            ArrayLength<u8> | Add<Sum<U2, Ke1StateLen<CS>>>,
        U2: Add<Ke1StateLen<CS>>,
        Sum<U2, Ke1StateLen<CS>>: ArrayLength<u8>,
        ClientLoginLen<CS>: ArrayLength<u8>;
    serde_::ser::Error::custom
);

/// The state elements the server holds to record a login
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(
    Debug, Eq, Hash, PartialEq;
    <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE2State,
)]
pub struct ServerLogin<CS: CipherSuite>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
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

impl<CS: CipherSuite> ServerSetup<CS, PrivateKey<CS::KeGroup>>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// Generate a new instance of server setup
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let keypair = KeyPair::generate_random(rng);
        Self::new_with_key(rng, keypair)
    }
}

/// Length of [`ServerSetup`] in bytes for serialization.
pub type ServerSetupLen<CS: CipherSuite, S: SecretKey<CS::KeGroup>> =
    Sum<Sum<OutputSize<CS::Hash>, S::Len>, <CS::KeGroup as KeGroup>::SkLen>;

impl<CS: CipherSuite, S: SecretKey<CS::KeGroup>> ServerSetup<CS, S>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
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
    pub fn serialize(&self) -> GenericArray<u8, ServerSetupLen<CS, S>>
    where
        // ServerSetup: Hash + KeSk + KeSk
        OutputSize<CS::Hash>: Add<S::Len>,
        Sum<OutputSize<CS::Hash>, S::Len>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::SkLen>,
        ServerSetupLen<CS, S>: ArrayLength<u8>,
    {
        self.oprf_seed
            .clone()
            .concat(self.keypair.private().serialize())
            .concat(self.fake_keypair.private().to_arr())
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError<S::Error>> {
        let seed_len = OutputSize::<CS::Hash>::USIZE;
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

pub(crate) type ClientRegistrationLen<CS: CipherSuite> =
    Sum<Sum<U2, <CS::OprfGroup as Group>::ScalarLen>, Sum<U2, <CS::OprfGroup as Group>::ElemLen>>;

impl<CS: CipherSuite> ClientRegistration<CS>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> Result<GenericArray<u8, ClientRegistrationLen<CS>>, ProtocolError>
    where
        // ClientRegistration: (2 + KgSk) + (2 + KgPk)
        U2: Add<<CS::OprfGroup as Group>::ScalarLen>,
        Sum<U2, <CS::OprfGroup as Group>::ScalarLen>:
            ArrayLength<u8> + Add<Sum<U2, <CS::OprfGroup as Group>::ElemLen>>,
        U2: Add<<CS::OprfGroup as Group>::ElemLen>,
        Sum<U2, <CS::OprfGroup as Group>::ElemLen>: ArrayLength<u8>,
        ClientRegistrationLen<CS>: ArrayLength<u8>,
    {
        Ok(
            Serialize::<U2, _>::from_owned(self.oprf_client.serialize())?
                .serialize()
                .concat(
                    Serialize::<U2, _>::from_owned(self.blinded_element.serialize())?.serialize(),
                ),
        )
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let (serialized_oprf_client, remainder) = tokenize(input, 2)?;
        let (serialized_blinded_element, remainder) = tokenize(remainder, 2)?;

        if !remainder.is_empty() {
            return Err(ProtocolError::SerializationError);
        }

        Ok(Self {
            oprf_client: voprf::NonVerifiableClient::deserialize(serialized_oprf_client)?,
            blinded_element: voprf::BlindedElement::deserialize(serialized_blinded_element)?,
        })
    }

    /// Only used for testing zeroize
    #[cfg(test)]
    pub(crate) fn to_vec(&self) -> std::vec::Vec<u8> {
        [
            self.oprf_client.serialize().to_vec(),
            self.blinded_element.serialize().to_vec(),
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
            params.slow_hash,
        )?;

        let mut masking_key = Output::<CS::Hash>::default();
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

impl<CS: CipherSuite> ServerRegistration<CS>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, ServerRegistrationLen<CS>>
    where
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<CS::Hash>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <CS::KeGroup as KeGroup>::PkLen: Add<OutputSize<CS::Hash>>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, OutputSize<CS::Hash>>:
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
        let evaluate_result = server.evaluate(&message.blinded_element, None)?;

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

pub(crate) type ClientLoginLen<CS: CipherSuite> = Sum<
    Sum<Sum<U2, <CS::OprfGroup as Group>::ScalarLen>, Sum<U2, CredentialRequestLen<CS>>>,
    Sum<U2, Ke1StateLen<CS>>,
>;

impl<CS: CipherSuite> ClientLogin<CS>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> Result<GenericArray<u8, ClientLoginLen<CS>>, ProtocolError>
    where
        // CredentialRequest: KgPk + Ke1Message
        <CS::OprfGroup as Group>::ElemLen: Add<Ke1MessageLen<CS>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
        // ClientLogin: (2 + KgSk) + (2 + CredentialRequest) + (2 + Ke1State)
        U2: Add<<CS::OprfGroup as Group>::ScalarLen>,
        Sum<U2, <CS::OprfGroup as Group>::ScalarLen>:
            ArrayLength<u8> + Add<Sum<U2, CredentialRequestLen<CS>>>,
        U2: Add<CredentialRequestLen<CS>>,
        Sum<U2, CredentialRequestLen<CS>>: ArrayLength<u8>,
        Sum<Sum<U2, <CS::OprfGroup as Group>::ScalarLen>, Sum<U2, CredentialRequestLen<CS>>>:
            ArrayLength<u8> + Add<Sum<U2, Ke1StateLen<CS>>>,
        U2: Add<Ke1StateLen<CS>>,
        Sum<U2, Ke1StateLen<CS>>: ArrayLength<u8>,
        ClientLoginLen<CS>: ArrayLength<u8>,
    {
        Ok(
            Serialize::<U2, _>::from_owned(self.oprf_client.serialize())?
                .serialize()
                .concat(
                    Serialize::<U2, _>::from_owned(self.credential_request.serialize())?
                        .serialize(),
                )
                .concat(Serialize::<U2, _>::from_owned(self.ke1_state.to_bytes())?.serialize()),
        )
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let (serialized_oprf_client, remainder) = tokenize(input, 2)?;
        let (serialized_credential_request, remainder) = tokenize(remainder, 2)?;
        let (ke1_state_bytes, remainder) = tokenize(remainder, 2)?;

        if !remainder.is_empty() {
            return Err(ProtocolError::SerializationError);
        }

        let ke1_state =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1State::from_bytes(
                ke1_state_bytes,
            )?;
        Ok(Self {
            oprf_client: voprf::NonVerifiableClient::deserialize(serialized_oprf_client)?,
            ke1_state,
            credential_request: CredentialRequest::deserialize(serialized_credential_request)?,
        })
    }

    /// Only used for testing zeroize
    #[cfg(test)]
    pub(crate) fn to_vec(&self) -> std::vec::Vec<u8>
    where
        // CredentialRequest: KgPk + Ke1Message
        <CS::OprfGroup as Group>::ElemLen: Add<Ke1MessageLen<CS>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
    {
        [
            self.oprf_client.serialize().to_vec(),
            self.credential_request.serialize().to_vec(),
            self.ke1_state.to_bytes().to_vec(),
        ]
        .concat()
    }
}

impl<CS: CipherSuite> ClientLogin<CS>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
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

        Ok(ClientLoginStartResult {
            message: credential_request.clone(),
            state: Self {
                oprf_client: blind_result.state,
                ke1_state,
                credential_request,
            },
        })
    }

    /// "Unblinds" the server's answer and returns the opened assets from
    /// the server
    pub fn finish(
        self,
        password: &[u8],
        credential_response: CredentialResponse<CS>,
        params: ClientLoginFinishParameters<CS>,
    ) -> Result<ClientLoginFinishResult<CS>, ProtocolError>
    where
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<CS::Hash>>,
        Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
    {
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
            params.slow_hash,
        )?;

        let mut masking_key = Output::<CS::Hash>::default();
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

        let beta = credential_response.evaluation_element.value().to_arr();
        let credential_response_component = CredentialResponse::<CS>::serialize_without_ke(
            &beta,
            &credential_response.masking_nonce,
            &credential_response.masked_response,
        );

        let blinded_element = self.credential_request.blinded_element.value().to_arr();
        let ke1_message = self.credential_request.ke1_message.to_bytes();
        let serialized_credential_request =
            CredentialRequest::<CS>::serialize_iter(&blinded_element, &ke1_message);

        let result = CS::KeyExchange::generate_ke3(
            credential_response_component,
            credential_response.ke2_message,
            &self.ke1_state,
            serialized_credential_request,
            server_s_pk.clone(),
            opened_envelope.client_static_keypair.private().clone(),
            opened_envelope.id_u.iter(),
            opened_envelope.id_s.iter(),
            params.context.unwrap_or(&[]),
        )?;

        Ok(ClientLoginFinishResult {
            message: CredentialFinalization {
                ke3_message: result.1,
            },
            session_key: result.0,
            export_key: opened_envelope.export_key,
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

impl<CS: CipherSuite> ServerLogin<CS>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, Ke2StateLen<CS>> {
        self.ke2_state.to_bytes()
    }

    /// Deserialization from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            _cs: PhantomData,
            ke2_state:
                <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE2State::from_bytes(
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
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<CS::Hash>>,
        Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
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
            masking_nonce.as_slice(),
            &server_s_pk,
            &record.0.envelope,
        )
        .map_err(ProtocolError::into_custom)?;

        let (id_u, id_s) = bytestrings_from_identifiers::<CS::KeGroup>(
            identifiers,
            client_s_pk.to_arr(),
            server_s_pk.to_arr(),
        )
        .map_err(ProtocolError::into_custom)?;

        let blinded_element = credential_request.blinded_element.value().to_arr();
        let ke1_message = credential_request.ke1_message.to_bytes();
        let credential_request_bytes =
            CredentialRequest::<CS>::serialize_iter(&blinded_element, &ke1_message);

        let oprf_key = oprf_key_from_seed::<CS::OprfGroup, CS::Hash>(
            &server_setup.oprf_seed,
            credential_identifier,
        )
        .map_err(ProtocolError::into_custom)?;
        let server = voprf::NonVerifiableServer::new_with_key(&oprf_key)
            .map_err(|e| ProtocolError::into_custom(e.into()))?;
        let evaluate_result = server
            .evaluate(&credential_request.blinded_element, None)
            .map_err(|e| ProtocolError::into_custom(e.into()))?;
        let evaluation_element = evaluate_result.message;

        let beta = evaluation_element.value().to_arr();
        let credential_response_component =
            CredentialResponse::<CS>::serialize_without_ke(&beta, &masking_nonce, &masked_response);

        let result = CS::KeyExchange::generate_ke2(
            rng,
            credential_request_bytes,
            credential_response_component,
            credential_request.ke1_message,
            client_s_pk,
            server_s_sk.clone(),
            id_u.iter(),
            id_s.iter(),
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
pub struct ClientRegistrationFinishParameters<'i, 'h, CS: CipherSuite>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// Specifying the identifiers idU and idS
    pub identifiers: Identifiers<'i>,
    /// Specifying a configuration for the slow hash
    pub slow_hash: Option<&'h CS::SlowHash>,
}

impl<'i, 'h, CS: CipherSuite> ClientRegistrationFinishParameters<'i, 'h, CS>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
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
pub struct ClientRegistrationStartResult<CS: CipherSuite>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// The registration request message to be sent to the server
    pub message: RegistrationRequest<CS>,
    /// The client state that must be persisted in order to complete registration
    pub state: ClientRegistration<CS>,
}

/// Contains the fields that are returned by a client registration finish
#[derive(DeriveWhere)]
#[derive_where(Clone)]
pub struct ClientRegistrationFinishResult<CS: CipherSuite>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// The registration upload message to be sent to the server
    pub message: RegistrationUpload<CS>,
    /// The export key output by client registration
    pub export_key: Output<CS::Hash>,
    /// The server's static public key
    pub server_s_pk: PublicKey<CS::KeGroup>,
    /// Instance of the ClientRegistration, only used in tests for checking zeroize
    #[cfg(test)]
    pub state: ClientRegistration<CS>,
    /// AuthKey, only used in tests
    #[cfg(test)]
    pub auth_key: Output<CS::Hash>,
    /// Password derived key, only used in tests
    #[cfg(test)]
    pub randomized_pwd: Output<CS::Hash>,
}

/// Contains the fields that are returned by a server registration start.
/// Note that there is no state output in this step
#[derive(DeriveWhere)]
#[derive_where(Clone)]
pub struct ServerRegistrationStartResult<CS: CipherSuite>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// The registration resposne message to send to the client
    pub message: RegistrationResponse<CS>,
    /// OPRF key, only used in tests
    #[cfg(test)]
    pub oprf_key: GenericArray<u8, <CS::OprfGroup as Group>::ScalarLen>,
}

/// Contains the fields that are returned by a client login start
#[derive(DeriveWhere)]
#[derive_where(Clone)]
pub struct ClientLoginStartResult<CS: CipherSuite>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// The message to send to the server to begin the login protocol
    pub message: CredentialRequest<CS>,
    /// The state that the client must keep in order to complete the protocol
    pub state: ClientLogin<CS>,
}

/// Optional parameters for client login finish
#[derive(DeriveWhere)]
#[derive_where(Clone, Default)]
pub struct ClientLoginFinishParameters<'c, 'i, 'h, CS: CipherSuite>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// Specifying a context field that the server must agree on
    pub context: Option<&'c [u8]>,
    /// Specifying a user identifier and server identifier that will be matched against the server
    pub identifiers: Identifiers<'i>,
    /// Specifying a configuration for the slow hash
    pub slow_hash: Option<&'h CS::SlowHash>,
}

impl<'c, 'i, 'h, CS: CipherSuite> ClientLoginFinishParameters<'c, 'i, 'h, CS>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
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
pub struct ClientLoginFinishResult<CS: CipherSuite>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// The message to send to the server to complete the protocol
    pub message: CredentialFinalization<CS>,
    /// The session key
    pub session_key: Output<CS::Hash>,
    /// The client-side export key
    pub export_key: Output<CS::Hash>,
    /// The server's static public key
    pub server_s_pk: PublicKey<CS::KeGroup>,
    /// Instance of the ClientLogin, only used in tests for checking zeroize
    #[cfg(test)]
    pub state: ClientLogin<CS>,
    /// Handshake secret, only used in tests
    #[cfg(test)]
    pub handshake_secret: Output<CS::Hash>,
    /// Client MAC key, only used in tests
    #[cfg(test)]
    pub client_mac_key: Output<CS::Hash>,
}

/// Contains the fields that are returned by a server login finish
#[derive(DeriveWhere)]
#[derive_where(Clone)]
#[cfg_attr(not(test), derive_where(Debug))]
#[cfg_attr(test, derive_where(Debug; ServerLogin<CS>))]
pub struct ServerLoginFinishResult<CS: CipherSuite>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// The session key between client and server
    pub session_key: Output<CS::Hash>,
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
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// The message to send back to the client
    pub message: CredentialResponse<CS>,
    /// The state that the server must keep in order to finish the protocl
    pub state: ServerLogin<CS>,
    /// Handshake secret, only used in tests
    #[cfg(test)]
    pub handshake_secret: Output<CS::Hash>,
    /// Server MAC key, only used in tests
    #[cfg(test)]
    pub server_mac_key: Output<CS::Hash>,
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
    input: &[u8],
    oprf_client: voprf::NonVerifiableClient<CS::OprfGroup, CS::Hash>,
    evaluation_element: voprf::EvaluationElement<CS::OprfGroup, CS::Hash>,
    slow_hash: Option<&CS::SlowHash>,
) -> Result<(Output<CS::Hash>, Hkdf<CS::Hash>), ProtocolError>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let oprf_output = oprf_client.finalize(input, &evaluation_element, None)?;

    let hardened_output = if let Some(slow_hash) = slow_hash {
        slow_hash.hash(oprf_output.clone())
    } else {
        CS::SlowHash::default().hash(oprf_output.clone())
    }
    .map_err(ProtocolError::from)?;

    let mut hkdf = HkdfExtract::<CS::Hash>::new(None);
    hkdf.input_ikm(&oprf_output);
    hkdf.input_ikm(&hardened_output);
    Ok(hkdf.finalize())
}

fn oprf_key_from_seed<G: Group, D: Hash>(
    oprf_seed: &Output<D>,
    credential_identifier: &[u8],
) -> Result<GenericArray<u8, G::ScalarLen>, ProtocolError>
where
    D::Core: ProxyHash,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let mut ikm = GenericArray::<_, G::ScalarLen>::default();
    Hkdf::<D>::from_prk(oprf_seed)
        .ok()
        .and_then(|hkdf| {
            hkdf.expand_multi_info(&[credential_identifier, STR_OPRF_KEY], &mut ikm)
                .ok()
        })
        .ok_or(InternalError::HkdfError)?;
    Ok(G::scalar_as_bytes(G::hash_to_scalar::<D, _, _>(
        [ikm.as_slice()],
        GenericArray::from(*STR_OPAQUE_DERIVE_KEY_PAIR),
    )?))
}

#[derive(DeriveWhere)]
#[derive_where(Clone)]
#[derive_where(Debug, Eq, Hash, PartialEq)]
pub(crate) struct MaskedResponse<CS: CipherSuite>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    pub(crate) nonce: GenericArray<u8, NonceLen>,
    pub(crate) hash: Output<CS::Hash>,
    pub(crate) pk: GenericArray<u8, <CS::KeGroup as KeGroup>::PkLen>,
}

pub(crate) type MaskedResponseLen<CS: CipherSuite> =
    Sum<Sum<NonceLen, OutputSize<CS::Hash>>, <CS::KeGroup as KeGroup>::PkLen>;

impl<CS: CipherSuite> MaskedResponse<CS>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    pub(crate) fn serialize(&self) -> GenericArray<u8, MaskedResponseLen<CS>>
    where
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<CS::Hash>>,
        Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
    {
        self.nonce.concat(self.hash.clone()).concat(self.pk.clone())
    }

    pub(crate) fn deserialize(bytes: &[u8]) -> Self {
        let nonce = NonceLen::USIZE;
        let hash = nonce + OutputSize::<CS::Hash>::USIZE;
        let pk = hash + <CS::KeGroup as KeGroup>::PkLen::USIZE;

        Self {
            nonce: GenericArray::clone_from_slice(&bytes[..nonce]),
            hash: GenericArray::clone_from_slice(&bytes[nonce..hash]),
            pk: GenericArray::clone_from_slice(&bytes[hash..pk]),
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &[u8]> {
        [self.nonce.as_slice(), &self.hash, &self.pk].into_iter()
    }
}

fn mask_response<CS: CipherSuite>(
    masking_key: &[u8],
    masking_nonce: &[u8],
    server_s_pk: &PublicKey<CS::KeGroup>,
    envelope: &Envelope<CS>,
) -> Result<MaskedResponse<CS>, ProtocolError>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,

    // MaskedResponse: (Nonce + Hash) + KePk
    NonceLen: Add<OutputSize<CS::Hash>>,
    Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
    MaskedResponseLen<CS>: ArrayLength<u8>,
{
    let mut xor_pad = GenericArray::<_, MaskedResponseLen<CS>>::default();

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

    Ok(MaskedResponse::deserialize(&xor_pad))
}

fn unmask_response<CS: CipherSuite>(
    masking_key: &[u8],
    masking_nonce: &[u8],
    masked_response: &MaskedResponse<CS>,
) -> Result<(PublicKey<CS::KeGroup>, Envelope<CS>), ProtocolError>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // MaskedResponse: (Nonce + Hash) + KePk
    NonceLen: Add<OutputSize<CS::Hash>>,
    Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
    MaskedResponseLen<CS>: ArrayLength<u8>,
{
    let mut xor_pad = GenericArray::<_, MaskedResponseLen<CS>>::default();

    Hkdf::<CS::Hash>::from_prk(masking_key)
        .map_err(|_| InternalError::HkdfError)?
        .expand_multi_info(&[masking_nonce, STR_CREDENTIAL_RESPONSE_PAD], &mut xor_pad)
        .map_err(|_| InternalError::HkdfError)?;

    for (x1, x2) in xor_pad.iter_mut().zip(masked_response.iter().flatten()) {
        *x1 ^= x2
    }

    let key_len = <CS::KeGroup as KeGroup>::PkLen::USIZE;
    let unchecked_server_s_pk = PublicKey::from_bytes(&xor_pad[..key_len])?;
    let envelope = Envelope::deserialize(&xor_pad[key_len..])?;

    // Ensure that public key is valid
    let server_s_pk = KeyPair::<CS::KeGroup>::check_public_key(unchecked_server_s_pk)
        .map_err(|_| ProtocolError::SerializationError)?;

    Ok((server_s_pk, envelope))
}

#[allow(clippy::type_complexity)]
pub(crate) fn bytestrings_from_identifiers<KG: KeGroup>(
    ids: Identifiers,
    client_s_pk: GenericArray<u8, KG::PkLen>,
    server_s_pk: GenericArray<u8, KG::PkLen>,
) -> Result<(Serialize<U2, KG::PkLen>, Serialize<U2, KG::PkLen>), ProtocolError> {
    let client_identity = if let Some(client) = ids.client {
        Serialize::<U2, _>::from(client)?
    } else {
        Serialize::<U2, _>::from_owned(client_s_pk)?
    };
    let server_identity = if let Some(server) = ids.server {
        Serialize::<U2, _>::from(server)?
    } else {
        Serialize::<U2, _>::from_owned(server_s_pk)?
    };

    Ok((client_identity, server_identity))
}

/// Internal function for computing the blind result by calling the
/// voprf library. Note that for tests, we use the deterministic blinding
/// in order to be able to set the blinding factor directly from the passed-in
/// rng.
fn blind<CS: CipherSuite, R: RngCore + CryptoRng>(
    rng: &mut R,
    password: &[u8],
) -> Result<voprf::NonVerifiableClientBlindResult<CS::OprfGroup, CS::Hash>, voprf::Error>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    #[cfg(not(test))]
    let result = voprf::NonVerifiableClient::blind(password, rng)?;

    #[cfg(test)]
    let result = {
        let mut blind_bytes = GenericArray::default();
        let blind = loop {
            rng.fill_bytes(&mut blind_bytes);
            let scalar = <CS::OprfGroup as Group>::from_scalar_slice_unchecked(&blind_bytes)?;
            match scalar
                .ct_eq(&<CS::OprfGroup as Group>::scalar_zero())
                .into()
            {
                false => break scalar,
                true => (),
            }
        };
        voprf::NonVerifiableClient::deterministic_blind_unchecked(password, blind)?
    };

    Ok(result)
}

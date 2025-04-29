// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! An implementation of the SIGMA-I key exchange protocol

use core::iter;
use core::marker::PhantomData;
use core::ops::Add;

use derive_where::derive_where;
use digest::core_api::BlockSizeUser;
use digest::{Digest, Output, OutputSizeUser, Update};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, Le, NonZero, Sum, U2, U256};
use generic_array::{ArrayLength, GenericArray};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use subtle::{ConstantTimeEq, CtOption};
use zeroize::Zeroize;

use crate::ciphersuite::{CipherSuite, KeGroup, KeHash, OprfGroup, OprfHash};
use crate::envelope::NonceLen;
use crate::errors::{InternalError, ProtocolError};
use crate::hash::{Hash, OutputSize, ProxyHash};
use crate::key_exchange::group::Group;
use crate::key_exchange::shared::{self, Ke1MessageIter, Ke1MessageIterLen, STR_CONTEXT};
pub use crate::key_exchange::shared::{Ke1Message, Ke1State};
use crate::key_exchange::traits::{
    CredentialRequestParts, CredentialRequestPartsLen, CredentialResponseParts,
    CredentialResponsePartsLen, Deserialize, GenerateKe2Result, GenerateKe3Result, KeyExchange,
    Serialize, SerializedIdentifiers,
};
use crate::keypair::{KeyPair, PrivateKey, PublicKey};
use crate::opaque::MaskedResponseLen;
use crate::serialization::{i2osp, SliceExt, UpdateExt};

/// The SIGMA-I key exchange implementation
///
/// Generic `SIG` determines the algorithm used for the signature. `KE`
/// determines the algorithm used for establishing the shared secret.
///
/// # Remote Key
///
/// [`ServerLoginBuilder::data()`](crate::ServerLoginBuilder::data()) will
/// return a message.
/// [`ServerLoginBuilder::build()`](crate::ServerLoginBuilder::build()) expects
/// a signature from signing the message with the servers private key and a
/// "verification state". The "verification state" will be passed to the
/// verification method in place of the message. For NIST curves this is the
/// pre-hash, for Ed25519 it is the message itself.
pub struct SigmaI<SIG, KE, KEH>(PhantomData<(SIG, KE, KEH)>);

/// Trait to implement for signatures for [`SigmaI`].
pub trait SignatureGroup {
    /// The [`Group`] used to generate and derive keys.
    type Group: Group;
    /// The signature.
    type Signature: Clone + Deserialize + Serialize + Zeroize;
    /// The state required to run the verification. This is used to cache the
    /// pre-hash for curves that support that.
    type VerifyState<CS: CipherSuite, KE: Group>: Clone + Zeroize;

    /// Returns a signature from the given message signed by this private key.
    fn sign<R: CryptoRng + RngCore, CS: CipherSuite, KE: Group>(
        sk: &<Self::Group as Group>::Sk,
        rng: &mut R,
        message: Message<CS, KE>,
    ) -> (Self::Signature, Self::VerifyState<CS, KE>);

    /// Validates that the signature was created by signing the given message
    /// with the corresponding private key.
    fn verify<CS: CipherSuite, KE: Group>(
        pk: &<Self::Group as Group>::Pk,
        state: Self::VerifyState<CS, KE>,
        signature: &Self::Signature,
    ) -> Result<(), ProtocolError>;
}

/// Shared secret computation implementation.
pub trait SharedSecret<KE: Group> {
    /// Length of the shared secret.
    type Len: ArrayLength<u8>;

    /// Returns a shared secret computed between the private key and the given
    /// public key.
    fn shared_secret(self, pk: KE::Pk) -> GenericArray<u8, Self::Len>;
}

/// Builder for the second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, PartialEq; PublicKey<KeGroup<CS>>, PublicKey<KE>)]
pub struct Ke2Builder<CS: CipherSuite, KE: Group, KEH: OutputSizeUser> {
    transcript: Message<CS, KE>,
    server_nonce: GenericArray<u8, NonceLen>,
    client_s_pk: PublicKey<KeGroup<CS>>,
    server_e_pk: PublicKey<KE>,
    mac: Output<KEH>,
    expected_mac: Output<KEH>,
    session_key: Output<KEH>,
    #[cfg(test)]
    km3: Output<KEH>,
    #[cfg(test)]
    handshake_secret: Output<KEH>,
}

/// This holds the message to be signed. See its methods for more information.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Message<CS: CipherSuite, KE: Group> {
    credential_request: CredentialRequestParts<CS>,
    ke1_message: Ke1MessageIter<KE>,
    credential_response: CredentialResponseParts<CS>,
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: GenericArray<u8, KE::PkLen>,
}

/// The server state produced after the second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "SIG::VerifyState<CS, KE>: serde::Deserialize<'de>",
        serialize = "SIG::VerifyState<CS, KE>: serde::Serialize"
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, PartialEq; <SIG::Group as Group>::Pk, SIG::VerifyState<CS, KE>)]
pub struct Ke2State<CS: CipherSuite, SIG: SignatureGroup, KE: Group, KEH: OutputSizeUser> {
    client_s_pk: PublicKey<SIG::Group>,
    session_key: Output<KEH>,
    verify_state: SIG::VerifyState<CS, KE>,
    expected_mac: Output<KEH>,
}

/// The second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "SIG::Signature: serde::Deserialize<'de>",
        serialize = "SIG::Signature: serde::Serialize"
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; KE::Pk, SIG::Signature)]
pub struct Ke2Message<SIG: SignatureGroup, KE: Group, KEH: Hash>
where
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: PublicKey<KE>,
    signature: SIG::Signature,
    mac: Output<KEH>,
}

/// The third key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "SIG::Signature: serde::Deserialize<'de>",
        serialize = "SIG::Signature: serde::Serialize"
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; SIG::Signature)]
pub struct Ke3Message<SIG: SignatureGroup, KEH: OutputSizeUser> {
    signature: SIG::Signature,
    mac: Output<KEH>,
}

impl<SIG: SignatureGroup, KE: 'static + Group, KEH: Hash> KeyExchange for SigmaI<SIG, KE, KEH>
where
    KE::Sk: SharedSecret<KE>,
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    type Group = SIG::Group;
    type Hash = KEH;

    type KE1State = Ke1State<KE>;
    type KE1Message = Ke1Message<KE>;
    type KE2Builder<CS: CipherSuite<KeyExchange = Self>> = Ke2Builder<CS, KE, KEH>;
    type KE2BuilderData<'a, CS: 'static + CipherSuite> = &'a Message<CS, KE>;
    type KE2BuilderInput<CS: CipherSuite> = (SIG::Signature, SIG::VerifyState<CS, KE>);
    type KE2State<CS: CipherSuite> = Ke2State<CS, SIG, KE, KEH>;
    type KE2Message = Ke2Message<SIG, KE, KEH>;
    type KE3Message = Ke3Message<SIG, KEH>;

    fn generate_ke1<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError> {
        let client_e_kp = KeyPair::<KE>::derive_random(rng);
        let client_nonce = shared::generate_nonce::<R>(rng);

        let ke1_message = Ke1Message {
            client_nonce,
            client_e_pk: client_e_kp.public().clone(),
        };

        Ok((
            Ke1State {
                client_e_sk: client_e_kp.private().clone(),
                client_nonce,
            },
            ke1_message,
        ))
    }

    fn ke2_builder<CS: CipherSuite<KeyExchange = Self>, R: RngCore + CryptoRng>(
        rng: &mut R,
        credential_request: CredentialRequestParts<CS>,
        ke1_message: Self::KE1Message,
        credential_response: CredentialResponseParts<CS>,
        client_s_pk: PublicKey<Self::Group>,
        identifiers: SerializedIdentifiers<'_, KeGroup<CS>>,
        context: &[u8],
    ) -> Result<Self::KE2Builder<CS>, ProtocolError> {
        let server_e = KeyPair::<KE>::derive_random(rng);
        let server_nonce = shared::generate_nonce::<R>(rng);

        let (message, info_hasher) = transcript(
            context,
            &identifiers,
            credential_request,
            &ke1_message,
            credential_response,
            server_nonce,
            server_e.public(),
        )?;

        let shared_secret = server_e
            .private()
            .ke_shared_secret(&ke1_message.client_e_pk);

        let derived_keys = shared::derive_keys::<KEH>(
            iter::once(shared_secret.as_slice()),
            &info_hasher.finalize(),
        )?;

        let mut mac_hasher =
            Hmac::<KEH>::new_from_slice(&derived_keys.km2).map_err(|_| InternalError::HmacError)?;
        mac_hasher.update_iter(identifiers.server.iter());
        let mac = mac_hasher.finalize().into_bytes();

        let mut mac_hasher =
            Hmac::<KEH>::new_from_slice(&derived_keys.km3).map_err(|_| InternalError::HmacError)?;
        mac_hasher.update_iter(identifiers.client.iter());
        Mac::update(&mut mac_hasher, &mac);
        let expected_mac = mac_hasher.finalize().into_bytes();

        Ok(Ke2Builder {
            transcript: message,
            server_nonce,
            client_s_pk,
            server_e_pk: server_e.public().clone(),
            mac,
            expected_mac,
            session_key: derived_keys.session_key,
            #[cfg(test)]
            km3: derived_keys.km3,
            #[cfg(test)]
            handshake_secret: derived_keys.handshake_secret,
        })
    }

    fn ke2_builder_data<CS: 'static + CipherSuite<KeyExchange = Self>>(
        builder: &Self::KE2Builder<CS>,
    ) -> Self::KE2BuilderData<'_, CS> {
        &builder.transcript
    }

    fn generate_ke2_input<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + RngCore>(
        builder: &Self::KE2Builder<CS>,
        rng: &mut R,
        server_s_sk: &PrivateKey<Self::Group>,
    ) -> Self::KE2BuilderInput<CS> {
        server_s_sk.sign::<_, CS, SIG, KE>(rng, builder.transcript.clone())
    }

    fn build_ke2<CS: CipherSuite<KeyExchange = Self>>(
        builder: Self::KE2Builder<CS>,
        input: Self::KE2BuilderInput<CS>,
    ) -> Result<GenerateKe2Result<CS>, ProtocolError> {
        Ok((
            Ke2State {
                client_s_pk: builder.client_s_pk.clone(),
                session_key: builder.session_key.clone(),
                verify_state: input.1,
                expected_mac: builder.expected_mac.clone(),
            },
            Ke2Message {
                server_nonce: builder.server_nonce,
                server_e_pk: builder.server_e_pk.clone(),
                signature: input.0,
                mac: builder.mac.clone(),
            },
            #[cfg(test)]
            builder.handshake_secret.clone(),
            #[cfg(test)]
            builder.km3.clone(),
        ))
    }

    fn generate_ke3<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + RngCore>(
        rng: &mut R,
        credential_request: CredentialRequestParts<CS>,
        ke1_message: Self::KE1Message,
        credential_response: CredentialResponseParts<CS>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        server_s_pk: PublicKey<Self::Group>,
        client_s_sk: PrivateKey<Self::Group>,
        identifiers: SerializedIdentifiers<'_, KeGroup<CS>>,
        context: &[u8],
    ) -> Result<GenerateKe3Result<Self>, ProtocolError> {
        let (transcript, info_hasher) = transcript(
            context,
            &identifiers,
            credential_request,
            &ke1_message,
            credential_response,
            ke2_message.server_nonce,
            &ke2_message.server_e_pk,
        )?;

        let (signature, state) = client_s_sk.sign::<_, CS, SIG, KE>(rng, transcript);

        server_s_pk.verify::<CS, SIG, KE>(state, &ke2_message.signature)?;

        let shared_secret = ke1_state
            .client_e_sk
            .ke_shared_secret(&ke2_message.server_e_pk);

        let derived_keys = shared::derive_keys::<KEH>(
            iter::once(shared_secret.as_slice()),
            &info_hasher.finalize(),
        )?;

        let mut server_mac =
            Hmac::<KEH>::new_from_slice(&derived_keys.km2).map_err(|_| InternalError::HmacError)?;
        server_mac.update_iter(identifiers.server.iter());

        Mac::verify(server_mac, &ke2_message.mac).map_err(|_| ProtocolError::InvalidLoginError)?;

        let mut client_mac =
            Hmac::<KEH>::new_from_slice(&derived_keys.km3).map_err(|_| InternalError::HmacError)?;
        client_mac.update_iter(identifiers.client.iter());
        Mac::update(&mut client_mac, &ke2_message.mac);

        Ok((
            derived_keys.session_key,
            Ke3Message {
                signature,
                mac: client_mac.finalize().into_bytes(),
            },
            #[cfg(test)]
            derived_keys.handshake_secret,
            #[cfg(test)]
            derived_keys.km3,
        ))
    }

    fn finish_ke<CS: CipherSuite>(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State<CS>,
    ) -> Result<Output<KEH>, ProtocolError> {
        ke2_state
            .client_s_pk
            .verify::<CS, SIG, KE>(ke2_state.verify_state.clone(), &ke3_message.signature)?;

        CtOption::new(
            ke2_state.session_key.clone(),
            ke2_state.expected_mac.ct_eq(&ke3_message.mac),
        )
        .into_option()
        .ok_or(ProtocolError::InvalidLoginError)
    }
}

impl<CS: CipherSuite, KE: Group> Message<CS, KE> {
    /// Returns the message to be signed. These are not multiple messages, but
    /// are just segments of one message to be signed.
    pub fn message_iter(&self) -> impl Clone + Iterator<Item = &[u8]> {
        self.credential_request
            .iter()
            .chain(self.ke1_message.iter())
            .chain(self.credential_response.iter())
            .chain([self.server_nonce.as_slice(), self.server_e_pk.as_slice()])
    }
}

impl<CS: CipherSuite, KE: Group> Deserialize for Message<CS, KE> {
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            credential_request: CredentialRequestParts::deserialize_take(input)?,
            ke1_message: Ke1MessageIter::deserialize_take(input)?,
            credential_response: CredentialResponseParts::deserialize_take(input)?,
            server_nonce: input.take_array("server nonce")?,
            server_e_pk: input.take_array("serialized server ephemeral key")?,
        })
    }
}

/// Length of the [message](Message::message()).
pub type MessageLen<CS: CipherSuite, KE: Group> = Sum<
    Sum<
        Sum<
            Sum<CredentialRequestPartsLen<CS>, Ke1MessageIterLen<KE>>,
            CredentialResponsePartsLen<CS>,
        >,
        NonceLen,
    >,
    KE::PkLen,
>;

impl<CS: CipherSuite, KE: Group> Serialize for Message<CS, KE>
where
    CredentialRequestPartsLen<CS>: ArrayLength<u8> + Add<Ke1MessageIterLen<KE>>,
    Sum<CredentialRequestPartsLen<CS>, Ke1MessageIterLen<KE>>:
        ArrayLength<u8> + Add<CredentialResponsePartsLen<CS>>,
    Sum<Sum<CredentialRequestPartsLen<CS>, Ke1MessageIterLen<KE>>, CredentialResponsePartsLen<CS>>:
        ArrayLength<u8> + Add<NonceLen>,
    Sum<
        Sum<
            Sum<CredentialRequestPartsLen<CS>, Ke1MessageIterLen<KE>>,
            CredentialResponsePartsLen<CS>,
        >,
        NonceLen,
    >: ArrayLength<u8> + Add<KE::PkLen>,
    MessageLen<CS, KE>: ArrayLength<u8>,
    // Ke1MessageIter
    NonceLen: Add<KE::PkLen>,
    Ke1MessageIterLen<KE>: ArrayLength<u8>,
    // CredentialResponseParts
    <OprfGroup<CS> as voprf::Group>::ElemLen: Add<NonceLen>,
    Sum<<OprfGroup<CS> as voprf::Group>::ElemLen, NonceLen>:
        ArrayLength<u8> + Add<MaskedResponseLen<CS>>,
    CredentialResponsePartsLen<CS>: ArrayLength<u8>,
    // MaskedResponse: (Nonce + Hash) + KePk
    NonceLen: Add<OutputSize<OprfHash<CS>>>,
    Sum<NonceLen, OutputSize<OprfHash<CS>>>: ArrayLength<u8> + Add<<KeGroup<CS> as Group>::PkLen>,
    MaskedResponseLen<CS>: ArrayLength<u8>,
{
    type Len = MessageLen<CS, KE>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.credential_request
            .serialize()
            .concat(self.ke1_message.serialize())
            .concat(self.credential_response.serialize())
            .concat(self.server_nonce)
            .concat(self.server_e_pk.clone())
    }
}

#[allow(clippy::too_many_arguments)]
fn transcript<CS: CipherSuite, KE: Group>(
    context: &[u8],
    identifiers: &SerializedIdentifiers<'_, KeGroup<CS>>,
    credential_request: CredentialRequestParts<CS>,
    ke1_message: &Ke1Message<KE>,
    credential_response: CredentialResponseParts<CS>,
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: &PublicKey<KE>,
) -> Result<(Message<CS, KE>, KeHash<CS>), ProtocolError> {
    let ke1_message = ke1_message.to_iter();
    let server_e_pk = server_e_pk.serialize();

    let info_hasher = KeHash::<CS>::new()
        .chain(STR_CONTEXT)
        .chain(i2osp::<U2>(context.len())?)
        .chain(context)
        .chain_iter(identifiers.client.iter())
        .chain_iter(credential_request.iter())
        .chain_iter(ke1_message.iter())
        .chain_iter(identifiers.server.iter())
        .chain_iter(credential_response.iter())
        .chain(server_nonce)
        .chain(&server_e_pk);

    let transcript = Message {
        credential_request,
        ke1_message,
        credential_response,
        server_nonce,
        server_e_pk,
    };

    Ok((transcript, info_hasher))
}

impl<CS: CipherSuite, SIG: SignatureGroup, KE: Group, KEH: OutputSizeUser> Deserialize
    for Ke2State<CS, SIG, KE, KEH>
where
    SIG::VerifyState<CS, KE>: Deserialize,
{
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            client_s_pk: PublicKey::deserialize_take(input)?,
            session_key: input.take_array("session key")?,
            verify_state: SIG::VerifyState::deserialize_take(input)?,
            expected_mac: input.take_array("expected mac")?,
        })
    }
}

type Ke2StateLen<CS, SIG: SignatureGroup, KE, KEH> = Sum<
    Sum<Sum<<SIG::Group as Group>::PkLen, OutputSize<KEH>>, VerifyStateLen<CS, SIG, KE>>,
    OutputSize<KEH>,
>;

type VerifyStateLen<CS, SIG: SignatureGroup, KE> = <SIG::VerifyState<CS, KE> as Serialize>::Len;

impl<CS: CipherSuite, SIG: SignatureGroup, KE: Group, KEH: Hash> Serialize
    for Ke2State<CS, SIG, KE, KEH>
where
    SIG::VerifyState<CS, KE>: Serialize,
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Ke2State: ((SigPk + Hash) + VerifyState) + Hash
    <SIG::Group as Group>::PkLen: Add<OutputSize<KEH>>,
    Sum<<SIG::Group as Group>::PkLen, OutputSize<KEH>>:
        ArrayLength<u8> + Add<VerifyStateLen<CS, SIG, KE>>,
    Sum<Sum<<SIG::Group as Group>::PkLen, OutputSize<KEH>>, VerifyStateLen<CS, SIG, KE>>:
        ArrayLength<u8> + Add<OutputSize<KEH>>,
    Ke2StateLen<CS, SIG, KE, KEH>: ArrayLength<u8>,
{
    type Len = Ke2StateLen<CS, SIG, KE, KEH>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.client_s_pk
            .serialize()
            .concat(self.session_key.clone())
            .concat(self.verify_state.serialize())
            .concat(self.expected_mac.clone())
    }
}

impl<SIG: SignatureGroup, KE: Group, KEH: Hash> Deserialize for Ke2Message<SIG, KE, KEH>
where
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            server_nonce: input.take_array("server nonce")?,
            server_e_pk: PublicKey::deserialize_take(input)?,
            signature: SIG::Signature::deserialize_take(input)?,
            mac: input.take_array("mac")?,
        })
    }
}

impl<SIG: SignatureGroup, KE: Group, KEH: Hash> Serialize for Ke2Message<SIG, KE, KEH>
where
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Ke2Message: ((Nonce + KePk) + Signature) + Hash
    NonceLen: Add<KE::PkLen>,
    Sum<NonceLen, KE::PkLen>: ArrayLength<u8> + Add<<SIG::Signature as Serialize>::Len>,
    Sum<Sum<NonceLen, KE::PkLen>, <SIG::Signature as Serialize>::Len>:
        ArrayLength<u8> + Add<OutputSize<KEH>>,
    Sum<Sum<Sum<NonceLen, KE::PkLen>, <SIG::Signature as Serialize>::Len>, OutputSize<KEH>>:
        ArrayLength<u8>,
{
    type Len =
        Sum<Sum<Sum<NonceLen, KE::PkLen>, <SIG::Signature as Serialize>::Len>, OutputSize<KEH>>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.server_nonce
            .concat(self.server_e_pk.serialize())
            .concat(self.signature.serialize())
            .concat(self.mac.clone())
    }
}

impl<SIG: SignatureGroup, KEH: Hash> Deserialize for Ke3Message<SIG, KEH>
where
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            signature: SIG::Signature::deserialize_take(input)?,
            mac: input.take_array("mac")?,
        })
    }
}

impl<SIG: SignatureGroup, KEH: Hash> Serialize for Ke3Message<SIG, KEH>
where
    KEH::Core: ProxyHash,
    <KEH::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<KEH::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Ke2Message: Signature + Hash
    <SIG::Signature as Serialize>::Len: Add<OutputSize<KEH>>,
    Sum<<SIG::Signature as Serialize>::Len, OutputSize<KEH>>: ArrayLength<u8>,
{
    type Len = Sum<<SIG::Signature as Serialize>::Len, OutputSize<KEH>>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.signature.serialize().concat(self.mac.clone())
    }
}

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::serialization::AssertZeroized;

#[cfg(test)]
impl<CS: CipherSuite, KE: Group> AssertZeroized for Message<CS, KE>
where
    Ke1MessageIter<KE>: AssertZeroized,
{
    fn assert_zeroized(&self) {
        let Self {
            credential_request,
            ke1_message,
            credential_response,
            server_nonce,
            server_e_pk,
        } = self;

        credential_request.assert_zeroized();
        ke1_message.assert_zeroized();
        credential_response.assert_zeroized();

        for byte in server_nonce.iter().chain(server_e_pk) {
            assert_eq!(byte, &0);
        }
    }
}

#[cfg(test)]
impl<CS: CipherSuite, SIG: SignatureGroup, KE: Group, KEH: OutputSizeUser> AssertZeroized
    for Ke2State<CS, SIG, KE, KEH>
where
    <SIG::Group as Group>::Pk: AssertZeroized,
    SIG::VerifyState<CS, KE>: AssertZeroized,
{
    fn assert_zeroized(&self) {
        let Self {
            client_s_pk,
            session_key,
            verify_state,
            expected_mac,
        } = self;

        client_s_pk.assert_zeroized();
        verify_state.assert_zeroized();

        for byte in session_key.iter().chain(expected_mac) {
            assert_eq!(byte, &0);
        }
    }
}

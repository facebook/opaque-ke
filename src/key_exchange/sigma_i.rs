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
use generic_array::typenum::{IsLess, Le, NonZero, Sum, Unsigned, U2, U256};
use generic_array::{ArrayLength, GenericArray};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use subtle::{ConstantTimeEq, CtOption};
use zeroize::Zeroize;

use crate::envelope::NonceLen;
use crate::errors::utils::{check_slice_size, check_slice_size_atleast};
use crate::errors::{InternalError, ProtocolError};
use crate::hash::{Hash, OutputSize, ProxyHash};
use crate::key_exchange::group::Group;
use crate::key_exchange::shared::{self, STR_CONTEXT};
pub use crate::key_exchange::shared::{Ke1Message, Ke1State};
use crate::key_exchange::traits::{
    Deserialize, GenerateKe2Result, GenerateKe3Result, KeyExchange, Serialize,
};
use crate::keypair::{KeyPair, PrivateKey, PublicKey};
use crate::serialization::{Input, MacExt, UpdateExt};

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
/// a signature from signing the message with the servers private key. The
/// message is already pre-hashed and should be treated as a digest.
pub struct SigmaI<SIG, KE, H>(PhantomData<(SIG, KE, H)>);

/// Private key signing implementation.
pub trait Sign {
    /// The signature.
    type Signature: Clone + Deserialize + Serialize + Zeroize;

    /// Returns a signature from the given message signed by this private key.
    /// The message is already prehashed and should be treated as a digest.
    fn sign<R: CryptoRng + RngCore>(self, rng: &mut R, prehash: &[u8]) -> Self::Signature;
}

/// Public key verifying implementation.
pub trait Verify<SIG: Group>
where
    SIG::Sk: Sign,
{
    /// Validates that the given signature was signed by the corresponding
    /// private key. The message is already prehashed and should be treated as a
    /// digest.
    fn verify(
        self,
        prehash: &[u8],
        signature: &<SIG::Sk as Sign>::Signature,
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
    serde(bound(
        deserialize = "PublicKey<SIG>: serde::Deserialize<'de>, PublicKey<KE>: \
                       serde::Deserialize<'de>",
        serialize = "PublicKey<SIG>: serde::Serialize, PublicKey<KE>: serde::Serialize",
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; PublicKey<SIG>, PublicKey<KE>)]
pub struct Ke2Builder<SIG: Group, KE: Group, H: Hash>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    server_nonce: GenericArray<u8, NonceLen>,
    transcript: Output<H>,
    client_s_pk: PublicKey<SIG>,
    server_e_pk: PublicKey<KE>,
    mac: Output<H>,
    expected_mac: Output<H>,
    session_key: Output<H>,
    #[cfg(test)]
    km3: Output<H>,
    #[cfg(test)]
    handshake_secret: Output<H>,
}

/// The server state produced after the second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; PublicKey<SIG>)]
pub struct Ke2State<SIG: Group, H: OutputSizeUser> {
    client_s_pk: PublicKey<SIG>,
    session_key: Output<H>,
    transcript: Output<H>,
    expected_mac: Output<H>,
}

/// The second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "<SIG::Sk as Sign>::Signature: serde::Deserialize<'de>",
        serialize = "<SIG::Sk as Sign>::Signature: serde::Serialize"
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; KE::Pk, <SIG::Sk as Sign>::Signature)]
pub struct Ke2Message<SIG: Group, KE: Group, H: Hash>
where
    SIG::Sk: Sign,
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: PublicKey<KE>,
    signature: <SIG::Sk as Sign>::Signature,
    mac: Output<H>,
}

/// The third key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "<SIG::Sk as Sign>::Signature: serde::Deserialize<'de>",
        serialize = "<SIG::Sk as Sign>::Signature: serde::Serialize"
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <SIG::Sk as Sign>::Signature)]
pub struct Ke3Message<SIG: Group, H: OutputSizeUser>
where
    SIG::Sk: Sign,
{
    signature: <SIG::Sk as Sign>::Signature,
    mac: Output<H>,
}

impl<SIG: 'static + Group, KE: 'static + Group, H: Hash> KeyExchange for SigmaI<SIG, KE, H>
where
    SIG::Sk: Sign,
    SIG::Pk: Verify<SIG>,
    KE::Sk: SharedSecret<KE>,
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    type Group = SIG;
    type Hash = H;

    type KE1State = Ke1State<KE>;
    type KE1Message = Ke1Message<KE>;
    type KE2Builder = Ke2Builder<SIG, KE, H>;
    type KE2BuilderData<'a> = &'a Output<H>;
    type KE2BuilderInput = <SIG::Sk as Sign>::Signature;
    type KE2State = Ke2State<SIG, H>;
    type KE2Message = Ke2Message<SIG, KE, H>;
    type KE3Message = Ke3Message<SIG, H>;

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

    fn ke2_builder<'a, 'b, 'c, 'd, R: RngCore + CryptoRng>(
        rng: &mut R,
        serialized_credential_request: impl Clone + Iterator<Item = &'a [u8]>,
        serialized_credential_response: impl Clone + Iterator<Item = &'b [u8]>,
        ke1_message: Self::KE1Message,
        client_s_pk: PublicKey<SIG>,
        id_u: impl Clone + Iterator<Item = &'c [u8]>,
        id_s: impl Clone + Iterator<Item = &'d [u8]>,
        context: &[u8],
    ) -> Result<Self::KE2Builder, ProtocolError> {
        let server_e = KeyPair::<KE>::derive_random(rng);
        let server_nonce = shared::generate_nonce::<R>(rng);

        let (transcript, info_hasher) = transcript::<KE, H>(
            context,
            id_u.clone(),
            serialized_credential_request,
            id_s.clone(),
            serialized_credential_response,
            server_nonce,
            server_e.public(),
        )?;

        let shared_secret = server_e
            .private()
            .ke_shared_secret(&ke1_message.client_e_pk);

        let derived_keys = shared::derive_keys::<H>(
            iter::once(shared_secret.as_slice()),
            &info_hasher.finalize(),
        )?;

        let mut mac_hasher =
            Hmac::<H>::new_from_slice(&derived_keys.km2).map_err(|_| InternalError::HmacError)?;
        mac_hasher.update_iter(id_s);
        let mac = mac_hasher.finalize().into_bytes();

        let mut mac_hasher =
            Hmac::<H>::new_from_slice(&derived_keys.km3).map_err(|_| InternalError::HmacError)?;
        mac_hasher.update_iter(id_u);
        Mac::update(&mut mac_hasher, &mac);
        let expected_mac = mac_hasher.finalize().into_bytes();

        Ok(Ke2Builder {
            server_nonce,
            transcript,
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

    fn ke2_builder_data(builder: &Self::KE2Builder) -> Self::KE2BuilderData<'_> {
        &builder.transcript
    }

    fn generate_ke2_input<R: CryptoRng + RngCore>(
        builder: &Self::KE2Builder,
        rng: &mut R,
        server_s_sk: &PrivateKey<SIG>,
    ) -> Self::KE2BuilderInput {
        server_s_sk.ke_sign(rng, &builder.transcript)
    }

    fn build_ke2(
        builder: Self::KE2Builder,
        input: Self::KE2BuilderInput,
    ) -> Result<GenerateKe2Result<Self>, ProtocolError> {
        Ok((
            Ke2State {
                client_s_pk: builder.client_s_pk.clone(),
                session_key: builder.session_key.clone(),
                transcript: builder.transcript.clone(),
                expected_mac: builder.expected_mac.clone(),
            },
            Ke2Message {
                server_nonce: builder.server_nonce,
                server_e_pk: builder.server_e_pk.clone(),
                signature: input,
                mac: builder.mac.clone(),
            },
            #[cfg(test)]
            builder.handshake_secret.clone(),
            #[cfg(test)]
            builder.km3.clone(),
        ))
    }

    fn generate_ke3<'a, 'b, 'c, 'd, R: CryptoRng + RngCore>(
        rng: &mut R,
        serialized_credential_response: impl Clone + Iterator<Item = &'a [u8]>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        serialized_credential_request: impl Clone + Iterator<Item = &'b [u8]>,
        server_s_pk: PublicKey<SIG>,
        client_s_sk: PrivateKey<SIG>,
        id_u: impl Clone + Iterator<Item = &'c [u8]>,
        id_s: impl Clone + Iterator<Item = &'d [u8]>,
        context: &[u8],
    ) -> Result<GenerateKe3Result<Self>, ProtocolError> {
        let (transcript, info_hasher) = transcript::<KE, H>(
            context,
            id_u.clone(),
            serialized_credential_request,
            id_s.clone(),
            serialized_credential_response,
            ke2_message.server_nonce,
            &ke2_message.server_e_pk,
        )?;

        server_s_pk.ke_verify(&transcript, &ke2_message.signature)?;

        let signature = client_s_sk.ke_sign(rng, &transcript);

        let shared_secret = ke1_state
            .client_e_sk
            .ke_shared_secret(&ke2_message.server_e_pk);

        let derived_keys = shared::derive_keys::<H>(
            iter::once(shared_secret.as_slice()),
            &info_hasher.finalize(),
        )?;

        let mut server_mac =
            Hmac::<H>::new_from_slice(&derived_keys.km2).map_err(|_| InternalError::HmacError)?;
        server_mac.update_iter(id_s);

        Mac::verify(server_mac, &ke2_message.mac).map_err(|_| ProtocolError::InvalidLoginError)?;

        let mut client_mac =
            Hmac::<H>::new_from_slice(&derived_keys.km3).map_err(|_| InternalError::HmacError)?;
        client_mac.update_iter(id_u);
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

    fn finish_ke(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State,
    ) -> Result<Output<H>, ProtocolError> {
        ke2_state
            .client_s_pk
            .ke_verify(&ke2_state.transcript, &ke3_message.signature)?;

        CtOption::new(
            ke2_state.session_key.clone(),
            ke2_state.expected_mac.ct_eq(&ke3_message.mac),
        )
        .into_option()
        .ok_or(ProtocolError::InvalidLoginError)
    }
}

fn transcript<'a, 'b, 'c, 'd, G: Group, H: Clone + Digest + Update>(
    context: &[u8],
    id_u: impl Iterator<Item = &'a [u8]>,
    serialized_credential_request: impl Clone + Iterator<Item = &'c [u8]>,
    id_s: impl Iterator<Item = &'b [u8]>,
    serialized_credential_response: impl Clone + Iterator<Item = &'d [u8]>,
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: &PublicKey<G>,
) -> Result<(Output<H>, H), ProtocolError> {
    let transcript_hasher = H::new()
        .chain(STR_CONTEXT)
        .chain_iter(Input::<U2>::from(context)?.iter());
    let transcript = transcript_hasher
        .clone()
        .chain_iter(serialized_credential_request.clone())
        .chain_iter(serialized_credential_response.clone())
        .chain(server_nonce)
        .chain(server_e_pk.serialize())
        .finalize();

    let info_hasher = transcript_hasher
        .chain_iter(id_u)
        .chain_iter(serialized_credential_request)
        .chain_iter(id_s)
        .chain_iter(serialized_credential_response)
        .chain(server_nonce)
        .chain(server_e_pk.serialize());

    Ok((transcript, info_hasher))
}

impl<SIG: Group, H: Hash> Deserialize for Ke2State<SIG, H>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let key_len = <SIG as Group>::PkLen::USIZE;
        let hash_len = OutputSize::<H>::USIZE;
        let checked_bytes = check_slice_size(input, key_len + 3 * hash_len, "ke2_state")?;

        Ok(Self {
            client_s_pk: PublicKey::deserialize(&input[..key_len])?,
            session_key: GenericArray::clone_from_slice(
                &checked_bytes[key_len..key_len + hash_len],
            ),
            transcript: GenericArray::clone_from_slice(
                &checked_bytes[key_len + hash_len..key_len + hash_len + hash_len],
            ),
            expected_mac: GenericArray::clone_from_slice(
                &checked_bytes[key_len + hash_len + hash_len..],
            ),
        })
    }
}

impl<SIG: Group, H: Hash> Serialize for Ke2State<SIG, H>
where
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Ke2State: ((SigPk + Hash) + Hash) + Hash
    SIG::PkLen: Add<OutputSize<H>>,
    Sum<SIG::PkLen, OutputSize<H>>: ArrayLength<u8> + Add<OutputSize<H>>,
    Sum<Sum<SIG::PkLen, OutputSize<H>>, OutputSize<H>>: ArrayLength<u8> + Add<OutputSize<H>>,
    Sum<Sum<Sum<SIG::PkLen, OutputSize<H>>, OutputSize<H>>, OutputSize<H>>: ArrayLength<u8>,
{
    type Len = Sum<Sum<Sum<SIG::PkLen, OutputSize<H>>, OutputSize<H>>, OutputSize<H>>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.client_s_pk
            .serialize()
            .concat(self.session_key.clone())
            .concat(self.transcript.clone())
            .concat(self.expected_mac.clone())
    }
}

impl<SIG: Group, KE: Group, H: Hash> Deserialize for Ke2Message<SIG, KE, H>
where
    SIG::Sk: Sign,
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let nonce_len = NonceLen::USIZE;
        let key_len = <KE as Group>::PkLen::USIZE;
        let signature_len = <<SIG::Sk as Sign>::Signature as Serialize>::Len::USIZE;
        let mac_len = OutputSize::<H>::USIZE;
        let checked_nonce = check_slice_size_atleast(input, nonce_len, "ke2_message nonce")?;

        let unchecked_server_e_pk = check_slice_size_atleast(
            &checked_nonce[nonce_len..],
            key_len,
            "ke2_message server_e_pk",
        )?;
        let checked_signature = check_slice_size_atleast(
            &unchecked_server_e_pk[key_len..],
            signature_len,
            "ke2_message signature",
        )?;
        let checked_mac = check_slice_size(
            &checked_signature[signature_len..],
            mac_len,
            "ke2_message mac",
        )?;

        // Check the public key bytes
        let server_e_pk = PublicKey::deserialize(&unchecked_server_e_pk[..key_len])?;

        Ok(Self {
            server_nonce: GenericArray::clone_from_slice(&checked_nonce[..nonce_len]),
            server_e_pk,
            signature: <SIG::Sk as Sign>::Signature::deserialize(
                &checked_signature[..signature_len],
            )?,
            mac: GenericArray::clone_from_slice(checked_mac),
        })
    }
}

impl<SIG: Group, KE: Group, H: Hash> Serialize for Ke2Message<SIG, KE, H>
where
    SIG::Sk: Sign,
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Ke2Message: ((Nonce + KePk) + Signature) + Hash
    NonceLen: Add<KE::PkLen>,
    Sum<NonceLen, KE::PkLen>:
        ArrayLength<u8> + Add<<<SIG::Sk as Sign>::Signature as Serialize>::Len>,
    Sum<Sum<NonceLen, KE::PkLen>, <<SIG::Sk as Sign>::Signature as Serialize>::Len>:
        ArrayLength<u8> + Add<OutputSize<H>>,
    Sum<
        Sum<Sum<NonceLen, KE::PkLen>, <<SIG::Sk as Sign>::Signature as Serialize>::Len>,
        OutputSize<H>,
    >: ArrayLength<u8>,
{
    type Len = Sum<
        Sum<Sum<NonceLen, KE::PkLen>, <<SIG::Sk as Sign>::Signature as Serialize>::Len>,
        OutputSize<H>,
    >;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.server_nonce
            .concat(self.server_e_pk.serialize())
            .concat(self.signature.serialize())
            .concat(self.mac.clone())
    }
}

impl<SIG: Group, H: Hash> Deserialize for Ke3Message<SIG, H>
where
    SIG::Sk: Sign,
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let signature_len = <<SIG::Sk as Sign>::Signature as Serialize>::Len::USIZE;
        let mac_len = OutputSize::<H>::USIZE;

        let checked_signature =
            check_slice_size_atleast(input, signature_len, "ke3_message signature")?;
        let checked_mac = check_slice_size(
            &checked_signature[signature_len..],
            mac_len,
            "ke3_message mac",
        )?;

        Ok(Self {
            signature: <SIG::Sk as Sign>::Signature::deserialize(
                &checked_signature[..signature_len],
            )?,
            mac: GenericArray::clone_from_slice(checked_mac),
        })
    }
}

impl<SIG: Group, H: Hash> Serialize for Ke3Message<SIG, H>
where
    SIG::Sk: Sign,
    H::Core: ProxyHash,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // Ke2Message: Signature + Hash
    <<SIG::Sk as Sign>::Signature as Serialize>::Len: Add<OutputSize<H>>,
    Sum<<<SIG::Sk as Sign>::Signature as Serialize>::Len, OutputSize<H>>: ArrayLength<u8>,
{
    type Len = Sum<<<SIG::Sk as Sign>::Signature as Serialize>::Len, OutputSize<H>>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.signature.serialize().concat(self.mac.clone())
    }
}

//////////////////////////
// Test Implementations //
//===================== //
//////////////////////////

#[cfg(test)]
use crate::util::AssertZeroized;

#[cfg(test)]
impl<SIG: Group, H: OutputSizeUser> AssertZeroized for Ke2State<SIG, H>
where
    SIG::Pk: AssertZeroized,
{
    fn assert_zeroized(&self) {
        let Self {
            client_s_pk,
            session_key,
            transcript,
            expected_mac,
        } = self;

        client_s_pk.assert_zeroized();

        for byte in session_key.iter().chain(transcript).chain(expected_mac) {
            assert_eq!(byte, &0);
        }
    }
}

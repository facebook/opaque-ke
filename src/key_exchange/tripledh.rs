// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of the Triple Diffie-Hellman key exchange protocol
use crate::{
    ake::Ake,
    ciphersuite::CipherSuite,
    errors::{
        utils::{check_slice_size, check_slice_size_atleast},
        InternalPakeError, PakeError, ProtocolError,
    },
    hash::Hash,
    key_exchange::traits::{
        FromBytes, GenerateKe2Result, GenerateKe3Result, KeyExchange, ToBytes, ToBytesWithPointers,
    },
    keypair::{KeyPair, PrivateKey, PublicKey, SecretKey, SizedBytesExt},
    serialization::serialize,
};
use digest::{Digest, FixedOutput};
use generic_array::{
    typenum::{Unsigned, U32},
    ArrayLength, GenericArray,
};
use generic_bytes::SizedBytes;
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use rand::{CryptoRng, RngCore};
use std::convert::TryFrom;
use zeroize::Zeroize;

pub(crate) type NonceLen = U32;

static STR_RFC: &[u8] = b"RFCXXXX";
static STR_CLIENT_MAC: &[u8] = b"ClientMAC";
static STR_HANDSHAKE_SECRET: &[u8] = b"HandshakeSecret";
static STR_SERVER_MAC: &[u8] = b"ServerMAC";
static STR_SESSION_KEY: &[u8] = b"SessionKey";
static STR_OPAQUE: &[u8] = b"OPAQUE-";

#[allow(clippy::upper_case_acronyms)]
/// The Triple Diffie-Hellman key exchange implementation
pub struct TripleDH;

impl<D: Hash, A: Ake> KeyExchange<D, A> for TripleDH {
    type KE1State = Ke1State<A>;
    type KE2State = Ke2State<<D as FixedOutput>::OutputSize>;
    type KE1Message = Ke1Message<A>;
    type KE2Message = Ke2Message<A, <D as FixedOutput>::OutputSize>;
    type KE3Message = Ke3Message<<D as FixedOutput>::OutputSize>;

    fn generate_ke1<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError> {
        let client_e_kp = KeyPair::<A>::generate_random(rng);
        let client_nonce = generate_nonce::<R>(rng);

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

    #[allow(clippy::type_complexity)]
    fn generate_ke2<R: RngCore + CryptoRng, S: SecretKey<A>>(
        rng: &mut R,
        serialized_credential_request: Vec<u8>,
        l2_bytes: Vec<u8>,
        ke1_message: Self::KE1Message,
        client_s_pk: PublicKey<A>,
        server_s_sk: S,
        id_u: Vec<u8>,
        id_s: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<GenerateKe2Result<Self, D, A>, ProtocolError<S::Error>> {
        let server_e_kp = KeyPair::<A>::generate_random(rng);
        let server_nonce = generate_nonce::<R>(rng);

        let mut transcript_hasher = D::new()
            .chain(STR_RFC)
            .chain(&serialize(&context, 2).map_err(PakeError::into_custom)?)
            .chain(&id_u)
            .chain(&serialized_credential_request[..])
            .chain(&id_s)
            .chain(&l2_bytes[..])
            .chain(&server_nonce[..])
            .chain(&server_e_kp.public().to_arr());

        let result = derive_3dh_keys::<D, A, S>(
            TripleDHComponents {
                pk1: ke1_message.client_e_pk.clone(),
                sk1: server_e_kp.private().clone(),
                pk2: ke1_message.client_e_pk,
                sk2: server_s_sk,
                pk3: client_s_pk,
                sk3: server_e_kp.private().clone(),
            },
            &transcript_hasher.clone().finalize(),
        )?;

        let mut mac_hasher =
            Hmac::<D>::new_from_slice(&result.1).map_err(|_| InternalPakeError::HmacError)?;
        mac_hasher.update(&transcript_hasher.clone().finalize());
        let mac = mac_hasher.finalize().into_bytes();

        transcript_hasher.update(&mac);

        Ok((
            Ke2State {
                km3: result.2,
                hashed_transcript: transcript_hasher.finalize(),
                session_key: result.0,
            },
            Ke2Message {
                server_nonce,
                server_e_pk: server_e_kp.public().clone(),
                mac,
            },
            #[cfg(test)]
            result.3,
            #[cfg(test)]
            result.1,
        ))
    }

    #[allow(clippy::type_complexity)]
    fn generate_ke3(
        l2_component: Vec<u8>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        serialized_credential_request: &[u8],
        server_s_pk: PublicKey<A>,
        client_s_sk: PrivateKey<A>,
        id_u: Vec<u8>,
        id_s: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<GenerateKe3Result<Self, D, A>, ProtocolError> {
        let mut transcript_hasher = D::new()
            .chain(STR_RFC)
            .chain(&serialize(&context, 2)?)
            .chain(&id_u)
            .chain(&serialized_credential_request)
            .chain(&id_s)
            .chain(&l2_component[..])
            .chain(&ke2_message.to_bytes_without_info_or_mac());

        let result = derive_3dh_keys::<D, A, PrivateKey<A>>(
            TripleDHComponents {
                pk1: ke2_message.server_e_pk.clone(),
                sk1: ke1_state.client_e_sk.clone(),
                pk2: server_s_pk,
                sk2: ke1_state.client_e_sk.clone(),
                pk3: ke2_message.server_e_pk.clone(),
                sk3: client_s_sk,
            },
            &transcript_hasher.clone().finalize(),
        )?;

        let mut server_mac =
            Hmac::<D>::new_from_slice(&result.1).map_err(|_| InternalPakeError::HmacError)?;
        server_mac.update(&transcript_hasher.clone().finalize());

        if server_mac.verify(&ke2_message.mac).is_err() {
            return Err(ProtocolError::VerificationError(
                PakeError::KeyExchangeMacValidationError,
            ));
        }

        transcript_hasher.update(ke2_message.mac.to_vec());

        let mut client_mac =
            Hmac::<D>::new_from_slice(&result.2).map_err(|_| InternalPakeError::HmacError)?;
        client_mac.update(&transcript_hasher.finalize());

        Ok((
            result.0.to_vec(),
            Ke3Message {
                mac: client_mac.finalize().into_bytes(),
            },
            #[cfg(test)]
            result.3,
            #[cfg(test)]
            result.2,
        ))
    }

    #[allow(clippy::type_complexity)]
    fn finish_ke(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State,
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut client_mac =
            Hmac::<D>::new_from_slice(&ke2_state.km3).map_err(|_| InternalPakeError::HmacError)?;
        client_mac.update(&ke2_state.hashed_transcript);

        if client_mac.verify(&ke3_message.mac).is_err() {
            return Err(ProtocolError::VerificationError(
                PakeError::KeyExchangeMacValidationError,
            ));
        }

        Ok(ke2_state.session_key.to_vec())
    }

    fn ke2_message_size() -> usize {
        NonceLen::to_usize()
            + <A as Ake>::PkLen::to_usize()
            + <<D as FixedOutput>::OutputSize as Unsigned>::to_usize()
    }
}

/// The client state produced after the first key exchange message
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
pub struct Ke1State<A: Ake> {
    client_e_sk: PrivateKey<A>,
    client_nonce: GenericArray<u8, NonceLen>,
}

impl_clone_for!(
    struct Ke1State<A: Ake>,
    [client_e_sk, client_nonce],
);
impl_debug_eq_hash_for!(
    struct Ke1State<A: Ake>,
    [client_e_sk, client_nonce],
);

// This can't be derived because of the use of a generic parameter
impl<A: Ake> Zeroize for Ke1State<A> {
    fn zeroize(&mut self) {
        self.client_e_sk.zeroize();
        self.client_nonce.zeroize();
    }
}

impl<A: Ake> Drop for Ke1State<A> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The first key exchange message
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
pub struct Ke1Message<A: Ake> {
    pub(crate) client_nonce: GenericArray<u8, NonceLen>,
    pub(crate) client_e_pk: PublicKey<A>,
}

impl_debug_eq_hash_for!(struct Ke1Message<A: Ake>, [client_nonce, client_e_pk]);
impl_clone_for!(struct Ke1Message<A: Ake>, [client_nonce, client_e_pk]);

impl<A: Ake> FromBytes for Ke1State<A> {
    fn from_bytes<CS: CipherSuite>(bytes: &[u8]) -> Result<Self, PakeError> {
        let key_len = <A as Ake>::PkLen::to_usize();

        let nonce_len = NonceLen::to_usize();
        let checked_bytes = check_slice_size_atleast(bytes, key_len + nonce_len, "ke1_state")?;

        Ok(Self {
            client_e_sk: PrivateKey::from_bytes(&checked_bytes[..key_len])?,
            client_nonce: GenericArray::clone_from_slice(
                &checked_bytes[key_len..key_len + nonce_len],
            ),
        })
    }
}

impl<A: Ake> ToBytesWithPointers for Ke1State<A> {
    fn to_bytes(&self) -> Vec<u8> {
        let output: Vec<u8> = [&self.client_e_sk.to_arr(), &self.client_nonce[..]].concat();
        output
    }

    #[cfg(test)]
    fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        vec![
            (self.client_e_sk.as_ptr(), A::SkLen::to_usize()),
            (self.client_nonce.as_ptr(), NonceLen::to_usize()),
        ]
    }
}

impl<A: Ake> ToBytes for Ke1Message<A> {
    fn to_bytes(&self) -> Vec<u8> {
        [&self.client_nonce[..], &self.client_e_pk.to_arr()].concat()
    }
}

impl<A: Ake> FromBytes for Ke1Message<A> {
    fn from_bytes<CS: CipherSuite>(ke1_message_bytes: &[u8]) -> Result<Self, PakeError> {
        let nonce_len = NonceLen::to_usize();
        let checked_nonce = check_slice_size(
            ke1_message_bytes,
            nonce_len + <A as Ake>::PkLen::to_usize(),
            "ke1_message nonce",
        )?;

        Ok(Self {
            client_nonce: GenericArray::clone_from_slice(&checked_nonce[..nonce_len]),
            client_e_pk: PublicKey::from_bytes(&checked_nonce[nonce_len..])?,
        })
    }
}
/// The server state produced after the second key exchange message
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serialize", serde(bound = ""))]
pub struct Ke2State<HashLen: ArrayLength<u8>> {
    km3: GenericArray<u8, HashLen>,
    hashed_transcript: GenericArray<u8, HashLen>,
    session_key: GenericArray<u8, HashLen>,
}

// This can't be derived because of the use of a phantom parameter
impl<HashLen: ArrayLength<u8>> Zeroize for Ke2State<HashLen> {
    fn zeroize(&mut self) {
        self.km3.zeroize();
        self.hashed_transcript.zeroize();
        self.session_key.zeroize();
    }
}

impl<HashLen: ArrayLength<u8>> Drop for Ke2State<HashLen> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<HashLen: ArrayLength<u8>> ToBytesWithPointers for Ke2State<HashLen> {
    fn to_bytes(&self) -> Vec<u8> {
        [
            &self.km3[..],
            &self.hashed_transcript[..],
            &self.session_key[..],
        ]
        .concat()
    }

    #[cfg(test)]
    fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        vec![
            (self.km3.as_ptr(), HashLen::to_usize()),
            (self.hashed_transcript.as_ptr(), HashLen::to_usize()),
            (self.session_key.as_ptr(), HashLen::to_usize()),
        ]
    }
}

/// The second key exchange message
#[derive(Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serialize", serde(bound = ""))]
pub struct Ke2Message<A: Ake, HashLen: ArrayLength<u8>> {
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: PublicKey<A>,
    mac: GenericArray<u8, HashLen>,
}

impl<A: Ake, HashLen: ArrayLength<u8>> Clone for Ke2Message<A, HashLen> {
    fn clone(&self) -> Self {
        Self {
            server_nonce: self.server_nonce,
            server_e_pk: self.server_e_pk.clone(),
            mac: self.mac.clone(),
        }
    }
}

impl<HashLen: ArrayLength<u8>> FromBytes for Ke2State<HashLen> {
    fn from_bytes<CS: CipherSuite>(input: &[u8]) -> Result<Self, PakeError> {
        let hash_len = HashLen::to_usize();
        let checked_bytes = check_slice_size(input, 3 * hash_len, "ke2_state")?;

        Ok(Self {
            km3: GenericArray::clone_from_slice(&checked_bytes[..hash_len]),
            hashed_transcript: GenericArray::clone_from_slice(
                &checked_bytes[hash_len..2 * hash_len],
            ),
            session_key: GenericArray::clone_from_slice(&checked_bytes[2 * hash_len..3 * hash_len]),
        })
    }
}

impl<A: Ake, HashLen: ArrayLength<u8>> ToBytes for Ke2Message<A, HashLen> {
    fn to_bytes(&self) -> Vec<u8> {
        [&self.to_bytes_without_info_or_mac(), &self.mac[..]].concat()
    }
}

impl<A: Ake, HashLen: ArrayLength<u8>> Ke2Message<A, HashLen> {
    fn to_bytes_without_info_or_mac(&self) -> Vec<u8> {
        [&self.server_nonce[..], &self.server_e_pk.to_arr()].concat()
    }
}

impl<A: Ake, HashLen: ArrayLength<u8>> FromBytes for Ke2Message<A, HashLen> {
    fn from_bytes<CS: CipherSuite>(input: &[u8]) -> Result<Self, PakeError> {
        let key_len = <A as Ake>::PkLen::to_usize();
        let nonce_len = NonceLen::to_usize();
        let checked_nonce = check_slice_size_atleast(input, nonce_len, "ke2_message nonce")?;

        let unchecked_server_e_pk = check_slice_size_atleast(
            &checked_nonce[nonce_len..],
            key_len,
            "ke2_message server_e_pk",
        )?;
        let checked_mac = check_slice_size(
            &unchecked_server_e_pk[key_len..],
            HashLen::to_usize(),
            "ke1_message mac",
        )?;

        // Check the public key bytes
        let server_e_pk = KeyPair::<CS::Ake>::check_public_key(PublicKey::from_bytes(
            &unchecked_server_e_pk[..key_len],
        )?)?;

        Ok(Self {
            server_nonce: GenericArray::clone_from_slice(&checked_nonce[..nonce_len]),
            server_e_pk: PublicKey::from_bytes(&server_e_pk)?,
            mac: GenericArray::clone_from_slice(checked_mac),
        })
    }
}

#[allow(clippy::upper_case_acronyms)]
// The triple of public and private components used in the 3DH computation
struct TripleDHComponents<A: Ake, S: SecretKey<A>> {
    pk1: PublicKey<A>,
    sk1: PrivateKey<A>,
    pk2: PublicKey<A>,
    sk2: S,
    pk3: PublicKey<A>,
    sk3: PrivateKey<A>,
}

// Consists of a session key, followed by two mac keys: (session_key, km2, km3)
#[cfg(not(test))]
#[allow(clippy::upper_case_acronyms)]
type TripleDHDerivationResult<D> = (
    GenericArray<u8, <D as FixedOutput>::OutputSize>,
    GenericArray<u8, <D as FixedOutput>::OutputSize>,
    GenericArray<u8, <D as FixedOutput>::OutputSize>,
);
#[cfg(test)]
type TripleDHDerivationResult<D> = (
    GenericArray<u8, <D as FixedOutput>::OutputSize>,
    GenericArray<u8, <D as FixedOutput>::OutputSize>,
    GenericArray<u8, <D as FixedOutput>::OutputSize>,
    Vec<u8>,
);

/// The third key exchange message
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serialize", serde(bound = ""))]
pub struct Ke3Message<HashLen: ArrayLength<u8>> {
    mac: GenericArray<u8, HashLen>,
}

impl<HashLen: ArrayLength<u8>> ToBytes for Ke3Message<HashLen> {
    fn to_bytes(&self) -> Vec<u8> {
        self.mac.to_vec()
    }
}

impl<HashLen: ArrayLength<u8>> FromBytes for Ke3Message<HashLen> {
    fn from_bytes<CS: CipherSuite>(bytes: &[u8]) -> Result<Self, PakeError> {
        let checked_bytes = check_slice_size(bytes, HashLen::to_usize(), "ke3_message")?;

        Ok(Self {
            mac: GenericArray::clone_from_slice(checked_bytes),
        })
    }
}

// Helper functions

// Internal function which takes the public and private components of the client and server keypairs, along
// with some auxiliary metadata, to produce the session key and two MAC keys
fn derive_3dh_keys<D: Hash, A: Ake, S: SecretKey<A>>(
    dh: TripleDHComponents<A, S>,
    hashed_derivation_transcript: &[u8],
) -> Result<TripleDHDerivationResult<D>, ProtocolError<S::Error>> {
    let ikm: Vec<u8> = [
        &dh.sk1
            .diffie_hellman(dh.pk1)
            .map_err(InternalPakeError::into_custom)?[..],
        &dh.sk2.diffie_hellman(dh.pk2)?[..],
        &dh.sk3
            .diffie_hellman(dh.pk3)
            .map_err(InternalPakeError::into_custom)?[..],
    ]
    .concat();

    let extracted_ikm = Hkdf::<D>::new(None, &ikm);
    let handshake_secret = derive_secrets::<D>(
        &extracted_ikm,
        STR_HANDSHAKE_SECRET,
        hashed_derivation_transcript,
    )
    .map_err(ProtocolError::into_custom)?;
    let session_key = derive_secrets::<D>(
        &extracted_ikm,
        STR_SESSION_KEY,
        hashed_derivation_transcript,
    )
    .map_err(ProtocolError::into_custom)?;

    let km2 = hkdf_expand_label::<D>(
        &handshake_secret,
        STR_SERVER_MAC,
        b"",
        <D as Digest>::OutputSize::to_usize(),
    )
    .map_err(ProtocolError::into_custom)?;
    let km3 = hkdf_expand_label::<D>(
        &handshake_secret,
        STR_CLIENT_MAC,
        b"",
        <D as Digest>::OutputSize::to_usize(),
    )
    .map_err(ProtocolError::into_custom)?;

    Ok((
        GenericArray::clone_from_slice(&session_key),
        GenericArray::clone_from_slice(&km2),
        GenericArray::clone_from_slice(&km3),
        #[cfg(test)]
        handshake_secret,
    ))
}

fn hkdf_expand_label<D: Hash>(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let h = Hkdf::<D>::from_prk(secret).map_err(|_| InternalPakeError::HkdfError)?;
    hkdf_expand_label_extracted(&h, label, context, length)
}

fn hkdf_expand_label_extracted<D: Hash>(
    hkdf: &Hkdf<D>,
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let mut okm = vec![0u8; length];

    let mut hkdf_label: Vec<u8> = Vec::new();

    let length_u16: u16 = u16::try_from(length).map_err(|_| PakeError::SerializationError)?;
    hkdf_label.extend_from_slice(&length_u16.to_be_bytes());

    let mut opaque_label: Vec<u8> = Vec::new();
    opaque_label.extend_from_slice(STR_OPAQUE);
    opaque_label.extend_from_slice(label);
    hkdf_label.extend_from_slice(&serialize(&opaque_label, 1)?);

    hkdf_label.extend_from_slice(&serialize(context, 1)?);

    hkdf.expand(&hkdf_label, &mut okm)
        .map_err(|_| InternalPakeError::HkdfError)?;
    Ok(okm)
}

fn derive_secrets<D: Hash>(
    hkdf: &Hkdf<D>,
    label: &[u8],
    hashed_derivation_transcript: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    hkdf_expand_label_extracted::<D>(
        hkdf,
        label,
        hashed_derivation_transcript,
        <D as Digest>::OutputSize::to_usize(),
    )
}

// Generate a random nonce up to NonceLen::to_usize() bytes.
fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> GenericArray<u8, NonceLen> {
    let mut nonce_bytes = vec![0u8; NonceLen::to_usize()];
    rng.fill_bytes(&mut nonce_bytes);
    GenericArray::clone_from_slice(&nonce_bytes)
}

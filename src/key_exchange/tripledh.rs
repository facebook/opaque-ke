// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of the Triple Diffie-Hellman key exchange protocol
use crate::{
    ciphersuite::CipherSuite,
    errors::{
        utils::{check_slice_size, check_slice_size_atleast},
        InternalPakeError, PakeError, ProtocolError,
    },
    group::Group,
    hash::Hash,
    key_exchange::traits::{FromBytes, KeyExchange, ToBytes, ToBytesWithPointers},
    keypair::{KeyPair, PrivateKey, PublicKey, SizedBytesExt},
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

const KEY_LEN: usize = 32;
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

impl<D: Hash, G: Group> KeyExchange<D, G> for TripleDH {
    type KE1State = Ke1State<G>;
    type KE2State = Ke2State<<D as FixedOutput>::OutputSize>;
    type KE1Message = Ke1Message<G>;
    type KE2Message = Ke2Message<G, <D as FixedOutput>::OutputSize>;
    type KE3Message = Ke3Message<<D as FixedOutput>::OutputSize>;

    fn generate_ke1<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError> {
        let client_e_kp = KeyPair::<G>::generate_random(rng);
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
    fn generate_ke2<R: RngCore + CryptoRng>(
        rng: &mut R,
        serialized_credential_request: Vec<u8>,
        l2_bytes: Vec<u8>,
        ke1_message: Self::KE1Message,
        client_s_pk: PublicKey<G>,
        server_s_sk: PrivateKey<G>,
        id_u: Vec<u8>,
        id_s: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<(Self::KE2State, Self::KE2Message), ProtocolError> {
        let server_e_kp = KeyPair::<G>::generate_random(rng);
        let server_nonce = generate_nonce::<R>(rng);

        let mut transcript_hasher = D::new()
            .chain(STR_RFC)
            .chain(&serialize(&context, 2))
            .chain(&id_u)
            .chain(&serialized_credential_request[..])
            .chain(&id_s)
            .chain(&l2_bytes[..])
            .chain(&server_nonce[..])
            .chain(&server_e_kp.public().to_arr());

        let (session_key, km2, km3) = derive_3dh_keys::<D, G>(
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
            Hmac::<D>::new_from_slice(&km2).map_err(|_| InternalPakeError::HmacError)?;
        mac_hasher.update(&transcript_hasher.clone().finalize());
        let mac = mac_hasher.finalize().into_bytes();

        transcript_hasher.update(&mac);

        Ok((
            Ke2State {
                km3,
                hashed_transcript: transcript_hasher.finalize(),
                session_key,
            },
            Ke2Message {
                server_nonce,
                server_e_pk: server_e_kp.public().clone(),
                mac,
            },
        ))
    }

    #[allow(clippy::type_complexity)]
    fn generate_ke3(
        l2_component: Vec<u8>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        serialized_credential_request: &[u8],
        server_s_pk: PublicKey<G>,
        client_s_sk: PrivateKey<G>,
        id_u: Vec<u8>,
        id_s: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::KE3Message), ProtocolError> {
        let mut transcript_hasher = D::new()
            .chain(STR_RFC)
            .chain(&serialize(&context, 2))
            .chain(&id_u)
            .chain(&serialized_credential_request)
            .chain(&id_s)
            .chain(&l2_component[..])
            .chain(&ke2_message.to_bytes_without_info_or_mac());

        let (session_key, km2, km3) = derive_3dh_keys::<D, G>(
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
            Hmac::<D>::new_from_slice(&km2).map_err(|_| InternalPakeError::HmacError)?;
        server_mac.update(&transcript_hasher.clone().finalize());

        if server_mac.verify(&ke2_message.mac).is_err() {
            return Err(ProtocolError::VerificationError(
                PakeError::KeyExchangeMacValidationError,
            ));
        }

        transcript_hasher.update(ke2_message.mac.to_vec());

        let mut client_mac =
            Hmac::<D>::new_from_slice(&km3).map_err(|_| InternalPakeError::HmacError)?;
        client_mac.update(&transcript_hasher.finalize());

        Ok((
            session_key.to_vec(),
            Ke3Message {
                mac: client_mac.finalize().into_bytes(),
            },
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
        NonceLen::to_usize() + KEY_LEN + <<D as FixedOutput>::OutputSize as Unsigned>::to_usize()
    }
}

/// The client state produced after the first key exchange message
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
pub struct Ke1State<G: Group> {
    client_e_sk: PrivateKey<G>,
    client_nonce: GenericArray<u8, NonceLen>,
}

impl_clone_for!(
    struct Ke1State<G: Group>,
    [client_e_sk, client_nonce],
);
impl_debug_eq_hash_for!(
    struct Ke1State<G: Group>,
    [client_e_sk, client_nonce],
);

// This can't be derived because of the use of a generic parameter
impl<G: Group> Zeroize for Ke1State<G> {
    fn zeroize(&mut self) {
        self.client_e_sk.zeroize();
        self.client_nonce.zeroize();
    }
}

impl<G: Group> Drop for Ke1State<G> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The first key exchange message
#[derive(PartialEq, Eq, Debug, Hash, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
pub struct Ke1Message<G: Group> {
    pub(crate) client_nonce: GenericArray<u8, NonceLen>,
    pub(crate) client_e_pk: PublicKey<G>,
}

impl<G: Group> FromBytes for Ke1State<G> {
    fn from_bytes<CS: CipherSuite>(bytes: &[u8]) -> Result<Self, PakeError> {
        let nonce_len = NonceLen::to_usize();
        let checked_bytes = check_slice_size_atleast(bytes, KEY_LEN + nonce_len, "ke1_state")?;

        Ok(Self {
            client_e_sk: PrivateKey::from_bytes(&checked_bytes[..KEY_LEN])?,
            client_nonce: GenericArray::clone_from_slice(
                &checked_bytes[KEY_LEN..KEY_LEN + nonce_len],
            ),
        })
    }
}

impl<G: Group> ToBytesWithPointers for Ke1State<G> {
    fn to_bytes(&self) -> Vec<u8> {
        let output: Vec<u8> = [&self.client_e_sk.to_arr(), &self.client_nonce[..]].concat();
        output
    }

    #[cfg(test)]
    fn as_byte_ptrs(&self) -> Vec<(*const u8, usize)> {
        vec![
            (
                self.client_e_sk.as_ptr(),
                <PrivateKey<G> as SizedBytes>::Len::to_usize(),
            ),
            (self.client_nonce.as_ptr(), NonceLen::to_usize()),
        ]
    }
}

impl<G: Group> ToBytes for Ke1Message<G> {
    fn to_bytes(&self) -> Vec<u8> {
        [&self.client_nonce[..], &self.client_e_pk.to_arr()].concat()
    }
}

impl<G: Group> FromBytes for Ke1Message<G> {
    fn from_bytes<CS: CipherSuite>(ke1_message_bytes: &[u8]) -> Result<Self, PakeError> {
        let nonce_len = NonceLen::to_usize();
        let checked_nonce =
            check_slice_size(ke1_message_bytes, nonce_len + KEY_LEN, "ke1_message nonce")?;

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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serialize", serde(bound = ""))]
pub struct Ke2Message<G: Group, HashLen: ArrayLength<u8>> {
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: PublicKey<G>,
    mac: GenericArray<u8, HashLen>,
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

impl<G: Group, HashLen: ArrayLength<u8>> ToBytes for Ke2Message<G, HashLen> {
    fn to_bytes(&self) -> Vec<u8> {
        [&self.to_bytes_without_info_or_mac(), &self.mac[..]].concat()
    }
}

impl<G: Group, HashLen: ArrayLength<u8>> Ke2Message<G, HashLen> {
    fn to_bytes_without_info_or_mac(&self) -> Vec<u8> {
        [&self.server_nonce[..], &self.server_e_pk.to_arr()].concat()
    }
}

impl<G: Group, HashLen: ArrayLength<u8>> FromBytes for Ke2Message<G, HashLen> {
    fn from_bytes<CS: CipherSuite>(input: &[u8]) -> Result<Self, PakeError> {
        let nonce_len = NonceLen::to_usize();
        let checked_nonce = check_slice_size_atleast(input, nonce_len, "ke2_message nonce")?;

        let unchecked_server_e_pk = check_slice_size_atleast(
            &checked_nonce[nonce_len..],
            KEY_LEN,
            "ke2_message server_e_pk",
        )?;
        let checked_mac = check_slice_size(
            &unchecked_server_e_pk[KEY_LEN..],
            HashLen::to_usize(),
            "ke1_message mac",
        )?;

        // Check the public key bytes
        let server_e_pk = KeyPair::<CS::Group>::check_public_key(PublicKey::from_bytes(
            &unchecked_server_e_pk[..KEY_LEN],
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
struct TripleDHComponents<G: Group> {
    pk1: PublicKey<G>,
    sk1: PrivateKey<G>,
    pk2: PublicKey<G>,
    sk2: PrivateKey<G>,
    pk3: PublicKey<G>,
    sk3: PrivateKey<G>,
}

#[allow(clippy::upper_case_acronyms)]
// Consists of a session key, followed by two mac keys: (session_key, km2, km3)
type TripleDHDerivationResult<D> = (
    GenericArray<u8, <D as FixedOutput>::OutputSize>,
    GenericArray<u8, <D as FixedOutput>::OutputSize>,
    GenericArray<u8, <D as FixedOutput>::OutputSize>,
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
fn derive_3dh_keys<D: Hash, G: Group>(
    dh: TripleDHComponents<G>,
    hashed_derivation_transcript: &[u8],
) -> Result<TripleDHDerivationResult<D>, ProtocolError> {
    let ikm: Vec<u8> = [
        &KeyPair::<G>::diffie_hellman(dh.pk1, dh.sk1)?[..],
        &KeyPair::<G>::diffie_hellman(dh.pk2, dh.sk2)?[..],
        &KeyPair::<G>::diffie_hellman(dh.pk3, dh.sk3)?[..],
    ]
    .concat();

    let extracted_ikm = Hkdf::<D>::new(None, &ikm);
    let handshake_secret = derive_secrets::<D>(
        &extracted_ikm,
        STR_HANDSHAKE_SECRET,
        hashed_derivation_transcript,
    )?;
    let session_key = derive_secrets::<D>(
        &extracted_ikm,
        STR_SESSION_KEY,
        hashed_derivation_transcript,
    )?;

    let km2 = hkdf_expand_label::<D>(
        &handshake_secret,
        STR_SERVER_MAC,
        b"",
        <D as Digest>::OutputSize::to_usize(),
    )?;
    let km3 = hkdf_expand_label::<D>(
        &handshake_secret,
        STR_CLIENT_MAC,
        b"",
        <D as Digest>::OutputSize::to_usize(),
    )?;

    Ok((
        GenericArray::clone_from_slice(&session_key),
        GenericArray::clone_from_slice(&km2),
        GenericArray::clone_from_slice(&km3),
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
    hkdf_label.extend_from_slice(&serialize(&opaque_label, 1));

    hkdf_label.extend_from_slice(&serialize(context, 1));

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

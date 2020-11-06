// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of the Triple Diffie-Hellman key exchange protocol
use crate::{
    errors::{utils::check_slice_size, InternalPakeError, PakeError, ProtocolError},
    hash::Hash,
    key_exchange::traits::{KeyExchange, ToBytes},
    keypair::{KeyPair, SizedBytesExt},
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
use rand_core::{CryptoRng, RngCore};

use std::convert::TryFrom;

const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 32;
pub(crate) type NonceLen = U32;
const KE1_STATE_LEN: usize = KEY_LEN + KEY_LEN + NONCE_LEN;

static STR_3DH: &[u8] = b"3DH keys";
static STR_CLIENT_MAC: &[u8] = b"client mac";
static STR_HANDSHAKE_SECRET: &[u8] = b"handshake secret";
static STR_SERVER_MAC: &[u8] = b"server mac";
static STR_SESSION_SECRET: &[u8] = b"session secret";
static STR_OPAQUE: &[u8] = b"OPAQUE ";

/// The Triple Diffie-Hellman key exchange implementation
pub struct TripleDH;

impl<D: Hash, KeyFormat: KeyPair> KeyExchange<D, KeyFormat> for TripleDH {
    type KE1State = KE1State<<D as FixedOutput>::OutputSize, KeyFormat>;
    type KE2State = KE2State<<D as FixedOutput>::OutputSize>;
    type KE1Message = KE1Message<KeyFormat>;
    type KE2Message = KE2Message<<D as FixedOutput>::OutputSize, KeyFormat>;
    type KE3Message = KE3Message<<D as FixedOutput>::OutputSize>;

    fn generate_ke1<R: RngCore + CryptoRng>(
        l1_component: Vec<u8>,
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError> {
        let client_e_kp = KeyFormat::generate_random(rng)?;
        let client_nonce: GenericArray<u8, NonceLen> = {
            let mut client_nonce_bytes = [0u8; NONCE_LEN];
            rng.fill_bytes(&mut client_nonce_bytes);
            client_nonce_bytes.into()
        };

        let ke1_message = KE1Message {
            client_nonce,
            client_e_pk: client_e_kp.public().clone(),
        };

        let l1_data: Vec<u8> = [&l1_component[..], &ke1_message.to_bytes()].concat();
        let mut hasher = D::new();
        hasher.update(&l1_data);
        let hashed_l1 = hasher.finalize();

        Ok((
            KE1State {
                client_e_sk: client_e_kp.private().clone(),
                client_nonce,
                hashed_l1,
            },
            ke1_message,
        ))
    }

    fn generate_ke2<R: RngCore + CryptoRng>(
        rng: &mut R,
        l1_bytes: Vec<u8>,
        l2_bytes: Vec<u8>,
        ke1_message: Self::KE1Message,
        client_s_pk: KeyFormat::Repr,
        server_s_sk: KeyFormat::Repr,
    ) -> Result<(Self::KE2State, Self::KE2Message), ProtocolError> {
        let server_e_kp = KeyFormat::generate_random(rng)?;
        let server_nonce: GenericArray<u8, NonceLen> = {
            let mut server_nonce_bytes = [0u8; NONCE_LEN];
            rng.fill_bytes(&mut server_nonce_bytes);
            server_nonce_bytes.into()
        };

        let (session_secret, km2, km3) = derive_3dh_keys::<KeyFormat, D>(
            TripleDHComponents {
                pk1: ke1_message.client_e_pk.clone(),
                sk1: server_e_kp.private().clone(),
                pk2: ke1_message.client_e_pk,
                sk2: server_s_sk.clone(),
                pk3: client_s_pk.clone(),
                sk3: server_e_kp.private().clone(),
            },
            &ke1_message.client_nonce,
            &server_nonce,
            client_s_pk,
            KeyFormat::public_from_private(&server_s_sk),
        )?;

        let mut hasher = D::new();
        hasher.update(&l1_bytes);
        let hashed_l1 = hasher.finalize();

        let transcript2: Vec<u8> = [
            &hashed_l1[..],
            &l2_bytes[..],
            &server_nonce[..],
            &server_e_kp.public().to_arr(),
        ]
        .concat();

        let mut hasher2 = D::new();
        hasher2.update(&transcript2);
        let hashed_transcript = hasher2.finalize();

        let mut mac = Hmac::<D>::new_varkey(&km2).map_err(|_| InternalPakeError::HmacError)?;
        mac.update(&hashed_transcript);

        Ok((
            KE2State {
                km3,
                hashed_transcript,
                session_secret,
            },
            KE2Message {
                server_nonce,
                server_e_pk: server_e_kp.public().clone(),
                mac: mac.finalize().into_bytes(),
            },
        ))
    }

    fn generate_ke3(
        l2_component: Vec<u8>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        server_s_pk: KeyFormat::Repr,
        client_s_sk: KeyFormat::Repr,
    ) -> Result<(Vec<u8>, Self::KE3Message), ProtocolError> {
        let (session_secret, km2, km3) = derive_3dh_keys::<KeyFormat, D>(
            TripleDHComponents {
                pk1: ke2_message.server_e_pk.clone(),
                sk1: ke1_state.client_e_sk.clone(),
                pk2: server_s_pk.clone(),
                sk2: ke1_state.client_e_sk.clone(),
                pk3: ke2_message.server_e_pk.clone(),
                sk3: client_s_sk.clone(),
            },
            &ke1_state.client_nonce,
            &ke2_message.server_nonce,
            KeyFormat::public_from_private(&client_s_sk),
            server_s_pk,
        )?;

        let transcript: Vec<u8> = [
            &ke1_state.hashed_l1[..],
            &l2_component[..],
            &ke2_message.server_nonce[..],
            &ke2_message.server_e_pk.to_arr(),
        ]
        .concat();

        let mut hasher = D::new();
        hasher.update(&transcript);
        let hashed_transcript = hasher.finalize();

        let mut server_mac =
            Hmac::<D>::new_varkey(&km2).map_err(|_| InternalPakeError::HmacError)?;
        server_mac.update(&hashed_transcript);

        if ke2_message.mac != server_mac.finalize().into_bytes() {
            return Err(ProtocolError::VerificationError(
                PakeError::KeyExchangeMacValidationError,
            ));
        }

        let mut client_mac =
            Hmac::<D>::new_varkey(&km3).map_err(|_| InternalPakeError::HmacError)?;
        client_mac.update(&hashed_transcript);

        Ok((
            session_secret.to_vec(),
            KE3Message {
                mac: client_mac.finalize().into_bytes(),
            },
        ))
    }

    fn finish_ke(
        ke3_message: Self::KE3Message,
        ke2_state: &Self::KE2State,
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut client_mac =
            Hmac::<D>::new_varkey(&ke2_state.km3).map_err(|_| InternalPakeError::HmacError)?;
        client_mac.update(&ke2_state.hashed_transcript);

        if ke3_message.mac != client_mac.finalize().into_bytes() {
            return Err(ProtocolError::VerificationError(
                PakeError::KeyExchangeMacValidationError,
            ));
        }

        Ok(ke2_state.session_secret.to_vec())
    }

    fn ke1_state_size() -> usize {
        KE1_STATE_LEN
    }

    fn ke2_message_size() -> usize {
        NONCE_LEN + KEY_LEN + <<D as FixedOutput>::OutputSize as Unsigned>::to_usize()
    }
}

/// The client state produced after the first key exchange message
#[derive(PartialEq, Eq)]
pub struct KE1State<HashLen: ArrayLength<u8>, KeyFormat: KeyPair> {
    client_e_sk: KeyFormat::Repr,
    client_nonce: GenericArray<u8, NonceLen>,
    hashed_l1: GenericArray<u8, HashLen>,
}

/// The first key exchange message
#[derive(PartialEq, Eq)]
pub struct KE1Message<KeyFormat: KeyPair> {
    pub(crate) client_nonce: GenericArray<u8, NonceLen>,
    pub(crate) client_e_pk: KeyFormat::Repr,
}

impl<HashLen: ArrayLength<u8>, KeyFormat: KeyPair> TryFrom<&[u8]> for KE1State<HashLen, KeyFormat> {
    type Error = InternalPakeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let checked_bytes = check_slice_size(
            bytes,
            KEY_LEN + NONCE_LEN + HashLen::to_usize(),
            "ke1_state",
        )?;

        Ok(Self {
            client_e_sk: KeyFormat::Repr::from_bytes(&checked_bytes[..KEY_LEN])?,
            client_nonce: GenericArray::clone_from_slice(
                &checked_bytes[KEY_LEN..KEY_LEN + NONCE_LEN],
            ),
            hashed_l1: GenericArray::clone_from_slice(&checked_bytes[KEY_LEN + NONCE_LEN..]),
        })
    }
}

impl<HashLen: ArrayLength<u8>, KeyFormat: KeyPair> ToBytes for KE1State<HashLen, KeyFormat> {
    fn to_bytes(&self) -> Vec<u8> {
        let output: Vec<u8> = [
            &self.client_e_sk.to_arr(),
            &self.client_nonce[..],
            &self.hashed_l1[..],
        ]
        .concat();
        output
    }
}

impl<KeyFormat: KeyPair> ToBytes for KE1Message<KeyFormat> {
    fn to_bytes(&self) -> Vec<u8> {
        [&self.client_nonce[..], &self.client_e_pk.to_arr()].concat()
    }
}

impl<KeyFormat: KeyPair> TryFrom<&[u8]> for KE1Message<KeyFormat> {
    type Error = InternalPakeError;

    fn try_from(ke1_message_bytes: &[u8]) -> Result<Self, Self::Error> {
        let checked_bytes =
            check_slice_size(ke1_message_bytes, NONCE_LEN + KEY_LEN, "ke1_message")?;

        Ok(Self {
            client_nonce: GenericArray::clone_from_slice(&checked_bytes[..NONCE_LEN]),
            client_e_pk: KeyFormat::Repr::from_bytes(&checked_bytes[NONCE_LEN..])?,
        })
    }
}
/// The server state produced after the second key exchange message
pub struct KE2State<HashLen: ArrayLength<u8>> {
    km3: GenericArray<u8, HashLen>,
    hashed_transcript: GenericArray<u8, HashLen>,
    session_secret: GenericArray<u8, HashLen>,
}

/// The second key exchange message
pub struct KE2Message<HashLen: ArrayLength<u8>, KeyFormat: KeyPair> {
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: KeyFormat::Repr,
    mac: GenericArray<u8, HashLen>,
}

impl<HashLen: ArrayLength<u8>> ToBytes for KE2State<HashLen> {
    fn to_bytes(&self) -> Vec<u8> {
        let output: Vec<u8> = [
            &self.km3[..],
            &self.hashed_transcript[..],
            &self.session_secret[..],
        ]
        .concat();
        output
    }
}

impl<HashLen: ArrayLength<u8>> TryFrom<&[u8]> for KE2State<HashLen> {
    type Error = InternalPakeError;

    fn try_from(ke1_message_bytes: &[u8]) -> Result<Self, Self::Error> {
        let checked_bytes = check_slice_size(ke1_message_bytes, 3 * KEY_LEN, "ke2_state")?;

        Ok(Self {
            km3: GenericArray::clone_from_slice(&checked_bytes[..KEY_LEN]),
            hashed_transcript: GenericArray::clone_from_slice(&checked_bytes[KEY_LEN..2 * KEY_LEN]),
            session_secret: GenericArray::clone_from_slice(&checked_bytes[2 * KEY_LEN..]),
        })
    }
}

impl<HashLen: ArrayLength<u8>, KeyFormat: KeyPair> ToBytes for KE2Message<HashLen, KeyFormat> {
    fn to_bytes(&self) -> Vec<u8> {
        let output: Vec<u8> = [
            &self.server_nonce[..],
            &self.server_e_pk.to_arr(),
            &self.mac[..],
        ]
        .concat();
        output
    }
}

impl<HashLen: ArrayLength<u8>, KeyFormat: KeyPair> TryFrom<&[u8]>
    for KE2Message<HashLen, KeyFormat>
{
    type Error = InternalPakeError;

    fn try_from(ke2_message_bytes: &[u8]) -> Result<Self, Self::Error> {
        let ke2_message_len = NONCE_LEN + KEY_LEN + HashLen::to_usize();
        let checked_bytes = check_slice_size(ke2_message_bytes, ke2_message_len, "ke2_message")?;

        Ok(Self {
            server_nonce: GenericArray::clone_from_slice(&checked_bytes[..NONCE_LEN]),
            server_e_pk: KeyFormat::Repr::from_bytes(
                &checked_bytes[NONCE_LEN..NONCE_LEN + KEY_LEN],
            )?,
            mac: GenericArray::clone_from_slice(&checked_bytes[NONCE_LEN + KEY_LEN..]),
        })
    }
}

// The triple of public and private components used in the 3DH computation
struct TripleDHComponents<KeyFormat: KeyPair> {
    pk1: KeyFormat::Repr,
    sk1: KeyFormat::Repr,
    pk2: KeyFormat::Repr,
    sk2: KeyFormat::Repr,
    pk3: KeyFormat::Repr,
    sk3: KeyFormat::Repr,
}

// Consists of a shared secret, followed by two mac keys: (session_secret, km2, km3)
type TripleDHDerivationResult<D> = (
    GenericArray<u8, <D as FixedOutput>::OutputSize>,
    GenericArray<u8, <D as FixedOutput>::OutputSize>,
    GenericArray<u8, <D as FixedOutput>::OutputSize>,
);

/// The third key exchange message
pub struct KE3Message<HashLen: ArrayLength<u8>> {
    mac: GenericArray<u8, HashLen>,
}

impl<HashLen: ArrayLength<u8>> ToBytes for KE3Message<HashLen> {
    fn to_bytes(&self) -> Vec<u8> {
        self.mac.to_vec()
    }
}

impl<HashLen: ArrayLength<u8>> TryFrom<&[u8]> for KE3Message<HashLen> {
    type Error = InternalPakeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let checked_bytes = check_slice_size(bytes, KEY_LEN, "ke3_message")?;

        Ok(Self {
            mac: GenericArray::clone_from_slice(&checked_bytes),
        })
    }
}

// Helper functions

// Internal function which takes the public and private components of the client and server keypairs, along
// with some auxiliary metadata, to produce the shared secret and two MAC keys
fn derive_3dh_keys<KeyFormat: KeyPair, D: Hash>(
    dh: TripleDHComponents<KeyFormat>,
    client_nonce: &GenericArray<u8, NonceLen>,
    server_nonce: &GenericArray<u8, NonceLen>,
    client_s_pk: KeyFormat::Repr,
    server_s_pk: KeyFormat::Repr,
) -> Result<TripleDHDerivationResult<D>, ProtocolError> {
    let ikm: Vec<u8> = [
        &KeyFormat::diffie_hellman(dh.pk1, dh.sk1)[..],
        &KeyFormat::diffie_hellman(dh.pk2, dh.sk2)[..],
        &KeyFormat::diffie_hellman(dh.pk3, dh.sk3)[..],
    ]
    .concat();

    let info: Vec<u8> = [
        STR_3DH,
        &serialize(&client_nonce, 2),
        &serialize(&server_nonce, 2),
        &serialize(&client_s_pk.to_arr(), 2),
        &serialize(&server_s_pk.to_arr(), 2),
    ]
    .concat();

    let extracted_ikm = Hkdf::<D>::new(None, &ikm);
    let handshake_secret = derive_secrets::<D>(&extracted_ikm, &STR_HANDSHAKE_SECRET, &info)?;
    let session_secret = derive_secrets::<D>(&extracted_ikm, &STR_SESSION_SECRET, &info)?;
    let km2 = hkdf_expand_label::<D>(
        &handshake_secret,
        &STR_SERVER_MAC,
        b"",
        <D as Digest>::OutputSize::to_usize(),
    )?;
    let km3 = hkdf_expand_label::<D>(
        &handshake_secret,
        &STR_CLIENT_MAC,
        b"",
        <D as Digest>::OutputSize::to_usize(),
    )?;

    Ok((
        GenericArray::clone_from_slice(&session_secret),
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
    let h = Hkdf::<D>::new(None, secret);
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
    hkdf_label.extend_from_slice(&length.to_be_bytes()[6..]);

    let mut opaque_label: Vec<u8> = Vec::new();
    opaque_label.extend_from_slice(&STR_OPAQUE);
    opaque_label.extend_from_slice(&label);
    hkdf_label.extend_from_slice(&serialize(&opaque_label, 1));

    hkdf_label.extend_from_slice(&serialize(&context, 1));

    hkdf.expand(&hkdf_label, &mut okm)
        .map_err(|_| InternalPakeError::HkdfError)?;
    Ok(okm)
}

fn derive_secrets<D: Hash>(
    hkdf: &Hkdf<D>,
    label: &[u8],
    transcript: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let hashed_transcript = D::digest(transcript);
    hkdf_expand_label_extracted::<D>(
        hkdf,
        label,
        &hashed_transcript,
        <D as Digest>::OutputSize::to_usize(),
    )
}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of the Triple Diffie-Hellman key exchange protocol
use crate::{
    errors::{utils::check_slice_size, InternalPakeError, PakeError, ProtocolError},
    hash::Hash,
    key_exchange::traits::{KeyExchange, ToBytes},
    keypair::{Key, KeyPair, SizedBytes},
    sized_bytes_using_constant_and_try_from,
};
use digest::Digest;
use generic_array::{
    typenum::{U64, U96},
    GenericArray,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use rand_core::{CryptoRng, RngCore};

use std::convert::TryFrom;

const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 32;
const KE1_STATE_LEN: usize = KEY_LEN + KEY_LEN + NONCE_LEN;
const KE2_MESSAGE_LEN: usize = NONCE_LEN + 2 * KEY_LEN;

static STR_3DH: &[u8] = b"3DH keys";

/// The Triple Diffie-Hellman key exchange implementation
pub struct TripleDH;

impl<D: Hash> KeyExchange<D> for TripleDH {
    type KE1State = KE1State;
    type KE2State = KE2State;
    type KE1Message = KE1Message;
    type KE2Message = KE2Message;
    type KE3Message = KE3Message;

    fn generate_ke1<R: RngCore + CryptoRng, KeyFormat: KeyPair<Repr = Key>>(
        l1_component: Vec<u8>,
        rng: &mut R,
    ) -> Result<(Self::KE1State, Self::KE1Message), ProtocolError> {
        let client_e_kp = KeyFormat::generate_random(rng)?;
        let mut client_nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut client_nonce);

        let ke1_message = KE1Message {
            client_nonce: client_nonce.to_vec(),
            client_e_pk: client_e_kp.public().clone(),
        };

        let l1_data: Vec<u8> = [&l1_component[..], &ke1_message.to_bytes()].concat();
        let mut hasher = D::new();
        hasher.update(&l1_data);
        let hashed_l1 = hasher.finalize();

        Ok((
            KE1State {
                client_e_sk: client_e_kp.private().clone(),
                client_nonce: client_nonce.to_vec(),
                hashed_l1: hashed_l1.to_vec(),
            },
            ke1_message,
        ))
    }

    fn generate_ke2<R: RngCore + CryptoRng, KeyFormat: KeyPair<Repr = Key>>(
        rng: &mut R,
        l1_bytes: Vec<u8>,
        l2_bytes: Vec<u8>,
        ke1_message: Self::KE1Message,
        client_s_pk: KeyFormat::Repr,
        server_s_sk: KeyFormat::Repr,
    ) -> Result<(Self::KE2State, Self::KE2Message), ProtocolError> {
        let server_e_kp = KeyFormat::generate_random(rng)?;
        let mut server_nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut server_nonce);

        let (shared_secret, km2, km3) = derive_3dh_keys::<KeyFormat, D>(
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
                km3: km3.to_vec(),
                hashed_transcript: hashed_transcript.to_vec(),
                shared_secret: shared_secret.to_vec(),
            },
            KE2Message {
                server_nonce: server_nonce.to_vec(),
                server_e_pk: server_e_kp.public().clone(),
                mac: mac.finalize().into_bytes().to_vec(),
            },
        ))
    }

    fn generate_ke3<KeyFormat: KeyPair<Repr = Key>>(
        l2_component: Vec<u8>,
        ke2_message: Self::KE2Message,
        ke1_state: &Self::KE1State,
        server_s_pk: KeyFormat::Repr,
        client_s_sk: KeyFormat::Repr,
    ) -> Result<(Vec<u8>, Self::KE3Message), ProtocolError> {
        let (shared_secret, km2, km3) = derive_3dh_keys::<KeyFormat, D>(
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
            &ke2_message.server_e_pk[..],
        ]
        .concat();

        let mut hasher = D::new();
        hasher.update(&transcript);
        let hashed_transcript = hasher.finalize();

        let mut server_mac =
            Hmac::<D>::new_varkey(&km2).map_err(|_| InternalPakeError::HmacError)?;
        server_mac.update(&hashed_transcript);

        if ke2_message.mac != server_mac.finalize().into_bytes().to_vec() {
            return Err(ProtocolError::VerificationError(
                PakeError::KeyExchangeMacValidationError,
            ));
        }

        let mut client_mac =
            Hmac::<D>::new_varkey(&km3).map_err(|_| InternalPakeError::HmacError)?;
        client_mac.update(&hashed_transcript);

        Ok((
            shared_secret.to_vec(),
            KE3Message {
                mac: client_mac.finalize().into_bytes().to_vec(),
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

        if ke3_message.mac != client_mac.finalize().into_bytes().to_vec() {
            return Err(ProtocolError::VerificationError(
                PakeError::KeyExchangeMacValidationError,
            ));
        }

        Ok(ke2_state.shared_secret.to_vec())
    }

    fn ke1_state_size() -> usize {
        KE1_STATE_LEN
    }

    fn ke2_message_size() -> usize {
        KE2_MESSAGE_LEN
    }
}

/// The client state produced after the first key exchange message
#[derive(PartialEq, Eq)]
pub struct KE1State {
    client_e_sk: Key,
    client_nonce: Vec<u8>,
    hashed_l1: Vec<u8>,
}

/// The first key exchange message
#[derive(PartialEq, Eq)]
pub struct KE1Message {
    pub(crate) client_nonce: Vec<u8>,
    pub(crate) client_e_pk: Key,
}

impl TryFrom<Vec<u8>> for KE1State {
    type Error = InternalPakeError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let checked_bytes = check_slice_size(&bytes, KE1_STATE_LEN, "ke1_state")?;

        Ok(Self {
            client_e_sk: Key::from_bytes(&checked_bytes[..KEY_LEN])?,
            client_nonce: checked_bytes[KEY_LEN..KEY_LEN + NONCE_LEN].to_vec(),
            hashed_l1: checked_bytes[KEY_LEN + NONCE_LEN..].to_vec(),
        })
    }
}

impl ToBytes for KE1State {
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

sized_bytes_using_constant_and_try_from!(KE1State, U96);

impl ToBytes for KE1Message {
    fn to_bytes(&self) -> Vec<u8> {
        [&self.client_nonce[..], &self.client_e_pk.to_arr()].concat()
    }
}

impl TryFrom<Vec<u8>> for KE1Message {
    type Error = InternalPakeError;

    fn try_from(ke1_message_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let checked_bytes =
            check_slice_size(&ke1_message_bytes, NONCE_LEN + KEY_LEN, "ke1_message")?;

        Ok(Self {
            client_nonce: checked_bytes[..NONCE_LEN].to_vec(),
            client_e_pk: Key::from_bytes(&checked_bytes[NONCE_LEN..])?,
        })
    }
}

sized_bytes_using_constant_and_try_from!(KE1Message, U64);

/// The server state produced after the second key exchange message
pub struct KE2State {
    km3: Vec<u8>,
    hashed_transcript: Vec<u8>,
    shared_secret: Vec<u8>,
}

/// The second key exchange message
pub struct KE2Message {
    server_nonce: Vec<u8>,
    server_e_pk: Key,
    mac: Vec<u8>,
}

impl ToBytes for KE2State {
    fn to_bytes(&self) -> Vec<u8> {
        let output: Vec<u8> = [
            &self.km3[..],
            &self.hashed_transcript[..],
            &self.shared_secret[..],
        ]
        .concat();
        output
    }
}

impl TryFrom<Vec<u8>> for KE2State {
    type Error = ProtocolError;

    fn try_from(ke1_message_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let checked_bytes = check_slice_size(&ke1_message_bytes, 3 * KEY_LEN, "ke2_state")?;

        Ok(Self {
            km3: checked_bytes[..KEY_LEN].to_vec(),
            hashed_transcript: checked_bytes[KEY_LEN..2 * KEY_LEN].to_vec(),
            shared_secret: checked_bytes[2 * KEY_LEN..].to_vec(),
        })
    }
}

impl ToBytes for KE2Message {
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

impl TryFrom<Vec<u8>> for KE2Message {
    type Error = ProtocolError;

    fn try_from(ke2_message_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let checked_bytes = check_slice_size(&ke2_message_bytes, KE2_MESSAGE_LEN, "ke2_message")?;

        Ok(Self {
            server_nonce: checked_bytes[..NONCE_LEN].to_vec(),
            server_e_pk: Key::from_bytes(&checked_bytes[NONCE_LEN..NONCE_LEN + KEY_LEN])?,
            mac: checked_bytes[NONCE_LEN + KEY_LEN..].to_vec(),
        })
    }
}

// The triple of public and private components used in the 3DH computation
struct TripleDHComponents {
    pk1: Key,
    sk1: Key,
    pk2: Key,
    sk2: Key,
    pk3: Key,
    sk3: Key,
}

// Consists of a shared secret, followed by two mac keys
type TripleDHDerivationResult<D> = (
    GenericArray<u8, <D as Hash>::OutputSize>,
    GenericArray<u8, <D as Hash>::OutputSize>,
    GenericArray<u8, <D as Hash>::OutputSize>,
);

// Internal function which takes the public and private components of the client and server keypairs, along
// with some auxiliary metadata, to produce the shared secret and two MAC keys
fn derive_3dh_keys<KeyFormat: KeyPair<Repr = Key>, D: Hash>(
    dh: TripleDHComponents,
    client_nonce: &[u8],
    server_nonce: &[u8],
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
        &client_nonce,
        &server_nonce,
        &client_s_pk.to_arr(),
        &server_s_pk.to_arr(),
    ]
    .concat();

    const OUTPUT_SIZE: usize = 32;
    let mut okm = [0u8; 3 * OUTPUT_SIZE];
    let h = Hkdf::<D>::new(None, &ikm);
    h.expand(&info, &mut okm)
        .map_err(|_| InternalPakeError::HkdfError)?;
    Ok((
        GenericArray::clone_from_slice(&okm[..OUTPUT_SIZE]),
        GenericArray::clone_from_slice(&okm[OUTPUT_SIZE..2 * OUTPUT_SIZE]),
        GenericArray::clone_from_slice(&okm[2 * OUTPUT_SIZE..]),
    ))
}

/// The third key exchange message
pub struct KE3Message {
    mac: Vec<u8>,
}

impl ToBytes for KE3Message {
    fn to_bytes(&self) -> Vec<u8> {
        self.mac.clone()
    }
}

impl TryFrom<Vec<u8>> for KE3Message {
    type Error = ProtocolError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let checked_bytes = check_slice_size(&bytes, KEY_LEN, "ke3_message")?;

        Ok(Self {
            mac: checked_bytes.to_vec(),
        })
    }
}

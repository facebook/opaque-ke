// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of the Triple Diffie-Hellman key exchange protocol
use crate::{
    errors::{InternalPakeError, PakeError, ProtocolError},
    key_exchange::traits::KeyExchange,
    keypair::{Key, KeyPair, SizedBytes},
};
use generic_array::{typenum::U32, GenericArray};
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use opaque_derive::{SizedBytes, TryFromForSizedBytes};
use rand_core::{CryptoRng, RngCore};

use sha2::{Digest, Sha256};
use std::convert::TryFrom;

const KEY_LEN: usize = 32;
pub(crate) type NonceLen = U32;
pub(crate) const NONCE_LEN: usize = 32;
const KE1_STATE_LEN: usize = KEY_LEN + KEY_LEN + NONCE_LEN;
const KE2_MESSAGE_LEN: usize = NONCE_LEN + 2 * KEY_LEN;

static STR_3DH: &[u8] = b"3DH keys";

/// The Triple Diffie-Hellman key exchange implementation
pub struct TripleDH {}

impl KeyExchange for TripleDH {
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
            client_nonce: GenericArray::clone_from_slice(&client_nonce),
            client_e_pk: client_e_kp.public().clone(),
        };

        let l1_data: Vec<u8> = [&l1_component[..], &ke1_message.to_arr()].concat();
        let mut hasher = Sha256::new();
        hasher.update(&l1_data);
        let hashed_l1 = hasher.finalize();

        Ok((
            KE1State {
                client_e_sk: client_e_kp.private().clone(),
                client_nonce: GenericArray::clone_from_slice(&client_nonce),
                hashed_l1,
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

        let (shared_secret, km2, km3) = derive_3dh_keys::<KeyFormat>(
            TripleDHComponents {
                pk1: ke1_message.client_e_pk.clone(),
                sk1: server_e_kp.private().clone(),
                pk2: ke1_message.client_e_pk,
                sk2: server_s_sk.clone(),
                pk3: client_s_pk.clone(),
                sk3: server_e_kp.private().clone(),
            },
            &ke1_message.client_nonce,
            GenericArray::<_, <Sha256 as Digest>::OutputSize>::from_slice(&server_nonce),
            client_s_pk,
            KeyFormat::public_from_private(&server_s_sk),
        )?;

        let mut hasher = Sha256::new();
        hasher.update(&l1_bytes);
        let hashed_l1 = hasher.finalize();

        let transcript2: Vec<u8> = [
            &hashed_l1[..],
            &l2_bytes[..],
            &server_nonce[..],
            &server_e_kp.public().to_arr(),
        ]
        .concat();

        let mut hasher2 = Sha256::new();
        hasher2.update(&transcript2);
        let hashed_transcript = hasher2.finalize();

        let mut mac = Hmac::<Sha256>::new_varkey(&km2).map_err(|_| InternalPakeError::HmacError)?;
        mac.update(&hashed_transcript);

        Ok((
            KE2State {
                km3,
                hashed_transcript,
                shared_secret,
            },
            KE2Message {
                server_nonce: GenericArray::clone_from_slice(&server_nonce),
                server_e_pk: server_e_kp.public().clone(),
                mac: mac.finalize().into_bytes(),
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
        let (shared_secret, km2, km3) = derive_3dh_keys::<KeyFormat>(
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

        let mut hasher = Sha256::new();
        hasher.update(&transcript);
        let hashed_transcript = hasher.finalize();

        let mut server_mac =
            Hmac::<Sha256>::new_varkey(&km2).map_err(|_| InternalPakeError::HmacError)?;
        server_mac.update(&hashed_transcript);

        if ke2_message.mac != server_mac.finalize().into_bytes() {
            return Err(ProtocolError::VerificationError(
                PakeError::KeyExchangeMacValidationError,
            ));
        }

        let mut client_mac =
            Hmac::<Sha256>::new_varkey(&km3).map_err(|_| InternalPakeError::HmacError)?;
        client_mac.update(&hashed_transcript);

        Ok((
            shared_secret.to_vec(),
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
            Hmac::<Sha256>::new_varkey(&ke2_state.km3).map_err(|_| InternalPakeError::HmacError)?;
        client_mac.update(&ke2_state.hashed_transcript);

        if ke3_message.mac != client_mac.finalize().into_bytes() {
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
#[derive(PartialEq, Eq, SizedBytes, TryFromForSizedBytes)]
pub struct KE1State {
    client_e_sk: Key,
    client_nonce: GenericArray<u8, NonceLen>,
    hashed_l1: GenericArray<u8, <Sha256 as Digest>::OutputSize>,
}

/// The first key exchange message
#[derive(PartialEq, Eq, SizedBytes, TryFromForSizedBytes)]
pub struct KE1Message {
    pub(crate) client_nonce: GenericArray<u8, NonceLen>,
    pub(crate) client_e_pk: Key,
}

/// The server state produced after the second key exchange message
#[derive(PartialEq, Eq, SizedBytes, TryFromForSizedBytes)]
pub struct KE2State {
    km3: GenericArray<u8, <Sha256 as Digest>::OutputSize>,
    hashed_transcript: GenericArray<u8, <Sha256 as Digest>::OutputSize>,
    shared_secret: GenericArray<u8, <Sha256 as Digest>::OutputSize>,
}

/// The second key exchange message
#[derive(PartialEq, Eq, SizedBytes, TryFromForSizedBytes)]
pub struct KE2Message {
    server_nonce: GenericArray<u8, NonceLen>,
    server_e_pk: Key,
    mac: GenericArray<u8, <Sha256 as Digest>::OutputSize>,
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
type TripleDHDerivationResult = (
    GenericArray<u8, <Sha256 as Digest>::OutputSize>,
    GenericArray<u8, <Sha256 as Digest>::OutputSize>,
    GenericArray<u8, <Sha256 as Digest>::OutputSize>,
);

// Internal function which takes the public and private components of the client and server keypairs, along
// with some auxiliary metadata, to produce the shared secret and two MAC keys
fn derive_3dh_keys<KeyFormat: KeyPair<Repr = Key>>(
    dh: TripleDHComponents,
    client_nonce: &[u8],
    server_nonce: &[u8],
    client_s_pk: KeyFormat::Repr,
    server_s_pk: KeyFormat::Repr,
) -> Result<TripleDHDerivationResult, ProtocolError> {
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
    let h = Hkdf::<Sha256>::new(None, &ikm);
    h.expand(&info, &mut okm)
        .map_err(|_| InternalPakeError::HkdfError)?;
    Ok((
        *GenericArray::from_slice(&okm[..OUTPUT_SIZE]),
        *GenericArray::from_slice(&okm[OUTPUT_SIZE..2 * OUTPUT_SIZE]),
        *GenericArray::from_slice(&okm[2 * OUTPUT_SIZE..]),
    ))
}

/// The third key exchange message
#[derive(PartialEq, SizedBytes, TryFromForSizedBytes)]
pub struct KE3Message {
    mac: GenericArray<u8, <Sha256 as Digest>::OutputSize>,
}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    envelope::Envelope,
    group::Group,
    key_exchange::{
        traits::{KeyExchange, ToBytes},
        tripledh::{TripleDH, NONCE_LEN},
    },
    keypair::{KeyPair, SizedBytes, X25519KeyPair},
    opaque::*,
    serialization::{serialize, ProtocolMessageType},
};

use curve25519_dalek::ristretto::RistrettoPoint;
use proptest::{collection::vec, prelude::*};
use rand_core::{OsRng, RngCore};

use sha2::{Digest, Sha256};
use std::convert::TryFrom;

struct Default;
impl CipherSuite for Default {
    type Group = RistrettoPoint;
    type KeyFormat = crate::keypair::X25519KeyPair;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha256;
    type SlowHash = crate::slow_hash::NoOpHash;
}

const MAX_ID_LENGTH: usize = 10;

fn random_ristretto_point() -> RistrettoPoint {
    let mut rng = OsRng;
    let mut random_bits = [0u8; 64];
    rng.fill_bytes(&mut random_bits);

    // This is because RistrettoPoint is on an obsolete sha2 version
    let mut bits = [0u8; 64];
    let mut hasher = sha2::Sha512::new();
    hasher.update(&random_bits[..]);
    bits.copy_from_slice(&hasher.finalize());

    RistrettoPoint::from_uniform_bytes(&bits)
}

#[test]
fn client_registration_roundtrip() {
    let pw = b"hunter2";
    let mut rng = OsRng;
    let sc = <RistrettoPoint as Group>::random_scalar(&mut rng);
    let id_u_length: usize = rng.gen_range(0, MAX_ID_LENGTH);
    let id_s_length: usize = rng.gen_range(0, MAX_ID_LENGTH);
    let mut id_u = [0u8; MAX_ID_LENGTH];
    rng.fill_bytes(&mut id_u);
    let mut id_s = [0u8; MAX_ID_LENGTH];
    rng.fill_bytes(&mut id_s);

    // serialization order: id_u, id_s, scalar, password
    let bytes: Vec<u8> = [
        &serialize(&id_u[..id_u_length], 2)[..],
        &serialize(&id_s[..id_s_length], 2)[..],
        &sc.as_bytes()[..],
        &pw[..],
    ]
    .concat();
    let reg = ClientRegistration::<Default>::try_from(&bytes[..]).unwrap();
    let reg_bytes = reg.to_bytes();
    assert_eq!(reg_bytes, bytes);
}

#[test]
fn server_registration_roundtrip() {
    // If we don't have envelope and client_pk, the server registration just
    // contains the prf key
    let mut rng = OsRng;
    let oprf_key = <RistrettoPoint as Group>::random_scalar(&mut rng);
    let mut oprf_bytes: Vec<u8> = vec![];
    oprf_bytes.extend_from_slice(oprf_key.as_bytes());
    let reg = ServerRegistration::<Default>::try_from(&oprf_bytes[..]).unwrap();
    let reg_bytes = reg.to_bytes();
    assert_eq!(reg_bytes, oprf_bytes);
    // If we do have envelope and client pk, the server registration contains
    // the whole kit

    // Construct a mock envelope
    let mut mock_envelope_bytes = Vec::new();
    mock_envelope_bytes.extend_from_slice(&[0; NONCE_LEN]); // empty nonce
    mock_envelope_bytes.extend_from_slice(&[0, 0]); // empty ciphertext
    mock_envelope_bytes.extend_from_slice(&[0, 0]); // empty auth_data
                                                    // length-32 hmac
    mock_envelope_bytes.extend_from_slice(&[0, 32]);
    mock_envelope_bytes.extend_from_slice(&[0; 32]);

    let mock_client_kp = Default::generate_random_keypair(&mut rng).unwrap();
    // serialization order: oprf_key, public key, envelope
    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(oprf_key.as_bytes());
    bytes.extend_from_slice(&mock_client_kp.public().to_arr());
    bytes.extend_from_slice(&mock_envelope_bytes);
    let reg = ServerRegistration::<Default>::try_from(&bytes[..]).unwrap();
    let reg_bytes = reg.to_bytes();
    assert_eq!(reg_bytes, bytes);
}

#[test]
fn register_first_message_roundtrip() {
    let pt = random_ristretto_point();
    let pt_bytes = pt.to_arr().to_vec();

    let mut rng = OsRng;
    let id_length: usize = rng.gen_range(0, MAX_ID_LENGTH);
    let mut id = [0u8; MAX_ID_LENGTH];
    rng.fill_bytes(&mut id);

    let alpha_length: usize = 32;
    let total_length: usize = alpha_length + id_length + 4;

    let mut input = Vec::new();
    input.extend_from_slice(&[ProtocolMessageType::RegistrationRequest as u8 + 1]);
    input.extend_from_slice(&total_length.to_be_bytes()[8 - 3..]);
    input.extend_from_slice(&id_length.to_be_bytes()[8 - 2..]);
    input.extend_from_slice(&id[..id_length]);
    input.extend_from_slice(&alpha_length.to_be_bytes()[8 - 2..]);
    input.extend_from_slice(pt_bytes.as_slice());

    let r1 = RegisterFirstMessage::<RistrettoPoint>::deserialize(input.as_slice()).unwrap();
    let r1_bytes = r1.serialize();
    assert_eq!(input, r1_bytes);
}

#[test]
fn register_second_message_roundtrip() {
    let pt = random_ristretto_point();
    let beta_bytes = pt.to_arr();
    let mut rng = OsRng;
    let skp = Default::generate_random_keypair(&mut rng).unwrap();
    let pubkey_bytes = skp.public().to_arr();
    let credential_types = [1, 1, 1, 3];

    let beta_length: usize = beta_bytes.len();
    let pubkey_length: usize = pubkey_bytes.len();
    let total_length: usize = beta_length + pubkey_length + credential_types.len() + 4;

    let mut input = Vec::new();
    input.extend_from_slice(&[ProtocolMessageType::RegistrationResponse as u8 + 1]);
    input.extend_from_slice(&total_length.to_be_bytes()[8 - 3..]);
    input.extend_from_slice(&beta_length.to_be_bytes()[8 - 2..]);
    input.extend_from_slice(beta_bytes.as_slice());
    input.extend_from_slice(&pubkey_length.to_be_bytes()[8 - 2..]);
    input.extend_from_slice(&pubkey_bytes.as_slice());
    input.extend_from_slice(&credential_types);

    let r2 = RegisterSecondMessage::<RistrettoPoint>::deserialize(input.as_slice()).unwrap();
    let r2_bytes = r2.serialize();
    assert_eq!(input, r2_bytes);
}

#[test]
fn register_third_message_roundtrip() {
    let mut rng = OsRng;
    let skp = Default::generate_random_keypair(&mut rng).unwrap();
    let pubkey_bytes = skp.public().to_arr();

    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);

    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);

    let (envelope, _) =
        Envelope::<sha2::Sha256>::seal_raw(&key, &msg, &pubkey_bytes, &mut rng).unwrap();
    let envelope_bytes = envelope.serialize();

    let pubkey_length: usize = pubkey_bytes.len();
    let total_length: usize = pubkey_length + envelope_bytes.len() + 2;

    let mut input = Vec::new();
    input.extend_from_slice(&[ProtocolMessageType::RegistrationUpload as u8 + 1]);
    input.extend_from_slice(&total_length.to_be_bytes()[8 - 3..]);
    input.extend_from_slice(&envelope_bytes);
    input.extend_from_slice(&pubkey_length.to_be_bytes()[8 - 2..]);
    input.extend_from_slice(&pubkey_bytes[..]);

    let r3 = RegisterThirdMessage::<X25519KeyPair, sha2::Sha256>::deserialize(&input[..]).unwrap();
    let r3_bytes = r3.serialize();
    assert_eq!(input, r3_bytes);
}

#[test]
fn login_first_message_roundtrip() {
    let mut rng = OsRng;
    let alpha = random_ristretto_point();
    let alpha_bytes = alpha.to_arr().to_vec();
    let id_length: usize = rng.gen_range(0, MAX_ID_LENGTH);
    let mut id = [0u8; MAX_ID_LENGTH];
    rng.fill_bytes(&mut id);

    let client_e_kp = Default::generate_random_keypair(&mut rng).unwrap();
    let mut client_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut client_nonce);

    let ke1m: Vec<u8> = [&client_nonce[..], &client_e_kp.public()].concat();

    let alpha_length = alpha_bytes.len();
    let total_length_without_ke1m: usize = id_length + alpha_length + 4;

    let mut input = Vec::new();
    input.extend_from_slice(&[ProtocolMessageType::CredentialRequest as u8 + 1]);
    input.extend_from_slice(&total_length_without_ke1m.to_be_bytes()[8 - 3..]);
    input.extend_from_slice(&id_length.to_be_bytes()[8 - 2..]);
    input.extend_from_slice(&id[..id_length]);
    input.extend_from_slice(&alpha_length.to_be_bytes()[8 - 2..]);
    input.extend_from_slice(&alpha_bytes);
    input.extend_from_slice(&ke1m[..]);

    let l1 = LoginFirstMessage::<Default>::deserialize(input.as_slice()).unwrap();
    let l1_bytes = l1.serialize();
    assert_eq!(input, l1_bytes);
}

#[test]
fn login_second_message_roundtrip() {
    let pt = random_ristretto_point();
    let pt_bytes = pt.to_arr().to_vec();

    let mut rng = OsRng;
    let skp = Default::generate_random_keypair(&mut rng).unwrap();
    let pubkey_bytes = skp.public().to_arr();

    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);

    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);

    let (envelope, _) =
        Envelope::<sha2::Sha256>::seal_raw(&key, &msg, &pubkey_bytes, &mut rng).unwrap();

    let server_e_kp = Default::generate_random_keypair(&mut rng).unwrap();
    let mut mac = [0u8; 32];
    rng.fill_bytes(&mut mac);
    let mut server_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut server_nonce);

    let ke2m: Vec<u8> = [&server_nonce[..], &server_e_kp.public(), &mac[..]].concat();

    let total_length_without_ke2m: usize = pt_bytes.len() + envelope.to_bytes().len() + 2;

    let mut input = Vec::new();
    input.extend_from_slice(&[ProtocolMessageType::CredentialResponse as u8 + 1]);
    input.extend_from_slice(&total_length_without_ke2m.to_be_bytes()[8 - 3..]);
    input.extend_from_slice(&pt_bytes.len().to_be_bytes()[8 - 2..]);
    input.extend_from_slice(pt_bytes.as_slice());
    input.extend_from_slice(&envelope.to_bytes());
    input.extend_from_slice(&ke2m[..]);

    let l2 = LoginSecondMessage::<Default>::deserialize(&input).unwrap();
    let l2_bytes = l2.serialize();
    assert_eq!(input, l2_bytes);
}

#[test]
fn client_login_roundtrip() {
    let pw = b"hunter2";
    let mut rng = OsRng;
    let id_u_length: usize = rng.gen_range(0, MAX_ID_LENGTH);
    let id_s_length: usize = rng.gen_range(0, MAX_ID_LENGTH);
    let mut id_u = [0u8; MAX_ID_LENGTH];
    rng.fill_bytes(&mut id_u);
    let mut id_s = [0u8; MAX_ID_LENGTH];
    rng.fill_bytes(&mut id_s);

    let sc = <RistrettoPoint as Group>::random_scalar(&mut rng);

    let client_e_kp = Default::generate_random_keypair(&mut rng).unwrap();
    let mut client_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut client_nonce);

    let l1_data = [&sc.to_bytes()[..], &client_nonce, client_e_kp.public()].concat();
    let mut hasher = Sha256::new();
    hasher.update(l1_data);
    let hashed_l1 = hasher.finalize();

    // serialization order: id_u, id_s, scalar, password, ke1_state
    let bytes: Vec<u8> = [
        &serialize(&id_u[..id_u_length], 2)[..],
        &serialize(&id_s[..id_s_length], 2)[..],
        &sc.as_bytes()[..],
        &pw[..],
        client_e_kp.public(),
        &client_nonce,
        hashed_l1.as_slice(),
    ]
    .concat();
    let reg = ClientLogin::<Default>::try_from(&bytes[..]).unwrap();
    let reg_bytes = reg.to_bytes();
    assert_eq!(reg_bytes, bytes);
}

#[test]
fn ke1_message_roundtrip() {
    let mut rng = OsRng;

    let client_e_kp = Default::generate_random_keypair(&mut rng).unwrap();
    let mut client_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut client_nonce);

    let ke1m: Vec<u8> = [&client_nonce[..], &client_e_kp.public()].concat();
    let reg =
        <TripleDH as KeyExchange<sha2::Sha256, crate::keypair::X25519KeyPair>>::KE1Message::try_from(&ke1m[..]).unwrap();
    let reg_bytes = reg.to_bytes();
    assert_eq!(reg_bytes, ke1m);
}

proptest! {

#[test]
fn test_nocrash_register_first_message(bytes in vec(any::<u8>(), 0..200)) {
    RegisterFirstMessage::<RistrettoPoint>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_register_second_message(bytes in vec(any::<u8>(), 0..200)) {
    RegisterSecondMessage::<RistrettoPoint>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_register_third_message(bytes in vec(any::<u8>(), 0..200)) {
    RegisterThirdMessage::<crate::keypair::X25519KeyPair, sha2::Sha512>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_login_first_message(bytes in vec(any::<u8>(), 0..500)) {
    LoginFirstMessage::<Default>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_login_second_message(bytes in vec(any::<u8>(), 0..500)) {
    LoginSecondMessage::<Default>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_login_third_message(bytes in vec(any::<u8>(), 0..500)) {
    LoginThirdMessage::<Default>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_client_registration(bytes in vec(any::<u8>(), 0..700)) {
    ClientRegistration::<Default>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_server_registration(bytes in vec(any::<u8>(), 0..700)) {
    ServerRegistration::<Default>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_client_login(bytes in vec(any::<u8>(), 0..700)) {
    ClientLogin::<Default>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_server_login(bytes in vec(any::<u8>(), 0..700)) {
    ServerLogin::<Default>::try_from(&bytes[..]).map_or(true, |_| true);
}

}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    envelope::{Envelope, InnerEnvelopeMode},
    group::Group,
    key_exchange::{
        traits::{KeyExchange, ToBytes},
        tripledh::{NonceLen, TripleDH},
    },
    opaque::*,
    serialization::{i2osp, os2ip, serialize},
    *,
};

use curve25519_dalek::ristretto::RistrettoPoint;
use generic_array::typenum::Unsigned;
use generic_bytes::SizedBytes;
use proptest::{collection::vec, prelude::*};
use rand::{rngs::OsRng, RngCore};

use sha2::Digest;
use std::convert::TryFrom;

struct Default;
impl CipherSuite for Default {
    type Group = RistrettoPoint;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = crate::slow_hash::NoOpHash;
}

const MAX_INFO_LENGTH: usize = 10;
const MAC_SIZE: usize = 64; // Because of SHA512

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

    // serialization order: scalar, password
    let bytes: Vec<u8> = [&sc.as_bytes()[..], &pw[..]].concat();
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
    mock_envelope_bytes.extend_from_slice(&[1; 1]); // mode = 1
    mock_envelope_bytes.extend_from_slice(&vec![0; NonceLen::to_usize()]); // empty nonce
    mock_envelope_bytes.extend_from_slice(&[0, 0]); // empty ciphertext
    mock_envelope_bytes.extend_from_slice(&[0; MAC_SIZE]); // length-MAC_SIZE hmac

    let mock_client_kp = Default::generate_random_keypair(&mut rng);
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

    let mut input = Vec::new();
    input.extend_from_slice(pt_bytes.as_slice());

    let r1 = RegistrationRequest::<Default>::deserialize(input.as_slice()).unwrap();
    let r1_bytes = r1.serialize();
    assert_eq!(input, r1_bytes);
}

#[test]
fn register_second_message_roundtrip() {
    let pt = random_ristretto_point();
    let beta_bytes = pt.to_arr();
    let mut rng = OsRng;
    let skp = Default::generate_random_keypair(&mut rng);
    let pubkey_bytes = skp.public().to_arr();

    let pubkey_length: usize = pubkey_bytes.len();

    let mut input = Vec::new();
    input.extend_from_slice(beta_bytes.as_slice());
    input.extend_from_slice(&pubkey_length.to_be_bytes()[std::mem::size_of::<usize>() - 2..]);
    input.extend_from_slice(&pubkey_bytes.as_slice());

    let r2 = RegistrationResponse::<Default>::deserialize(input.as_slice()).unwrap();
    let r2_bytes = r2.serialize();
    assert_eq!(input, r2_bytes);
}

#[test]
fn register_third_message_roundtrip() {
    let mut rng = OsRng;
    let skp = Default::generate_random_keypair(&mut rng);
    let pubkey_bytes = skp.public().to_arr();

    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);

    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);

    let (envelope, _) = Envelope::<sha2::Sha512>::seal_raw(
        &mut rng,
        &key,
        &msg,
        &pubkey_bytes,
        InnerEnvelopeMode::Base,
    )
    .unwrap();
    let envelope_bytes = envelope.serialize();

    let pubkey_length: usize = pubkey_bytes.len();

    let mut input = Vec::new();
    input.extend_from_slice(&pubkey_length.to_be_bytes()[std::mem::size_of::<usize>() - 2..]);
    input.extend_from_slice(&pubkey_bytes[..]);
    input.extend_from_slice(&envelope_bytes);

    let r3 = RegistrationUpload::<Default>::deserialize(&input[..]).unwrap();
    let r3_bytes = r3.serialize();
    assert_eq!(input, r3_bytes);
}

#[test]
fn login_first_message_roundtrip() {
    let mut rng = OsRng;
    let alpha = random_ristretto_point();
    let alpha_bytes = alpha.to_arr().to_vec();

    let client_e_kp = Default::generate_random_keypair(&mut rng);
    let mut client_nonce = vec![0u8; NonceLen::to_usize()];
    rng.fill_bytes(&mut client_nonce);

    let mut info = [0u8; MAX_INFO_LENGTH];
    rng.fill_bytes(&mut info);

    let ke1m: Vec<u8> = [
        &client_nonce[..],
        &serialize(&info.to_vec(), 2),
        &client_e_kp.public(),
    ]
    .concat();

    let mut input = Vec::new();
    input.extend_from_slice(&alpha_bytes);
    input.extend_from_slice(&ke1m[..]);

    let l1 = CredentialRequest::<Default>::deserialize(input.as_slice()).unwrap();
    let l1_bytes = l1.serialize();
    assert_eq!(input, l1_bytes);
}

#[test]
fn login_second_message_roundtrip() {
    let pt = random_ristretto_point();
    let pt_bytes = pt.to_arr().to_vec();

    let mut rng = OsRng;
    let skp = Default::generate_random_keypair(&mut rng);
    let pubkey_bytes = skp.public().to_arr();
    let pubkey_length: usize = pubkey_bytes.len();

    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);

    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);

    let (envelope, _) = Envelope::<sha2::Sha512>::seal_raw(
        &mut rng,
        &key,
        &msg,
        &pubkey_bytes,
        InnerEnvelopeMode::Base,
    )
    .unwrap();

    let server_e_kp = Default::generate_random_keypair(&mut rng);
    let mut mac = [0u8; MAC_SIZE];
    rng.fill_bytes(&mut mac);
    let mut server_nonce = vec![0u8; NonceLen::to_usize()];
    rng.fill_bytes(&mut server_nonce);

    let mut e_info = [0u8; MAX_INFO_LENGTH];
    rng.fill_bytes(&mut e_info);

    let ke2m: Vec<u8> = [
        &server_nonce[..],
        &server_e_kp.public(),
        &serialize(&e_info.to_vec(), 2),
        &mac[..],
    ]
    .concat();

    let mut input = Vec::new();
    input.extend_from_slice(pt_bytes.as_slice());
    input.extend_from_slice(&pubkey_length.to_be_bytes()[std::mem::size_of::<usize>() - 2..]);
    input.extend_from_slice(&pubkey_bytes.as_slice());
    input.extend_from_slice(&envelope.serialize());
    input.extend_from_slice(&ke2m[..]);

    let l2 = CredentialResponse::<Default>::deserialize(&input).unwrap();
    let l2_bytes = l2.serialize();
    assert_eq!(input, l2_bytes);
}

#[test]
fn login_third_message_roundtrip() {
    let mut rng = OsRng;
    let mut mac = [0u8; MAC_SIZE];
    rng.fill_bytes(&mut mac);

    let input: Vec<u8> = [&mac[..]].concat();

    let l3 = CredentialFinalization::<Default>::deserialize(&input).unwrap();
    let l3_bytes = l3.serialize();
    assert_eq!(input, l3_bytes);
}

#[test]
fn client_login_roundtrip() {
    let pw = b"hunter2";
    let mut rng = OsRng;
    let sc = <RistrettoPoint as Group>::random_scalar(&mut rng);

    let client_e_kp = Default::generate_random_keypair(&mut rng);
    let mut client_nonce = vec![0u8; NonceLen::to_usize()];
    rng.fill_bytes(&mut client_nonce);

    let serialized_credential_request = b"serialized credential_request".to_vec();
    let l1_data = [client_e_kp.private().to_arr().to_vec(), client_nonce].concat();

    // serialization order: scalar, credential_request, ke1_state, password
    let bytes: Vec<u8> = [
        &sc.as_bytes()[..],
        &serialize(&serialized_credential_request, 2),
        &serialize(&l1_data, 2),
        &pw[..],
    ]
    .concat();
    let reg = ClientLogin::<Default>::try_from(&bytes[..]).unwrap();
    let reg_bytes = reg.to_bytes();
    assert_eq!(reg_bytes, bytes);
}

#[test]
fn ke1_message_roundtrip() {
    let mut rng = OsRng;

    let client_e_kp = Default::generate_random_keypair(&mut rng);
    let mut client_nonce = vec![0u8; NonceLen::to_usize()];
    rng.fill_bytes(&mut client_nonce);

    let mut info = [0u8; MAX_INFO_LENGTH];
    rng.fill_bytes(&mut info);

    let ke1m: Vec<u8> = [
        &client_nonce[..],
        &serialize(&info.to_vec(), 2),
        &client_e_kp.public(),
    ]
    .concat();
    let reg =
        <TripleDH as KeyExchange<sha2::Sha512, RistrettoPoint>>::KE1Message::try_from(&ke1m[..])
            .unwrap();
    let reg_bytes = reg.to_bytes();
    assert_eq!(reg_bytes, ke1m);
}

#[test]
fn ke2_message_roundtrip() {
    let mut rng = OsRng;

    let server_e_kp = Default::generate_random_keypair(&mut rng);
    let mut mac = [0u8; MAC_SIZE];
    rng.fill_bytes(&mut mac);
    let mut server_nonce = vec![0u8; NonceLen::to_usize()];
    rng.fill_bytes(&mut server_nonce);
    let mut e_info = [0u8; MAX_INFO_LENGTH];
    rng.fill_bytes(&mut e_info);

    let ke2m: Vec<u8> = [
        &server_nonce[..],
        &server_e_kp.public(),
        &serialize(&e_info.to_vec(), 2),
        &mac[..],
    ]
    .concat();

    let reg =
        <TripleDH as KeyExchange<sha2::Sha512, RistrettoPoint>>::KE2Message::try_from(&ke2m[..])
            .unwrap();
    let reg_bytes = reg.to_bytes();
    assert_eq!(reg_bytes, ke2m);
}

#[test]
fn ke3_message_roundtrip() {
    let mut rng = OsRng;
    let mut mac = [0u8; MAC_SIZE];
    rng.fill_bytes(&mut mac);

    let ke3m: Vec<u8> = [&mac[..]].concat();

    let reg =
        <TripleDH as KeyExchange<sha2::Sha512, RistrettoPoint>>::KE3Message::try_from(&ke3m[..])
            .unwrap();
    let reg_bytes = reg.to_bytes();
    assert_eq!(reg_bytes, ke3m);
}

proptest! {

#[test]
fn test_i2osp_os2ip(bytes in vec(any::<u8>(), 0..std::mem::size_of::<usize>())) {
    assert_eq!(i2osp(os2ip(&bytes)?, bytes.len()), bytes);
}

#[test]
fn test_nocrash_register_first_message(bytes in vec(any::<u8>(), 0..200)) {
    RegistrationRequest::<Default>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_register_second_message(bytes in vec(any::<u8>(), 0..200)) {
    RegistrationResponse::<Default>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_register_third_message(bytes in vec(any::<u8>(), 0..200)) {
    RegistrationUpload::<Default>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_login_first_message(bytes in vec(any::<u8>(), 0..500)) {
    CredentialRequest::<Default>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_login_second_message(bytes in vec(any::<u8>(), 0..500)) {
    CredentialResponse::<Default>::try_from(&bytes[..]).map_or(true, |_| true);
}

#[test]
fn test_nocrash_login_third_message(bytes in vec(any::<u8>(), 0..500)) {
    CredentialFinalization::<Default>::try_from(&bytes[..]).map_or(true, |_| true);
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

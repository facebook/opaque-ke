// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    group::Group,
    keypair::{KeyPair, SizedBytes, X25519KeyPair},
    opaque::*,
    rkr_encryption::{RKRCipher as _, RKRCiphertext},
};

use curve25519_dalek::ristretto::RistrettoPoint;

use chacha20poly1305::ChaCha20Poly1305;
use rand_core::{OsRng, RngCore};

use sha2::Digest;
use std::convert::TryFrom;

struct Default;
impl CipherSuite for Default {
    type Aead = ChaCha20Poly1305;
    type Group = RistrettoPoint;
    type KeyFormat = crate::keypair::X25519KeyPair;
    type SlowHash = crate::slow_hash::NoOpHash;
}

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
    let sc = <RistrettoPoint as Group>::random_scalar(&mut rng);
    let mut oprf_bytes: Vec<u8> = vec![];
    oprf_bytes.extend_from_slice(sc.as_bytes());
    let reg = ServerRegistration::<Default>::try_from(&oprf_bytes[..]).unwrap();
    let reg_bytes = reg.to_bytes();
    assert_eq!(reg_bytes, oprf_bytes);
    // If we do have envelope and client pk, the server registration contains
    // the whole kit
    let rkr_size = RKRCiphertext::<ChaCha20Poly1305>::rkr_with_nonce_size();
    let mut mock_rkr_bytes = vec![0u8; rkr_size];
    rng.fill_bytes(&mut mock_rkr_bytes);
    println!("{}", mock_rkr_bytes.len());
    let mock_client_kp = Default::generate_random_keypair(&mut rng).unwrap();
    // serialization order: scalar, public key, envelope
    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(sc.as_bytes());
    bytes.extend_from_slice(&mock_client_kp.public().to_arr());
    bytes.extend_from_slice(&mock_rkr_bytes);
    let reg = ServerRegistration::<Default>::try_from(&bytes[..]).unwrap();
    let reg_bytes = reg.to_bytes();
    assert_eq!(reg_bytes, bytes);
}

#[test]
fn register_first_message_roundtrip() {
    let pt = random_ristretto_point();
    let pt_bytes = pt.to_bytes();
    let r1 = RegisterFirstMessage::<RistrettoPoint>::try_from(pt_bytes.as_slice()).unwrap();
    let r1_bytes = r1.to_bytes();
    assert_eq!(pt_bytes, r1_bytes);
}

#[test]
fn register_second_message_roundtrip() {
    let pt = random_ristretto_point();
    let pt_bytes = pt.to_bytes();

    let message = pt_bytes.to_vec();
    let r2 = RegisterSecondMessage::<RistrettoPoint>::try_from(&message[..]).unwrap();
    let r2_bytes = r2.to_bytes();
    assert_eq!(message, r2_bytes);
}

#[test]
fn register_third_message_roundtrip() {
    let mut rng = OsRng;
    let skp = Default::generate_random_keypair(&mut rng).unwrap();
    let pubkey_bytes = skp.public().to_arr();

    let mut encryption_key = [0u8; 32];
    rng.fill_bytes(&mut encryption_key);
    let mut hmac_key = [0u8; 32];
    rng.fill_bytes(&mut hmac_key);

    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);

    let ciphertext = RKRCiphertext::<ChaCha20Poly1305>::encrypt(
        &encryption_key,
        &hmac_key,
        &msg,
        &pubkey_bytes,
        &mut rng,
    )
    .unwrap();

    let message: Vec<u8> = [&ciphertext.to_bytes(), &pubkey_bytes[..]].concat();
    let r3 =
        RegisterThirdMessage::<ChaCha20Poly1305, X25519KeyPair>::try_from(&message[..]).unwrap();
    let r3_bytes = r3.to_bytes();
    assert_eq!(message, r3_bytes);
}

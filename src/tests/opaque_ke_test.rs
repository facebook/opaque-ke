// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    errors::*,
    group::Group,
    key_exchange::NONCE_LEN,
    keypair::{Key, KeyPair},
    opaque::*,
    tests::mock_rng::CycleRng,
};
use aes_gcm::Aes256Gcm;
use curve25519_dalek::edwards::EdwardsPoint;
use rand_core::{OsRng, RngCore};
use serde_json::Value;
use std::convert::TryFrom;

// Tests
// =====

struct AesgcmX255193dhNoSlowHash;
impl CipherSuite for AesgcmX255193dhNoSlowHash {
    type Aead = Aes256Gcm;
    type Group = EdwardsPoint;
    type KeyFormat = crate::keypair::X25519KeyPair;
    type SlowHash = crate::slow_hash::NoOpHash;
}

pub struct TestVectorParameters {
    pub client_s_pk: Vec<u8>,
    pub client_s_sk: Vec<u8>,
    pub client_e_pk: Vec<u8>,
    pub client_e_sk: Vec<u8>,
    pub server_s_pk: Vec<u8>,
    pub server_s_sk: Vec<u8>,
    pub server_e_pk: Vec<u8>,
    pub server_e_sk: Vec<u8>,
    pub password: Vec<u8>,
    pub blinding_factor_raw: Vec<u8>,
    pub blinding_factor: Vec<u8>,
    pub pepper: Vec<u8>,
    pub oprf_key: Vec<u8>,
    pub envelope_nonce: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub server_nonce: Vec<u8>,
    pub r1: Vec<u8>,
    pub r2: Vec<u8>,
    pub r3: Vec<u8>,
    pub l1: Vec<u8>,
    pub l2: Vec<u8>,
    pub l3: Vec<u8>,
    client_registration_state: Vec<u8>,
    server_registration_state: Vec<u8>,
    client_login_state: Vec<u8>,
    server_login_state: Vec<u8>,
    pub password_file: Vec<u8>,
    pub opaque_key: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

static TEST_VECTOR: &str = r#"
{
    "client_s_pk": "f7b150789db3322c8c7b8c4a10ce42baa5ee846de83eaf04c17ffbd0d9e5cd60",
    "client_s_sk": "601ed276a42ec5795b3471f1a64e312f192e17ff252ce6053c8ecaf210138273",
    "client_e_pk": "57260d4e231035f0f3e1fb836fe5d9ddb498c956cacb5fab1d6b287e1422376c",
    "client_e_sk": "e89d0fa4e387a9bd7c26466704ec30e62f58892bf3dfd1fd25133be52f34ea68",
    "server_s_pk": "a2b4e12d0621ebfb2631e00f5c872ab749e1a33915f16fb11203658b2189cc5e",
    "server_s_sk": "90b6ca2ea8a37306060c7cd0998d4cdae59e972af7760312f7cf77099e78f940",
    "server_e_pk": "64ce4a453eb8c27b1d81f6acdc01d36d3ae6cea506432e9509917b195ad90073",
    "server_e_sk": "883148cc1ba70acb1eb909d99e09493b5d4b3fe6b12c75e2f5aeea6c5d4b267f",
    "password": "70617373776f7264",
    "blinding_factor_raw": "b85e0df2ad0495771edf09a04b1073045e6472e2f86a41e9bab3143ebfb8eb08a3462503eb3750bf006dc82c93b37e07cdf3768018c22b431cf5146a9caeda1c",
    "blinding_factor": "fac0ed1c38bc8945a91dc4d944af22c466cbffc24fc3d97b8a91798d1ec8b60f",
    "pepper": "706570706572",
    "oprf_key": "d5cedff72509af4702a985bb31af8dbe88d72c4eee13a09e3f52a76766fa6f0b",
    "envelope_nonce": "c87e44792a9dfd8858db676e",
    "client_nonce": "1f023acc6155a06166ee7e5b7ef0360277ed5da3a46adcd4a0a5bce938a67a23",
    "server_nonce": "d448cb1f58c38605fc29069ac688ec9c667c99d0316b38cd1b2609c1bc14aa90",
    "r1": "e46efe7d673805b6135a5293ecab13082b322c45f029595efa4b8d1d53ccd897",
    "r2": "a2a3df89cf85976c4aa5add752736419f728805722571a9646983587ce4c55fb",
    "r3": "374c49768e4399d4cd46e8b3bc2050e2f6737e3a2f8aee6fddc82e117f340f79a7f10c84445657c6bb4940bd02bc08ca0f107618d810ec94639e8ae43af48ab66f1f75e8bbc169eed0035e347310978bc87e44792a9dfd8858db676ef7b150789db3322c8c7b8c4a10ce42baa5ee846de83eaf04c17ffbd0d9e5cd60",
    "l1": "e46efe7d673805b6135a5293ecab13082b322c45f029595efa4b8d1d53ccd8971f023acc6155a06166ee7e5b7ef0360277ed5da3a46adcd4a0a5bce938a67a2357260d4e231035f0f3e1fb836fe5d9ddb498c956cacb5fab1d6b287e1422376c",
    "l2": "a2a3df89cf85976c4aa5add752736419f728805722571a9646983587ce4c55fb374c49768e4399d4cd46e8b3bc2050e2f6737e3a2f8aee6fddc82e117f340f79a7f10c84445657c6bb4940bd02bc08ca0f107618d810ec94639e8ae43af48ab66f1f75e8bbc169eed0035e347310978bc87e44792a9dfd8858db676e883148cc1ba70acb1eb909d99e09493b5d4b3fe6b12c75e2f5aeea6c5d4b267f64ce4a453eb8c27b1d81f6acdc01d36d3ae6cea506432e9509917b195ad90073d81a1104fbd599ef56228bdbe9bf7be4a38ae907a8717ca0883b9d69b2efc529",
    "l3": "a01332643e8aa7113f6f160205a9b3bd0705f3b33d8e4ea8eab9eae6685a6adb",
    "client_registration_state": "fac0ed1c38bc8945a91dc4d944af22c466cbffc24fc3d97b8a91798d1ec8b60f70617373776f7264",
    "client_login_state": "fac0ed1c38bc8945a91dc4d944af22c466cbffc24fc3d97b8a91798d1ec8b60fe89d0fa4e387a9bd7c26466704ec30e62f58892bf3dfd1fd25133be52f34ea681f023acc6155a06166ee7e5b7ef0360277ed5da3a46adcd4a0a5bce938a67a23dd1a7c2b4e9f9be94bd36f3b6c7f23aa9f1e6b3fda9030412a918d1288b4af1970617373776f7264",
    "server_registration_state": "d5cedff72509af4702a985bb31af8dbe88d72c4eee13a09e3f52a76766fa6f0b",
    "server_login_state": "809f95143f8f7fc1d0b42f578a83f714f58cfd96d9499aacee730ad296b37b19c18c903396e85da607d02542d4d07456e5357ff2e2eade3aaa42e532d4e9364f66317ab0460307e33d6151e99c7406f2fa1d309f507b46e43f732924d1dc8d0d",
    "password_file": "d5cedff72509af4702a985bb31af8dbe88d72c4eee13a09e3f52a76766fa6f0bf7b150789db3322c8c7b8c4a10ce42baa5ee846de83eaf04c17ffbd0d9e5cd60374c49768e4399d4cd46e8b3bc2050e2f6737e3a2f8aee6fddc82e117f340f79a7f10c84445657c6bb4940bd02bc08ca0f107618d810ec94639e8ae43af48ab66f1f75e8bbc169eed0035e347310978bc87e44792a9dfd8858db676e",
    "opaque_key": "682f2868a3e1460fed5a16767bd8778c33b4aecac6607270f848aa61c95a1a68",
    "shared_secret": "66317ab0460307e33d6151e99c7406f2fa1d309f507b46e43f732924d1dc8d0d"
}
"#;

fn decode(values: &Value, key: &str) -> Option<Vec<u8>> {
    values[key]
        .as_str()
        .and_then(|s| hex::decode(&s.to_string()).ok())
}

fn populate_test_vectors(values: &Value) -> TestVectorParameters {
    TestVectorParameters {
        client_s_pk: decode(&values, "client_s_pk").unwrap(),
        client_s_sk: decode(&values, "client_s_sk").unwrap(),
        client_e_pk: decode(&values, "client_e_pk").unwrap(),
        client_e_sk: decode(&values, "client_e_sk").unwrap(),
        server_s_pk: decode(&values, "server_s_pk").unwrap(),
        server_s_sk: decode(&values, "server_s_sk").unwrap(),
        server_e_pk: decode(&values, "server_e_pk").unwrap(),
        server_e_sk: decode(&values, "server_e_sk").unwrap(),
        password: decode(&values, "password").unwrap(),
        blinding_factor_raw: decode(&values, "blinding_factor_raw").unwrap(),
        blinding_factor: decode(&values, "blinding_factor").unwrap(),
        pepper: decode(&values, "pepper").unwrap(),
        oprf_key: decode(&values, "oprf_key").unwrap(),
        envelope_nonce: decode(&values, "envelope_nonce").unwrap(),
        client_nonce: decode(&values, "client_nonce").unwrap(),
        server_nonce: decode(&values, "server_nonce").unwrap(),
        r1: decode(&values, "r1").unwrap(),
        r2: decode(&values, "r2").unwrap(),
        r3: decode(&values, "r3").unwrap(),
        l1: decode(&values, "l1").unwrap(),
        l2: decode(&values, "l2").unwrap(),
        l3: decode(&values, "l3").unwrap(),
        client_registration_state: decode(&values, "client_registration_state").unwrap(),
        client_login_state: decode(&values, "client_login_state").unwrap(),
        server_registration_state: decode(&values, "server_registration_state").unwrap(),
        server_login_state: decode(&values, "server_login_state").unwrap(),
        password_file: decode(&values, "password_file").unwrap(),
        opaque_key: decode(&values, "opaque_key").unwrap(),
        shared_secret: decode(&values, "shared_secret").unwrap(),
    }
}

fn stringify_test_vectors(p: &TestVectorParameters) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(format!("\"client_s_pk\": \"{}\",\n", hex::encode(&p.client_s_pk)).as_str());
    s.push_str(format!("\"client_s_sk\": \"{}\",\n", hex::encode(&p.client_s_sk)).as_str());
    s.push_str(format!("\"client_e_pk\": \"{}\",\n", hex::encode(&p.client_e_pk)).as_str());
    s.push_str(format!("\"client_e_sk\": \"{}\",\n", hex::encode(&p.client_e_sk)).as_str());
    s.push_str(format!("\"server_s_pk\": \"{}\",\n", hex::encode(&p.server_s_pk)).as_str());
    s.push_str(format!("\"server_s_sk\": \"{}\",\n", hex::encode(&p.server_s_sk)).as_str());
    s.push_str(format!("\"server_e_pk\": \"{}\",\n", hex::encode(&p.server_e_pk)).as_str());
    s.push_str(format!("\"server_e_sk\": \"{}\",\n", hex::encode(&p.server_e_sk)).as_str());
    s.push_str(format!("\"password\": \"{}\",\n", hex::encode(&p.password)).as_str());
    s.push_str(
        format!(
            "\"blinding_factor_raw\": \"{}\",\n",
            hex::encode(&p.blinding_factor_raw)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "\"blinding_factor\": \"{}\",\n",
            hex::encode(&p.blinding_factor)
        )
        .as_str(),
    );
    s.push_str(format!("\"pepper\": \"{}\",\n", hex::encode(&p.pepper)).as_str());
    s.push_str(format!("\"oprf_key\": \"{}\",\n", hex::encode(&p.oprf_key)).as_str());
    s.push_str(
        format!(
            "\"envelope_nonce\": \"{}\",\n",
            hex::encode(&p.envelope_nonce)
        )
        .as_str(),
    );
    s.push_str(format!("\"client_nonce\": \"{}\",\n", hex::encode(&p.client_nonce)).as_str());
    s.push_str(format!("\"server_nonce\": \"{}\",\n", hex::encode(&p.server_nonce)).as_str());
    s.push_str(format!("\"r1\": \"{}\",\n", hex::encode(&p.r1)).as_str());
    s.push_str(format!("\"r2\": \"{}\",\n", hex::encode(&p.r2)).as_str());
    s.push_str(format!("\"r3\": \"{}\",\n", hex::encode(&p.r3)).as_str());
    s.push_str(format!("\"l1\": \"{}\",\n", hex::encode(&p.l1)).as_str());
    s.push_str(format!("\"l2\": \"{}\",\n", hex::encode(&p.l2)).as_str());
    s.push_str(format!("\"l3\": \"{}\",\n", hex::encode(&p.l3)).as_str());
    s.push_str(
        format!(
            "\"client_registration_state\": \"{}\",\n",
            hex::encode(&p.client_registration_state)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "\"client_login_state\": \"{}\",\n",
            hex::encode(&p.client_login_state)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "\"server_registration_state\": \"{}\",\n",
            hex::encode(&p.server_registration_state)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "\"server_login_state\": \"{}\",\n",
            hex::encode(&p.server_login_state)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "\"password_file\": \"{}\",\n",
            hex::encode(&p.password_file)
        )
        .as_str(),
    );
    s.push_str(format!("\"opaque_key\": \"{}\",\n", hex::encode(&p.opaque_key)).as_str());
    s.push_str(format!("\"shared_secret\": \"{}\"\n", hex::encode(&p.shared_secret)).as_str());
    s.push_str("}\n");
    s
}

fn generate_parameters() -> TestVectorParameters {
    let mut rng = OsRng;

    // Inputs
    let server_s_kp = AesgcmX255193dhNoSlowHash::generate_random_keypair(&mut rng).unwrap();
    let server_e_kp = AesgcmX255193dhNoSlowHash::generate_random_keypair(&mut rng).unwrap();
    let client_s_kp = AesgcmX255193dhNoSlowHash::generate_random_keypair(&mut rng).unwrap();
    let client_e_kp = AesgcmX255193dhNoSlowHash::generate_random_keypair(&mut rng).unwrap();
    let password = b"password";
    let pepper = b"pepper";
    let mut blinding_factor_raw = [0u8; 64];
    rng.fill_bytes(&mut blinding_factor_raw);
    let mut oprf_key_raw = [0u8; 32];
    rng.fill_bytes(&mut oprf_key_raw);
    let mut envelope_nonce = [0u8; 12];
    rng.fill_bytes(&mut envelope_nonce);
    let mut client_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut client_nonce);
    let mut server_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut server_nonce);

    let mut blinding_factor_registration_rng = CycleRng::new(blinding_factor_raw.to_vec());
    let (r1, client_registration) = ClientRegistration::<AesgcmX255193dhNoSlowHash>::start(
        password,
        Some(pepper),
        &mut blinding_factor_registration_rng,
    )
    .unwrap();
    let r1_bytes = r1.to_bytes().to_vec();
    let blinding_factor_bytes = client_registration.blinding_factor.to_bytes();
    let client_registration_state = client_registration.to_bytes().to_vec();

    let mut oprf_key_rng = CycleRng::new(oprf_key_raw.to_vec());
    let (r2, server_registration) =
        ServerRegistration::<AesgcmX255193dhNoSlowHash>::start(r1, &mut oprf_key_rng).unwrap();
    let r2_bytes = r2.to_bytes().to_vec();
    let oprf_key = server_registration.oprf_key;
    let oprf_key_bytes = EdwardsPoint::scalar_as_bytes(&oprf_key);
    let server_registration_state = server_registration.to_bytes().to_vec();

    let mut client_s_sk_and_nonce: Vec<u8> = Vec::new();
    client_s_sk_and_nonce.extend_from_slice(&client_s_kp.private());
    client_s_sk_and_nonce.extend_from_slice(&envelope_nonce);

    let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
    let (r3, opaque_key_registration) = client_registration
        .finish(r2, server_s_kp.public(), &mut finish_registration_rng)
        .unwrap();
    let r3_bytes = r3.to_bytes().to_vec();

    let password_file = server_registration.finish(r3).unwrap();
    let password_file_bytes = password_file.to_bytes();

    let mut client_login_start: Vec<u8> = Vec::new();
    client_login_start.extend_from_slice(&blinding_factor_raw);
    client_login_start.extend_from_slice(&client_e_kp.private());
    client_login_start.extend_from_slice(&client_nonce);

    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let (l1, client_login) = ClientLogin::<AesgcmX255193dhNoSlowHash>::start(
        password,
        Some(pepper),
        &mut client_login_start_rng,
    )
    .unwrap();
    let l1_bytes = l1.to_bytes().to_vec();
    let client_login_state = client_login.to_bytes().to_vec();

    let mut server_e_sk_rng = CycleRng::new(server_e_kp.private().to_vec());
    let (l2, server_login) = ServerLogin::start(
        password_file,
        server_s_kp.private(),
        l1,
        &mut server_e_sk_rng,
    )
    .unwrap();
    let l2_bytes = l2.to_bytes().to_vec();
    let server_login_state = server_login.to_bytes().to_vec();

    let mut client_e_sk_rng = CycleRng::new(client_e_kp.private().to_vec());
    let (l3, client_shared_secret, _opaque_key_login) = client_login
        .finish(l2, server_s_kp.public(), &mut client_e_sk_rng)
        .unwrap();
    let l3_bytes = l3.to_bytes().to_vec();

    TestVectorParameters {
        client_s_pk: client_s_kp.public().to_vec(),
        client_s_sk: client_s_kp.private().to_vec(),
        client_e_pk: client_e_kp.public().to_vec(),
        client_e_sk: client_e_kp.private().to_vec(),
        server_s_pk: server_s_kp.public().to_vec(),
        server_s_sk: server_s_kp.private().to_vec(),
        server_e_pk: server_e_kp.public().to_vec(),
        server_e_sk: server_e_kp.private().to_vec(),
        password: password.to_vec(),
        blinding_factor_raw: blinding_factor_raw.to_vec(),
        blinding_factor: blinding_factor_bytes.to_vec(),
        pepper: pepper.to_vec(),
        oprf_key: oprf_key_bytes.to_vec(),
        envelope_nonce: envelope_nonce.to_vec(),
        client_nonce: client_nonce.to_vec(),
        server_nonce: server_nonce.to_vec(),
        r1: r1_bytes,
        r2: r2_bytes,
        r3: r3_bytes,
        l1: l1_bytes,
        l2: l2_bytes,
        l3: l3_bytes,
        password_file: password_file_bytes,
        client_registration_state,
        server_registration_state,
        client_login_state,
        server_login_state,
        shared_secret: client_shared_secret,
        opaque_key: opaque_key_registration.to_vec(),
    }
}

#[test]
fn generate_test_vectors() {
    let parameters = generate_parameters();
    println!("{}", stringify_test_vectors(&parameters));
}

#[test]
fn test_r1() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut blinding_factor_rng = CycleRng::new(parameters.blinding_factor_raw);
    let (r1, client_registration) = ClientRegistration::<AesgcmX255193dhNoSlowHash>::start(
        &parameters.password,
        Some(&parameters.pepper),
        &mut blinding_factor_rng,
    )
    .unwrap();
    assert_eq!(hex::encode(&parameters.r1), hex::encode(r1.to_bytes()));
    assert_eq!(
        hex::encode(&parameters.client_registration_state),
        hex::encode(client_registration.to_bytes())
    );
    Ok(())
}

#[test]
fn test_r2() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut oprf_key_rng = CycleRng::new(parameters.oprf_key);
    let (r2, server_registration) = ServerRegistration::<AesgcmX255193dhNoSlowHash>::start(
        RegisterFirstMessage::try_from(&parameters.r1[..]).unwrap(),
        &mut oprf_key_rng,
    )
    .unwrap();
    assert_eq!(hex::encode(parameters.r2), hex::encode(r2.to_bytes()));
    assert_eq!(
        hex::encode(&parameters.server_registration_state),
        hex::encode(server_registration.to_bytes())
    );
    Ok(())
}

#[test]
fn test_r3() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_s_sk_and_nonce: Vec<u8> =
        [parameters.client_s_sk, parameters.envelope_nonce].concat();
    let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
    let (r3, opaque_key_registration) = ClientRegistration::<AesgcmX255193dhNoSlowHash>::try_from(
        &parameters.client_registration_state[..],
    )
    .unwrap()
    .finish(
        RegisterSecondMessage::try_from(&parameters.r2[..]).unwrap(),
        &Key::try_from(&parameters.server_s_pk[..]).unwrap(),
        &mut finish_registration_rng,
    )
    .unwrap();

    assert_eq!(hex::encode(parameters.r3), hex::encode(r3.to_bytes()));
    assert_eq!(
        hex::encode(parameters.opaque_key),
        hex::encode(opaque_key_registration.to_vec())
    );

    Ok(())
}

#[test]
fn test_password_file() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let server_registration = ServerRegistration::<AesgcmX255193dhNoSlowHash>::try_from(
        &parameters.server_registration_state[..],
    )
    .unwrap();
    let password_file = server_registration
        .finish(RegisterThirdMessage::try_from(&parameters.r3[..]).unwrap())
        .unwrap();

    assert_eq!(
        hex::encode(parameters.password_file),
        hex::encode(password_file.to_bytes())
    );
    Ok(())
}

#[test]
fn test_l1() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_login_start = [
        parameters.blinding_factor_raw,
        parameters.client_e_sk,
        parameters.client_nonce,
    ]
    .concat();
    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let (l1, client_login) = ClientLogin::<AesgcmX255193dhNoSlowHash>::start(
        &parameters.password,
        Some(&parameters.pepper),
        &mut client_login_start_rng,
    )
    .unwrap();
    assert_eq!(hex::encode(&parameters.l1), hex::encode(l1.to_bytes()));
    assert_eq!(
        hex::encode(&parameters.client_login_state),
        hex::encode(client_login.to_bytes())
    );
    Ok(())
}

#[test]
fn test_l2() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let mut server_e_sk_rng = CycleRng::new(parameters.server_e_sk);
    let (l2, server_login) = ServerLogin::start::<AesgcmX255193dhNoSlowHash, _>(
        ServerRegistration::try_from(&parameters.password_file[..]).unwrap(),
        &Key::try_from(&parameters.server_s_sk[..]).unwrap(),
        LoginFirstMessage::<EdwardsPoint>::try_from(&parameters.l1[..]).unwrap(),
        &mut server_e_sk_rng,
    )
    .unwrap();

    assert_eq!(hex::encode(&parameters.l2), hex::encode(l2.to_bytes()));
    assert_eq!(
        hex::encode(&parameters.server_login_state),
        hex::encode(server_login.to_bytes())
    );
    Ok(())
}

#[test]
fn test_l3() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let mut client_e_sk_rng = CycleRng::new(parameters.client_e_sk.to_vec());
    let (l3, shared_secret, opaque_key_login) =
        ClientLogin::<AesgcmX255193dhNoSlowHash>::try_from(&parameters.client_login_state[..])
            .unwrap()
            .finish(
                LoginSecondMessage::<Aes256Gcm, EdwardsPoint>::try_from(&parameters.l2[..])
                    .unwrap(),
                &Key::try_from(&parameters.server_s_pk[..])?,
                &mut client_e_sk_rng,
            )
            .unwrap();

    assert_eq!(
        hex::encode(&parameters.shared_secret),
        hex::encode(&shared_secret)
    );
    assert_eq!(hex::encode(&parameters.l3), hex::encode(l3.to_bytes()));
    assert_eq!(
        hex::encode(&parameters.opaque_key),
        hex::encode(opaque_key_login)
    );

    Ok(())
}

#[test]
fn test_server_login_finish() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let shared_secret = ServerLogin::try_from(&parameters.server_login_state[..])
        .unwrap()
        .finish(LoginThirdMessage::try_from(&parameters.l3[..])?)
        .unwrap();

    assert_eq!(
        hex::encode(parameters.shared_secret),
        hex::encode(shared_secret)
    );

    Ok(())
}

fn test_complete_flow(
    registration_password: &[u8],
    login_password: &[u8],
) -> Result<(), ProtocolError> {
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_kp = AesgcmX255193dhNoSlowHash::generate_random_keypair(&mut server_rng)?;
    let (register_m1, client_state) = ClientRegistration::<AesgcmX255193dhNoSlowHash>::start(
        registration_password,
        None,
        &mut client_rng,
    )?;
    let (register_m2, server_state) =
        ServerRegistration::<AesgcmX255193dhNoSlowHash>::start(register_m1, &mut server_rng)?;
    let (register_m3, registration_opaque_key) =
        client_state.finish(register_m2, server_kp.public(), &mut client_rng)?;
    let p_file = server_state.finish(register_m3)?;
    let (login_m1, client_login_state) =
        ClientLogin::<AesgcmX255193dhNoSlowHash>::start(login_password, None, &mut client_rng)?;
    let (login_m2, server_login_state) =
        ServerLogin::start(p_file, &server_kp.private(), login_m1, &mut server_rng)?;

    let client_login_result =
        client_login_state.finish(login_m2, &server_kp.public(), &mut client_rng);

    if hex::encode(registration_password) == hex::encode(login_password) {
        let (login_m3, client_shared_secret, login_opaque_key) = client_login_result?;
        let server_shared_secret = server_login_state.finish(login_m3)?;

        assert_eq!(
            hex::encode(server_shared_secret),
            hex::encode(client_shared_secret)
        );
        assert_eq!(
            hex::encode(registration_opaque_key),
            hex::encode(login_opaque_key)
        );
    } else {
        let res = match client_login_result {
            Err(ProtocolError::VerificationError(PakeError::InvalidLoginError)) => true,
            _ => false,
        };
        assert!(res);
    }

    Ok(())
}

#[test]
fn test_complete_flow_success() -> Result<(), ProtocolError> {
    test_complete_flow(b"good password", b"good password")
}

#[test]
fn test_complete_flow_fail() -> Result<(), ProtocolError> {
    test_complete_flow(b"good password", b"bad password")
}

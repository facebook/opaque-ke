// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    errors::*,
    group::Group,
    key_exchange::tripledh::{TripleDH, NONCE_LEN},
    keypair::{Key, KeyPair, X25519KeyPair},
    opaque::*,
    slow_hash::NoOpHash,
    tests::mock_rng::CycleRng,
};
use curve25519_dalek::edwards::EdwardsPoint;
use rand_core::{OsRng, RngCore};
use serde_json::Value;
use std::convert::TryFrom;

// Tests
// =====

struct X255193dhNoSlowHash;
impl CipherSuite for X255193dhNoSlowHash {
    type Group = EdwardsPoint;
    type KeyFormat = X25519KeyPair;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha256;
    type SlowHash = NoOpHash;
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
    pub export_key: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

static TEST_VECTOR: &str = r#"
{
    "client_s_pk": "b2341df425f90244c72d8e19b249ca0d6d1a3a3dfe6ee1773e1b782a81efef29",
    "client_s_sk": "701e8cd1263abd2f2a22d4dc94b1d5fe3c9cb14030e7e7c154745825b059fd7f",
    "client_e_pk": "97cb1eb93a69542597517b110ccca457d5ce8d8bfcbfb2a9258bb7b4bd7f716e",
    "client_e_sk": "80616968ed8daae02c02d3ba41a70104ed0deecd2276e058994d601a1351b359",
    "server_s_pk": "e12d737e520eaf8504fbf302c2945011bff360bdf02ee102f2ebd6a883c80e02",
    "server_s_sk": "9075d3d3c5b6bc2f6218e7672c0532c619ce09dddf196006c5ffdaf628a3d760",
    "server_e_pk": "f73d27d7ca78ded52209bc3bae000f9d95b147360edac1e97c148a3a7396a279",
    "server_e_sk": "a0e59a07908fc793c590fd83343003a54330e24af908ed31c921e6e6504c3248",
    "password": "70617373776f7264",
    "blinding_factor_raw": "ca2d8ae51794579bd0f46044d7daccf222b4590053536b48575bc169f7478fd0a0b580fb0aae948c26ba403a2e7b98f563e434a0aad93f4105419c474453c34e",
    "blinding_factor": "5a9a073b1a1efedebdb404bc073ae74b316920d68ab628bed0c500cae95d6e02",
    "pepper": "706570706572",
    "oprf_key": "203fabe2af9c8dc668b81db1ece9c2412c94c276495f33202479886de1b12907",
    "envelope_nonce": "b0076712e01fecdb12301d5d7da92236e47f20494e68defb32084f1ab6c3d4f8",
    "client_nonce": "b9f09e9b0606fa88c4194011d5c204861b73c43cbf1ea0d08c03ec2fd6d05572",
    "server_nonce": "a213c02274e7f20fc3b571d25e98854c5dae2cfde6c9bf228a66bf3eff3e2a97",
    "r1": "01000024000000207e2c67a156ab27490f20008fcae9e9f722d8a9f4eeac373a711259981ca05dd5",
    "r2": "020000280020710fdd19883e869e784c84f2864fa0bfc227662404b77cc8a54d79ae7fb931ea000001010103",
    "r3": "03000088b0076712e01fecdb12301d5d7da92236e47f20494e68defb32084f1ab6c3d4f80020923b1d26cac4e3d91cec445b3322f4cc69a727f184353cb4dfe6d55a4c7d2bb400000020b77fbd41eacb8434f102c8c29cd4831e708046d38615df566675421ae8eb49330020b2341df425f90244c72d8e19b249ca0d6d1a3a3dfe6ee1773e1b782a81efef29",
    "l1": "04000024000000207e2c67a156ab27490f20008fcae9e9f722d8a9f4eeac373a711259981ca05dd5b9f09e9b0606fa88c4194011d5c204861b73c43cbf1ea0d08c03ec2fd6d0557297cb1eb93a69542597517b110ccca457d5ce8d8bfcbfb2a9258bb7b4bd7f716e",
    "l2": "050000860020710fdd19883e869e784c84f2864fa0bfc227662404b77cc8a54d79ae7fb931ea0060b0076712e01fecdb12301d5d7da92236e47f20494e68defb32084f1ab6c3d4f8923b1d26cac4e3d91cec445b3322f4cc69a727f184353cb4dfe6d55a4c7d2bb4b77fbd41eacb8434f102c8c29cd4831e708046d38615df566675421ae8eb49330000a0e59a07908fc793c590fd83343003a54330e24af908ed31c921e6e6504c3248f73d27d7ca78ded52209bc3bae000f9d95b147360edac1e97c148a3a7396a27939ccf2a17a5b281068665b4865e6c6331533461a8e10a4ceffc4c6a6609c326a",
    "l3": "127144e6469e001d56237a58c8c869a8173e042bf2ff19d8331441d36ada9c3f",
    "client_registration_state": "5a9a073b1a1efedebdb404bc073ae74b316920d68ab628bed0c500cae95d6e0270617373776f7264",
    "client_login_state": "5a9a073b1a1efedebdb404bc073ae74b316920d68ab628bed0c500cae95d6e0280616968ed8daae02c02d3ba41a70104ed0deecd2276e058994d601a1351b359b9f09e9b0606fa88c4194011d5c204861b73c43cbf1ea0d08c03ec2fd6d05572f258311568d792d6ebecee225c0fde4512139e29a435e9f9a0b82dc3809a83ab70617373776f7264",
    "server_registration_state": "203fabe2af9c8dc668b81db1ece9c2412c94c276495f33202479886de1b12907",
    "server_login_state": "ebc0953924d55ad66aa801a7c85f47f35889b90002451a04fb7134b8a2a5a33cd69098c0a81ce06f58cbe4fd6ba23c9c1404ad6f639ba64d5f0f7bf0a041fc5872b17f13bd41cbfbdfa8d74bc94ec1abcc77b9a3da8fbad918ca0a5f84a81443",
    "password_file": "203fabe2af9c8dc668b81db1ece9c2412c94c276495f33202479886de1b12907b2341df425f90244c72d8e19b249ca0d6d1a3a3dfe6ee1773e1b782a81efef29b0076712e01fecdb12301d5d7da92236e47f20494e68defb32084f1ab6c3d4f8923b1d26cac4e3d91cec445b3322f4cc69a727f184353cb4dfe6d55a4c7d2bb4b77fbd41eacb8434f102c8c29cd4831e708046d38615df566675421ae8eb4933",
    "export_key": "da3a52148a58168c9f804df5e216e3d3f16e935d4d70a5eb249433d88e02ae4c",
    "shared_secret": "72b17f13bd41cbfbdfa8d74bc94ec1abcc77b9a3da8fbad918ca0a5f84a81443"
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
        export_key: decode(&values, "export_key").unwrap(),
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
    s.push_str(format!("\"export_key\": \"{}\",\n", hex::encode(&p.export_key)).as_str());
    s.push_str(format!("\"shared_secret\": \"{}\"\n", hex::encode(&p.shared_secret)).as_str());
    s.push_str("}\n");
    s
}

fn generate_parameters<CS: CipherSuite>() -> TestVectorParameters {
    let mut rng = OsRng;

    // Inputs
    let server_s_kp = CS::generate_random_keypair(&mut rng).unwrap();
    let server_e_kp = CS::generate_random_keypair(&mut rng).unwrap();
    let client_s_kp = CS::generate_random_keypair(&mut rng).unwrap();
    let client_e_kp = CS::generate_random_keypair(&mut rng).unwrap();
    let password = b"password";
    let pepper = b"pepper";
    let mut blinding_factor_raw = [0u8; 64];
    rng.fill_bytes(&mut blinding_factor_raw);
    let mut oprf_key_raw = [0u8; 32];
    rng.fill_bytes(&mut oprf_key_raw);
    let mut envelope_nonce = [0u8; 32];
    rng.fill_bytes(&mut envelope_nonce);
    let mut client_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut client_nonce);
    let mut server_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut server_nonce);

    let mut blinding_factor_registration_rng = CycleRng::new(blinding_factor_raw.to_vec());
    let (r1, client_registration) = ClientRegistration::<CS>::start(
        password,
        Some(pepper),
        &mut blinding_factor_registration_rng,
    )
    .unwrap();
    let r1_bytes = r1.serialize().to_vec();
    let blinding_factor_bytes =
        CS::Group::scalar_as_bytes(&client_registration.blinding_factor).clone();
    let client_registration_state = client_registration.to_bytes().to_vec();

    let mut oprf_key_rng = CycleRng::new(oprf_key_raw.to_vec());
    let (r2, server_registration) = ServerRegistration::<CS>::start(r1, &mut oprf_key_rng).unwrap();
    let r2_bytes = r2.serialize().to_vec();
    let oprf_key_bytes = CS::Group::scalar_as_bytes(&server_registration.oprf_key).clone();
    let server_registration_state = server_registration.to_bytes().to_vec();

    let mut client_s_sk_and_nonce: Vec<u8> = Vec::new();
    client_s_sk_and_nonce.extend_from_slice(&client_s_kp.private());
    client_s_sk_and_nonce.extend_from_slice(&envelope_nonce);

    let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
    let (r3, export_key_registration) = client_registration
        .finish(r2, server_s_kp.public(), &mut finish_registration_rng)
        .unwrap();
    let r3_bytes = r3.serialize().to_vec();

    let password_file = server_registration.finish(r3).unwrap();
    let password_file_bytes = password_file.to_bytes();

    let mut client_login_start: Vec<u8> = Vec::new();
    client_login_start.extend_from_slice(&blinding_factor_raw);
    client_login_start.extend_from_slice(&client_e_kp.private());
    client_login_start.extend_from_slice(&client_nonce);

    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let (l1, client_login) =
        ClientLogin::<CS>::start(password, Some(pepper), &mut client_login_start_rng).unwrap();
    let l1_bytes = l1.serialize().to_vec();
    let client_login_state = client_login.to_bytes().to_vec();

    let mut server_e_sk_rng = CycleRng::new(server_e_kp.private().to_vec());
    let (l2, server_login) = ServerLogin::<CS>::start(
        password_file,
        server_s_kp.private(),
        l1,
        &mut server_e_sk_rng,
    )
    .unwrap();
    let l2_bytes = l2.serialize().to_vec();
    let server_login_state = server_login.to_bytes().to_vec();

    let mut client_e_sk_rng = CycleRng::new(client_e_kp.private().to_vec());
    let (l3, client_shared_secret, _export_key_login) = client_login
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
        export_key: export_key_registration.to_vec(),
    }
}

#[test]
fn generate_test_vectors() {
    let parameters = generate_parameters::<X255193dhNoSlowHash>();
    println!("{}", stringify_test_vectors(&parameters));
}

#[test]
fn test_r1() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut blinding_factor_rng = CycleRng::new(parameters.blinding_factor_raw);
    let (r1, client_registration) = ClientRegistration::<X255193dhNoSlowHash>::start(
        &parameters.password,
        Some(&parameters.pepper),
        &mut blinding_factor_rng,
    )
    .unwrap();
    assert_eq!(hex::encode(&parameters.r1), hex::encode(r1.serialize()));
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
    let (r2, server_registration) = ServerRegistration::<X255193dhNoSlowHash>::start(
        RegisterFirstMessage::deserialize(&parameters.r1[..]).unwrap(),
        &mut oprf_key_rng,
    )
    .unwrap();
    assert_eq!(hex::encode(parameters.r2), hex::encode(r2.serialize()));
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
    let (r3, export_key_registration) = ClientRegistration::<X255193dhNoSlowHash>::try_from(
        &parameters.client_registration_state[..],
    )
    .unwrap()
    .finish(
        RegisterSecondMessage::deserialize(&parameters.r2[..]).unwrap(),
        &Key::try_from(&parameters.server_s_pk[..]).unwrap(),
        &mut finish_registration_rng,
    )
    .unwrap();

    assert_eq!(hex::encode(parameters.r3), hex::encode(r3.serialize()));
    assert_eq!(
        hex::encode(parameters.export_key),
        hex::encode(export_key_registration.to_vec())
    );

    Ok(())
}

#[test]
fn test_password_file() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let server_registration = ServerRegistration::<X255193dhNoSlowHash>::try_from(
        &parameters.server_registration_state[..],
    )
    .unwrap();
    let password_file = server_registration
        .finish(RegisterThirdMessage::deserialize(&parameters.r3[..]).unwrap())
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
    let (l1, client_login) = ClientLogin::<X255193dhNoSlowHash>::start(
        &parameters.password,
        Some(&parameters.pepper),
        &mut client_login_start_rng,
    )
    .unwrap();
    assert_eq!(hex::encode(&parameters.l1), hex::encode(l1.serialize()));
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
    let (l2, server_login) = ServerLogin::<X255193dhNoSlowHash>::start(
        ServerRegistration::try_from(&parameters.password_file[..]).unwrap(),
        &Key::try_from(&parameters.server_s_sk[..]).unwrap(),
        LoginFirstMessage::<X255193dhNoSlowHash>::deserialize(&parameters.l1[..]).unwrap(),
        &mut server_e_sk_rng,
    )
    .unwrap();

    assert_eq!(hex::encode(&parameters.l2), hex::encode(l2.serialize()));
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
    let (l3, shared_secret, export_key_login) = ClientLogin::<X255193dhNoSlowHash>::try_from(
        &parameters.client_login_state[..],
    )
    .unwrap()
    .finish(
        LoginSecondMessage::<EdwardsPoint, X25519KeyPair, TripleDH, sha2::Sha256>::deserialize(
            &parameters.l2[..],
        )
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
        hex::encode(&parameters.export_key),
        hex::encode(export_key_login)
    );

    Ok(())
}

#[test]
fn test_server_login_finish() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let shared_secret =
        ServerLogin::<X255193dhNoSlowHash>::try_from(&parameters.server_login_state[..])
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
    let server_kp = X255193dhNoSlowHash::generate_random_keypair(&mut server_rng)?;
    let (register_m1, client_state) = ClientRegistration::<X255193dhNoSlowHash>::start(
        registration_password,
        None,
        &mut client_rng,
    )?;
    let (register_m2, server_state) =
        ServerRegistration::<X255193dhNoSlowHash>::start(register_m1, &mut server_rng)?;
    let (register_m3, registration_export_key) =
        client_state.finish(register_m2, server_kp.public(), &mut client_rng)?;
    let p_file = server_state.finish(register_m3)?;
    let (login_m1, client_login_state) =
        ClientLogin::<X255193dhNoSlowHash>::start(login_password, None, &mut client_rng)?;
    let (login_m2, server_login_state) = ServerLogin::<X255193dhNoSlowHash>::start(
        p_file,
        &server_kp.private(),
        login_m1,
        &mut server_rng,
    )?;

    let client_login_result =
        client_login_state.finish(login_m2, &server_kp.public(), &mut client_rng);

    if hex::encode(registration_password) == hex::encode(login_password) {
        let (login_m3, client_shared_secret, login_export_key) = client_login_result?;
        let server_shared_secret = server_login_state.finish(login_m3)?;

        assert_eq!(
            hex::encode(server_shared_secret),
            hex::encode(client_shared_secret)
        );
        assert_eq!(
            hex::encode(registration_export_key),
            hex::encode(login_export_key)
        );
    } else {
        let res = matches!(
            client_login_result,
            Err(ProtocolError::VerificationError(
                PakeError::InvalidLoginError
            ))
        );
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

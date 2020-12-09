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
    *,
};
use curve25519_dalek::edwards::EdwardsPoint;
use generic_array::GenericArray;
use generic_bytes::SizedBytes;
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
    pub id_u: Vec<u8>,
    pub id_s: Vec<u8>,
    pub password: Vec<u8>,
    pub blinding_factor: Vec<u8>,
    pub oprf_key: Vec<u8>,
    pub envelope_nonce: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub server_nonce: Vec<u8>,
    pub info1: Vec<u8>,
    pub info2: Vec<u8>,
    pub einfo2: Vec<u8>,
    pub info3: Vec<u8>,
    pub einfo3: Vec<u8>,
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
    "client_s_pk": "5320b55752ad2061c1804050f8a225a4ab1184bc17d8fa6b3c86470c33d9ce42",
    "client_s_sk": "e8719d2f7aca0ab85a991ac4221ff7fde7665b9bd17658777c5417ef5c59796a",
    "client_e_pk": "77fc3fefb8178ae08461756b54364c4f2d1363d5ce3187af128a3f84a6c5722a",
    "client_e_sk": "48b452f6d0b28387cfa98245bda9230b6df215ed5b820bffb8511ec6802d8075",
    "server_s_pk": "b8c5defc933aaf3640d13f217c392e06fe5fd41fae8571204fcbb804a566cd2e",
    "server_s_sk": "60f5ab9ff1a3ba9cf6242812be91635db16e8e1826bf06fb97893d7cf82a2656",
    "server_e_pk": "5a314dc389c12bf041b14e131fadebcc98e0fc33d3cd996ad9392c7ae6bff468",
    "server_e_sk": "606034b9be54759ea5802a2dd71e4413e98d52c46e60f2d0868642ad9e6a9b46",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "c0accb2010d728cfce827d4cb3769000c8b42ac341db8ba196fbe75809d91300",
    "oprf_key": "7f1d2a048a7aad9d1cf2b96473e3adbb1e0626eafe0abdfd09f1f700beda9d0f",
    "envelope_nonce": "abb706633ac7092e2aa63dedd4b456d7d99870f099c4f2c51ba75da0f20db8e8",
    "client_nonce": "1a92d39b2f9acdbef96dcc586b35ae056a085ede41b05f9f81801f69558d44c7",
    "server_nonce": "e04e9f1a4d35882c0ce435e3f467f601f26fe246e5f60ee9b600d9a63b91c0ad",
    "info1": "696e666f31",
    "info2": "696e666f32",
    "einfo2": "65696e666f32",
    "info3": "696e666f33",
    "einfo3": "65696e666f33",
    "r1": "0020c4ad91692b704470e0613850b9bfcc5b265d43f9ba03dd6ff028f0fb6b365957",
    "r2": "00205cbfd7b74c7fe6088f8117e7e63000675762920b75e0f4630ed67d4d960c7aa80020b8c5defc933aaf3640d13f217c392e06fe5fd41fae8571204fcbb804a566cd2e01010103",
    "r3": "abb706633ac7092e2aa63dedd4b456d7d99870f099c4f2c51ba75da0f20db8e80023e76da9b9fbf400fea214ecdab24966e4d3fea9d0c3d5d672597e1e702eb30547495ada0023030020b8c5defc933aaf3640d13f217c392e06fe5fd41fae8571204fcbb804a566cd2e00204e0e5754fbbd48efcdab43cee37f6455f357f3edc54316cb69da8f8e92f5ed8900205320b55752ad2061c1804050f8a225a4ab1184bc17d8fa6b3c86470c33d9ce42",
    "l1": "0020c4ad91692b704470e0613850b9bfcc5b265d43f9ba03dd6ff028f0fb6b3659571a92d39b2f9acdbef96dcc586b35ae056a085ede41b05f9f81801f69558d44c70005696e666f3177fc3fefb8178ae08461756b54364c4f2d1363d5ce3187af128a3f84a6c5722a",
    "l2": "00205cbfd7b74c7fe6088f8117e7e63000675762920b75e0f4630ed67d4d960c7aa8abb706633ac7092e2aa63dedd4b456d7d99870f099c4f2c51ba75da0f20db8e80023e76da9b9fbf400fea214ecdab24966e4d3fea9d0c3d5d672597e1e702eb30547495ada0023030020b8c5defc933aaf3640d13f217c392e06fe5fd41fae8571204fcbb804a566cd2e00204e0e5754fbbd48efcdab43cee37f6455f357f3edc54316cb69da8f8e92f5ed89606034b9be54759ea5802a2dd71e4413e98d52c46e60f2d0868642ad9e6a9b460005696e666f325a314dc389c12bf041b14e131fadebcc98e0fc33d3cd996ad9392c7ae6bff468000665696e666f32661aa1d3e579032df30a78312d38a4c3d8d8a0f1b9bb7bbdbff040e0881a248e",
    "l3": "0005696e666f33000665696e666f3317090781af5a220941ddd6db7d4f2af33d9b316a48aee163647131970bae50ba",
    "client_registration_state": "00036964550003696453c0accb2010d728cfce827d4cb3769000c8b42ac341db8ba196fbe75809d9130070617373776f7264",
    "client_login_state": "00036964550003696453c0accb2010d728cfce827d4cb3769000c8b42ac341db8ba196fbe75809d9130048b452f6d0b28387cfa98245bda9230b6df215ed5b820bffb8511ec6802d80751a92d39b2f9acdbef96dcc586b35ae056a085ede41b05f9f81801f69558d44c7288b735853d9e1d8ab699b7c4aef54680f036c56140dc0a4991f6d02a95babc970617373776f7264",
    "server_registration_state": "7f1d2a048a7aad9d1cf2b96473e3adbb1e0626eafe0abdfd09f1f700beda9d0f",
    "server_login_state": "2bfb97200c110fa3a9a020920829ce9e7e74a9e843ae86949e16300dc6e25b09e7e0522de623f021a7ba5d150ab8cba2eca4be458d3c22ae6109813a215a03d88f757f3390c767cd9433007c1abf9226c9e0da8e5d1a3d5722773c070b05f44b",
    "password_file": "7f1d2a048a7aad9d1cf2b96473e3adbb1e0626eafe0abdfd09f1f700beda9d0f5320b55752ad2061c1804050f8a225a4ab1184bc17d8fa6b3c86470c33d9ce42abb706633ac7092e2aa63dedd4b456d7d99870f099c4f2c51ba75da0f20db8e80023e76da9b9fbf400fea214ecdab24966e4d3fea9d0c3d5d672597e1e702eb30547495ada0023030020b8c5defc933aaf3640d13f217c392e06fe5fd41fae8571204fcbb804a566cd2e00204e0e5754fbbd48efcdab43cee37f6455f357f3edc54316cb69da8f8e92f5ed89",
    "export_key": "139998e9d44e2fa629689d8bef9f900a60278e2acd55f4e59906255b10494d58",
    "shared_secret": "8f757f3390c767cd9433007c1abf9226c9e0da8e5d1a3d5722773c070b05f44b"
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
        id_u: decode(&values, "id_u").unwrap(),
        id_s: decode(&values, "id_s").unwrap(),
        password: decode(&values, "password").unwrap(),
        blinding_factor: decode(&values, "blinding_factor").unwrap(),
        oprf_key: decode(&values, "oprf_key").unwrap(),
        envelope_nonce: decode(&values, "envelope_nonce").unwrap(),
        client_nonce: decode(&values, "client_nonce").unwrap(),
        server_nonce: decode(&values, "server_nonce").unwrap(),
        info1: decode(&values, "info1").unwrap(),
        info2: decode(&values, "info2").unwrap(),
        einfo2: decode(&values, "einfo2").unwrap(),
        info3: decode(&values, "info3").unwrap(),
        einfo3: decode(&values, "einfo3").unwrap(),
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
    s.push_str(format!("\"id_u\": \"{}\",\n", hex::encode(&p.id_u)).as_str());
    s.push_str(format!("\"id_s\": \"{}\",\n", hex::encode(&p.id_s)).as_str());
    s.push_str(format!("\"password\": \"{}\",\n", hex::encode(&p.password)).as_str());
    s.push_str(
        format!(
            "\"blinding_factor\": \"{}\",\n",
            hex::encode(&p.blinding_factor)
        )
        .as_str(),
    );
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
    s.push_str(format!("\"info1\": \"{}\",\n", hex::encode(&p.info1)).as_str());
    s.push_str(format!("\"info2\": \"{}\",\n", hex::encode(&p.info2)).as_str());
    s.push_str(format!("\"einfo2\": \"{}\",\n", hex::encode(&p.einfo2)).as_str());
    s.push_str(format!("\"info3\": \"{}\",\n", hex::encode(&p.info3)).as_str());
    s.push_str(format!("\"einfo3\": \"{}\",\n", hex::encode(&p.einfo3)).as_str());
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

fn generate_parameters<CS: CipherSuite>() -> TestVectorParameters
where
    // Unsightly constraints due to the (required) use of the SizedBytes
    // instance for KP in ServerRegistration::start. See also the impl
    // Tryfrom<&[u8]> for ServerRegistration (those are the same constraints).
    <<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len:
        std::ops::Add<<<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len>,
    generic_array::typenum::Sum<
        <<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len,
        <<CS::KeyFormat as KeyPair>::Repr as SizedBytes>::Len,
    >: generic_array::ArrayLength<u8>,
{
    let mut rng = OsRng;

    // Inputs
    let server_s_kp = CS::generate_random_keypair(&mut rng).unwrap();
    let server_e_kp = CS::generate_random_keypair(&mut rng).unwrap();
    let client_s_kp = CS::generate_random_keypair(&mut rng).unwrap();
    let client_e_kp = CS::generate_random_keypair(&mut rng).unwrap();
    let id_u = b"idU";
    let id_s = b"idS";
    let password = b"password";
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

    let info1 = b"info1";
    let info2 = b"info2";
    let einfo2 = b"einfo2";
    let info3 = b"info3";
    let einfo3 = b"einfo3";

    let mut blinding_factor_registration_rng = CycleRng::new(blinding_factor_raw.to_vec());
    let (r1, client_registration) = ClientRegistration::<CS>::start(
        password,
        ClientRegistrationStartParameters::WithIdentifiers(id_u.to_vec(), id_s.to_vec()),
        &mut blinding_factor_registration_rng,
        std::convert::identity,
    )
    .unwrap();
    let r1_bytes = r1.serialize().to_vec();
    let blinding_factor_bytes =
        CS::Group::scalar_as_bytes(&client_registration.token.blind).clone();
    let client_registration_state = client_registration.to_bytes().to_vec();

    let mut oprf_key_rng = CycleRng::new(oprf_key_raw.to_vec());
    let (r2, server_registration) =
        ServerRegistration::<CS>::start(r1, server_s_kp.public(), &mut oprf_key_rng).unwrap();
    let r2_bytes = r2.serialize().to_vec();
    let oprf_key_bytes = CS::Group::scalar_as_bytes(&server_registration.oprf_key).clone();
    let server_registration_state = server_registration.to_bytes().to_vec();

    let mut client_s_sk_and_nonce: Vec<u8> = Vec::new();
    client_s_sk_and_nonce.extend_from_slice(&client_s_kp.private().to_arr());
    client_s_sk_and_nonce.extend_from_slice(&envelope_nonce);

    let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
    let (r3, export_key_registration) = client_registration
        .finish(r2, &mut finish_registration_rng)
        .unwrap();
    let r3_bytes = r3.serialize().to_vec();

    let password_file = server_registration.finish(r3).unwrap();
    let password_file_bytes = password_file.to_bytes();

    let mut client_login_start: Vec<u8> = Vec::new();
    client_login_start.extend_from_slice(&blinding_factor_raw);
    client_login_start.extend_from_slice(&client_e_kp.private().to_arr());
    client_login_start.extend_from_slice(&client_nonce);

    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let client_login_start_result = ClientLogin::<CS>::start(
        password,
        &mut client_login_start_rng,
        ClientLoginStartParameters::WithInfoAndIdentifiers(
            info1.to_vec(),
            id_u.to_vec(),
            id_s.to_vec(),
        ),
        std::convert::identity,
    )
    .unwrap();
    let l1_bytes = client_login_start_result
        .credential_request
        .serialize()
        .to_vec();
    let client_login_state = client_login_start_result
        .client_login_state
        .to_bytes()
        .to_vec();

    let mut server_e_sk_rng = CycleRng::new(server_e_kp.private().to_arr().to_vec());
    let server_login_start_result = ServerLogin::<CS>::start(
        password_file,
        server_s_kp.private(),
        client_login_start_result.credential_request,
        &mut server_e_sk_rng,
        ServerLoginStartParameters::WithInfo(info2.to_vec(), einfo2.to_vec()),
    )
    .unwrap();
    let l2_bytes = server_login_start_result
        .credential_response
        .serialize()
        .to_vec();
    let server_login_state = server_login_start_result
        .server_login_state
        .to_bytes()
        .to_vec();

    let client_login_finish_result = client_login_start_result
        .client_login_state
        .finish(
            server_login_start_result.credential_response,
            ClientLoginFinishParameters::WithInfo(info3.to_vec(), einfo3.to_vec()),
        )
        .unwrap();
    let l3_bytes = client_login_finish_result.key_exchange.to_bytes().to_vec();

    TestVectorParameters {
        client_s_pk: client_s_kp.public().to_arr().to_vec(),
        client_s_sk: client_s_kp.private().to_arr().to_vec(),
        client_e_pk: client_e_kp.public().to_arr().to_vec(),
        client_e_sk: client_e_kp.private().to_arr().to_vec(),
        server_s_pk: server_s_kp.public().to_arr().to_vec(),
        server_s_sk: server_s_kp.private().to_arr().to_vec(),
        server_e_pk: server_e_kp.public().to_arr().to_vec(),
        server_e_sk: server_e_kp.private().to_arr().to_vec(),
        id_u: id_u.to_vec(),
        id_s: id_s.to_vec(),
        password: password.to_vec(),
        blinding_factor: blinding_factor_bytes.to_vec(),
        oprf_key: oprf_key_bytes.to_vec(),
        envelope_nonce: envelope_nonce.to_vec(),
        client_nonce: client_nonce.to_vec(),
        server_nonce: server_nonce.to_vec(),
        info1: info1.to_vec(),
        info2: info2.to_vec(),
        einfo2: einfo2.to_vec(),
        info3: info3.to_vec(),
        einfo3: einfo3.to_vec(),
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
        shared_secret: client_login_finish_result.session_secret,
        export_key: export_key_registration.to_vec(),
    }
}

#[test]
fn generate_test_vectors() {
    let parameters = generate_parameters::<X255193dhNoSlowHash>();
    println!("{}", stringify_test_vectors(&parameters));
}

// For fixing the blinding factor
fn postprocess_blinding_factor<G: Group>(_: G::Scalar) -> G::Scalar {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    G::from_scalar_slice(GenericArray::from_slice(&parameters.blinding_factor[..])).unwrap()
}

#[test]
fn test_r1() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut rng = OsRng;
    let (r1, client_registration) = ClientRegistration::<X255193dhNoSlowHash>::start(
        &parameters.password,
        ClientRegistrationStartParameters::WithIdentifiers(parameters.id_u, parameters.id_s),
        &mut rng,
        postprocess_blinding_factor::<<X255193dhNoSlowHash as CipherSuite>::Group>,
    )?;
    assert_eq!(hex::encode(&parameters.r1), hex::encode(r1.serialize()));
    assert_eq!(
        hex::encode(&parameters.client_registration_state),
        hex::encode(client_registration.to_bytes())
    );
    Ok(())
}

#[test]
fn test_r2() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut oprf_key_rng = CycleRng::new(parameters.oprf_key);
    let (r2, server_registration) = ServerRegistration::<X255193dhNoSlowHash>::start(
        RegisterFirstMessage::deserialize(&parameters.r1[..]).unwrap(),
        &Key::try_from(&parameters.server_s_pk[..]).unwrap(),
        &mut oprf_key_rng,
    )?;
    assert_eq!(hex::encode(parameters.r2), hex::encode(r2.serialize()));
    assert_eq!(
        hex::encode(&parameters.server_registration_state),
        hex::encode(server_registration.to_bytes())
    );
    Ok(())
}

#[test]
fn test_r3() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_s_sk_and_nonce: Vec<u8> =
        [parameters.client_s_sk, parameters.envelope_nonce].concat();
    let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
    let (r3, export_key_registration) = ClientRegistration::<X255193dhNoSlowHash>::try_from(
        &parameters.client_registration_state[..],
    )?
    .finish(
        RegisterSecondMessage::deserialize(&parameters.r2[..]).unwrap(),
        &mut finish_registration_rng,
    )?;
    assert_eq!(hex::encode(parameters.r3), hex::encode(r3.serialize()));
    assert_eq!(
        hex::encode(parameters.export_key),
        hex::encode(export_key_registration.to_vec())
    );

    Ok(())
}

#[test]
fn test_password_file() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let server_registration = ServerRegistration::<X255193dhNoSlowHash>::try_from(
        &parameters.server_registration_state[..],
    )?;
    let password_file = server_registration
        .finish(RegisterThirdMessage::deserialize(&parameters.r3[..]).unwrap())?;
    assert_eq!(
        hex::encode(parameters.password_file),
        hex::encode(password_file.to_bytes())
    );
    Ok(())
}

#[test]
fn test_l1() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_login_start = [
        vec![0u8; 64], // FIXME: don't hardcode this
        parameters.client_e_sk,
        parameters.client_nonce,
    ]
    .concat();
    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let client_login_start_result = ClientLogin::<X255193dhNoSlowHash>::start(
        &parameters.password,
        &mut client_login_start_rng,
        ClientLoginStartParameters::WithInfoAndIdentifiers(
            parameters.info1,
            parameters.id_u,
            parameters.id_s,
        ),
        postprocess_blinding_factor::<<X255193dhNoSlowHash as CipherSuite>::Group>,
    )?;
    assert_eq!(
        hex::encode(&parameters.l1),
        hex::encode(client_login_start_result.credential_request.serialize())
    );
    assert_eq!(
        hex::encode(&parameters.client_login_state),
        hex::encode(client_login_start_result.client_login_state.to_bytes())
    );
    Ok(())
}

#[test]
fn test_l2() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let mut server_e_sk_rng = CycleRng::new(parameters.server_e_sk);
    let server_login_start_result = ServerLogin::<X255193dhNoSlowHash>::start(
        ServerRegistration::try_from(&parameters.password_file[..]).unwrap(),
        &Key::try_from(&parameters.server_s_sk[..]).unwrap(),
        LoginFirstMessage::<X255193dhNoSlowHash>::deserialize(&parameters.l1[..]).unwrap(),
        &mut server_e_sk_rng,
        ServerLoginStartParameters::WithInfo(parameters.info2.to_vec(), parameters.einfo2.to_vec()),
    )?;
    assert_eq!(
        hex::encode(&parameters.info1),
        hex::encode(server_login_start_result.plain_info),
    );
    assert_eq!(
        hex::encode(&parameters.client_s_pk),
        hex::encode(server_login_start_result.client_s_pk),
    );
    assert_eq!(
        hex::encode(&parameters.l2),
        hex::encode(server_login_start_result.credential_response.serialize())
    );
    assert_eq!(
        hex::encode(&parameters.server_login_state),
        hex::encode(server_login_start_result.server_login_state.to_bytes())
    );
    Ok(())
}

#[test]
fn test_l3() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_login_finish_result =
        ClientLogin::<X255193dhNoSlowHash>::try_from(&parameters.client_login_state[..])?.finish(
            LoginSecondMessage::<X255193dhNoSlowHash>::deserialize(&parameters.l2[..]).unwrap(),
            ClientLoginFinishParameters::WithInfo(
                parameters.info3.to_vec(),
                parameters.einfo3.to_vec(),
            ),
        )?;
    assert_eq!(
        hex::encode(&parameters.info2),
        hex::encode(&client_login_finish_result.plain_info)
    );
    assert_eq!(
        hex::encode(&parameters.einfo2),
        hex::encode(&client_login_finish_result.confidential_info)
    );
    assert_eq!(
        hex::encode(&parameters.server_s_pk),
        hex::encode(&client_login_finish_result.server_s_pk)
    );
    assert_eq!(None, client_login_finish_result.id_s);
    assert_eq!(
        hex::encode(&parameters.shared_secret),
        hex::encode(&client_login_finish_result.session_secret)
    );
    assert_eq!(
        hex::encode(&parameters.l3),
        hex::encode(client_login_finish_result.key_exchange.to_bytes())
    );
    assert_eq!(
        hex::encode(&parameters.export_key),
        hex::encode(client_login_finish_result.export_key)
    );

    Ok(())
}

#[test]
fn test_server_login_finish() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let server_login_result =
        ServerLogin::<X255193dhNoSlowHash>::try_from(&parameters.server_login_state[..])?
            .finish(LoginThirdMessage::try_from(&parameters.l3[..])?)?;
    assert_eq!(
        hex::encode(parameters.info3),
        hex::encode(server_login_result.plain_info)
    );
    assert_eq!(
        hex::encode(parameters.einfo3),
        hex::encode(server_login_result.confidential_info)
    );
    assert_eq!(
        hex::encode(parameters.shared_secret),
        hex::encode(server_login_result.session_secret)
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
        ClientRegistrationStartParameters::default(),
        &mut client_rng,
        std::convert::identity,
    )?;
    let (register_m2, server_state) = ServerRegistration::<X255193dhNoSlowHash>::start(
        register_m1,
        server_kp.public(),
        &mut server_rng,
    )?;
    let (register_m3, registration_export_key) =
        client_state.finish(register_m2, &mut client_rng)?;
    let p_file = server_state.finish(register_m3)?;
    let client_login_start_result = ClientLogin::<X255193dhNoSlowHash>::start(
        login_password,
        &mut client_rng,
        ClientLoginStartParameters::default(),
        std::convert::identity,
    )?;
    let server_login_start_result = ServerLogin::<X255193dhNoSlowHash>::start(
        p_file,
        &server_kp.private(),
        client_login_start_result.credential_request,
        &mut server_rng,
        ServerLoginStartParameters::default(),
    )?;

    let client_login_result = client_login_start_result.client_login_state.finish(
        server_login_start_result.credential_response,
        ClientLoginFinishParameters::default(),
    );

    if hex::encode(registration_password) == hex::encode(login_password) {
        let client_login_finish_result = client_login_result?;
        let server_login_finish_result = server_login_start_result
            .server_login_state
            .finish(client_login_finish_result.key_exchange)?;

        assert_eq!(
            hex::encode(server_login_finish_result.session_secret),
            hex::encode(client_login_finish_result.session_secret)
        );
        assert_eq!(
            hex::encode(registration_export_key),
            hex::encode(client_login_finish_result.export_key)
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

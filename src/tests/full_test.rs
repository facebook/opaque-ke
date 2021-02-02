// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    errors::*,
    group::Group,
    key_exchange::tripledh::{NonceLen, TripleDH},
    keypair::Key,
    opaque::*,
    slow_hash::NoOpHash,
    tests::mock_rng::CycleRng,
    *,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use generic_array::typenum::Unsigned;
use generic_bytes::SizedBytes;
use rand_core::{OsRng, RngCore};
use serde_json::Value;
use std::convert::TryFrom;

// Tests
// =====

struct RistrettoSha5123dhNoSlowHash;
impl CipherSuite for RistrettoSha5123dhNoSlowHash {
    type Group = RistrettoPoint;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha512;
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
    pub einfo2: Vec<u8>,
    pub registration_request: Vec<u8>,
    pub registration_response: Vec<u8>,
    pub registration_upload: Vec<u8>,
    pub credential_request: Vec<u8>,
    pub credential_response: Vec<u8>,
    pub credential_finalization: Vec<u8>,
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
    "client_s_pk": "ba8c7e239ed64ea1e6068b52cbd5a34ba6f55d635d20a4593884dc271865ea63",
    "client_s_sk": "edb5e886441ddcd4fdd80593d9ea7b7f82f284fcc1d565b802e99997457b960a",
    "client_e_pk": "08973113b27d6f2291aaaeb92f34a8438d279a48b1b412bddbf2785be660e479",
    "client_e_sk": "28fb3aadbc2716844d8de562d35e61914da734dcea0fa6ebd79603ef9eff4e01",
    "server_s_pk": "b67d948b98eecfb516a626fab94170e490ccd90da05fce94a016c4d5d6b7136a",
    "server_s_sk": "52350a684c353e39bbaadeb042b2de94226a493f6ae172b7fc45408bbfda6401",
    "server_e_pk": "42103d44b03f3886fe3e419b1b96521fa5a706bb1a4e003907daa381960d664a",
    "server_e_sk": "564e113d5b2784fcf3a55d5ca48512a2fd5c3c393753f6cfd157cb712b317c04",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "a70b37951d84ed312a0a8e025b71eafdd362b4e7db872881762d506a271b6e07",
    "oprf_key": "1eaf3cdd64da67e17e3364182f00ed0c323bfb44b20a1b7e0025a0334ab6d40d",
    "envelope_nonce": "5dba53e994e82b6d76353341102791cdfb1c2b460e1f913c5741a9c8cf2017c9",
    "client_nonce": "488244dbf75f86ebaa30307773d3e0eabccb91be349abef8a69c458dbf236e4c",
    "server_nonce": "13cc5ceb7687d80293005e7f9452ce104d1bac6598dd2265f184cacd558d6b31",
    "info1": "696e666f31",
    "einfo2": "65696e666f32",
    "registration_request": "ecf819ef83351e4c75e016ef845b62a12c14f397328960574935a42e04e0fa42",
    "registration_response": "2e9bf80e5c101ee2d391ff2aec06af97af17f443fc93a5cc98189681cb943d700020b67d948b98eecfb516a626fab94170e490ccd90da05fce94a016c4d5d6b7136a",
    "registration_upload": "0020ba8c7e239ed64ea1e6068b52cbd5a34ba6f55d635d20a4593884dc271865ea63015dba53e994e82b6d76353341102791cdfb1c2b460e1f913c5741a9c8cf2017c90022f11b89b207eb0735f2bdb2a9968bc9d7c1c962fd0274b4fc1fff2466c769d3710586a3a21ac8ecf13aafe2dc5460eb2f52d8f760396a17beeaf1ef3d1e4e50dd906555832fc51fc474554cb9ff063f6685f9043efc08fd6816666833d68d3b0eb6d9",
    "credential_request": "ecf819ef83351e4c75e016ef845b62a12c14f397328960574935a42e04e0fa42488244dbf75f86ebaa30307773d3e0eabccb91be349abef8a69c458dbf236e4c0005696e666f3108973113b27d6f2291aaaeb92f34a8438d279a48b1b412bddbf2785be660e479",
    "credential_response": "2e9bf80e5c101ee2d391ff2aec06af97af17f443fc93a5cc98189681cb943d700020b67d948b98eecfb516a626fab94170e490ccd90da05fce94a016c4d5d6b7136a015dba53e994e82b6d76353341102791cdfb1c2b460e1f913c5741a9c8cf2017c90022f11b89b207eb0735f2bdb2a9968bc9d7c1c962fd0274b4fc1fff2466c769d3710586a3a21ac8ecf13aafe2dc5460eb2f52d8f760396a17beeaf1ef3d1e4e50dd906555832fc51fc474554cb9ff063f6685f9043efc08fd6816666833d68d3b0eb6d913cc5ceb7687d80293005e7f9452ce104d1bac6598dd2265f184cacd558d6b3142103d44b03f3886fe3e419b1b96521fa5a706bb1a4e003907daa381960d664a0006a0f4de671e13c37b24e29138ff9d3df3d55c3b822fedee8dcefd643a1deab7cda5aa1c20f31a0c2a1823c8de3e793f50b257833788b75609fb6c5c4a9cad225f3a981c4ff7b2",
    "credential_finalization": "0640114ec21fbad6da11c61dfa77a48026646a2a1bd091ef5c9dc46b45f9e53c72f5d714e026d808b6de8911947eef437e9f6a6e969e1ea13f2f4880adc7c879",
    "client_registration_state": "a70b37951d84ed312a0a8e025b71eafdd362b4e7db872881762d506a271b6e0770617373776f7264",
    "client_login_state": "a70b37951d84ed312a0a8e025b71eafdd362b4e7db872881762d506a271b6e070067ecf819ef83351e4c75e016ef845b62a12c14f397328960574935a42e04e0fa42488244dbf75f86ebaa30307773d3e0eabccb91be349abef8a69c458dbf236e4c0005696e666f3108973113b27d6f2291aaaeb92f34a8438d279a48b1b412bddbf2785be660e479004028fb3aadbc2716844d8de562d35e61914da734dcea0fa6ebd79603ef9eff4e01488244dbf75f86ebaa30307773d3e0eabccb91be349abef8a69c458dbf236e4c70617373776f7264",
    "server_registration_state": "1eaf3cdd64da67e17e3364182f00ed0c323bfb44b20a1b7e0025a0334ab6d40d",
    "server_login_state": "4952acf61167e6d0e799572827724fdf8c80bda8c62ac28deb68d125661dade2cc1136e634d5fb93f1de4d170ae3e2f5885e333ac3b72d630ab56618c2247fa4d5968eefd69cd270ed14fbcb39627fea9a93cd18175e1b5cfceb06f705bbcb5ecddcd0602aacd7cb358f3273b1099895210bf8baa37d2fab5ed8c092fe9e5739bc6c50cf08ca7d4f4107d48057507480e0c9534b4f04d77cd5156cbd112565d8a2d5beaa473003dcf8dd82d4046648a701c72afeed0f627fcb782627dfaed3ca",
    "password_file": "1eaf3cdd64da67e17e3364182f00ed0c323bfb44b20a1b7e0025a0334ab6d40dba8c7e239ed64ea1e6068b52cbd5a34ba6f55d635d20a4593884dc271865ea63015dba53e994e82b6d76353341102791cdfb1c2b460e1f913c5741a9c8cf2017c90022f11b89b207eb0735f2bdb2a9968bc9d7c1c962fd0274b4fc1fff2466c769d3710586a3a21ac8ecf13aafe2dc5460eb2f52d8f760396a17beeaf1ef3d1e4e50dd906555832fc51fc474554cb9ff063f6685f9043efc08fd6816666833d68d3b0eb6d9",
    "export_key": "2b86667de895e4d2c15b93bc70f0aa2df67b83987fa53deac9473697e2fade045e0fd0e4af478ccff52165c1467272993da34dcb3baa45aa59cf9d817e6c6bcb",
    "shared_secret": "bc6c50cf08ca7d4f4107d48057507480e0c9534b4f04d77cd5156cbd112565d8a2d5beaa473003dcf8dd82d4046648a701c72afeed0f627fcb782627dfaed3ca"
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
        einfo2: decode(&values, "einfo2").unwrap(),
        registration_request: decode(&values, "registration_request").unwrap(),
        registration_response: decode(&values, "registration_response").unwrap(),
        registration_upload: decode(&values, "registration_upload").unwrap(),
        credential_request: decode(&values, "credential_request").unwrap(),
        credential_response: decode(&values, "credential_response").unwrap(),
        credential_finalization: decode(&values, "credential_finalization").unwrap(),
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
    s.push_str(format!("\"einfo2\": \"{}\",\n", hex::encode(&p.einfo2)).as_str());
    s.push_str(
        format!(
            "\"registration_request\": \"{}\",\n",
            hex::encode(&p.registration_request)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "\"registration_response\": \"{}\",\n",
            hex::encode(&p.registration_response)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "\"registration_upload\": \"{}\",\n",
            hex::encode(&p.registration_upload)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "\"credential_request\": \"{}\",\n",
            hex::encode(&p.credential_request)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "\"credential_response\": \"{}\",\n",
            hex::encode(&p.credential_response)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "\"credential_finalization\": \"{}\",\n",
            hex::encode(&p.credential_finalization)
        )
        .as_str(),
    );
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
    let server_s_kp = CS::generate_random_keypair(&mut rng);
    let server_e_kp = CS::generate_random_keypair(&mut rng);
    let client_s_kp = CS::generate_random_keypair(&mut rng);
    let client_e_kp = CS::generate_random_keypair(&mut rng);
    let id_u = b"idU";
    let id_s = b"idS";
    let password = b"password";
    let mut oprf_key_raw = [0u8; 32];
    rng.fill_bytes(&mut oprf_key_raw);
    let mut envelope_nonce = [0u8; 32];
    rng.fill_bytes(&mut envelope_nonce);
    let mut client_nonce = vec![0u8; NonceLen::to_usize()];
    rng.fill_bytes(&mut client_nonce);
    let mut server_nonce = vec![0u8; NonceLen::to_usize()];
    rng.fill_bytes(&mut server_nonce);

    let blinding_factor = CS::Group::random_scalar(&mut rng);
    let blinding_factor_bytes = CS::Group::scalar_as_bytes(&blinding_factor).clone();

    let info1 = b"info1";
    let einfo2 = b"einfo2";

    let mut blinding_factor_registration_rng = CycleRng::new(blinding_factor_bytes.to_vec());
    let client_registration_start_result =
        ClientRegistration::<CS>::start(&mut blinding_factor_registration_rng, password).unwrap();
    let blinding_factor_bytes_returned =
        CS::Group::scalar_as_bytes(&client_registration_start_result.state.token.blind).clone();
    assert_eq!(
        hex::encode(&blinding_factor_bytes),
        hex::encode(&blinding_factor_bytes_returned)
    );

    let registration_request_bytes = client_registration_start_result
        .message
        .serialize()
        .to_vec();
    let client_registration_state = client_registration_start_result.state.to_bytes().to_vec();

    let mut oprf_key_rng = CycleRng::new(oprf_key_raw.to_vec());
    let server_registration_start_result = ServerRegistration::<CS>::start(
        &mut oprf_key_rng,
        client_registration_start_result.message,
        server_s_kp.public(),
    )
    .unwrap();
    let registration_response_bytes = server_registration_start_result
        .message
        .serialize()
        .to_vec();
    let oprf_key_bytes =
        CS::Group::scalar_as_bytes(&server_registration_start_result.state.oprf_key).clone();
    let server_registration_state = server_registration_start_result.state.to_bytes().to_vec();

    let mut client_s_sk_and_nonce: Vec<u8> = Vec::new();
    client_s_sk_and_nonce.extend_from_slice(&client_s_kp.private().to_arr());
    client_s_sk_and_nonce.extend_from_slice(&envelope_nonce);

    let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
    let client_registration_finish_result = client_registration_start_result
        .state
        .finish(
            &mut finish_registration_rng,
            server_registration_start_result.message,
            ClientRegistrationFinishParameters::WithIdentifiers(id_u.to_vec(), id_s.to_vec()),
        )
        .unwrap();
    let registration_upload_bytes = client_registration_finish_result
        .message
        .serialize()
        .to_vec();

    let password_file = server_registration_start_result
        .state
        .finish(client_registration_finish_result.message)
        .unwrap();
    let password_file_bytes = password_file.to_bytes();

    let mut client_login_start: Vec<u8> = Vec::new();
    client_login_start.extend_from_slice(&blinding_factor_bytes);
    client_login_start.extend_from_slice(&client_e_kp.private().to_arr());
    client_login_start.extend_from_slice(&client_nonce);

    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let client_login_start_result = ClientLogin::<CS>::start(
        &mut client_login_start_rng,
        password,
        ClientLoginStartParameters::WithInfo(info1.to_vec()),
    )
    .unwrap();
    let credential_request_bytes = client_login_start_result.message.serialize().to_vec();
    let client_login_state = client_login_start_result.state.to_bytes().to_vec();

    let mut server_e_sk_and_nonce_rng = CycleRng::new(
        [
            server_e_kp.private().to_arr().to_vec(),
            server_nonce.to_vec(),
        ]
        .concat(),
    );
    let server_login_start_result = ServerLogin::<CS>::start(
        &mut server_e_sk_and_nonce_rng,
        password_file,
        server_s_kp.private(),
        client_login_start_result.message,
        ServerLoginStartParameters::WithInfoAndIdentifiers(
            einfo2.to_vec(),
            id_u.to_vec(),
            id_s.to_vec(),
        ),
    )
    .unwrap();
    let credential_response_bytes = server_login_start_result.message.serialize().to_vec();
    let server_login_state = server_login_start_result.state.to_bytes().to_vec();

    let client_login_finish_result = client_login_start_result
        .state
        .finish(
            server_login_start_result.message,
            ClientLoginFinishParameters::WithIdentifiers(id_u.to_vec(), id_s.to_vec()),
        )
        .unwrap();
    let credential_finalization_bytes = client_login_finish_result.message.to_bytes().to_vec();

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
        einfo2: einfo2.to_vec(),
        registration_request: registration_request_bytes,
        registration_response: registration_response_bytes,
        registration_upload: registration_upload_bytes,
        credential_request: credential_request_bytes,
        credential_response: credential_response_bytes,
        credential_finalization: credential_finalization_bytes,
        password_file: password_file_bytes,
        client_registration_state,
        server_registration_state,
        client_login_state,
        server_login_state,
        shared_secret: client_login_finish_result.shared_secret,
        export_key: client_registration_finish_result.export_key.to_vec(),
    }
}

#[test]
fn generate_test_vectors() {
    let parameters = generate_parameters::<RistrettoSha5123dhNoSlowHash>();
    println!("{}", stringify_test_vectors(&parameters));
}

#[test]
fn test_registration_request() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut rng = CycleRng::new(parameters.blinding_factor.to_vec());
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(&mut rng, &parameters.password)?;
    assert_eq!(
        hex::encode(&parameters.registration_request),
        hex::encode(client_registration_start_result.message.serialize())
    );
    assert_eq!(
        hex::encode(&parameters.client_registration_state),
        hex::encode(client_registration_start_result.state.to_bytes())
    );
    Ok(())
}

#[test]
fn test_registration_response() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut oprf_key_rng = CycleRng::new(parameters.oprf_key);
    let server_registration_start_result =
        ServerRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut oprf_key_rng,
            RegistrationRequest::deserialize(&parameters.registration_request[..])?,
            &Key::try_from(&parameters.server_s_pk[..])?,
        )?;
    assert_eq!(
        hex::encode(parameters.registration_response),
        hex::encode(server_registration_start_result.message.serialize())
    );
    assert_eq!(
        hex::encode(&parameters.server_registration_state),
        hex::encode(server_registration_start_result.state.to_bytes())
    );
    Ok(())
}

#[test]
fn test_registration_upload() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_s_sk_and_nonce: Vec<u8> =
        [parameters.client_s_sk, parameters.envelope_nonce].concat();
    let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
    let result = ClientRegistration::<RistrettoSha5123dhNoSlowHash>::try_from(
        &parameters.client_registration_state[..],
    )?
    .finish(
        &mut finish_registration_rng,
        RegistrationResponse::deserialize(&parameters.registration_response[..])?,
        ClientRegistrationFinishParameters::WithIdentifiers(parameters.id_u, parameters.id_s),
    )?;

    assert_eq!(
        hex::encode(parameters.registration_upload),
        hex::encode(result.message.serialize())
    );
    assert_eq!(
        hex::encode(parameters.export_key),
        hex::encode(result.export_key.to_vec())
    );

    Ok(())
}

#[test]
fn test_password_file() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let server_registration = ServerRegistration::<RistrettoSha5123dhNoSlowHash>::try_from(
        &parameters.server_registration_state[..],
    )?;
    let password_file = server_registration.finish(RegistrationUpload::deserialize(
        &parameters.registration_upload[..],
    )?)?;

    assert_eq!(
        hex::encode(parameters.password_file),
        hex::encode(password_file.to_bytes())
    );
    Ok(())
}

#[test]
fn test_credential_request() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_login_start_rng = [
        parameters.blinding_factor,
        parameters.client_e_sk,
        parameters.client_nonce,
    ]
    .concat();
    let mut client_login_start_rng = CycleRng::new(client_login_start_rng);
    let client_login_start_result = ClientLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut client_login_start_rng,
        &parameters.password,
        ClientLoginStartParameters::WithInfo(parameters.info1),
    )?;
    assert_eq!(
        hex::encode(&parameters.credential_request),
        hex::encode(client_login_start_result.message.serialize())
    );
    assert_eq!(
        hex::encode(&parameters.client_login_state),
        hex::encode(client_login_start_result.state.to_bytes())
    );
    Ok(())
}

#[test]
fn test_credential_response() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let mut server_e_sk_and_nonce_rng =
        CycleRng::new([parameters.server_e_sk, parameters.server_nonce].concat());
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_e_sk_and_nonce_rng,
        ServerRegistration::try_from(&parameters.password_file[..])?,
        &Key::try_from(&parameters.server_s_sk[..])?,
        CredentialRequest::<RistrettoSha5123dhNoSlowHash>::deserialize(
            &parameters.credential_request[..],
        )?,
        ServerLoginStartParameters::WithInfoAndIdentifiers(
            parameters.einfo2.to_vec(),
            parameters.id_u,
            parameters.id_s,
        ),
    )?;
    assert_eq!(
        hex::encode(&parameters.info1),
        hex::encode(server_login_start_result.plain_info),
    );
    assert_eq!(
        hex::encode(&parameters.credential_response),
        hex::encode(server_login_start_result.message.serialize())
    );
    assert_eq!(
        hex::encode(&parameters.server_login_state),
        hex::encode(server_login_start_result.state.to_bytes())
    );
    Ok(())
}

#[test]
fn test_credential_finalization() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_login_finish_result =
        ClientLogin::<RistrettoSha5123dhNoSlowHash>::try_from(&parameters.client_login_state[..])?
            .finish(
                CredentialResponse::<RistrettoSha5123dhNoSlowHash>::deserialize(
                    &parameters.credential_response[..],
                )?,
                ClientLoginFinishParameters::WithIdentifiers(parameters.id_u, parameters.id_s),
            )?;

    assert_eq!(
        hex::encode(&parameters.einfo2),
        hex::encode(&client_login_finish_result.confidential_info)
    );
    assert_eq!(
        hex::encode(&parameters.server_s_pk),
        hex::encode(&client_login_finish_result.server_s_pk.to_arr().to_vec())
    );
    assert_eq!(
        hex::encode(&parameters.shared_secret),
        hex::encode(&client_login_finish_result.shared_secret)
    );
    assert_eq!(
        hex::encode(&parameters.credential_finalization),
        hex::encode(client_login_finish_result.message.to_bytes())
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
        ServerLogin::<RistrettoSha5123dhNoSlowHash>::try_from(&parameters.server_login_state[..])?
            .finish(CredentialFinalization::try_from(
                &parameters.credential_finalization[..],
            )?)?;

    assert_eq!(
        hex::encode(parameters.shared_secret),
        hex::encode(server_login_result.shared_secret)
    );

    Ok(())
}

fn test_complete_flow(
    registration_password: &[u8],
    login_password: &[u8],
) -> Result<(), ProtocolError> {
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_kp = RistrettoSha5123dhNoSlowHash::generate_random_keypair(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            registration_password,
        )?;
    let server_registration_start_result =
        ServerRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut server_rng,
            client_registration_start_result.message,
            server_kp.public(),
        )?;
    let client_registration_finish_result = client_registration_start_result.state.finish(
        &mut client_rng,
        server_registration_start_result.message,
        ClientRegistrationFinishParameters::default(),
    )?;
    let p_file = server_registration_start_result
        .state
        .finish(client_registration_finish_result.message)?;
    let client_login_start_result = ClientLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut client_rng,
        login_password,
        ClientLoginStartParameters::default(),
    )?;
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_rng,
        p_file,
        &server_kp.private(),
        client_login_start_result.message,
        ServerLoginStartParameters::default(),
    )?;

    let client_login_result = client_login_start_result.state.finish(
        server_login_start_result.message,
        ClientLoginFinishParameters::default(),
    );

    if hex::encode(registration_password) == hex::encode(login_password) {
        let client_login_finish_result = client_login_result?;
        let server_login_finish_result = server_login_start_result
            .state
            .finish(client_login_finish_result.message)?;

        assert_eq!(
            hex::encode(server_login_finish_result.shared_secret),
            hex::encode(client_login_finish_result.shared_secret)
        );
        assert_eq!(
            hex::encode(client_registration_finish_result.export_key),
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

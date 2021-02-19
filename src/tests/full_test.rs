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
use rand::{rngs::OsRng, RngCore};
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
    pub session_key: Vec<u8>,
}

static TEST_VECTOR: &str = r#"
{
    "client_s_pk": "88a330a73dd4b166307c5efc6e7a0a30d9b36ff6cc13cdb7f4e9adb9308a7637",
    "client_s_sk": "a3f2becb1604e524d414d75e34d69b1984403715f4fb64dbecdf94ee67c56007",
    "client_e_pk": "782e5d1fba5fc5127f56d026a0796320670260a58007b0c7b8e2c4591a6c2441",
    "client_e_sk": "117dbea41b3a73f38af6ec5e94f4addcb157fafd01db5640a782cbd205af1c01",
    "server_s_pk": "ce16950ab0939c9827479b7f7c94662f2aad8149a47260b4e9a36f3013472924",
    "server_s_sk": "7731db9c827d8d2736dcec7900e635d05b8eb024ba03398be7b3e14380983a07",
    "server_e_pk": "f8f1a6de4b3708baec68ea94f47b9577f3d36458e82e36f431ba8ce77e2d2e11",
    "server_e_sk": "f7b415289b0e0f043465d9bf5d6f93393b042aa6f45eb74c1ed29e63484dd705",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "7691a5530384fae7ce5d118b770900b38d523d0ea62f7328410718cdc26a5707",
    "oprf_key": "c66dc3992fbcbb969647fe94390db974c4a5c6c46457373f28385c8898e9fb07",
    "envelope_nonce": "a2c8292a03df900668a81badb1003c80bacbb9a4776228997a264d58e7b2a2c6",
    "client_nonce": "d54b0fb476f66a3c5ac93647c462590431594e63f8b21aeb371cb0f835841a40",
    "server_nonce": "458b1ca0d48d3d04e6a21127db53ae4208cd5c6ae0aa6b0e2db3146022725c45",
    "info1": "696e666f31",
    "einfo2": "65696e666f32",
    "registration_request": "86115e7b95618fbd5015765d2f212494d5d68e770b96da153d0bb9a00bc5f54d",
    "registration_response": "42538263dcf753f1255c85eb66b558c32bd593f3787d284eb126787393d586330020ce16950ab0939c9827479b7f7c94662f2aad8149a47260b4e9a36f3013472924",
    "registration_upload": "002088a330a73dd4b166307c5efc6e7a0a30d9b36ff6cc13cdb7f4e9adb9308a763702a2c8292a03df900668a81badb1003c80bacbb9a4776228997a264d58e7b2a2c60022fe0b9953fd5e784a3f47ed9b1ea1a33a39231dff88e930edebd1d437b850972a2a1c51bcf77483a4315eeb5db1cb61e7dbd874194f893daaf32006de7502a0e33860cadcfec6e038662e8484e9f488efa1f336bf10a125409d20bce6a6cb22a70d8e",
    "credential_request": "86115e7b95618fbd5015765d2f212494d5d68e770b96da153d0bb9a00bc5f54dd54b0fb476f66a3c5ac93647c462590431594e63f8b21aeb371cb0f835841a400005696e666f31782e5d1fba5fc5127f56d026a0796320670260a58007b0c7b8e2c4591a6c2441",
    "credential_response": "42538263dcf753f1255c85eb66b558c32bd593f3787d284eb126787393d586330020ce16950ab0939c9827479b7f7c94662f2aad8149a47260b4e9a36f301347292402a2c8292a03df900668a81badb1003c80bacbb9a4776228997a264d58e7b2a2c60022fe0b9953fd5e784a3f47ed9b1ea1a33a39231dff88e930edebd1d437b850972a2a1c51bcf77483a4315eeb5db1cb61e7dbd874194f893daaf32006de7502a0e33860cadcfec6e038662e8484e9f488efa1f336bf10a125409d20bce6a6cb22a70d8e458b1ca0d48d3d04e6a21127db53ae4208cd5c6ae0aa6b0e2db3146022725c45f8f1a6de4b3708baec68ea94f47b9577f3d36458e82e36f431ba8ce77e2d2e110006ded053c5cfa292afbc005f84f965ca179800aba13974d7c96ae5c386207bc631dc9f70030ebdbf19503e40d45944d0bdc7cb01d3d44701a582d12a2a807648b6763b7c8b7ca4",
    "credential_finalization": "afa7239945acc304e0c40a6a9e594d7978aaff24565a44fcb5bc62b577211e854be9cb3f55261f1e34a8ebac192f98625ec59d54ce5c64346e1f9afa18facda3",
    "client_registration_state": "7691a5530384fae7ce5d118b770900b38d523d0ea62f7328410718cdc26a570770617373776f7264",
    "client_login_state": "7691a5530384fae7ce5d118b770900b38d523d0ea62f7328410718cdc26a5707006786115e7b95618fbd5015765d2f212494d5d68e770b96da153d0bb9a00bc5f54dd54b0fb476f66a3c5ac93647c462590431594e63f8b21aeb371cb0f835841a400005696e666f31782e5d1fba5fc5127f56d026a0796320670260a58007b0c7b8e2c4591a6c24410040117dbea41b3a73f38af6ec5e94f4addcb157fafd01db5640a782cbd205af1c01d54b0fb476f66a3c5ac93647c462590431594e63f8b21aeb371cb0f835841a4070617373776f7264",
    "server_registration_state": "c66dc3992fbcbb969647fe94390db974c4a5c6c46457373f28385c8898e9fb07",
    "server_login_state": "e05749068700eec7d07c4e2e6e5e63336e41cc1f3c0ddf3c635b46c6d53deffed876378fc1eb32dcfd1d7e35a63c52e638c0b8da7977269143be95f88024ab0735fac1d0b2dce50a5c19e6500c73aa055fabff9f548720dd1cacaa21566b7afde7a9b97fbc4da0482aaf2063c627926bbeeab98356b151881973460c4fad531f13721b6f004e8f73c8d2010df34700717c74350c9275fb29991f6296c85f7d1dd931f784f47ccd6bc2866423cc200fb3872a1cb29a47088b6f6750432e3f6c72",
    "password_file": "c66dc3992fbcbb969647fe94390db974c4a5c6c46457373f28385c8898e9fb0788a330a73dd4b166307c5efc6e7a0a30d9b36ff6cc13cdb7f4e9adb9308a763702a2c8292a03df900668a81badb1003c80bacbb9a4776228997a264d58e7b2a2c60022fe0b9953fd5e784a3f47ed9b1ea1a33a39231dff88e930edebd1d437b850972a2a1c51bcf77483a4315eeb5db1cb61e7dbd874194f893daaf32006de7502a0e33860cadcfec6e038662e8484e9f488efa1f336bf10a125409d20bce6a6cb22a70d8e",
    "export_key": "aa2cdeaa4281a834bda57d4fff88702cba1a22d556790e812bdfd408162ba3b6a17305c576ea9549523592470ef3047aa8ace4be71f92d71f0b5cc6465dfc9e4",
    "session_key": "13721b6f004e8f73c8d2010df34700717c74350c9275fb29991f6296c85f7d1dd931f784f47ccd6bc2866423cc200fb3872a1cb29a47088b6f6750432e3f6c72"
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
        session_key: decode(&values, "session_key").unwrap(),
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
    s.push_str(format!("\"session_key\": \"{}\"\n", hex::encode(&p.session_key)).as_str());
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
    let client_registration_state = client_registration_start_result.state.serialize().to_vec();

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
    let server_registration_state = server_registration_start_result.state.serialize().to_vec();

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
    let password_file_bytes = password_file.serialize();

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
    let client_login_state = client_login_start_result.state.serialize().to_vec();

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
    let server_login_state = server_login_start_result.state.serialize().to_vec();

    let client_login_finish_result = client_login_start_result
        .state
        .finish(
            server_login_start_result.message,
            ClientLoginFinishParameters::WithIdentifiers(id_u.to_vec(), id_s.to_vec()),
        )
        .unwrap();
    let credential_finalization_bytes = client_login_finish_result.message.serialize();

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
        session_key: client_login_finish_result.session_key,
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
        hex::encode(client_registration_start_result.state.serialize())
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
        hex::encode(server_registration_start_result.state.serialize())
    );
    Ok(())
}

#[test]
fn test_registration_upload() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_s_sk_and_nonce: Vec<u8> =
        [parameters.client_s_sk, parameters.envelope_nonce].concat();
    let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
    let result = ClientRegistration::<RistrettoSha5123dhNoSlowHash>::deserialize(
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

    let server_registration = ServerRegistration::<RistrettoSha5123dhNoSlowHash>::deserialize(
        &parameters.server_registration_state[..],
    )?;
    let password_file = server_registration.finish(RegistrationUpload::deserialize(
        &parameters.registration_upload[..],
    )?)?;

    assert_eq!(
        hex::encode(parameters.password_file),
        hex::encode(password_file.serialize())
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
        hex::encode(client_login_start_result.state.serialize())
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
        ServerRegistration::deserialize(&parameters.password_file[..])?,
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
        hex::encode(server_login_start_result.state.serialize())
    );
    Ok(())
}

#[test]
fn test_credential_finalization() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_login_finish_result = ClientLogin::<RistrettoSha5123dhNoSlowHash>::deserialize(
        &parameters.client_login_state[..],
    )?
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
        hex::encode(&parameters.session_key),
        hex::encode(&client_login_finish_result.session_key)
    );
    assert_eq!(
        hex::encode(&parameters.credential_finalization),
        hex::encode(client_login_finish_result.message.serialize())
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

    let server_login_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::deserialize(
        &parameters.server_login_state[..],
    )?
    .finish(CredentialFinalization::deserialize(
        &parameters.credential_finalization[..],
    )?)?;

    assert_eq!(
        hex::encode(parameters.session_key),
        hex::encode(server_login_result.session_key)
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
            hex::encode(server_login_finish_result.session_key),
            hex::encode(client_login_finish_result.session_key)
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

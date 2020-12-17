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
    pub registration_request: Vec<u8>,
    pub registration_response: Vec<u8>,
    pub registration_upload: Vec<u8>,
    pub credential_request: Vec<u8>,
    pub credential_response: Vec<u8>,
    pub key_exchange: Vec<u8>,
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
    "client_s_pk": "15ac69b4b2ed5159c41e6522be68e9ecb8f9a36a0c5f87e3b40441a2f70c3c13",
    "client_s_sk": "9856141d88217b303ceaa4d48ce4271baefcce3d9b9db119dabce597a18c5b7b",
    "client_e_pk": "92380a7ffb59a800ba1256b1f91934eef2c703a7c95e06fca3887dc006a96203",
    "client_e_sk": "d038503babf0b662cb06115823590b21c9737beda4009efca6923caaf5728f42",
    "server_s_pk": "03da70333c51449c72a8282170d9e6a15c8ff221e26542eb812be186cdb5b025",
    "server_s_sk": "18f1d52bb05df44671599a9d63ed3d327ea69eec1cada57c2cd287f9d21ef67e",
    "server_e_pk": "9a808154123cda50e79bc9e42c96fe67b3d6b44fe920a0fd24ccd3eba97f7f20",
    "server_e_sk": "b04fbabf986c77f7fc38dbc874f857da71719c73d821468e825ed3c83694ca65",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "d2b1e25c51a6dcc03c228d650fee985161e91992753ebde17bfd3d31f6fd5102",
    "oprf_key": "5bff6043ea154271aabb77433670a308599647dde78c52cee1066f4d45faa907",
    "envelope_nonce": "b18428a147bbd11cac7e8732aa2291f5f56aef0e2ff20bebe473e6d8a24c4c74",
    "client_nonce": "67dbc61533747146040f15782e8cae54912d81d5dd48d89c540a2d76501aad58",
    "server_nonce": "e7a1329a7293f3fe32b35b09522d1afd6a2133341c0b60b38b5617a0ffee12a2",
    "info1": "696e666f31",
    "info2": "696e666f32",
    "einfo2": "65696e666f32",
    "info3": "696e666f33",
    "einfo3": "65696e666f33",
    "registration_request": "00200bdcb3a4076577657b7fbb2e472882710c1fc5794df6f6d0e16a454feef607c3",
    "registration_response": "002045b7272936aae186fa84b98a47e66850e34e0599002d48bfbc799c079606372c002003da70333c51449c72a8282170d9e6a15c8ff221e26542eb812be186cdb5b02501010103",
    "registration_upload": "b18428a147bbd11cac7e8732aa2291f5f56aef0e2ff20bebe473e6d8a24c4c740023778d07a4b4385527786c67d0365623e84c492dfe56c1d5598e7478634d3ea94fd85eea002303002003da70333c51449c72a8282170d9e6a15c8ff221e26542eb812be186cdb5b02500209f8df539c6b1a6eaa12facd3c469fc418a7a3bd874181fb8c16e20f6eed033fc002015ac69b4b2ed5159c41e6522be68e9ecb8f9a36a0c5f87e3b40441a2f70c3c13",
    "credential_request": "00200bdcb3a4076577657b7fbb2e472882710c1fc5794df6f6d0e16a454feef607c367dbc61533747146040f15782e8cae54912d81d5dd48d89c540a2d76501aad580005696e666f3192380a7ffb59a800ba1256b1f91934eef2c703a7c95e06fca3887dc006a96203",
    "credential_response": "002045b7272936aae186fa84b98a47e66850e34e0599002d48bfbc799c079606372cb18428a147bbd11cac7e8732aa2291f5f56aef0e2ff20bebe473e6d8a24c4c740023778d07a4b4385527786c67d0365623e84c492dfe56c1d5598e7478634d3ea94fd85eea002303002003da70333c51449c72a8282170d9e6a15c8ff221e26542eb812be186cdb5b02500209f8df539c6b1a6eaa12facd3c469fc418a7a3bd874181fb8c16e20f6eed033fcb04fbabf986c77f7fc38dbc874f857da71719c73d821468e825ed3c83694ca650005696e666f329a808154123cda50e79bc9e42c96fe67b3d6b44fe920a0fd24ccd3eba97f7f20000665696e666f32c36b4e4987357f90247da7ca99eb259efacb48e894049d30d16a0bef9f0c14f4",
    "key_exchange": "0005696e666f33000665696e666f33676707238432bfcfacd0a4e9d087776d0e3e32fe034e7e259fdaa25a69f4f4ba",
    "client_registration_state": "d2b1e25c51a6dcc03c228d650fee985161e91992753ebde17bfd3d31f6fd510270617373776f7264",
    "client_login_state": "00036964550003696453d2b1e25c51a6dcc03c228d650fee985161e91992753ebde17bfd3d31f6fd5102d038503babf0b662cb06115823590b21c9737beda4009efca6923caaf5728f4267dbc61533747146040f15782e8cae54912d81d5dd48d89c540a2d76501aad58ba195961229f243fa68e9bb23e228308dcccde52a59fa4655cef23beab52fc2f70617373776f7264",
    "server_registration_state": "5bff6043ea154271aabb77433670a308599647dde78c52cee1066f4d45faa907",
    "server_login_state": "4fadb7bdfc4691eb5f0fc3d20c218fd9d066b70feaa75412d57287b3157f8f557bcde6814f15097b1a2c7ad80d3c6bea53525fc7b79f9311b9412a69a47ac7deaff4e62f4302141d288651e4368aa37eb542f54a7a71d5091fdcf4dd71d78e12",
    "password_file": "5bff6043ea154271aabb77433670a308599647dde78c52cee1066f4d45faa90715ac69b4b2ed5159c41e6522be68e9ecb8f9a36a0c5f87e3b40441a2f70c3c13b18428a147bbd11cac7e8732aa2291f5f56aef0e2ff20bebe473e6d8a24c4c740023778d07a4b4385527786c67d0365623e84c492dfe56c1d5598e7478634d3ea94fd85eea002303002003da70333c51449c72a8282170d9e6a15c8ff221e26542eb812be186cdb5b02500209f8df539c6b1a6eaa12facd3c469fc418a7a3bd874181fb8c16e20f6eed033fc",
    "export_key": "c4d8e55e747645234c187724d11e7b9af7c2299972c3724a0850f5a3b7ee0d77",
    "shared_secret": "aff4e62f4302141d288651e4368aa37eb542f54a7a71d5091fdcf4dd71d78e12"
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
        registration_request: decode(&values, "registration_request").unwrap(),
        registration_response: decode(&values, "registration_response").unwrap(),
        registration_upload: decode(&values, "registration_upload").unwrap(),
        credential_request: decode(&values, "credential_request").unwrap(),
        credential_response: decode(&values, "credential_response").unwrap(),
        key_exchange: decode(&values, "key_exchange").unwrap(),
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
    s.push_str(format!("\"key_exchange\": \"{}\",\n", hex::encode(&p.key_exchange)).as_str());
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
    let client_registration_start_result = ClientRegistration::<CS>::start(
        &mut blinding_factor_registration_rng,
        password,
        std::convert::identity,
    )
    .unwrap();
    let registration_request_bytes = client_registration_start_result
        .message
        .serialize()
        .to_vec();
    let blinding_factor_bytes =
        CS::Group::scalar_as_bytes(&client_registration_start_result.state.token.blind).clone();
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
    client_login_start.extend_from_slice(&blinding_factor_raw);
    client_login_start.extend_from_slice(&client_e_kp.private().to_arr());
    client_login_start.extend_from_slice(&client_nonce);

    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let client_login_start_result = ClientLogin::<CS>::start(
        &mut client_login_start_rng,
        password,
        ClientLoginStartParameters::WithInfoAndIdentifiers(
            info1.to_vec(),
            id_u.to_vec(),
            id_s.to_vec(),
        ),
        std::convert::identity,
    )
    .unwrap();
    let credential_request_bytes = client_login_start_result.message.serialize().to_vec();
    let client_login_state = client_login_start_result.state.to_bytes().to_vec();

    let mut server_e_sk_rng = CycleRng::new(server_e_kp.private().to_arr().to_vec());
    let server_login_start_result = ServerLogin::<CS>::start(
        &mut server_e_sk_rng,
        password_file,
        server_s_kp.private(),
        client_login_start_result.message,
        ServerLoginStartParameters::WithInfo(info2.to_vec(), einfo2.to_vec()),
    )
    .unwrap();
    let credential_response_bytes = server_login_start_result.message.serialize().to_vec();
    let server_login_state = server_login_start_result.state.to_bytes().to_vec();

    let client_login_finish_result = client_login_start_result
        .state
        .finish(
            server_login_start_result.message,
            ClientLoginFinishParameters::WithInfo(info3.to_vec(), einfo3.to_vec()),
        )
        .unwrap();
    let key_exchange_bytes = client_login_finish_result.message.to_bytes().to_vec();

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
        registration_request: registration_request_bytes,
        registration_response: registration_response_bytes,
        registration_upload: registration_upload_bytes,
        credential_request: credential_request_bytes,
        credential_response: credential_response_bytes,
        key_exchange: key_exchange_bytes,
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
    let parameters = generate_parameters::<X255193dhNoSlowHash>();
    println!("{}", stringify_test_vectors(&parameters));
}

// For fixing the blinding factor
fn postprocess_blinding_factor<G: Group>(_: G::Scalar) -> G::Scalar {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    G::from_scalar_slice(GenericArray::from_slice(&parameters.blinding_factor[..])).unwrap()
}

#[test]
fn test_registration_request() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut rng = OsRng;
    let client_registration_start_result = ClientRegistration::<X255193dhNoSlowHash>::start(
        &mut rng,
        &parameters.password,
        postprocess_blinding_factor::<<X255193dhNoSlowHash as CipherSuite>::Group>,
    )?;
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
    let server_registration_start_result = ServerRegistration::<X255193dhNoSlowHash>::start(
        &mut oprf_key_rng,
        RegistrationRequest::deserialize(&parameters.registration_request[..]).unwrap(),
        &Key::try_from(&parameters.server_s_pk[..]).unwrap(),
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
    let result = ClientRegistration::<X255193dhNoSlowHash>::try_from(
        &parameters.client_registration_state[..],
    )?
    .finish(
        &mut finish_registration_rng,
        RegistrationResponse::deserialize(&parameters.registration_response[..]).unwrap(),
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

    let server_registration = ServerRegistration::<X255193dhNoSlowHash>::try_from(
        &parameters.server_registration_state[..],
    )?;
    let password_file = server_registration
        .finish(RegistrationUpload::deserialize(&parameters.registration_upload[..]).unwrap())?;

    assert_eq!(
        hex::encode(parameters.password_file),
        hex::encode(password_file.to_bytes())
    );
    Ok(())
}

#[test]
fn test_credential_request() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_login_start = [
        vec![0u8; 64], // FIXME: don't hardcode this
        parameters.client_e_sk,
        parameters.client_nonce,
    ]
    .concat();
    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let client_login_start_result = ClientLogin::<X255193dhNoSlowHash>::start(
        &mut client_login_start_rng,
        &parameters.password,
        ClientLoginStartParameters::WithInfoAndIdentifiers(
            parameters.info1,
            parameters.id_u,
            parameters.id_s,
        ),
        postprocess_blinding_factor::<<X255193dhNoSlowHash as CipherSuite>::Group>,
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

    let mut server_e_sk_rng = CycleRng::new(parameters.server_e_sk);
    let server_login_start_result = ServerLogin::<X255193dhNoSlowHash>::start(
        &mut server_e_sk_rng,
        ServerRegistration::try_from(&parameters.password_file[..]).unwrap(),
        &Key::try_from(&parameters.server_s_sk[..]).unwrap(),
        CredentialRequest::<X255193dhNoSlowHash>::deserialize(&parameters.credential_request[..])
            .unwrap(),
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
fn test_key_exchange() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_login_finish_result =
        ClientLogin::<X255193dhNoSlowHash>::try_from(&parameters.client_login_state[..])
            .unwrap()
            .finish(
                CredentialResponse::<X255193dhNoSlowHash>::deserialize(
                    &parameters.credential_response[..],
                )?,
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
        hex::encode(&client_login_finish_result.shared_secret)
    );
    assert_eq!(
        hex::encode(&parameters.key_exchange),
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
        ServerLogin::<X255193dhNoSlowHash>::try_from(&parameters.server_login_state[..])?.finish(
            CredentialFinalization::try_from(&parameters.key_exchange[..])?,
        )?;

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
    let server_kp = X255193dhNoSlowHash::generate_random_keypair(&mut server_rng)?;
    let client_registration_start_result = ClientRegistration::<X255193dhNoSlowHash>::start(
        &mut client_rng,
        registration_password,
        std::convert::identity,
    )?;
    let server_registration_start_result = ServerRegistration::<X255193dhNoSlowHash>::start(
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
    let client_login_start_result = ClientLogin::<X255193dhNoSlowHash>::start(
        &mut client_rng,
        login_password,
        ClientLoginStartParameters::default(),
        std::convert::identity,
    )?;
    let server_login_start_result = ServerLogin::<X255193dhNoSlowHash>::start(
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

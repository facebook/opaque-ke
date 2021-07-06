// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#![allow(unsafe_code)]

use crate::{
    ciphersuite::CipherSuite,
    errors::*,
    group::Group,
    key_exchange::tripledh::{NonceLen, TripleDH},
    keypair::KeyPair,
    opaque::*,
    slow_hash::NoOpHash,
    tests::mock_rng::CycleRng,
    *,
};
use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use generic_array::typenum::Unsigned;
use generic_bytes::SizedBytes;
use rand::{rngs::OsRng, RngCore};
use serde_json::Value;
use std::slice::from_raw_parts;
use zeroize::Zeroize;

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
    pub fake_sk: Vec<u8>,
    pub credential_identifier: Vec<u8>,
    pub id_u: Vec<u8>,
    pub id_s: Vec<u8>,
    pub password: Vec<u8>,
    pub blinding_factor: Vec<u8>,
    pub oprf_seed: Vec<u8>,
    pub masking_nonce: Vec<u8>,
    pub envelope_nonce: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub server_nonce: Vec<u8>,
    pub context: Vec<u8>,
    pub registration_request: Vec<u8>,
    pub registration_response: Vec<u8>,
    pub registration_upload: Vec<u8>,
    pub credential_request: Vec<u8>,
    pub credential_response: Vec<u8>,
    pub credential_finalization: Vec<u8>,
    client_registration_state: Vec<u8>,
    client_login_state: Vec<u8>,
    server_login_state: Vec<u8>,
    pub password_file: Vec<u8>,
    pub export_key: Vec<u8>,
    pub session_key: Vec<u8>,
}

static STR_PASSWORD: &str = "password";
static STR_CREDENTIAL_IDENTIFIER: &str = "credential_identifier";

static TEST_VECTOR: &str = r#"
{
    "client_s_pk": "b47c69b4ea5e87139649349516c2842145993a2a00cc6e63d27c57f170475260",
    "client_s_sk": "60a33dd8e1970aa3d2ed09c03ad0380e0cf628a669d3b7d030d3fea0dd7f5c06",
    "client_e_pk": "5a513aecfa17dab422221a980819c680aea9a49947c7c0caca94fc61dcb4632c",
    "client_e_sk": "9f42ca864614d4175e1540e4c56fe18362cb56b778dccf6b0a9446a23735dc03",
    "server_s_pk": "8ed3fd51aa5e6931559fa6ae9be9829e609e441efbabb0846933fd5e30a3a268",
    "server_s_sk": "a514a8842cd760449887fb2f943440b17073b5073691ceeaa0552210e693ea01",
    "server_e_pk": "e8249649f7614f6268df01e54eb992043d49df04c98f8c8cea27c263d95dec4b",
    "server_e_sk": "a4b66443250a0cc39ad9baae6ada72c243ddee53b712eb48933993230c13500f",
    "fake_sk": "60a33dd8e1970aa3d2ed09c03ad0380e0cf628a669d3b7d030d3fea0dd7f5c06",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "08f845725404c823f477eb1e8f79dab63fdbbb2110a6c360fc98a4d2720e9d0a",
    "oprf_seed": "1e7fddf167679cb1e83a179d4275034c09d2d745a1fec311a5e59ed30d0b80e2100ee8e6bbc996dc298f7f9e7dcc03c052853a02e4273d33c2973c7a6128affd",
    "masking_nonce": "2b49d01802a69aacdad4979c503b96d08f44e4c67eaf82bbf6e71c6bb5473aa819359428f408bda29976beb0243c8a91fbeb2ee57840b90c62f4d87f88344db0",
    "envelope_nonce": "f4351a2d4f1efb09877fbef82d44bff3a963b08cc727874aa75c5d57d604aa2e",
    "client_nonce": "e56a024c1d89f05ff245b98ba097cdfdcc5c181b3d5e9d52100d421d3160f80a",
    "server_nonce": "9b78591d87600abf26789c0691dd5f760d5620aa58e34181cb24503bf04c936a",
    "context": "636f6e74657874",
    "registration_request": "0cdc7df1cca989b56917c95127e59ec8f05bda7c606cb45e714bfa582b429832",
    "registration_response": "e88418f5a9145287062e50b060e6f6790583ec8646430af1bff0a2729bf20d1b8ed3fd51aa5e6931559fa6ae9be9829e609e441efbabb0846933fd5e30a3a268",
    "registration_upload": "d6f1486284e595707ae341a4d083d454477933b1bcf770bfc4087127c0a8e844e833f76e997aef5b46d2108811667183d08f0cc0a8465dac277287591cac1e42933ed23a2c9476cfa939854a40fc746c21606535b19f0a48cf8cc565f7c3e6df60a33dd8e1970aa3d2ed09c03ad0380e0cf628a669d3b7d030d3fea0dd7f5c0654e4188e55b7fe2eed8a7aee79ae6cfefabab86e7b7822f05bc422ac7e7a9acb968001b3dc5ead255a2d7599a7be60aa97ebed89808db20faa445e912f7df2da",
    "credential_request": "0cdc7df1cca989b56917c95127e59ec8f05bda7c606cb45e714bfa582b429832e56a024c1d89f05ff245b98ba097cdfdcc5c181b3d5e9d52100d421d3160f80a5a513aecfa17dab422221a980819c680aea9a49947c7c0caca94fc61dcb4632c",
    "credential_response": "e88418f5a9145287062e50b060e6f6790583ec8646430af1bff0a2729bf20d1b2b49d01802a69aacdad4979c503b96d08f44e4c67eaf82bbf6e71c6bb5473aa8718337df372fbb0de1beb29e2f4e6a2419858326ffe3f2a24172cca25e6344edd7db031cac3e206218eda4555d816f341c428317a4d37ed63441a278f78185b202b675b620e6f35056964d400c311cad23a1e6b0d9a91837d9d0021280bf0facf422961c96cffea530a24eb2486d4fa91adadaf7ac9a17d35b329b2add32e368a4b66443250a0cc39ad9baae6ada72c243ddee53b712eb48933993230c13500f2896e6f69e8610ced17584f34c09d872300bac6c99b8157392517ab9e9ed1f4aa163f8040d899cc77cf1f0ca2c4be6aef1616288cd3a6ac21989bdfc07bc4e94a284cf4c588583b2361195feab1ddcd390defde6282db2edc3eb535ede66404b",
    "credential_finalization": "2f8c71675d7db1b32ed3daaa7f15fc353f6af536ab1199e41e43ece9871d8b69336b8c84c4906810bb87c1a0407bd5f5d780c7d10a1c94016103639e507cf6d0",
    "client_registration_state": "08f845725404c823f477eb1e8f79dab63fdbbb2110a6c360fc98a4d2720e9d0a70617373776f7264",
    "client_login_state": "08f845725404c823f477eb1e8f79dab63fdbbb2110a6c360fc98a4d2720e9d0a00600cdc7df1cca989b56917c95127e59ec8f05bda7c606cb45e714bfa582b429832e56a024c1d89f05ff245b98ba097cdfdcc5c181b3d5e9d52100d421d3160f80a5a513aecfa17dab422221a980819c680aea9a49947c7c0caca94fc61dcb4632c00409f42ca864614d4175e1540e4c56fe18362cb56b778dccf6b0a9446a23735dc03e56a024c1d89f05ff245b98ba097cdfdcc5c181b3d5e9d52100d421d3160f80a70617373776f7264",
    "server_login_state": "a62f305635e341c151f5e51b89307940031337a0ad8f1369ddec9b672dc31f35d59be00eb66d77bda0079d6eda94809c863da359fef3a636704ae3fa1c9b9b2d18eb9b193528fbb392a5eab5da8068b7c276c8fe00814213ddd70d02157902bebfce850b403aaa4c99f8dbd5ff50d4ad3e703fb564a3fc474861e3f69d7c9a90037d3dbf36f215082644d5c5bc91e138f9665e7bc538f4bc70f97c91dfcd029b1c027b03dc99137478b3570d9da27922b88a8784f1c2f07cd04a0db04246531a",
    "password_file": "d6f1486284e595707ae341a4d083d454477933b1bcf770bfc4087127c0a8e844e833f76e997aef5b46d2108811667183d08f0cc0a8465dac277287591cac1e42933ed23a2c9476cfa939854a40fc746c21606535b19f0a48cf8cc565f7c3e6df60a33dd8e1970aa3d2ed09c03ad0380e0cf628a669d3b7d030d3fea0dd7f5c0654e4188e55b7fe2eed8a7aee79ae6cfefabab86e7b7822f05bc422ac7e7a9acb968001b3dc5ead255a2d7599a7be60aa97ebed89808db20faa445e912f7df2da",
    "export_key": "f1abeb7ab0a43ff1924b59d744053b271d999f341eedc740f1f62d785d19bec939479e5e39f2ec25f5ef712ecd10a085653ad1ed9049092cb2a3d44d6cc205ba",
    "session_key": "037d3dbf36f215082644d5c5bc91e138f9665e7bc538f4bc70f97c91dfcd029b1c027b03dc99137478b3570d9da27922b88a8784f1c2f07cd04a0db04246531a"
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
        fake_sk: decode(&values, "fake_sk").unwrap(),
        credential_identifier: decode(&values, "credential_identifier").unwrap(),
        id_u: decode(&values, "id_u").unwrap(),
        id_s: decode(&values, "id_s").unwrap(),
        password: decode(&values, "password").unwrap(),
        blinding_factor: decode(&values, "blinding_factor").unwrap(),
        oprf_seed: decode(&values, "oprf_seed").unwrap(),
        masking_nonce: decode(&values, "masking_nonce").unwrap(),
        envelope_nonce: decode(&values, "envelope_nonce").unwrap(),
        client_nonce: decode(&values, "client_nonce").unwrap(),
        server_nonce: decode(&values, "server_nonce").unwrap(),
        context: decode(&values, "context").unwrap(),
        registration_request: decode(&values, "registration_request").unwrap(),
        registration_response: decode(&values, "registration_response").unwrap(),
        registration_upload: decode(&values, "registration_upload").unwrap(),
        credential_request: decode(&values, "credential_request").unwrap(),
        credential_response: decode(&values, "credential_response").unwrap(),
        credential_finalization: decode(&values, "credential_finalization").unwrap(),
        client_registration_state: decode(&values, "client_registration_state").unwrap(),
        client_login_state: decode(&values, "client_login_state").unwrap(),
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
    s.push_str(
        format!(
            "\"credential_identifier\": \"{}\",\n",
            hex::encode(&p.credential_identifier)
        )
        .as_str(),
    );
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
    s.push_str(format!("\"oprf_seed\": \"{}\",\n", hex::encode(&p.oprf_seed)).as_str());
    s.push_str(
        format!(
            "\"masking_nonce\": \"{}\",\n",
            hex::encode(&p.masking_nonce)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "\"envelope_nonce\": \"{}\",\n",
            hex::encode(&p.envelope_nonce)
        )
        .as_str(),
    );
    s.push_str(format!("\"client_nonce\": \"{}\",\n", hex::encode(&p.client_nonce)).as_str());
    s.push_str(format!("\"server_nonce\": \"{}\",\n", hex::encode(&p.server_nonce)).as_str());
    s.push_str(format!("\"context\": \"{}\",\n", hex::encode(&p.context)).as_str());
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
    let server_s_kp = KeyPair::<CS::Group>::generate_random(&mut rng);
    let server_e_kp = KeyPair::<CS::Group>::generate_random(&mut rng);
    let client_s_kp = KeyPair::<CS::Group>::generate_random(&mut rng);
    let client_e_kp = KeyPair::<CS::Group>::generate_random(&mut rng);
    let fake_kp = KeyPair::<CS::Group>::generate_random(&mut rng);
    let credential_identifier = b"credIdentifier";
    let id_u = b"idU";
    let id_s = b"idS";
    let password = b"password";
    let context = b"context";
    let mut oprf_seed = [0u8; 64];
    rng.fill_bytes(&mut oprf_seed);
    let mut masking_nonce = [0u8; 64];
    rng.fill_bytes(&mut masking_nonce);
    let mut envelope_nonce = [0u8; 32];
    rng.fill_bytes(&mut envelope_nonce);
    let mut client_nonce = vec![0u8; NonceLen::to_usize()];
    rng.fill_bytes(&mut client_nonce);
    let mut server_nonce = vec![0u8; NonceLen::to_usize()];
    rng.fill_bytes(&mut server_nonce);

    let fake_sk: Vec<u8> = fake_kp.private().to_vec();
    let server_setup = ServerSetup::<CS>::deserialize(
        &[&oprf_seed, &server_s_kp.private().to_arr()[..], &fake_sk].concat(),
    )
    .unwrap();

    let blinding_factor = CS::Group::random_nonzero_scalar(&mut rng);
    let blinding_factor_bytes = CS::Group::scalar_as_bytes(blinding_factor);

    let mut blinding_factor_registration_rng = CycleRng::new(blinding_factor_bytes.to_vec());
    let client_registration_start_result =
        ClientRegistration::<CS>::start(&mut blinding_factor_registration_rng, password).unwrap();
    let blinding_factor_bytes_returned =
        CS::Group::scalar_as_bytes(client_registration_start_result.state.token.blind);
    assert_eq!(
        hex::encode(&blinding_factor_bytes),
        hex::encode(&blinding_factor_bytes_returned)
    );

    let registration_request_bytes = client_registration_start_result
        .message
        .serialize()
        .to_vec();
    let client_registration_state = client_registration_start_result.state.serialize().to_vec();

    let server_registration_start_result = ServerRegistration::<CS>::start(
        &server_setup,
        client_registration_start_result.message,
        &credential_identifier[..],
    )
    .unwrap();
    let registration_response_bytes = server_registration_start_result
        .message
        .serialize()
        .to_vec();

    let mut client_s_sk_and_nonce: Vec<u8> = Vec::new();
    client_s_sk_and_nonce.extend_from_slice(&client_s_kp.private().to_arr());
    client_s_sk_and_nonce.extend_from_slice(&envelope_nonce);

    let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
    let client_registration_finish_result = client_registration_start_result
        .state
        .finish(
            &mut finish_registration_rng,
            server_registration_start_result.message,
            ClientRegistrationFinishParameters::WithIdentifiers(
                Identifiers::ClientAndServerIdentifiers(id_u.to_vec(), id_s.to_vec()),
            ),
        )
        .unwrap();
    let registration_upload_bytes = client_registration_finish_result
        .message
        .serialize()
        .to_vec();

    let password_file = ServerRegistration::finish(client_registration_finish_result.message);
    let password_file_bytes = password_file.serialize();

    let mut client_login_start: Vec<u8> = Vec::new();
    client_login_start.extend_from_slice(&blinding_factor_bytes);
    client_login_start.extend_from_slice(&client_e_kp.private().to_arr());
    client_login_start.extend_from_slice(&client_nonce);

    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let client_login_start_result =
        ClientLogin::<CS>::start(&mut client_login_start_rng, password).unwrap();
    let credential_request_bytes = client_login_start_result.message.serialize().to_vec();
    let client_login_state = client_login_start_result.state.serialize().to_vec();

    let mut server_e_sk_and_nonce_rng = CycleRng::new(
        [
            masking_nonce.to_vec(),
            server_e_kp.private().to_arr().to_vec(),
            server_nonce.to_vec(),
        ]
        .concat(),
    );
    let server_login_start_result = ServerLogin::<CS>::start(
        &mut server_e_sk_and_nonce_rng,
        &server_setup,
        Some(password_file),
        client_login_start_result.message,
        credential_identifier,
        ServerLoginStartParameters::WithContextAndIdentifiers(
            context.to_vec(),
            Identifiers::ClientAndServerIdentifiers(id_u.to_vec(), id_s.to_vec()),
        ),
    )
    .unwrap();
    let credential_response_bytes = server_login_start_result.message.serialize().to_vec();
    let server_login_state = server_login_start_result.state.serialize().to_vec();

    let client_login_finish_result = client_login_start_result
        .state
        .finish(
            server_login_start_result.message,
            ClientLoginFinishParameters::WithContextAndIdentifiers(
                context.to_vec(),
                Identifiers::ClientAndServerIdentifiers(id_u.to_vec(), id_s.to_vec()),
            ),
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
        fake_sk,
        credential_identifier: credential_identifier.to_vec(),
        id_u: id_u.to_vec(),
        id_s: id_s.to_vec(),
        password: password.to_vec(),
        blinding_factor: blinding_factor_bytes.to_vec(),
        oprf_seed: oprf_seed.to_vec(),
        masking_nonce: masking_nonce.to_vec(),
        envelope_nonce: envelope_nonce.to_vec(),
        client_nonce: client_nonce.to_vec(),
        server_nonce: server_nonce.to_vec(),
        context: context.to_vec(),
        registration_request: registration_request_bytes,
        registration_response: registration_response_bytes,
        registration_upload: registration_upload_bytes,
        credential_request: credential_request_bytes,
        credential_response: credential_response_bytes,
        credential_finalization: credential_finalization_bytes,
        password_file: password_file_bytes,
        client_registration_state,
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

#[cfg(feature = "serialize")]
#[test]
fn test_serialization() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut rng = CycleRng::new(parameters.blinding_factor.to_vec());
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(&mut rng, &parameters.password)?;
    {
        // Test the json serialization (human-readable, base64).
        let registration_request_json =
            serde_json::to_string(&client_registration_start_result.message).unwrap();
        assert_eq!(
            registration_request_json,
            r#""DNx98cypibVpF8lRJ+WeyPBb2nxgbLRecUv6WCtCmDI=""#
        );
        let registration_request: RegistrationRequest<RistrettoSha5123dhNoSlowHash> =
            serde_json::from_str(&registration_request_json).unwrap();
        assert_eq!(
            hex::encode(client_registration_start_result.message.serialize()),
            hex::encode(registration_request.serialize()),
        );
    }
    {
        // Test the bincode serialization (binary).
        let registration_request_bin =
            bincode::serialize(&client_registration_start_result.message).unwrap();
        assert_eq!(registration_request_bin.len(), 40);
        let registration_request: RegistrationRequest<RistrettoSha5123dhNoSlowHash> =
            bincode::deserialize(&registration_request_bin).unwrap();
        assert_eq!(
            hex::encode(client_registration_start_result.message.serialize()),
            hex::encode(registration_request.serialize()),
        );
    }
    Ok(())
}
#[test]
fn test_registration_response() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let server_setup = ServerSetup::<RistrettoSha5123dhNoSlowHash>::deserialize(
        &[
            &parameters.oprf_seed[..],
            &parameters.server_s_sk[..],
            &parameters.fake_sk[..],
        ]
        .concat(),
    )?;

    let server_registration_start_result =
        ServerRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &server_setup,
            RegistrationRequest::deserialize(&parameters.registration_request[..])?,
            &parameters.credential_identifier,
        )?;
    assert_eq!(
        hex::encode(parameters.registration_response),
        hex::encode(server_registration_start_result.message.serialize())
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
        ClientRegistrationFinishParameters::WithIdentifiers(
            Identifiers::ClientAndServerIdentifiers(parameters.id_u, parameters.id_s),
        ),
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

    let password_file = ServerRegistration::finish(RegistrationUpload::<
        RistrettoSha5123dhNoSlowHash,
    >::deserialize(
        &parameters.registration_upload[..]
    )?);

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

    let server_setup = ServerSetup::<RistrettoSha5123dhNoSlowHash>::deserialize(
        &[
            &parameters.oprf_seed[..],
            &parameters.server_s_sk[..],
            &parameters.fake_sk[..],
        ]
        .concat(),
    )?;

    let mut server_e_sk_and_nonce_rng = CycleRng::new(
        [
            parameters.masking_nonce,
            parameters.server_e_sk,
            parameters.server_nonce,
        ]
        .concat(),
    );
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_e_sk_and_nonce_rng,
        &server_setup,
        Some(ServerRegistration::deserialize(
            &parameters.password_file[..],
        )?),
        CredentialRequest::<RistrettoSha5123dhNoSlowHash>::deserialize(
            &parameters.credential_request[..],
        )?,
        &parameters.credential_identifier,
        ServerLoginStartParameters::WithContextAndIdentifiers(
            parameters.context,
            Identifiers::ClientAndServerIdentifiers(parameters.id_u, parameters.id_s),
        ),
    )?;
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
        ClientLoginFinishParameters::WithContextAndIdentifiers(
            parameters.context,
            Identifiers::ClientAndServerIdentifiers(parameters.id_u, parameters.id_s),
        ),
    )?;

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
        hex::encode(&server_login_result.session_key)
    );

    Ok(())
}

fn test_complete_flow(
    registration_password: &[u8],
    login_password: &[u8],
) -> Result<(), ProtocolError> {
    let credential_identifier = b"credentialIdentifier";
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<RistrettoSha5123dhNoSlowHash>::new(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            registration_password,
        )?;
    let server_registration_start_result =
        ServerRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &server_setup,
            client_registration_start_result.message,
            credential_identifier,
        )?;
    let client_registration_finish_result = client_registration_start_result.state.finish(
        &mut client_rng,
        server_registration_start_result.message,
        ClientRegistrationFinishParameters::default(),
    )?;
    let p_file = ServerRegistration::finish(client_registration_finish_result.message);
    let client_login_start_result =
        ClientLogin::<RistrettoSha5123dhNoSlowHash>::start(&mut client_rng, login_password)?;
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_rng,
        &server_setup,
        Some(p_file),
        client_login_start_result.message,
        credential_identifier,
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
            hex::encode(&server_login_finish_result.session_key),
            hex::encode(&client_login_finish_result.session_key)
        );
        assert_eq!(
            hex::encode(client_registration_finish_result.export_key),
            hex::encode(client_login_finish_result.export_key)
        );
    } else {
        assert!(match client_login_result {
            Err(ProtocolError::VerificationError(PakeError::InvalidLoginError)) => true,
            _ => false,
        });
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

// Zeroize tests

#[test]
fn test_zeroize_client_registration_start() -> Result<(), ProtocolError> {
    let mut client_rng = OsRng;
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
        )?;

    let mut state = client_registration_start_result.state;
    let ptrs = state.as_byte_ptrs();
    state.zeroize();

    for (ptr, len) in ptrs {
        let bytes = unsafe { from_raw_parts(ptr, len) };
        assert!(bytes.iter().all(|&x| x == 0));
    }

    Ok(())
}

#[test]
fn test_zeroize_client_registration_finish() -> Result<(), ProtocolError> {
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<RistrettoSha5123dhNoSlowHash>::new(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
        )?;
    let server_registration_start_result =
        ServerRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &server_setup,
            client_registration_start_result.message,
            STR_CREDENTIAL_IDENTIFIER.as_bytes(),
        )?;
    let client_registration_finish_result = client_registration_start_result.state.finish(
        &mut client_rng,
        server_registration_start_result.message,
        ClientRegistrationFinishParameters::default(),
    )?;

    let mut state = client_registration_finish_result.state;
    let ptrs = state.as_byte_ptrs();
    state.zeroize();

    for (ptr, len) in ptrs {
        let bytes = unsafe { from_raw_parts(ptr, len) };
        assert!(bytes.iter().all(|&x| x == 0));
    }

    Ok(())
}

#[test]
fn test_zeroize_server_registration_finish() -> Result<(), ProtocolError> {
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<RistrettoSha5123dhNoSlowHash>::new(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
        )?;
    let server_registration_start_result =
        ServerRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &server_setup,
            client_registration_start_result.message,
            STR_CREDENTIAL_IDENTIFIER.as_bytes(),
        )?;
    let client_registration_finish_result = client_registration_start_result.state.finish(
        &mut client_rng,
        server_registration_start_result.message,
        ClientRegistrationFinishParameters::default(),
    )?;
    let p_file = ServerRegistration::finish(client_registration_finish_result.message);

    let mut state = p_file;
    let ptrs = state.as_byte_ptrs();
    state.zeroize();

    for (ptr, len) in ptrs {
        let bytes = unsafe { from_raw_parts(ptr, len) };
        assert!(bytes.iter().all(|&x| x == 0));
    }

    Ok(())
}

#[test]
fn test_zeroize_client_login_start() -> Result<(), ProtocolError> {
    let mut client_rng = OsRng;
    let client_login_start_result = ClientLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut client_rng,
        STR_PASSWORD.as_bytes(),
    )?;

    let mut state = client_login_start_result.state;
    let ptrs = state.as_byte_ptrs();
    state.zeroize();

    for (ptr, len) in ptrs {
        let bytes = unsafe { from_raw_parts(ptr, len) };
        assert!(bytes.iter().all(|&x| x == 0));
    }

    Ok(())
}

#[test]
fn test_zeroize_server_login_start() -> Result<(), ProtocolError> {
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<RistrettoSha5123dhNoSlowHash>::new(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
        )?;
    let server_registration_start_result =
        ServerRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &server_setup,
            client_registration_start_result.message,
            STR_CREDENTIAL_IDENTIFIER.as_bytes(),
        )?;
    let client_registration_finish_result = client_registration_start_result.state.finish(
        &mut client_rng,
        server_registration_start_result.message,
        ClientRegistrationFinishParameters::default(),
    )?;
    let p_file = ServerRegistration::finish(client_registration_finish_result.message);
    let client_login_start_result = ClientLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut client_rng,
        STR_PASSWORD.as_bytes(),
    )?;
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_rng,
        &server_setup,
        Some(p_file),
        client_login_start_result.message,
        STR_CREDENTIAL_IDENTIFIER.as_bytes(),
        ServerLoginStartParameters::default(),
    )?;

    let mut state = server_login_start_result.state;
    let ptrs = state.as_byte_ptrs();
    state.zeroize();

    for (ptr, len) in ptrs {
        let bytes = unsafe { from_raw_parts(ptr, len) };
        assert!(bytes.iter().all(|&x| x == 0));
    }

    Ok(())
}

#[test]
fn test_zeroize_client_login_finish() -> Result<(), ProtocolError> {
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<RistrettoSha5123dhNoSlowHash>::new(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
        )?;
    let server_registration_start_result =
        ServerRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &server_setup,
            client_registration_start_result.message,
            STR_CREDENTIAL_IDENTIFIER.as_bytes(),
        )?;
    let client_registration_finish_result = client_registration_start_result.state.finish(
        &mut client_rng,
        server_registration_start_result.message,
        ClientRegistrationFinishParameters::default(),
    )?;
    let p_file = ServerRegistration::finish(client_registration_finish_result.message);
    let client_login_start_result = ClientLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut client_rng,
        STR_PASSWORD.as_bytes(),
    )?;
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_rng,
        &server_setup,
        Some(p_file),
        client_login_start_result.message,
        STR_CREDENTIAL_IDENTIFIER.as_bytes(),
        ServerLoginStartParameters::default(),
    )?;
    let client_login_finish_result = client_login_start_result.state.finish(
        server_login_start_result.message,
        ClientLoginFinishParameters::default(),
    )?;

    let mut state = client_login_finish_result.state;
    let ptrs = state.as_byte_ptrs();
    state.zeroize();

    for (ptr, len) in ptrs {
        let bytes = unsafe { from_raw_parts(ptr, len) };
        assert!(bytes.iter().all(|&x| x == 0));
    }

    Ok(())
}

#[test]
fn test_zeroize_server_login_finish() -> Result<(), ProtocolError> {
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<RistrettoSha5123dhNoSlowHash>::new(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
        )?;
    let server_registration_start_result =
        ServerRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &server_setup,
            client_registration_start_result.message,
            STR_CREDENTIAL_IDENTIFIER.as_bytes(),
        )?;
    let client_registration_finish_result = client_registration_start_result.state.finish(
        &mut client_rng,
        server_registration_start_result.message,
        ClientRegistrationFinishParameters::default(),
    )?;
    let p_file = ServerRegistration::finish(client_registration_finish_result.message);
    let client_login_start_result = ClientLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut client_rng,
        STR_PASSWORD.as_bytes(),
    )?;
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_rng,
        &server_setup,
        Some(p_file),
        client_login_start_result.message,
        STR_CREDENTIAL_IDENTIFIER.as_bytes(),
        ServerLoginStartParameters::default(),
    )?;
    let client_login_finish_result = client_login_start_result.state.finish(
        server_login_start_result.message,
        ClientLoginFinishParameters::default(),
    )?;
    let server_login_finish_result = server_login_start_result
        .state
        .finish(client_login_finish_result.message)?;

    let mut state = server_login_finish_result.state;
    let ptrs = state.as_byte_ptrs();
    state.zeroize();

    for (ptr, len) in ptrs {
        let bytes = unsafe { from_raw_parts(ptr, len) };
        assert!(bytes.iter().all(|&x| x == 0));
    }

    Ok(())
}

#[test]
fn test_scalar_always_nonzero() -> Result<(), ProtocolError> {
    // Start out with a bunch of zeros to force resampling of scalar
    let mut client_registration_rng = CycleRng::new([vec![0u8; 128], vec![1u8; 128]].concat());
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_registration_rng,
            STR_PASSWORD.as_bytes(),
        )?;

    assert_ne!(
        RistrettoPoint::identity(),
        client_registration_start_result
            .message
            .get_alpha_for_testing()
    );

    Ok(())
}

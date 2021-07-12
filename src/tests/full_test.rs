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
    "client_s_pk": "0a6c4964697edd7399bd5d785053a1e2539c488d01368e4e413d16e12fec097f",
    "client_s_sk": "aa831710cef76640aa5a9dc1442a20276fefb476a13ba0e58b503ef0ef1f2e0d",
    "client_e_pk": "be80f3170a73645d10246cfa928e086c994d206c611468b1f5f053b82d3feb07",
    "client_e_sk": "21bb9572af542ec7bf97487d81f3c80115f615067a8d1267722aea841d594108",
    "server_s_pk": "3883f3d1d9703cdb90d12d388730f73b91b682fb5f375ce1a191b2ce025de703",
    "server_s_sk": "bd8d91db143ac70aad47d7c6651578df489a8eaca3f91e7ea8116d89d1319303",
    "server_e_pk": "1014d0390f2a96649a1ff6352a030bd78b98771d588d9b204c0121f6b520f96d",
    "server_e_sk": "14774279665c0ae85e78f1e33d809eaa282a1adc8688a76e6ff4f87c3c34720a",
    "fake_sk": "59905ec82b7db1d9eb54dec8660905b011de8030af1d3ed9bb3c135103db7b08",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "9a8f70c839f0a9dd821d00208f43e89442df2b844a0cf0dcc0508e8dd3cc3c00",
    "oprf_seed": "bd122c79da3f2b04b05793dea984c1229448c8281638f3e7a263b4933b7ba1a82141ad1e24b08076bafb218d0639dcc10d56e87de10c050499b2121c02e4de27",
    "masking_nonce": "e56ddfa0e8008f7960e8eef1e05e96ffbc3b86e2e4ff208d711055ecb34e7a16ec457b7d3caea53224fe7f1e4f883de940d04fa2ae69622743c80b75ebe7f809",
    "envelope_nonce": "2bad92ff095e50a2b1a995027a46da433610646223cf7932506c550fc1407b97",
    "client_nonce": "f71932596f3e394216b5bacae7e1baa29ed87736bae5ffa311d81b57503391b4",
    "server_nonce": "dbddcbe38456a6f6d91ccd9321436c74b81e83083dc084a571758ed710293dd9",
    "context": "636f6e74657874",
    "registration_request": "beb3c2ade1d495856db52d9ce9c1729aae621a6b90a4e892a6f48e08a3290032",
    "registration_response": "84d28db17b088e33583c3579e54d74bfca04d2fe542049c1302a48125dcc8b343883f3d1d9703cdb90d12d388730f73b91b682fb5f375ce1a191b2ce025de703",
    "registration_upload": "f637f1f78397fbc7fd403b2f2c0185a0d61749799e39f46c0f32c0e1629e4e35c903e24984244885abd0ba4e38249c22aeee196b7ab357c0eeb8c70118cb9ac6e377b835bb4b3d0677de272651d2e37da651e42b8dd2460b818fa0243fb69598aa831710cef76640aa5a9dc1442a20276fefb476a13ba0e58b503ef0ef1f2e0d5ddd6ad89f1c35cd5b5f8624ccf83b5e48ba57e1d29e4976ec3ca01dc4c83df5b3f5b891a2e67535d13e0baebc0aeee8807ba2a7254a376687dda6d527d7a069",
    "credential_request": "beb3c2ade1d495856db52d9ce9c1729aae621a6b90a4e892a6f48e08a3290032f71932596f3e394216b5bacae7e1baa29ed87736bae5ffa311d81b57503391b4be80f3170a73645d10246cfa928e086c994d206c611468b1f5f053b82d3feb07",
    "credential_response": "84d28db17b088e33583c3579e54d74bfca04d2fe542049c1302a48125dcc8b34e56ddfa0e8008f7960e8eef1e05e96ffbc3b86e2e4ff208d711055ecb34e7a169266466939f4ea87803eee09cc4657f16bfe4e04218818376d0eaefe03104a08ff0fb79b22494078c67f3e35b4e74f5830bff2c60a885bcf7a4b6d3ae1884a13144fb6ef6e9de572cd8d111a246243cb77d9242ee009d32f29a2bfa884d672a646415c1e2ef241f67a6572c7f2c4c6297a5b44c2d25f63348371f6bd509d238314774279665c0ae85e78f1e33d809eaa282a1adc8688a76e6ff4f87c3c34720ac26e902d6251c25a81546601e727ca875961a86b21a56c6aa8ea8b5412a5c05c885a44bf7efa323db909cdafbd5f87bd8bd90328c8f3323063677bb2ebbf385bccc1857a2beb6a0ce9feb23eb7bde83f12200aa4a3ee7aab8d216e2b085206cc",
    "credential_finalization": "a88839b8eabbf400d30e8f65fe9219045213af3a227643324eedce7042db99bb3bf40f6fa0939d75b0e4ddc9dcd751a09c321aa777bc5022e52e7d8314972ca6",
    "client_registration_state": "9a8f70c839f0a9dd821d00208f43e89442df2b844a0cf0dcc0508e8dd3cc3c0070617373776f7264",
    "client_login_state": "9a8f70c839f0a9dd821d00208f43e89442df2b844a0cf0dcc0508e8dd3cc3c000060beb3c2ade1d495856db52d9ce9c1729aae621a6b90a4e892a6f48e08a3290032f71932596f3e394216b5bacae7e1baa29ed87736bae5ffa311d81b57503391b4be80f3170a73645d10246cfa928e086c994d206c611468b1f5f053b82d3feb07004021bb9572af542ec7bf97487d81f3c80115f615067a8d1267722aea841d594108f71932596f3e394216b5bacae7e1baa29ed87736bae5ffa311d81b57503391b470617373776f7264",
    "server_login_state": "4d7cb8dac6a41b430f8d18e846461e5f6100f884f4916d7bd2e09f3642598358cabd9bc3e00a9fb6140d106ceab8c08437d9ea0967ffd31178f1e4659bf0571162b453052f9b0c0e6ba47dc6a7bf50d27702b3184164bdf8bb946b951b59d05298c24c401980856eb25590541316e324a0c32dae96ad8c0fb5995f8b69f37dabeff8b2b00ab3c5790b7277b63fef74bc61d4c2d4eed56690f33bb1ab0e7a0d3dfb51978be7b575b9ddf01ba5d6bb934267fc4c865d6a18aacc5246b6dddf519f",
    "password_file": "f637f1f78397fbc7fd403b2f2c0185a0d61749799e39f46c0f32c0e1629e4e35c903e24984244885abd0ba4e38249c22aeee196b7ab357c0eeb8c70118cb9ac6e377b835bb4b3d0677de272651d2e37da651e42b8dd2460b818fa0243fb69598aa831710cef76640aa5a9dc1442a20276fefb476a13ba0e58b503ef0ef1f2e0d5ddd6ad89f1c35cd5b5f8624ccf83b5e48ba57e1d29e4976ec3ca01dc4c83df5b3f5b891a2e67535d13e0baebc0aeee8807ba2a7254a376687dda6d527d7a069",
    "export_key": "11112a0747b2c943de39ac237ceed5b7e4a6a36359545cbb2cdd600c639603891d4ec768c63eb0a2d9b79282815369e2370449a8ab415f9bc12e5d8fc1c4b976",
    "session_key": "eff8b2b00ab3c5790b7277b63fef74bc61d4c2d4eed56690f33bb1ab0e7a0d3dfb51978be7b575b9ddf01ba5d6bb934267fc4c865d6a18aacc5246b6dddf519f"
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
    s.push_str(format!("\"fake_sk\": \"{}\",\n", hex::encode(&p.fake_sk)).as_str());
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
    let client_login_state = client_login_start_result
        .state
        .serialize()
        .unwrap()
        .to_vec();

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
            r#""vrPCreHUlYVttS2c6cFymq5iGmuQpOiSpvSOCKMpADI=""#
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
        hex::encode(client_login_start_result.state.serialize()?)
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

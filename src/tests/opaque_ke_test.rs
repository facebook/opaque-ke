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
    pub einfo2: Vec<u8>,
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
    "client_s_pk": "d762053e2da32c990b1edb22408138369282462feeaa68fc0acfd157c2745740",
    "client_s_sk": "b06303fb12bde8fb2875ffc052c0c0cdb4bbef7b6a32ec9bb4a00a3a56fb9545",
    "client_e_pk": "0375e9aa445b859a02e9ccacd45772758e560f8640ee067319a86374cd93a435",
    "client_e_sk": "c835f5854f1651c8551e24aee6ab1b81bf44e4cb906d0ac9fcf1aaa26ef3b872",
    "server_s_pk": "b7d6d756fb2b3972125245f53c042c53c8b3bf5e9d2b576809548c5510f33136",
    "server_s_sk": "b81e81698a315f4ee817e5c9bd4426db1bf8dd9fec2e6fc82639d08d90509e6f",
    "server_e_pk": "6ce63bc56b7b2141680b4fc4c8d3b4d09b903c5a2d657fc79432c586d0e9bd64",
    "server_e_sk": "a0f3efd594b41deaba4480cae066c658529b90754f5109f9b0b61d42266f234e",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "78b54192e145ff02458385f8540fdf54e94c2a20f0a7f8f98944bc17af795e04",
    "oprf_key": "98a9232ccfda91d14ea305e5cfb4e552ab8aa972ac6c79befe15ccf9f4f2970a",
    "envelope_nonce": "46c395bdc879bfebae229024f0004721448e713643a341146310d50c84cef011",
    "client_nonce": "197b1147bb214fafde9f5ce6f5e903d69be0ca006c51ac8f949ce7ab73a828ed",
    "server_nonce": "73a56c702168d9d534429fd45c37390ed6f55b6ea79f2025e4584a04d35aa229",
    "info1": "696e666f31",
    "einfo2": "65696e666f32",
    "registration_request": "0020ed5ca18ae23e622694611af62744f21c70f68d495ce36ae17784f03d225b573c",
    "registration_response": "002078b592b789e7239481637419438333cbdcd3dd909534ac28e5473683d023719d0020b7d6d756fb2b3972125245f53c042c53c8b3bf5e9d2b576809548c5510f33136",
    "registration_upload": "0146c395bdc879bfebae229024f0004721448e713643a341146310d50c84cef0110022f6906b64d3d45c4d77dd8c002b841749f716efc9e3e2cff762004b4878e75c0a7abe002c0020b7d6d756fb2b3972125245f53c042c53c8b3bf5e9d2b576809548c5510f33136000369645500036964530020e4444a287fc0bc8921d0c6423d36948fa176f68671196592cb947984b082bacd0020d762053e2da32c990b1edb22408138369282462feeaa68fc0acfd157c2745740",
    "credential_request": "0020ed5ca18ae23e622694611af62744f21c70f68d495ce36ae17784f03d225b573c197b1147bb214fafde9f5ce6f5e903d69be0ca006c51ac8f949ce7ab73a828ed0005696e666f310375e9aa445b859a02e9ccacd45772758e560f8640ee067319a86374cd93a435",
    "credential_response": "002078b592b789e7239481637419438333cbdcd3dd909534ac28e5473683d023719d0020b7d6d756fb2b3972125245f53c042c53c8b3bf5e9d2b576809548c5510f331360146c395bdc879bfebae229024f0004721448e713643a341146310d50c84cef0110022f6906b64d3d45c4d77dd8c002b841749f716efc9e3e2cff762004b4878e75c0a7abe002c0020b7d6d756fb2b3972125245f53c042c53c8b3bf5e9d2b576809548c5510f33136000369645500036964530020e4444a287fc0bc8921d0c6423d36948fa176f68671196592cb947984b082bacda0f3efd594b41deaba4480cae066c658529b90754f5109f9b0b61d42266f234e6ce63bc56b7b2141680b4fc4c8d3b4d09b903c5a2d657fc79432c586d0e9bd6400061e51f6093a7669db4e4a493137440cada18dcff631462e349de1d043a14a7a1de77b85638fbd",
    "key_exchange": "11d1a3f15b490c059bfa06f7d0fae9cde9ff6af80270f3327161a362ec84570e",
    "client_registration_state": "78b54192e145ff02458385f8540fdf54e94c2a20f0a7f8f98944bc17af795e0470617373776f7264",
    "client_login_state": "78b54192e145ff02458385f8540fdf54e94c2a20f0a7f8f98944bc17af795e04c835f5854f1651c8551e24aee6ab1b81bf44e4cb906d0ac9fcf1aaa26ef3b872197b1147bb214fafde9f5ce6f5e903d69be0ca006c51ac8f949ce7ab73a828ed3a139e3e250129a1d3e7633052f853006a501e24b1d3c6ba6403aeb9cca7eda170617373776f7264",
    "server_registration_state": "98a9232ccfda91d14ea305e5cfb4e552ab8aa972ac6c79befe15ccf9f4f2970a",
    "server_login_state": "8be81bab99a1ce566adb4f33d14b012a8583f0ecf8b467bad1930a6adbf7178dcc8daa2de4be476dde1d8193f9fe7786601d7db0af7302c19501b516ad5e53329706a48a68a6bbf3dea894447a53b423fc5b5e561c9c3fa9b1b278d6790bbb74",
    "password_file": "98a9232ccfda91d14ea305e5cfb4e552ab8aa972ac6c79befe15ccf9f4f2970ad762053e2da32c990b1edb22408138369282462feeaa68fc0acfd157c27457400146c395bdc879bfebae229024f0004721448e713643a341146310d50c84cef0110022f6906b64d3d45c4d77dd8c002b841749f716efc9e3e2cff762004b4878e75c0a7abe002c0020b7d6d756fb2b3972125245f53c042c53c8b3bf5e9d2b576809548c5510f33136000369645500036964530020e4444a287fc0bc8921d0c6423d36948fa176f68671196592cb947984b082bacd",
    "export_key": "3cdf9ad930b46fad7855faab02a7f2e28282cc73f82fdd411f1a7f6c300c8ab1",
    "shared_secret": "9706a48a68a6bbf3dea894447a53b423fc5b5e561c9c3fa9b1b278d6790bbb74"
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
    let einfo2 = b"einfo2";

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
        ClientLoginStartParameters::WithInfo(info1.to_vec()),
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
        einfo2: einfo2.to_vec(),
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
        ClientLoginStartParameters::WithInfo(parameters.info1),
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
fn test_key_exchange() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_login_finish_result =
        ClientLogin::<X255193dhNoSlowHash>::try_from(&parameters.client_login_state[..])
            .unwrap()
            .finish(
                CredentialResponse::<X255193dhNoSlowHash>::deserialize(
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

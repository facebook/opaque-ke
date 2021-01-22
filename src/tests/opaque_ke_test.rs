// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    errors::*,
    group::Group,
    key_exchange::tripledh::{TripleDH, NONCE_LEN},
    keypair::Key,
    opaque::*,
    slow_hash::NoOpHash,
    tests::mock_rng::CycleRng,
    *,
};
use curve25519_dalek::ristretto::RistrettoPoint;
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
    "client_s_pk": "64b071d0b8eccc39673b16384e86df49f258a12bad24f21f5d5f4a9a8f45561c",
    "client_s_sk": "98a23d0757ac5c7aba8b218c5643c3a3029fb815a656de24cfc05df877925809",
    "client_e_pk": "3a575317d7a6269bc4e76074ec906d8886b4c135fb6b590972f6fdd6c1a55676",
    "client_e_sk": "163b91328785a5e84e21579e941be1dd7bdbc44d4c959f603d7f79417ab6b201",
    "server_s_pk": "fc0d7d59e0fabe7c876c01c8d5408fc60dc5fdec7b89acdc5af2bc7c0de26d75",
    "server_s_sk": "f7068582fdf2a57f7da63e6f5142abda805a7b508ce171c84f58a4e5e634a406",
    "server_e_pk": "8e32a64f670b9d2115eba0006b00667972523bf2f8686933ef2a2819d6b5a13b",
    "server_e_sk": "a3a06d81eeb60aeedaee96769149ae5f45184eec66e1b2bdeb04114d27019206",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "3497d8c6728a3dc0873e363dcd60acd95f7897d15d33cdf1d49c8b856f061900",
    "oprf_key": "c728d1ea06fb94f577ef63d50d1645e9fea14575987971e4a64e05dda367c703",
    "envelope_nonce": "d7d138a3a4cb796662814391f5221e05b66438a92e5f57cc9624e6227da34eab",
    "client_nonce": "ad87ae4609f1f56aeb1de0f4760120fa75ceff39751dffc35d25ff3f2896bb60",
    "server_nonce": "d7a8cd7cd2c4f0f7650390f6f2d4858ae99ac79f2769a9e15583d570b11c434c",
    "info1": "696e666f31",
    "einfo2": "65696e666f32",
    "registration_request": "002096738fbc9883a85a8067763abe33efadce0adb2bc64857d3cd0a6cc92e9ce325",
    "registration_response": "0020a86baffac435f6239cfe5f61d823e7458ac211dce1d3c364375e9d1f40843c750020fc0d7d59e0fabe7c876c01c8d5408fc60dc5fdec7b89acdc5af2bc7c0de26d75",
    "registration_upload": "01d7d138a3a4cb796662814391f5221e05b66438a92e5f57cc9624e6227da34eab002229979df679067f8baecbbe063ee97e2b5be88c2b99163d595b32a74d640138771d70002c0020fc0d7d59e0fabe7c876c01c8d5408fc60dc5fdec7b89acdc5af2bc7c0de26d750003696455000369645300400b6119d0de405d85e0e6b1748eb66194b1768ea71fd47c103f8e1fcbc837add2b282889469921798d626a02b6dd763ee9cd028f333386a19c13a3d4d4c6a3312002064b071d0b8eccc39673b16384e86df49f258a12bad24f21f5d5f4a9a8f45561c",
    "credential_request": "002096738fbc9883a85a8067763abe33efadce0adb2bc64857d3cd0a6cc92e9ce325ad87ae4609f1f56aeb1de0f4760120fa75ceff39751dffc35d25ff3f2896bb600005696e666f313a575317d7a6269bc4e76074ec906d8886b4c135fb6b590972f6fdd6c1a55676",
    "credential_response": "0020a86baffac435f6239cfe5f61d823e7458ac211dce1d3c364375e9d1f40843c750020fc0d7d59e0fabe7c876c01c8d5408fc60dc5fdec7b89acdc5af2bc7c0de26d7501d7d138a3a4cb796662814391f5221e05b66438a92e5f57cc9624e6227da34eab002229979df679067f8baecbbe063ee97e2b5be88c2b99163d595b32a74d640138771d70002c0020fc0d7d59e0fabe7c876c01c8d5408fc60dc5fdec7b89acdc5af2bc7c0de26d750003696455000369645300400b6119d0de405d85e0e6b1748eb66194b1768ea71fd47c103f8e1fcbc837add2b282889469921798d626a02b6dd763ee9cd028f333386a19c13a3d4d4c6a3312a3a06d81eeb60aeedaee96769149ae5f45184eec66e1b2bdeb04114d270192068e32a64f670b9d2115eba0006b00667972523bf2f8686933ef2a2819d6b5a13b00066c7c22ba8dbae814beb02d1b89659379ca61697cd3212169d387b61f5659b77f6993833a1542a692cb5ad259244a1d53a51243fb5366a5bd8e4ed7eb2f50caa9a568fc8267e9",
    "key_exchange": "3f9d3754920514328529bf4e78d4c2d0f411dfb871a4ef83c87d3462119b836381bdc651096cb62ca96de5f4b5a9acaa87b180d2acefebd2f3feb5785adcd038",
    "client_registration_state": "3497d8c6728a3dc0873e363dcd60acd95f7897d15d33cdf1d49c8b856f06190070617373776f7264",
    "client_login_state": "3497d8c6728a3dc0873e363dcd60acd95f7897d15d33cdf1d49c8b856f061900163b91328785a5e84e21579e941be1dd7bdbc44d4c959f603d7f79417ab6b201ad87ae4609f1f56aeb1de0f4760120fa75ceff39751dffc35d25ff3f2896bb607962b421c96efcfdb465365eea8fe9914e6ac5c0b216e2b07c7fb3b17fa0d21ee8c37373fee8dfec6a5eae559f21c8c4e1505ed974ce8baff3529304cb4d90b570617373776f7264",
    "server_registration_state": "c728d1ea06fb94f577ef63d50d1645e9fea14575987971e4a64e05dda367c703",
    "server_login_state": "644fb6d36a91e0197f5d82d17f04354f9e24794988923160534d99c80970b66fe54a3d8b36d5a4d21eaf0fa7bb4717ed1741be3f7d24b96d27aeb7f4b59a72bf80d0d969a2398ea5a5232d3257c60516dcc0de65b66fc5a07b8e2f58523eb0079ac09798a23cee0e31454594d25e40f34b10b92195fea6f90e197c0fbc8658bb3435bb6179370029f03d2dbd5efa2d0f8b8f4f69ca42ef70245686f70c2d7f326d0a8bc596145099e6a668d23ce1a93f9a3f83bfdddde15c78f467a639f124dd",
    "password_file": "c728d1ea06fb94f577ef63d50d1645e9fea14575987971e4a64e05dda367c70364b071d0b8eccc39673b16384e86df49f258a12bad24f21f5d5f4a9a8f45561c01d7d138a3a4cb796662814391f5221e05b66438a92e5f57cc9624e6227da34eab002229979df679067f8baecbbe063ee97e2b5be88c2b99163d595b32a74d640138771d70002c0020fc0d7d59e0fabe7c876c01c8d5408fc60dc5fdec7b89acdc5af2bc7c0de26d750003696455000369645300400b6119d0de405d85e0e6b1748eb66194b1768ea71fd47c103f8e1fcbc837add2b282889469921798d626a02b6dd763ee9cd028f333386a19c13a3d4d4c6a3312",
    "export_key": "005ba69bed794d3e24ac750ed575165a0235e103d1f8d7ca1b9aa0cfc2c3d9b6",
    "shared_secret": "3435bb6179370029f03d2dbd5efa2d0f8b8f4f69ca42ef70245686f70c2d7f326d0a8bc596145099e6a668d23ce1a93f9a3f83bfdddde15c78f467a639f124dd"
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
    let mut client_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut client_nonce);
    let mut server_nonce = [0u8; NONCE_LEN];
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
    let result = ClientRegistration::<RistrettoSha5123dhNoSlowHash>::try_from(
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

    let server_registration = ServerRegistration::<RistrettoSha5123dhNoSlowHash>::try_from(
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

    let mut server_e_sk_rng = CycleRng::new(parameters.server_e_sk);
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_e_sk_rng,
        ServerRegistration::try_from(&parameters.password_file[..]).unwrap(),
        &Key::try_from(&parameters.server_s_sk[..]).unwrap(),
        CredentialRequest::<RistrettoSha5123dhNoSlowHash>::deserialize(
            &parameters.credential_request[..],
        )
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
        ClientLogin::<RistrettoSha5123dhNoSlowHash>::try_from(&parameters.client_login_state[..])
            .unwrap()
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
        ServerLogin::<RistrettoSha5123dhNoSlowHash>::try_from(&parameters.server_login_state[..])?
            .finish(CredentialFinalization::try_from(
                &parameters.key_exchange[..],
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

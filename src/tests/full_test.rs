// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#![allow(unsafe_code)]

use crate::{
    ciphersuite::CipherSuite, errors::*, key_exchange::tripledh::TripleDH, keypair::Key, opaque::*,
    slow_hash::NoOpHash, tests::mock_rng::CycleRng, *,
};

#[cfg(feature = "std")]
use crate::group::Group;
#[cfg(feature = "std")]
use crate::key_exchange::tripledh::NonceLen;
#[cfg(feature = "std")]
use generic_array::typenum::Unsigned;
#[cfg(feature = "std")]
use rand::RngCore;

use alloc::vec;
use alloc::vec::Vec;
use core::slice::from_raw_parts;
use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use rand::rngs::OsRng;
use serde_json::Value;
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

static STR_PASSWORD: &str = "password";

static TEST_VECTOR: &str = r#"
{
    "client_s_pk": "4275bd003b150aa16dfe06cff83669e2edcf78c18e7608426e5e0d4b706dba18",
    "client_s_sk": "f0bc6e351b8354e41566c8c9629a9cdceeca640f7e473adaaa1892d97c80640f",
    "client_e_pk": "165f15328fe643007508b702b14888a14a3bae283cfe5f427aac3e4aae4ca844",
    "client_e_sk": "c573022221ca5e98bab4556a0d29a8fce930b1b8ac6919f14dc35dececf5c10e",
    "server_s_pk": "64b44e3d26748057e3d06cc38711e98121ba0baaf8124e95b27ee9d59feabc5b",
    "server_s_sk": "12be4dd74732e5a4d4eb4069ffa8b5ee19c99f3a61607dad29db239fab868007",
    "server_e_pk": "d2b56121a97769d578f80d5ffa653b781a7a1db6297a951afd43ef74d132aa53",
    "server_e_sk": "1cd12dc39777dd5a3bfd4969de2402d9cb074837faa996425e871458e71b7404",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "f8ab29fa00f1412b78b2f4c993ae3fab4ee644ddf30a784892b3d0d81d838200",
    "oprf_key": "ca00ce46525fa67aa5101420f2f0643c3e5c12ac8e283d83d7d28213ca777a08",
    "envelope_nonce": "2695cb3afd4df2029b8d3353f7220876619ad8109e27da917114245071613474",
    "client_nonce": "8b7a191f297023b5abdf54c4896d57d0c168a2dde7dce00f32886c016298f606",
    "server_nonce": "2477b1825fc64764e309facda26b5cb046af668d1c2a4e88aab0138317784825",
    "info1": "696e666f31",
    "einfo2": "65696e666f32",
    "registration_request": "28259e84c7eb4b776a87481d4761cafac4b5585bf6f7f4939734c422fc82aa5d",
    "registration_response": "94a37d9174f7083c44f85017027a6371941ad74eb35b2c666498bd7c5eef3c2a64b44e3d26748057e3d06cc38711e98121ba0baaf8124e95b27ee9d59feabc5b",
    "registration_upload": "4275bd003b150aa16dfe06cff83669e2edcf78c18e7608426e5e0d4b706dba18022695cb3afd4df2029b8d3353f7220876619ad8109e27da9171142450716134746a4dba2b7bf8e8763cad213fa81c9511135be6e42c44a2806e9fb416dc760884136277c6644682cddbf03a8472dca2925ceb9d7d804c7b616843bdf4e80ae35672aff300a03dfb6e79c9079509645a790f792caebc9b07003ead9d98d1d179c1",
    "credential_request": "28259e84c7eb4b776a87481d4761cafac4b5585bf6f7f4939734c422fc82aa5d8b7a191f297023b5abdf54c4896d57d0c168a2dde7dce00f32886c016298f6060005696e666f31165f15328fe643007508b702b14888a14a3bae283cfe5f427aac3e4aae4ca844",
    "credential_response": "94a37d9174f7083c44f85017027a6371941ad74eb35b2c666498bd7c5eef3c2a64b44e3d26748057e3d06cc38711e98121ba0baaf8124e95b27ee9d59feabc5b022695cb3afd4df2029b8d3353f7220876619ad8109e27da9171142450716134746a4dba2b7bf8e8763cad213fa81c9511135be6e42c44a2806e9fb416dc760884136277c6644682cddbf03a8472dca2925ceb9d7d804c7b616843bdf4e80ae35672aff300a03dfb6e79c9079509645a790f792caebc9b07003ead9d98d1d179c12477b1825fc64764e309facda26b5cb046af668d1c2a4e88aab0138317784825d2b56121a97769d578f80d5ffa653b781a7a1db6297a951afd43ef74d132aa530006b71e6bcb7951b448e2b8ad7ab0b358019af909e03090e0f5a65d0f26186e31b10bfc1024e60a5f0c2dbb2648b33d59a3447e9d5618048efe55b7ea9476f90132520d78e3d91f",
    "credential_finalization": "0df019bc4652ad1539de43bfdd33761ac0b526ff27c46fd1d7c89c6d46c5d179beeab30c060cf7bf0e17114812c1ac9d90369e76c6284e4a04b43ff9a67afb87",
    "client_registration_state": "28259e84c7eb4b776a87481d4761cafac4b5585bf6f7f4939734c422fc82aa5df8ab29fa00f1412b78b2f4c993ae3fab4ee644ddf30a784892b3d0d81d83820070617373776f7264",
    "client_login_state": "f8ab29fa00f1412b78b2f4c993ae3fab4ee644ddf30a784892b3d0d81d838200006728259e84c7eb4b776a87481d4761cafac4b5585bf6f7f4939734c422fc82aa5d8b7a191f297023b5abdf54c4896d57d0c168a2dde7dce00f32886c016298f6060005696e666f31165f15328fe643007508b702b14888a14a3bae283cfe5f427aac3e4aae4ca8440040c573022221ca5e98bab4556a0d29a8fce930b1b8ac6919f14dc35dececf5c10e8b7a191f297023b5abdf54c4896d57d0c168a2dde7dce00f32886c016298f60670617373776f7264",
    "server_registration_state": "ca00ce46525fa67aa5101420f2f0643c3e5c12ac8e283d83d7d28213ca777a08",
    "server_login_state": "b4c7da6422bd9558887022647974a6b391df989ba0f421eec64bdd8e8329f2aec5fab88b8fd55a2071ac02ffd67acb35a3a7d1a3d9dcbb5406542a2a24b1ed6d7378a115cb801e1cd64c152bfbde36b4c22d77e5d98888ec9af51489315ade5f3f34252c9aafc211e7de9703a039def76adef33074be35a978e729ca125aecfed13415079fc276064cb61eada57c6b59041fbd8cdf4ba55cfb8a5ea9c6e100f85b6cfdd85ffbe99e6e2d80fc9c5f8399aa838e384e8451ce78efde5aa8f03c15",
    "password_file": "ca00ce46525fa67aa5101420f2f0643c3e5c12ac8e283d83d7d28213ca777a084275bd003b150aa16dfe06cff83669e2edcf78c18e7608426e5e0d4b706dba18022695cb3afd4df2029b8d3353f7220876619ad8109e27da9171142450716134746a4dba2b7bf8e8763cad213fa81c9511135be6e42c44a2806e9fb416dc760884136277c6644682cddbf03a8472dca2925ceb9d7d804c7b616843bdf4e80ae35672aff300a03dfb6e79c9079509645a790f792caebc9b07003ead9d98d1d179c1",
    "export_key": "88514619c2a0ec5567cedb69c6d0e5596ace9bf5414b326e3cb80f41a62d55d4343f2c5eb41b030f25cbf9d9d0956a20cf70255f356f143f15a175a3adaa37c2",
    "session_key": "d13415079fc276064cb61eada57c6b59041fbd8cdf4ba55cfb8a5ea9c6e100f85b6cfdd85ffbe99e6e2d80fc9c5f8399aa838e384e8451ce78efde5aa8f03c15"
}
"#;

fn decode(values: &Value, key: &str) -> Option<Vec<u8>> {
    values[key].as_str().and_then(|s| hex::decode(s).ok())
}

fn populate_test_vectors(values: &Value) -> TestVectorParameters {
    TestVectorParameters {
        client_s_pk: decode(values, "client_s_pk").unwrap(),
        client_s_sk: decode(values, "client_s_sk").unwrap(),
        client_e_pk: decode(values, "client_e_pk").unwrap(),
        client_e_sk: decode(values, "client_e_sk").unwrap(),
        server_s_pk: decode(values, "server_s_pk").unwrap(),
        server_s_sk: decode(values, "server_s_sk").unwrap(),
        server_e_pk: decode(values, "server_e_pk").unwrap(),
        server_e_sk: decode(values, "server_e_sk").unwrap(),
        id_u: decode(values, "id_u").unwrap(),
        id_s: decode(values, "id_s").unwrap(),
        password: decode(values, "password").unwrap(),
        blinding_factor: decode(values, "blinding_factor").unwrap(),
        oprf_key: decode(values, "oprf_key").unwrap(),
        envelope_nonce: decode(values, "envelope_nonce").unwrap(),
        client_nonce: decode(values, "client_nonce").unwrap(),
        server_nonce: decode(values, "server_nonce").unwrap(),
        info1: decode(values, "info1").unwrap(),
        einfo2: decode(values, "einfo2").unwrap(),
        registration_request: decode(values, "registration_request").unwrap(),
        registration_response: decode(values, "registration_response").unwrap(),
        registration_upload: decode(values, "registration_upload").unwrap(),
        credential_request: decode(values, "credential_request").unwrap(),
        credential_response: decode(values, "credential_response").unwrap(),
        credential_finalization: decode(values, "credential_finalization").unwrap(),
        client_registration_state: decode(values, "client_registration_state").unwrap(),
        client_login_state: decode(values, "client_login_state").unwrap(),
        server_registration_state: decode(values, "server_registration_state").unwrap(),
        server_login_state: decode(values, "server_login_state").unwrap(),
        password_file: decode(values, "password_file").unwrap(),
        export_key: decode(values, "export_key").unwrap(),
        session_key: decode(values, "session_key").unwrap(),
    }
}

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
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

    let blinding_factor = CS::Group::random_nonzero_scalar(&mut rng);
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
    let credential_request_bytes = client_login_start_result
        .message
        .serialize()
        .unwrap()
        .to_vec();
    let client_login_state = client_login_start_result
        .state
        .serialize()
        .unwrap()
        .to_vec();

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
    let credential_response_bytes = server_login_start_result
        .message
        .serialize()
        .unwrap()
        .to_vec();
    let server_login_state = server_login_start_result
        .state
        .serialize()
        .unwrap()
        .to_vec();

    let client_login_finish_result = client_login_start_result
        .state
        .finish(
            server_login_start_result.message,
            ClientLoginFinishParameters::WithIdentifiers(id_u.to_vec(), id_s.to_vec()),
        )
        .unwrap();
    let credential_finalization_bytes = client_login_finish_result.message.serialize().unwrap();

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
        session_key: client_login_finish_result.session_key.clone(),
        export_key: client_registration_finish_result.export_key.to_vec(),
    }
}

#[cfg(feature = "std")]
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
            &Key::from_bytes(&parameters.server_s_pk[..])?,
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
        hex::encode(result.export_key)
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
        hex::encode(client_login_start_result.message.serialize().unwrap())
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

    let mut server_e_sk_and_nonce_rng =
        CycleRng::new([parameters.server_e_sk, parameters.server_nonce].concat());
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_e_sk_and_nonce_rng,
        ServerRegistration::deserialize(&parameters.password_file[..])?,
        &Key::from_bytes(&parameters.server_s_sk[..])?,
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
        hex::encode(server_login_start_result.message.serialize().unwrap())
    );
    assert_eq!(
        hex::encode(&parameters.server_login_state),
        hex::encode(server_login_start_result.state.serialize().unwrap())
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
        hex::encode(client_login_finish_result.server_s_pk.to_arr())
    );
    assert_eq!(
        hex::encode(&parameters.session_key),
        hex::encode(&client_login_finish_result.session_key)
    );
    assert_eq!(
        hex::encode(&parameters.credential_finalization),
        hex::encode(client_login_finish_result.message.serialize().unwrap())
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
        server_kp.private(),
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
    state.zeroize();
    let ptrs = state.as_byte_ptrs();

    for (ptr, len) in ptrs {
        let bytes = unsafe { from_raw_parts(ptr, len) };
        assert!(bytes.iter().all(|&x| x == 0));
    }

    Ok(())
}

#[test]
fn test_zeroize_server_registration_start() -> Result<(), ProtocolError> {
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_kp = RistrettoSha5123dhNoSlowHash::generate_random_keypair(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
        )?;
    let server_registration_start_result =
        ServerRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut server_rng,
            client_registration_start_result.message,
            server_kp.public(),
        )?;

    let mut state = server_registration_start_result.state;
    state.zeroize();
    let ptrs = state.as_byte_ptrs();

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
    let server_kp = RistrettoSha5123dhNoSlowHash::generate_random_keypair(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
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

    let mut state = client_registration_finish_result.state;
    state.zeroize();
    let ptrs = state.as_byte_ptrs();

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
    let server_kp = RistrettoSha5123dhNoSlowHash::generate_random_keypair(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
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

    let mut state = p_file;
    state.zeroize();
    let ptrs = state.as_byte_ptrs();

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
        ClientLoginStartParameters::default(),
    )?;

    let mut state = client_login_start_result.state;
    state.zeroize();
    let ptrs = state.as_byte_ptrs();

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
    let server_kp = RistrettoSha5123dhNoSlowHash::generate_random_keypair(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
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
        STR_PASSWORD.as_bytes(),
        ClientLoginStartParameters::default(),
    )?;
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_rng,
        p_file,
        server_kp.private(),
        client_login_start_result.message,
        ServerLoginStartParameters::default(),
    )?;

    let mut state = server_login_start_result.state;
    state.zeroize();
    let ptrs = state.as_byte_ptrs();

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
    let server_kp = RistrettoSha5123dhNoSlowHash::generate_random_keypair(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
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
        STR_PASSWORD.as_bytes(),
        ClientLoginStartParameters::default(),
    )?;
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_rng,
        p_file,
        server_kp.private(),
        client_login_start_result.message,
        ServerLoginStartParameters::default(),
    )?;
    let client_login_finish_result = client_login_start_result.state.finish(
        server_login_start_result.message,
        ClientLoginFinishParameters::default(),
    )?;

    let mut state = client_login_finish_result.state;
    state.zeroize();
    let ptrs = state.as_byte_ptrs();

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
    let server_kp = RistrettoSha5123dhNoSlowHash::generate_random_keypair(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
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
        STR_PASSWORD.as_bytes(),
        ClientLoginStartParameters::default(),
    )?;
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_rng,
        p_file,
        server_kp.private(),
        client_login_start_result.message,
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
    state.zeroize();
    let ptrs = state.as_byte_ptrs();

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

#[test]
fn test_reflected_value_error_registration() -> Result<(), ProtocolError> {
    let password = b"password";
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_kp = RistrettoSha5123dhNoSlowHash::generate_random_keypair(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(&mut client_rng, password)?;
    let alpha = client_registration_start_result
        .message
        .get_alpha_for_testing();
    let server_registration_start_result =
        ServerRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &mut server_rng,
            client_registration_start_result.message,
            server_kp.public(),
        )?;

    let reflected_registration_response = server_registration_start_result
        .message
        .set_beta_for_testing(alpha);

    let client_registration_finish_result = client_registration_start_result.state.finish(
        &mut client_rng,
        reflected_registration_response,
        ClientRegistrationFinishParameters::default(),
    );

    assert!(match client_registration_finish_result {
        Err(ProtocolError::ReflectedValueError) => true,
        _ => false,
    });

    Ok(())
}

#[test]
fn test_reflected_value_error_login() -> Result<(), ProtocolError> {
    let password = b"password";
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_kp = RistrettoSha5123dhNoSlowHash::generate_random_keypair(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(&mut client_rng, password)?;
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
        password,
        ClientLoginStartParameters::default(),
    )?;
    let alpha = client_login_start_result.message.get_alpha_for_testing();
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_rng,
        p_file,
        server_kp.private(),
        client_login_start_result.message,
        ServerLoginStartParameters::default(),
    )?;

    let reflected_credential_response = server_login_start_result
        .message
        .set_beta_for_testing(alpha);

    let client_login_result = client_login_start_result.state.finish(
        reflected_credential_response,
        ClientLoginFinishParameters::default(),
    );

    assert!(match client_login_result {
        Err(ProtocolError::ReflectedValueError) => true,
        _ => false,
    });
    Ok(())
}

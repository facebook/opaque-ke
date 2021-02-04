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
    "client_s_pk": "3a776afc0ba554a731cc8e2c8fef1ba3e9110195a7902d9b15ecc1352867833e",
    "client_s_sk": "bd42afe22725696df96e193ff4d0580e565ad8b769ea718f343245ea83625505",
    "client_e_pk": "c22c46082bae3fcb2e5690c0c9a27fa59f752ff9a78ad5c41a18f7f665a3da05",
    "client_e_sk": "21616ff86563a235ab01eb7e13f057b1cae8533dc7a4e99076e56d29f948c40b",
    "server_s_pk": "d685d935664b0f8175456c9594cb3205329352970a560a4efedb5bfb39335811",
    "server_s_sk": "5e37d39ed0c5880c748818b834d97fd8235f4b77a7e06287664c02e5bafd6407",
    "server_e_pk": "0202a269a71da47901e071eab4702d92288e9e3ac12b77cc9eae1a6a3be5bf25",
    "server_e_sk": "055453a054b87b50c8e9f2ae4eac6e56348ec82b3e3271d843a958b0f634ed0b",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "67c5f74c953923c950c978b332f306454a8dc7ae7888449281b9d550ab05e204",
    "oprf_key": "94ddb3f439fb4d69ac31b3220604066316b370b4402403d04f9efece28d6a00f",
    "envelope_nonce": "c2956142808696bc993b1b1424166afcf0e7de8ba45d8348cd5ff0fbbf528485",
    "client_nonce": "b61c639342a00e60652c0567423bc332fc7af6558da4651bd53b89f688fc1274",
    "server_nonce": "ebb9dcbbfe8776aa3831763a4172f6e95cec5714d08a0e0a03151f561135c416",
    "info1": "696e666f31",
    "einfo2": "65696e666f32",
    "registration_request": "5ea0a0a57a2882691c3fc8e0dfe09bf05b130723b24371f8ac03b9c75d0d5b79",
    "registration_response": "c0ebf6cc43f92c2da075f93da39cb37d7571e61c26bfab69bbcdb35a0a313e260020d685d935664b0f8175456c9594cb3205329352970a560a4efedb5bfb39335811",
    "registration_upload": "00203a776afc0ba554a731cc8e2c8fef1ba3e9110195a7902d9b15ecc1352867833e01c2956142808696bc993b1b1424166afcf0e7de8ba45d8348cd5ff0fbbf52848500223b28798f911bb2f0c6cc626f27daf055271234dc1c1e32df59e864cffe946dfb02795cc53d6bcadf5e9535341c473f72b7ea88f4ff87fe941c0dace9f9975fa8887ac0bb7c84a5028fcdd10b41f9216523ba3513c95eb127437155feb0c022469334",
    "credential_request": "5ea0a0a57a2882691c3fc8e0dfe09bf05b130723b24371f8ac03b9c75d0d5b79b61c639342a00e60652c0567423bc332fc7af6558da4651bd53b89f688fc12740005696e666f31c22c46082bae3fcb2e5690c0c9a27fa59f752ff9a78ad5c41a18f7f665a3da05",
    "credential_response": "c0ebf6cc43f92c2da075f93da39cb37d7571e61c26bfab69bbcdb35a0a313e260020d685d935664b0f8175456c9594cb3205329352970a560a4efedb5bfb3933581101c2956142808696bc993b1b1424166afcf0e7de8ba45d8348cd5ff0fbbf52848500223b28798f911bb2f0c6cc626f27daf055271234dc1c1e32df59e864cffe946dfb02795cc53d6bcadf5e9535341c473f72b7ea88f4ff87fe941c0dace9f9975fa8887ac0bb7c84a5028fcdd10b41f9216523ba3513c95eb127437155feb0c022469334ebb9dcbbfe8776aa3831763a4172f6e95cec5714d08a0e0a03151f561135c4160202a269a71da47901e071eab4702d92288e9e3ac12b77cc9eae1a6a3be5bf250006148cc6985fd9c04245efa02487d25a5e4ffa64fdb7f7fd627839ca70f29da495e59489891e14b7122656edcf2bfc788f92bf458fac31d4b0ddd6b6aa764e08c56d16e803e919",
    "credential_finalization": "c6c0ccf4e5155b2cecabc61efc289824e00eb2e5d3c15d508100d35d8f0d3ba317797270af96cd4610b954ec21898f2e9df02411c21352a3220259034c711487",
    "client_registration_state": "67c5f74c953923c950c978b332f306454a8dc7ae7888449281b9d550ab05e20470617373776f7264",
    "client_login_state": "67c5f74c953923c950c978b332f306454a8dc7ae7888449281b9d550ab05e20400675ea0a0a57a2882691c3fc8e0dfe09bf05b130723b24371f8ac03b9c75d0d5b79b61c639342a00e60652c0567423bc332fc7af6558da4651bd53b89f688fc12740005696e666f31c22c46082bae3fcb2e5690c0c9a27fa59f752ff9a78ad5c41a18f7f665a3da05004021616ff86563a235ab01eb7e13f057b1cae8533dc7a4e99076e56d29f948c40bb61c639342a00e60652c0567423bc332fc7af6558da4651bd53b89f688fc127470617373776f7264",
    "server_registration_state": "94ddb3f439fb4d69ac31b3220604066316b370b4402403d04f9efece28d6a00f",
    "server_login_state": "fa7795f9a3a3f93e950d4d902689157f98cdf839fe64847b9b24dc2c7d07e9d674cdcb3db4c7653dcf133c49eadbf2b3a0665e19c37461352a8bdce781cefd5d8c8153b0b60a3abbb9cc2a34fe3c53541b1e7df3216d3bac1e8280fa697db9ee6b2468e585f9912bd227c51b702671691b6d6a3542db4597c18013fbae903b5c9d5ff920b8a7231d717155af4475b3591973245b9dd26cf956383e8145fa3e8c1e508b72f3e3c42e3d116611b676780628591acf37757c74ad297f71a0b54b39",
    "password_file": "94ddb3f439fb4d69ac31b3220604066316b370b4402403d04f9efece28d6a00f3a776afc0ba554a731cc8e2c8fef1ba3e9110195a7902d9b15ecc1352867833e01c2956142808696bc993b1b1424166afcf0e7de8ba45d8348cd5ff0fbbf52848500223b28798f911bb2f0c6cc626f27daf055271234dc1c1e32df59e864cffe946dfb02795cc53d6bcadf5e9535341c473f72b7ea88f4ff87fe941c0dace9f9975fa8887ac0bb7c84a5028fcdd10b41f9216523ba3513c95eb127437155feb0c022469334",
    "export_key": "c250b23ac69b71bcc246db97398487198c94c73c84e1256b57c3ceb32a76fdc7547a8953bfc94b530e5b660f559faa53572f98ec0168e378087017b9a7393f57",
    "shared_secret": "9d5ff920b8a7231d717155af4475b3591973245b9dd26cf956383e8145fa3e8c1e508b72f3e3c42e3d116611b676780628591acf37757c74ad297f71a0b54b39"
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

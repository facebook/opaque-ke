// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#![allow(unsafe_code)]

use crate::{
    ciphersuite::CipherSuite, errors::*, key_exchange::tripledh::TripleDH, opaque::*,
    slow_hash::NoOpHash, tests::mock_rng::CycleRng, *,
};
use alloc::string::ToString;
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
    type OprfGroup = RistrettoPoint;
    type KeGroup = RistrettoPoint;
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

// To regenerate, run: cargo test -- --nocapture generate_test_vectors
static TEST_VECTOR: &str = r#"
{
    "client_s_pk": "520364faf278ac5b407465c8a802ac57bf61ec4bbf3e1c508a39e1667c7cf904",
    "client_s_sk": "e30c1ca67d865b65333bd5567a3ea54c6df36d1641953ca4470a886e7117bf06",
    "client_e_pk": "1c0344d0e057a1f6651d80b00e188aa35efb4844173c531d186729f81411bc24",
    "client_e_sk": "56b7ff7a43c7d6f75d881606f733c12a53af70b35d8c5cd982a8e94a816dfa0d",
    "server_s_pk": "bcf39fe745ca2f945c7d75b542bfe4217fe6f481c49b7ce410f4a13079cd0d2b",
    "server_s_sk": "cd4a4916bf0226c7fa1f18c97cbf5e0c03d1ae8b74d1155270202d848f4d640e",
    "server_e_pk": "e02644fdcb782c335c0c1f801b70f7a873bc2613e3ed2a6ad05103a85dd2ec01",
    "server_e_sk": "b9b14238988b6ea6e6aa6e8981a65c45e28ba01ddedf9437aff62a7071a64d09",
    "fake_sk": "55ed2b029216bd0953db96c614c737001fc9c79ad4b2c896f2aeebe052e9770a",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "1d906fc19848da043a39b51b22620802d7df4f11abf994a269d7ada2cc7edd04",
    "oprf_seed": "aee2ac3f7c043526f1cbda952f34840482a63afbf959e32f9172343d8b9fe076cd0a87a017f16e6511c37f171cea277d906d6d1dc31a3de4c0cc99c46e76c94c",
    "masking_nonce": "62f49aa47625d01466051799e1ba6f99e1916c15fa1cc651867d1bbc55c6c5255269d21a5854a9756ffd8fc33de366da1d715c5de16609f7aa55e7e8ce01c8f5",
    "envelope_nonce": "3cf5a62a4ce8ffe7e1da0ac2066597f1d7cd7a91285e8a108943f6beea91b1aa",
    "client_nonce": "de58ba7427030a4792107bf9f4a9334599f4e437d97a73ae1db4f1d3f9362879",
    "server_nonce": "50d85de8a9a6fb656981a17811db0a381dd98aa37514a90d8abf990b56829daf",
    "context": "636f6e74657874",
    "registration_request": "7ea276a79194704a5056d17c3e2e1751d98b1d1fc5d1d78d11004e9a44c7c52c",
    "registration_response": "389fcdd9b327e1ad9eaa30b8ea9db665b49a52b96583c4952f087d21aa47e15abcf39fe745ca2f945c7d75b542bfe4217fe6f481c49b7ce410f4a13079cd0d2b",
    "registration_upload": "7a1daeb91dc6af4e8685287922020dda9e4445ddb107aa76f30ef3defec982046c81af9eba7baef5e5dc3aca419a62b207542315edc732834b18fa394cbfa9c210caed864e36bb19cdd7324553b7e35d1a7384f4262a15e38049f910b2ca6baae30c1ca67d865b65333bd5567a3ea54c6df36d1641953ca4470a886e7117bf06383ff4ec0a1f237f70e51cae0f859e7476917cb8d28cda3aeccd970a205a71e20d3e592eaadabc2216d0ed14e494dbf733984e607b6d5f8b68f9b2321ca01b30",
    "credential_request": "7ea276a79194704a5056d17c3e2e1751d98b1d1fc5d1d78d11004e9a44c7c52cde58ba7427030a4792107bf9f4a9334599f4e437d97a73ae1db4f1d3f93628791c0344d0e057a1f6651d80b00e188aa35efb4844173c531d186729f81411bc24",
    "credential_response": "389fcdd9b327e1ad9eaa30b8ea9db665b49a52b96583c4952f087d21aa47e15a62f49aa47625d01466051799e1ba6f99e1916c15fa1cc651867d1bbc55c6c5257e7d8f435b95456607ec8767840b5c192c1132d78b38cf72511ae4605a8539f570452bbfd864a34a71b635f77c9d7dee227b7906697ab0dea2dda3043672c523a0a2c651e9bbef212e85439c8f227c564470cdb6d9a74ac8b7d2f6f3eba59b43489082c93f17f7de3c2840848e2c5db07bf4a8c5011f6ff01895bcb0a3b10ca0b9b14238988b6ea6e6aa6e8981a65c45e28ba01ddedf9437aff62a7071a64d098eaf6a09f9dd3db7e9ea307c4df21852c24fdd27bc335815afdfa03237facb0834b5d393d8b5d61526d8a61077a345a864020a10be67f46a6a6a02fd86ea05a2f25e262d9fe23bfe9489d5bc585dd4a018fa5dea295e51a7824526b6360cc03a",
    "credential_finalization": "eefb1823d84629dc0d9e149dbb07fb115e473d0d3a004e0b2dd20fdb168a7d33423347c07960d272f1fa670f45ca8e6571d3b396661383da8f07380d89488116",
    "client_registration_state": "7ea276a79194704a5056d17c3e2e1751d98b1d1fc5d1d78d11004e9a44c7c52c1d906fc19848da043a39b51b22620802d7df4f11abf994a269d7ada2cc7edd0470617373776f7264",
    "client_login_state": "1d906fc19848da043a39b51b22620802d7df4f11abf994a269d7ada2cc7edd0400607ea276a79194704a5056d17c3e2e1751d98b1d1fc5d1d78d11004e9a44c7c52cde58ba7427030a4792107bf9f4a9334599f4e437d97a73ae1db4f1d3f93628791c0344d0e057a1f6651d80b00e188aa35efb4844173c531d186729f81411bc24004056b7ff7a43c7d6f75d881606f733c12a53af70b35d8c5cd982a8e94a816dfa0dde58ba7427030a4792107bf9f4a9334599f4e437d97a73ae1db4f1d3f936287970617373776f7264",
    "server_login_state": "b54d627533bf9545c5450b4c518e4cb298b118b34383db02ceddd2178683e7201d1e3ffd5eff03bc224a75760cecd10ce0a6514ba4f638fbfc21f968398d159f5f5a78b6309646b6e9ecd5856aa109abdc53d720791f198edde539d19ee7deeb5438f6a1156476d8e11404b344c2a97db92902eb2d77d723defeb3a7d3be1c5e954c3ba56dff507f6d0de3e9c02b1fe3d8935b32fbaa4be2cf5c82225b9e47c931bb51eb04a2a5345914c33a52c3f7d5184b631fe1a5efd4633f433e408589fa",
    "password_file": "7a1daeb91dc6af4e8685287922020dda9e4445ddb107aa76f30ef3defec982046c81af9eba7baef5e5dc3aca419a62b207542315edc732834b18fa394cbfa9c210caed864e36bb19cdd7324553b7e35d1a7384f4262a15e38049f910b2ca6baae30c1ca67d865b65333bd5567a3ea54c6df36d1641953ca4470a886e7117bf06383ff4ec0a1f237f70e51cae0f859e7476917cb8d28cda3aeccd970a205a71e20d3e592eaadabc2216d0ed14e494dbf733984e607b6d5f8b68f9b2321ca01b30",
    "export_key": "9eaea2ca345b9fac4c7924abe5783d23ac7452d61ebb026d40ecab402178c8669b135783e5dcd148554e9d861fa4af809f1e41c1ccca929000cdb3a78a2dc4fb",
    "session_key": "954c3ba56dff507f6d0de3e9c02b1fe3d8935b32fbaa4be2cf5c82225b9e47c931bb51eb04a2a5345914c33a52c3f7d5184b631fe1a5efd4633f433e408589fa"
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

fn stringify_test_vectors(p: &TestVectorParameters) -> alloc::string::String {
    let mut s = alloc::string::String::new();
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
    use crate::{group::Group, key_exchange::tripledh::NonceLen, keypair::KeyPair};
    use generic_array::typenum::Unsigned;
    use rand::RngCore;

    let mut rng = OsRng;

    // Inputs
    let server_s_kp = KeyPair::<CS::OprfGroup>::generate_random(&mut rng);
    let server_e_kp = KeyPair::<CS::OprfGroup>::generate_random(&mut rng);
    let client_s_kp = KeyPair::<CS::OprfGroup>::generate_random(&mut rng);
    let client_e_kp = KeyPair::<CS::OprfGroup>::generate_random(&mut rng);
    let fake_kp = KeyPair::<CS::OprfGroup>::generate_random(&mut rng);
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
    let mut client_nonce = vec![0u8; NonceLen::USIZE];
    rng.fill_bytes(&mut client_nonce);
    let mut server_nonce = vec![0u8; NonceLen::USIZE];
    rng.fill_bytes(&mut server_nonce);

    let fake_sk: Vec<u8> = fake_kp.private().to_vec();
    let server_setup = ServerSetup::<CS>::deserialize(
        &[&oprf_seed, &server_s_kp.private().to_arr()[..], &fake_sk].concat(),
    )
    .unwrap();

    let blinding_factor = CS::OprfGroup::random_nonzero_scalar(&mut rng);
    let blinding_factor_bytes = CS::OprfGroup::scalar_as_bytes(blinding_factor);

    let mut blinding_factor_registration_rng = CycleRng::new(blinding_factor_bytes.to_vec());
    let client_registration_start_result =
        ClientRegistration::<CS>::start(&mut blinding_factor_registration_rng, password).unwrap();
    let blinding_factor_bytes_returned =
        CS::OprfGroup::scalar_as_bytes(client_registration_start_result.state.token.blind);
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
            ClientRegistrationFinishParameters::new(
                Some(Identifiers::ClientAndServerIdentifiers(
                    id_u.to_vec(),
                    id_s.to_vec(),
                )),
                None,
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
            ClientLoginFinishParameters::new(
                Some(context.to_vec()),
                Some(Identifiers::ClientAndServerIdentifiers(
                    id_u.to_vec(),
                    id_s.to_vec(),
                )),
                None,
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
            r#""fqJ2p5GUcEpQVtF8Pi4XUdmLHR/F0deNEQBOmkTHxSw=""#
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
        ClientRegistrationFinishParameters::new(
            Some(Identifiers::ClientAndServerIdentifiers(
                parameters.id_u,
                parameters.id_s,
            )),
            None,
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
        ClientLoginFinishParameters::new(
            Some(parameters.context),
            Some(Identifiers::ClientAndServerIdentifiers(
                parameters.id_u,
                parameters.id_s,
            )),
            None,
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
            Err(ProtocolError::InvalidLoginError) => true,
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

#[test]
fn test_reflected_value_error_registration() -> Result<(), ProtocolError> {
    let credential_identifier = b"credentialIdentifier";
    let password = b"password";
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<RistrettoSha5123dhNoSlowHash>::new(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(&mut client_rng, password)?;
    let alpha = client_registration_start_result
        .message
        .get_alpha_for_testing();
    let server_registration_start_result =
        ServerRegistration::<RistrettoSha5123dhNoSlowHash>::start(
            &server_setup,
            client_registration_start_result.message,
            credential_identifier,
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
    let credential_identifier = b"credentialIdentifier";
    let password = b"password";
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<RistrettoSha5123dhNoSlowHash>::new(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<RistrettoSha5123dhNoSlowHash>::start(&mut client_rng, password)?;
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
        ClientLogin::<RistrettoSha5123dhNoSlowHash>::start(&mut client_rng, password)?;
    let alpha = client_login_start_result.message.get_alpha_for_testing();
    let server_login_start_result = ServerLogin::<RistrettoSha5123dhNoSlowHash>::start(
        &mut server_rng,
        &server_setup,
        Some(p_file),
        client_login_start_result.message,
        credential_identifier,
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

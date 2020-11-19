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
    test_vectors::{CycleRng, TestVectorParameters},
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

static TEST_VECTOR: &str = r#"
{
    "client_s_pk": "aee30cf198cc78b5b1a5ed5a4bda21bceb5e4732fffbddf867e32ee814d67317",
    "client_s_sk": "1811b9d5fc4ea11b32405510632c643a2f760659c73298fe12a458ef39258b48",
    "client_e_pk": "1fb90ca40034a0ee0d9d087a2c12743329d792b21e4c4424e561a665a1031b00",
    "client_e_sk": "a86125633d89a6799a09456e45b5968e3958641c084e0e85185392ef67e59d40",
    "server_s_pk": "9ef0646ad66cf13ce4052294c7325e044853f0c1fd03e91288f8339d812d4a57",
    "server_s_sk": "807548d5912d55092f88c5ba1ca2588a795b43adcdc877497d8a983a3c3ed146",
    "server_e_pk": "b2df778b631c83d1fdd76feb9978d156ad0c1d18fedbe2b15a309f673e3d8464",
    "server_e_sk": "f021332310d7f6a1c8272d11610e0244cf462efe1a7d9e6657cf12f74d30f272",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "f614e957f0441399ede44bed38487eee12f154e5ac14adedb1402bdea174670b",
    "oprf_key": "9c13cf985a00394cb6acdebf846eafaa60d0ff81cd4d52655d6db3eee123760e",
    "envelope_nonce": "b326061dfc120f5b261b28bbae4262c26ad343a640b5fb4b90ba3f16600e1c89",
    "client_nonce": "8bdd8689f4ea9486aaa3bac182d31f31e3c62d76b3869ae1dd05d5c708b13e86",
    "server_nonce": "d529ed9480524236ed6f6cafd92ebab3c6091afde54f47f9079575c090cad7d6",
    "r1": "010000220020ada5910d73be53a8a6c50d32e9efcc0eb3e871103c05fb993fcb8312aff7fc79",
    "r2": "02000048002035104271fe25c0074ea715af805c019772a97b6e975376f411e1c37831a56fa700209ef0646ad66cf13ce4052294c7325e044853f0c1fd03e91288f8339d812d4a5701010103",
    "r3": "030000aeb326061dfc120f5b261b28bbae4262c26ad343a640b5fb4b90ba3f16600e1c89002375ba1dad2970f60479c4ce0fe1e62271f2c5561757557c88941d9278ededbc981de07c00230300209ef0646ad66cf13ce4052294c7325e044853f0c1fd03e91288f8339d812d4a570020c575cad080bafce229c0de9700269d48d8102d3f0f70497a770d9c0bcb5d181e0020aee30cf198cc78b5b1a5ed5a4bda21bceb5e4732fffbddf867e32ee814d67317",
    "l1": "040000220020ada5910d73be53a8a6c50d32e9efcc0eb3e871103c05fb993fcb8312aff7fc798bdd8689f4ea9486aaa3bac182d31f31e3c62d76b3869ae1dd05d5c708b13e8600001fb90ca40034a0ee0d9d087a2c12743329d792b21e4c4424e561a665a1031b00",
    "l2": "050000ae002035104271fe25c0074ea715af805c019772a97b6e975376f411e1c37831a56fa7b326061dfc120f5b261b28bbae4262c26ad343a640b5fb4b90ba3f16600e1c89002375ba1dad2970f60479c4ce0fe1e62271f2c5561757557c88941d9278ededbc981de07c00230300209ef0646ad66cf13ce4052294c7325e044853f0c1fd03e91288f8339d812d4a570020c575cad080bafce229c0de9700269d48d8102d3f0f70497a770d9c0bcb5d181ef021332310d7f6a1c8272d11610e0244cf462efe1a7d9e6657cf12f74d30f2720000b2df778b631c83d1fdd76feb9978d156ad0c1d18fedbe2b15a309f673e3d846400003bc4221316aaad7b6110910bae5a3bc0e498738634916021546f6fce652adc78",
    "l3": "00000000a06be277ca4254db95ab90deeb5111effd46a9e619d26098806e34b8315f6c78",
    "client_registration_state": "00036964550003696453f614e957f0441399ede44bed38487eee12f154e5ac14adedb1402bdea174670b70617373776f7264",
    "client_login_state": "00036964550003696453f614e957f0441399ede44bed38487eee12f154e5ac14adedb1402bdea174670ba86125633d89a6799a09456e45b5968e3958641c084e0e85185392ef67e59d408bdd8689f4ea9486aaa3bac182d31f31e3c62d76b3869ae1dd05d5c708b13e86b8990f815be25d3ab39421afac70cd6427ff73d364ed52d76320775e1320f7c570617373776f7264",
    "server_registration_state": "9c13cf985a00394cb6acdebf846eafaa60d0ff81cd4d52655d6db3eee123760e",
    "server_login_state": "d71ab2471d28aec63b7c5227048a10e68e292b5acc75e12035816f3f1857740dcceb58e1095db8918dd41ad1aea631468dd161e165b5222d162f223dea33c53b50fc81d1199cf256ad4839860c168a5a42e785e4f375775ffd8f9f96c16d12ec",
    "password_file": "9c13cf985a00394cb6acdebf846eafaa60d0ff81cd4d52655d6db3eee123760eaee30cf198cc78b5b1a5ed5a4bda21bceb5e4732fffbddf867e32ee814d67317b326061dfc120f5b261b28bbae4262c26ad343a640b5fb4b90ba3f16600e1c89002375ba1dad2970f60479c4ce0fe1e62271f2c5561757557c88941d9278ededbc981de07c00230300209ef0646ad66cf13ce4052294c7325e044853f0c1fd03e91288f8339d812d4a570020c575cad080bafce229c0de9700269d48d8102d3f0f70497a770d9c0bcb5d181e",
    "export_key": "405705c182c2afd6cc474cbd8827f4d046d74ec46b841727ae208333191be764",
    "shared_secret": "50fc81d1199cf256ad4839860c168a5a42e785e4f375775ffd8f9f96c16d12ec"
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
        r1: decode(&values, "r1").unwrap(),
        r2: decode(&values, "r2").unwrap(),
        r3: decode(&values, "r3").unwrap(),
        l1: decode(&values, "l1").unwrap(),
        l2: decode(&values, "l2").unwrap(),
        l3: decode(&values, "l3").unwrap(),
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
    s.push_str(format!("\"r1\": \"{}\",\n", hex::encode(&p.r1)).as_str());
    s.push_str(format!("\"r2\": \"{}\",\n", hex::encode(&p.r2)).as_str());
    s.push_str(format!("\"r3\": \"{}\",\n", hex::encode(&p.r3)).as_str());
    s.push_str(format!("\"l1\": \"{}\",\n", hex::encode(&p.l1)).as_str());
    s.push_str(format!("\"l2\": \"{}\",\n", hex::encode(&p.l2)).as_str());
    s.push_str(format!("\"l3\": \"{}\",\n", hex::encode(&p.l3)).as_str());
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

    let mut blinding_factor_registration_rng = CycleRng::new(blinding_factor_raw.to_vec());
    let (r1, client_registration) = ClientRegistration::<CS>::start(
        password,
        ClientRegistrationStartParameters::WithIdentifiers(id_u.to_vec(), id_s.to_vec()),
        &mut blinding_factor_registration_rng,
        std::convert::identity,
    )
    .unwrap();
    let r1_bytes = r1.serialize().to_vec();
    let blinding_factor_bytes =
        CS::Group::scalar_as_bytes(&client_registration.token.blind).clone();
    let client_registration_state = client_registration.to_bytes().to_vec();

    let mut oprf_key_rng = CycleRng::new(oprf_key_raw.to_vec());
    let (r2, server_registration) =
        ServerRegistration::<CS>::start(r1, server_s_kp.public(), &mut oprf_key_rng).unwrap();
    let r2_bytes = r2.serialize().to_vec();
    let oprf_key_bytes = CS::Group::scalar_as_bytes(&server_registration.oprf_key).clone();
    let server_registration_state = server_registration.to_bytes().to_vec();

    let mut client_s_sk_and_nonce: Vec<u8> = Vec::new();
    client_s_sk_and_nonce.extend_from_slice(&client_s_kp.private().to_arr());
    client_s_sk_and_nonce.extend_from_slice(&envelope_nonce);

    let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
    let (r3, export_key_registration) = client_registration
        .finish(r2, &mut finish_registration_rng)
        .unwrap();
    let r3_bytes = r3.serialize().to_vec();

    let password_file = server_registration.finish(r3).unwrap();
    let password_file_bytes = password_file.to_bytes();

    let mut client_login_start: Vec<u8> = Vec::new();
    client_login_start.extend_from_slice(&blinding_factor_raw);
    client_login_start.extend_from_slice(&client_e_kp.private().to_arr());
    client_login_start.extend_from_slice(&client_nonce);

    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let client_login_start_result = ClientLogin::<CS>::start(
        password,
        &mut client_login_start_rng,
        ClientLoginStartParameters::WithIdentifiersAndInfo(
            Vec::new(),
            id_u.to_vec(),
            id_s.to_vec(),
        ),
        std::convert::identity,
    )
    .unwrap();
    let l1_bytes = client_login_start_result
        .credential_request
        .serialize()
        .to_vec();
    let client_login_state = client_login_start_result
        .client_login_state
        .to_bytes()
        .to_vec();

    let mut server_e_sk_rng = CycleRng::new(server_e_kp.private().to_arr().to_vec());
    let server_login_start_result = ServerLogin::<CS>::start(
        password_file,
        server_s_kp.private(),
        client_login_start_result.credential_request,
        &mut server_e_sk_rng,
        ServerLoginStartParameters::default(),
    )
    .unwrap();
    let l2_bytes = server_login_start_result
        .credential_response
        .serialize()
        .to_vec();
    let server_login_state = server_login_start_result
        .server_login_state
        .to_bytes()
        .to_vec();

    let client_login_finish_result = client_login_start_result
        .client_login_state
        .finish(
            server_login_start_result.credential_response,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();
    let l3_bytes = client_login_finish_result.key_exchange.to_bytes().to_vec();

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
        r1: r1_bytes,
        r2: r2_bytes,
        r3: r3_bytes,
        l1: l1_bytes,
        l2: l2_bytes,
        l3: l3_bytes,
        password_file: password_file_bytes,
        client_registration_state,
        server_registration_state,
        client_login_state,
        server_login_state,
        shared_secret: client_login_finish_result.session_secret,
        export_key: export_key_registration.to_vec(),
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
fn test_r1() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut rng = OsRng;
    let (r1, client_registration) = ClientRegistration::<X255193dhNoSlowHash>::start(
        &parameters.password,
        ClientRegistrationStartParameters::WithIdentifiers(parameters.id_u, parameters.id_s),
        &mut rng,
        postprocess_blinding_factor::<<X255193dhNoSlowHash as CipherSuite>::Group>,
    )
    .unwrap();
    assert_eq!(hex::encode(&parameters.r1), hex::encode(r1.serialize()));
    assert_eq!(
        hex::encode(&parameters.client_registration_state),
        hex::encode(client_registration.to_bytes())
    );
    Ok(())
}

#[test]
fn test_r2() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut oprf_key_rng = CycleRng::new(parameters.oprf_key);
    let (r2, server_registration) = ServerRegistration::<X255193dhNoSlowHash>::start(
        RegisterFirstMessage::deserialize(&parameters.r1[..]).unwrap(),
        &Key::try_from(&parameters.server_s_pk[..]).unwrap(),
        &mut oprf_key_rng,
    )
    .unwrap();
    assert_eq!(hex::encode(parameters.r2), hex::encode(r2.serialize()));
    assert_eq!(
        hex::encode(&parameters.server_registration_state),
        hex::encode(server_registration.to_bytes())
    );
    Ok(())
}

#[test]
fn test_r3() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_s_sk_and_nonce: Vec<u8> =
        [parameters.client_s_sk, parameters.envelope_nonce].concat();
    let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
    let (r3, export_key_registration) = ClientRegistration::<X255193dhNoSlowHash>::try_from(
        &parameters.client_registration_state[..],
    )
    .unwrap()
    .finish(
        RegisterSecondMessage::deserialize(&parameters.r2[..]).unwrap(),
        &mut finish_registration_rng,
    )
    .unwrap();

    assert_eq!(hex::encode(parameters.r3), hex::encode(r3.serialize()));
    assert_eq!(
        hex::encode(parameters.export_key),
        hex::encode(export_key_registration.to_vec())
    );

    Ok(())
}

#[test]
fn test_password_file() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let server_registration = ServerRegistration::<X255193dhNoSlowHash>::try_from(
        &parameters.server_registration_state[..],
    )
    .unwrap();
    let password_file = server_registration
        .finish(RegisterThirdMessage::deserialize(&parameters.r3[..]).unwrap())
        .unwrap();

    assert_eq!(
        hex::encode(parameters.password_file),
        hex::encode(password_file.to_bytes())
    );
    Ok(())
}

#[test]
fn test_l1() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_login_start = [
        vec![0u8; 64], // FIXME: don't hardcode this
        parameters.client_e_sk,
        parameters.client_nonce,
    ]
    .concat();
    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let client_login_start_result = ClientLogin::<X255193dhNoSlowHash>::start(
        &parameters.password,
        &mut client_login_start_rng,
        ClientLoginStartParameters::WithIdentifiersAndInfo(
            Vec::new(),
            parameters.id_u,
            parameters.id_s,
        ),
        postprocess_blinding_factor::<<X255193dhNoSlowHash as CipherSuite>::Group>,
    )
    .unwrap();
    assert_eq!(
        hex::encode(&parameters.l1),
        hex::encode(client_login_start_result.credential_request.serialize())
    );
    assert_eq!(
        hex::encode(&parameters.client_login_state),
        hex::encode(client_login_start_result.client_login_state.to_bytes())
    );
    Ok(())
}

#[test]
fn test_l2() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let mut server_e_sk_rng = CycleRng::new(parameters.server_e_sk);
    let server_login_start_result = ServerLogin::<X255193dhNoSlowHash>::start(
        ServerRegistration::try_from(&parameters.password_file[..]).unwrap(),
        &Key::try_from(&parameters.server_s_sk[..]).unwrap(),
        LoginFirstMessage::<X255193dhNoSlowHash>::deserialize(&parameters.l1[..]).unwrap(),
        &mut server_e_sk_rng,
        ServerLoginStartParameters::default(),
    )
    .unwrap();

    assert_eq!(
        hex::encode(&parameters.l2),
        hex::encode(server_login_start_result.credential_response.serialize())
    );
    assert_eq!(
        hex::encode(&parameters.server_login_state),
        hex::encode(server_login_start_result.server_login_state.to_bytes())
    );
    Ok(())
}

#[test]
fn test_l3() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_login_finish_result =
        ClientLogin::<X255193dhNoSlowHash>::try_from(&parameters.client_login_state[..])
            .unwrap()
            .finish(
                LoginSecondMessage::<X255193dhNoSlowHash>::deserialize(&parameters.l2[..]).unwrap(),
                ClientLoginFinishParameters::default(),
            )
            .unwrap();

    assert_eq!(
        hex::encode(&parameters.shared_secret),
        hex::encode(&client_login_finish_result.session_secret)
    );
    assert_eq!(
        hex::encode(&parameters.l3),
        hex::encode(client_login_finish_result.key_exchange.to_bytes())
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
        ServerLogin::<X255193dhNoSlowHash>::try_from(&parameters.server_login_state[..])
            .unwrap()
            .finish(LoginThirdMessage::try_from(&parameters.l3[..])?)
            .unwrap();

    assert_eq!(
        hex::encode(parameters.shared_secret),
        hex::encode(server_login_result.session_secret)
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
    let (register_m1, client_state) = ClientRegistration::<X255193dhNoSlowHash>::start(
        registration_password,
        ClientRegistrationStartParameters::default(),
        &mut client_rng,
        std::convert::identity,
    )?;
    let (register_m2, server_state) = ServerRegistration::<X255193dhNoSlowHash>::start(
        register_m1,
        server_kp.public(),
        &mut server_rng,
    )?;
    let (register_m3, registration_export_key) =
        client_state.finish(register_m2, &mut client_rng)?;
    let p_file = server_state.finish(register_m3)?;
    let client_login_start_result = ClientLogin::<X255193dhNoSlowHash>::start(
        login_password,
        &mut client_rng,
        ClientLoginStartParameters::default(),
        std::convert::identity,
    )?;
    let server_login_start_result = ServerLogin::<X255193dhNoSlowHash>::start(
        p_file,
        &server_kp.private(),
        client_login_start_result.credential_request,
        &mut server_rng,
        ServerLoginStartParameters::default(),
    )?;

    let client_login_result = client_login_start_result.client_login_state.finish(
        server_login_start_result.credential_response,
        ClientLoginFinishParameters::default(),
    );

    if hex::encode(registration_password) == hex::encode(login_password) {
        let client_login_finish_result = client_login_result?;
        let server_login_finish_result = server_login_start_result
            .server_login_state
            .finish(client_login_finish_result.key_exchange)?;

        assert_eq!(
            hex::encode(server_login_finish_result.session_secret),
            hex::encode(client_login_finish_result.session_secret)
        );
        assert_eq!(
            hex::encode(registration_export_key),
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

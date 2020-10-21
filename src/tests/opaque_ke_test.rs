// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    errors::*,
    group::Group,
    key_exchange::tripledh::{TripleDH, NONCE_LEN},
    keypair::{Key, KeyPair, SizedBytes, X25519KeyPair},
    opaque::*,
    slow_hash::NoOpHash,
    tests::mock_rng::CycleRng,
};
use curve25519_dalek::edwards::EdwardsPoint;
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
    pub password: Vec<u8>,
    pub blinding_factor_raw: Vec<u8>,
    pub blinding_factor: Vec<u8>,
    pub pepper: Vec<u8>,
    pub oprf_key: Vec<u8>,
    pub envelope_nonce: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub server_nonce: Vec<u8>,
    pub r1: Vec<u8>,
    pub r2: Vec<u8>,
    pub r3: Vec<u8>,
    pub l1: Vec<u8>,
    pub l2: Vec<u8>,
    pub l3: Vec<u8>,
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
    "client_s_pk": "6c3f4c134a1697cda1d494cef349e99117aaedecb6792c3aeab06fc1da5f463d",
    "client_s_sk": "98f628dfaed00892809f1ff24f44eddb933ca593eeb88c532827249c3fdae56d",
    "client_e_pk": "b20d78da45e7d91fb9185be968ba20c680bfb735e5dbdec36c2aefdb261d6903",
    "client_e_sk": "88f058f4de21fc364603318edce30931a60fe78f7953722e3214203c02d52a79",
    "server_s_pk": "511b18e0a82493d9b0d7988f5a7e2d05fe6886cb26e9813d476e3fe6d3ca1349",
    "server_s_sk": "e00d089a96b19c74f77dcc6079277ba18b2dd1f603d0bc5c46664d4fe5c2867a",
    "server_e_pk": "98e12670ffd22a9a827d74bfa5ac44c9f83cb52b477b1ab201a589a8fd643674",
    "server_e_sk": "080f051060d51c9f1406e7cf5d9ac3212d8ba3829ca94fdd7c8f43e80fa8b278",
    "password": "70617373776f7264",
    "blinding_factor_raw": "3def40a264b30c15dfcafc8d52cbe309d2d08e015d516b515f17cf98443bb39d6d164e9bd391303d890697b38dc59ee7e9ec196682528a078d51983ab18c227b",
    "blinding_factor": "d315d7e6c81d5398c015af3d55ded87f0979dfdb28b6f222ee8699905fd41e0a",
    "pepper": "706570706572",
    "oprf_key": "75e559c8cc7a81642e61b77651bc61b71d3eb7d8b6cd9ca13d8532cb684d5405",
    "envelope_nonce": "3048ea382aa7357dbcd480047c884b717c4fea3ca627f2c498001b2a46e015da",
    "client_nonce": "47b20166a022bb319ba9a09d5c328b6e2d6cc5813018f7dd5b53f380f914e79f",
    "server_nonce": "1bf2cc47738524a83c995122a44c7832be18b48b606897d71fc942e8ec6d9b2e",
    "r1": "01000024000000204df6277df3ee67e084af0d24e27a6567b75589dc887d5acbe5e5830dc8dc7eb0",
    "r2": "0200002800208d04d78807ed18542f65707f964d96089a322a8bb06dad269cb7a4bee8c20b57000001010103",
    "r3": "030000ae3048ea382aa7357dbcd480047c884b717c4fea3ca627f2c498001b2a46e015da0023469a6c15d59bc2b9cf07e4e37138292e58070a34eb76f8cb5e3015c542b8e96346482f0023030020511b18e0a82493d9b0d7988f5a7e2d05fe6886cb26e9813d476e3fe6d3ca13490020b3fc2eb3ffc0ddfa3b9d94a33874d297263cb768077f128e7ec798b03c5c7ba300206c3f4c134a1697cda1d494cef349e99117aaedecb6792c3aeab06fc1da5f463d",
    "l1": "04000024000000204df6277df3ee67e084af0d24e27a6567b75589dc887d5acbe5e5830dc8dc7eb047b20166a022bb319ba9a09d5c328b6e2d6cc5813018f7dd5b53f380f914e79fb20d78da45e7d91fb9185be968ba20c680bfb735e5dbdec36c2aefdb261d6903",
    "l2": "050000ae00208d04d78807ed18542f65707f964d96089a322a8bb06dad269cb7a4bee8c20b573048ea382aa7357dbcd480047c884b717c4fea3ca627f2c498001b2a46e015da0023469a6c15d59bc2b9cf07e4e37138292e58070a34eb76f8cb5e3015c542b8e96346482f0023030020511b18e0a82493d9b0d7988f5a7e2d05fe6886cb26e9813d476e3fe6d3ca13490020b3fc2eb3ffc0ddfa3b9d94a33874d297263cb768077f128e7ec798b03c5c7ba3080f051060d51c9f1406e7cf5d9ac3212d8ba3829ca94fdd7c8f43e80fa8b27898e12670ffd22a9a827d74bfa5ac44c9f83cb52b477b1ab201a589a8fd64367476b2f0458ade73668e3aaab6e1cd7d48dacc702b9a49147d8431a18e649f814e",
    "l3": "ed9d2f5af8d30d7927458a6d10f309ae6f49792d5e86d12f5e163a980f49c7ff",
    "client_registration_state": "00000000d315d7e6c81d5398c015af3d55ded87f0979dfdb28b6f222ee8699905fd41e0a70617373776f7264",
    "client_login_state": "00000000d315d7e6c81d5398c015af3d55ded87f0979dfdb28b6f222ee8699905fd41e0a88f058f4de21fc364603318edce30931a60fe78f7953722e3214203c02d52a7947b20166a022bb319ba9a09d5c328b6e2d6cc5813018f7dd5b53f380f914e79f2e9c4b0c4bc9bdd4fca317dab50240fb32c31f9ec3742ec610a7e5016ad88de570617373776f7264",
    "server_registration_state": "75e559c8cc7a81642e61b77651bc61b71d3eb7d8b6cd9ca13d8532cb684d5405",
    "server_login_state": "54a3c257ad6e5406be86e9f983bcb25a50dcdaf8c8bd6928f17ea8b001db400c02b16899d3fe648ef86fb914dba9892d09df4a449f6f077e3ad903c01e309d6fd8e21fc482f3d3a396b8c1f5587e00806c860e5a2b82f0da989333ce870ee1ee",
    "password_file": "75e559c8cc7a81642e61b77651bc61b71d3eb7d8b6cd9ca13d8532cb684d54056c3f4c134a1697cda1d494cef349e99117aaedecb6792c3aeab06fc1da5f463d3048ea382aa7357dbcd480047c884b717c4fea3ca627f2c498001b2a46e015da0023469a6c15d59bc2b9cf07e4e37138292e58070a34eb76f8cb5e3015c542b8e96346482f0023030020511b18e0a82493d9b0d7988f5a7e2d05fe6886cb26e9813d476e3fe6d3ca13490020b3fc2eb3ffc0ddfa3b9d94a33874d297263cb768077f128e7ec798b03c5c7ba3",
    "export_key": "90f9b6ec1edd53a60a9be4f744950befecf5bbfbd973702082fa031aa192bb5a",
    "shared_secret": "d8e21fc482f3d3a396b8c1f5587e00806c860e5a2b82f0da989333ce870ee1ee"
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
        password: decode(&values, "password").unwrap(),
        blinding_factor_raw: decode(&values, "blinding_factor_raw").unwrap(),
        blinding_factor: decode(&values, "blinding_factor").unwrap(),
        pepper: decode(&values, "pepper").unwrap(),
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
    s.push_str(format!("\"password\": \"{}\",\n", hex::encode(&p.password)).as_str());
    s.push_str(
        format!(
            "\"blinding_factor_raw\": \"{}\",\n",
            hex::encode(&p.blinding_factor_raw)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "\"blinding_factor\": \"{}\",\n",
            hex::encode(&p.blinding_factor)
        )
        .as_str(),
    );
    s.push_str(format!("\"pepper\": \"{}\",\n", hex::encode(&p.pepper)).as_str());
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
    let password = b"password";
    let pepper = b"pepper";
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
        Some(pepper),
        &mut blinding_factor_registration_rng,
    )
    .unwrap();
    let r1_bytes = r1.serialize().to_vec();
    let blinding_factor_bytes =
        CS::Group::scalar_as_bytes(&client_registration.blinding_factor).clone();
    let client_registration_state = client_registration.to_bytes().to_vec();

    let mut oprf_key_rng = CycleRng::new(oprf_key_raw.to_vec());
    let (r2, server_registration) = ServerRegistration::<CS>::start(r1, &mut oprf_key_rng).unwrap();
    let r2_bytes = r2.serialize().to_vec();
    let oprf_key_bytes = CS::Group::scalar_as_bytes(&server_registration.oprf_key).clone();
    let server_registration_state = server_registration.to_bytes().to_vec();

    let mut client_s_sk_and_nonce: Vec<u8> = Vec::new();
    client_s_sk_and_nonce.extend_from_slice(&client_s_kp.private().to_arr());
    client_s_sk_and_nonce.extend_from_slice(&envelope_nonce);

    let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
    let (r3, export_key_registration) = client_registration
        .finish(r2, server_s_kp.public(), &mut finish_registration_rng)
        .unwrap();
    let r3_bytes = r3.serialize().to_vec();

    let password_file = server_registration.finish(r3).unwrap();
    let password_file_bytes = password_file.to_bytes();

    let mut client_login_start: Vec<u8> = Vec::new();
    client_login_start.extend_from_slice(&blinding_factor_raw);
    client_login_start.extend_from_slice(&client_e_kp.private().to_arr());
    client_login_start.extend_from_slice(&client_nonce);

    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let (l1, client_login) =
        ClientLogin::<CS>::start(password, Some(pepper), &mut client_login_start_rng).unwrap();
    let l1_bytes = l1.serialize().to_vec();
    let client_login_state = client_login.to_bytes().to_vec();

    let mut server_e_sk_rng = CycleRng::new(server_e_kp.private().to_arr().to_vec());
    let (l2, server_login) = ServerLogin::<CS>::start(
        password_file,
        server_s_kp.private(),
        l1,
        &mut server_e_sk_rng,
    )
    .unwrap();
    let l2_bytes = l2.serialize().to_vec();
    let server_login_state = server_login.to_bytes().to_vec();

    let mut client_e_sk_rng = CycleRng::new(client_e_kp.private().to_arr().to_vec());
    let (l3, client_shared_secret, _export_key_login) = client_login
        .finish(l2, server_s_kp.public(), &mut client_e_sk_rng)
        .unwrap();
    let l3_bytes = l3.to_bytes().to_vec();

    TestVectorParameters {
        client_s_pk: client_s_kp.public().to_arr().to_vec(),
        client_s_sk: client_s_kp.private().to_arr().to_vec(),
        client_e_pk: client_e_kp.public().to_arr().to_vec(),
        client_e_sk: client_e_kp.private().to_arr().to_vec(),
        server_s_pk: server_s_kp.public().to_arr().to_vec(),
        server_s_sk: server_s_kp.private().to_arr().to_vec(),
        server_e_pk: server_e_kp.public().to_arr().to_vec(),
        server_e_sk: server_e_kp.private().to_arr().to_vec(),
        password: password.to_vec(),
        blinding_factor_raw: blinding_factor_raw.to_vec(),
        blinding_factor: blinding_factor_bytes.to_vec(),
        pepper: pepper.to_vec(),
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
        shared_secret: client_shared_secret,
        export_key: export_key_registration.to_vec(),
    }
}

#[test]
fn generate_test_vectors() {
    let parameters = generate_parameters::<X255193dhNoSlowHash>();
    println!("{}", stringify_test_vectors(&parameters));
}

#[test]
fn test_r1() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut blinding_factor_rng = CycleRng::new(parameters.blinding_factor_raw);
    let (r1, client_registration) = ClientRegistration::<X255193dhNoSlowHash>::start(
        &parameters.password,
        Some(&parameters.pepper),
        &mut blinding_factor_rng,
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
        &Key::try_from(&parameters.server_s_pk[..]).unwrap(),
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
        parameters.blinding_factor_raw,
        parameters.client_e_sk,
        parameters.client_nonce,
    ]
    .concat();
    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let (l1, client_login) = ClientLogin::<X255193dhNoSlowHash>::start(
        &parameters.password,
        Some(&parameters.pepper),
        &mut client_login_start_rng,
    )
    .unwrap();
    assert_eq!(hex::encode(&parameters.l1), hex::encode(l1.serialize()));
    assert_eq!(
        hex::encode(&parameters.client_login_state),
        hex::encode(client_login.to_bytes())
    );
    Ok(())
}

#[test]
fn test_l2() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let mut server_e_sk_rng = CycleRng::new(parameters.server_e_sk);
    let (l2, server_login) = ServerLogin::<X255193dhNoSlowHash>::start(
        ServerRegistration::try_from(&parameters.password_file[..]).unwrap(),
        &Key::try_from(&parameters.server_s_sk[..]).unwrap(),
        LoginFirstMessage::<X255193dhNoSlowHash>::deserialize(&parameters.l1[..]).unwrap(),
        &mut server_e_sk_rng,
    )
    .unwrap();

    assert_eq!(hex::encode(&parameters.l2), hex::encode(l2.serialize()));
    assert_eq!(
        hex::encode(&parameters.server_login_state),
        hex::encode(server_login.to_bytes())
    );
    Ok(())
}

#[test]
fn test_l3() -> Result<(), PakeError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let mut client_e_sk_rng = CycleRng::new(parameters.client_e_sk.to_vec());
    let (l3, shared_secret, export_key_login) =
        ClientLogin::<X255193dhNoSlowHash>::try_from(&parameters.client_login_state[..])
            .unwrap()
            .finish(
                LoginSecondMessage::<X255193dhNoSlowHash>::deserialize(&parameters.l2[..]).unwrap(),
                &Key::try_from(&parameters.server_s_pk[..])?,
                &mut client_e_sk_rng,
            )
            .unwrap();

    assert_eq!(
        hex::encode(&parameters.shared_secret),
        hex::encode(&shared_secret)
    );
    assert_eq!(hex::encode(&parameters.l3), hex::encode(l3.to_bytes()));
    assert_eq!(
        hex::encode(&parameters.export_key),
        hex::encode(export_key_login)
    );

    Ok(())
}

#[test]
fn test_server_login_finish() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let shared_secret =
        ServerLogin::<X255193dhNoSlowHash>::try_from(&parameters.server_login_state[..])
            .unwrap()
            .finish(LoginThirdMessage::try_from(&parameters.l3[..])?)
            .unwrap();

    assert_eq!(
        hex::encode(parameters.shared_secret),
        hex::encode(shared_secret)
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
        None,
        &mut client_rng,
    )?;
    let (register_m2, server_state) =
        ServerRegistration::<X255193dhNoSlowHash>::start(register_m1, &mut server_rng)?;
    let (register_m3, registration_export_key) =
        client_state.finish(register_m2, server_kp.public(), &mut client_rng)?;
    let p_file = server_state.finish(register_m3)?;
    let (login_m1, client_login_state) =
        ClientLogin::<X255193dhNoSlowHash>::start(login_password, None, &mut client_rng)?;
    let (login_m2, server_login_state) = ServerLogin::<X255193dhNoSlowHash>::start(
        p_file,
        &server_kp.private(),
        login_m1,
        &mut server_rng,
    )?;

    let client_login_result =
        client_login_state.finish(login_m2, &server_kp.public(), &mut client_rng);

    if hex::encode(registration_password) == hex::encode(login_password) {
        let (login_m3, client_shared_secret, login_export_key) = client_login_result?;
        let server_shared_secret = server_login_state.finish(login_m3)?;

        assert_eq!(
            hex::encode(server_shared_secret),
            hex::encode(client_shared_secret)
        );
        assert_eq!(
            hex::encode(registration_export_key),
            hex::encode(login_export_key)
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

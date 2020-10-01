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
    "client_s_pk": "db67c19dde3ff9df4226c638056bf740811d6136b41d81a9995a29d8ae4da74a",
    "client_s_sk": "c0580c0dcfba5b38e3bf7dd110bd5025c319678b30c8baecaf9c2ef3c959f253",
    "client_e_pk": "c3a4413191704cbe3ee1cc8293a565e260a3cbadfdb091bc00e953b33883c363",
    "client_e_sk": "18be455fafb4cbe97a7531c2fc4ff2ce9b7bfc0119b0fcd7660443ddd0ec4068",
    "server_s_pk": "2d3e373aaa1b3fb0df397789b671ca33f1b880bcc5ebc89b9e390b5ebb720e1d",
    "server_s_sk": "48bb316e50d6c93a6d4a95eba0652ab147eb422c7207bc780ebd47f952a8f164",
    "server_e_pk": "6bcb8d80d0fcf242e4ed4d414375d66a696d1bfe220af29681c89835444b9d7b",
    "server_e_sk": "b88df6767ae031eb77be76b66ad467bea6ff26a41db963ff3b4db81ed6c72452",
    "password": "70617373776f7264",
    "blinding_factor_raw": "7235ed80e9335579c8fbda9e61e8c92358b53267f33d14002cf1ee8e4a452190706c642cda5611d54aba2d8aebe91c20d230ce350d6bc76ccde2bbe3c3b38af3",
    "blinding_factor": "ccfacfd5e65693b9ea7b1bbe8c61d83e20bc67a54465d0659573f2801a474b0a",
    "pepper": "706570706572",
    "oprf_key": "44f6b4ad762943517e400ce878e0c1409573ee98d96c14e5a507e601788c2207",
    "envelope_nonce": "ed0eb006204e163097595826da4f4e8df648fdcb54feef22cefbbdd1c9e85038",
    "client_nonce": "774cd501736601475cea7a382cb1d38b34c574baab82c0e87cbe3dcf9de3d0a6",
    "server_nonce": "a627d3525b162594be0c134ccf5fd4cab719e37ec945e70a128d66abb3bb58c4",
    "r1": "010000240000002060ebaf93d439cd229e8fd843b9cd2656d40cba15981f04464c9842f98557f30b",
    "r2": "020000280020ab7af6fd8628eded06289ccf85ad8e2f4bc8d584129b923cdc6a2865300a8f6a000001010103",
    "r3": "030000aeed0eb006204e163097595826da4f4e8df648fdcb54feef22cefbbdd1c9e85038002358a913a1bcdee339dde801af723f204f5cdc9335e0256eed49a4b36a226a1a062ddc9500230300202d3e373aaa1b3fb0df397789b671ca33f1b880bcc5ebc89b9e390b5ebb720e1d0020a2eb1b19e25b90e0089e543dd391ca362f05d01fa6d521d00c35312755c665f00020db67c19dde3ff9df4226c638056bf740811d6136b41d81a9995a29d8ae4da74a",
    "l1": "040000240000002060ebaf93d439cd229e8fd843b9cd2656d40cba15981f04464c9842f98557f30b774cd501736601475cea7a382cb1d38b34c574baab82c0e87cbe3dcf9de3d0a6c3a4413191704cbe3ee1cc8293a565e260a3cbadfdb091bc00e953b33883c363",
    "l2": "050000b00020ab7af6fd8628eded06289ccf85ad8e2f4bc8d584129b923cdc6a2865300a8f6a008ced0eb006204e163097595826da4f4e8df648fdcb54feef22cefbbdd1c9e85038002358a913a1bcdee339dde801af723f204f5cdc9335e0256eed49a4b36a226a1a062ddc9500230300202d3e373aaa1b3fb0df397789b671ca33f1b880bcc5ebc89b9e390b5ebb720e1d0020a2eb1b19e25b90e0089e543dd391ca362f05d01fa6d521d00c35312755c665f0b88df6767ae031eb77be76b66ad467bea6ff26a41db963ff3b4db81ed6c724526bcb8d80d0fcf242e4ed4d414375d66a696d1bfe220af29681c89835444b9d7b3a1f7e046c1460ed3a47fff7be87b5670d568a1bab2ae7f5b7ee70ff99c3d21d",
    "l3": "28b18759b0f5977c607170b7ceb1b5d75bffbc185991ae001c0fded87f826d89",
    "client_registration_state": "00000000ccfacfd5e65693b9ea7b1bbe8c61d83e20bc67a54465d0659573f2801a474b0a70617373776f7264",
    "client_login_state": "00000000ccfacfd5e65693b9ea7b1bbe8c61d83e20bc67a54465d0659573f2801a474b0a18be455fafb4cbe97a7531c2fc4ff2ce9b7bfc0119b0fcd7660443ddd0ec4068774cd501736601475cea7a382cb1d38b34c574baab82c0e87cbe3dcf9de3d0a68d5a62ba390f1ee0419616e1a135e609ad248c7a3ee7edf4fb90f575148758d070617373776f7264",
    "server_registration_state": "44f6b4ad762943517e400ce878e0c1409573ee98d96c14e5a507e601788c2207",
    "server_login_state": "14e5fe977591bb71f1e2bcd0542d26023c818048a257781fe276a3e8f9e0be4d58075843e2050013c815c6ef3d015a4ef1294543225832281adec71e1a92fa32a783f8c52f881f276f1c780f21b3fcb4eb36b75daea84b3bb9f7ce0699842864",
    "password_file": "44f6b4ad762943517e400ce878e0c1409573ee98d96c14e5a507e601788c2207db67c19dde3ff9df4226c638056bf740811d6136b41d81a9995a29d8ae4da74aed0eb006204e163097595826da4f4e8df648fdcb54feef22cefbbdd1c9e85038002358a913a1bcdee339dde801af723f204f5cdc9335e0256eed49a4b36a226a1a062ddc9500230300202d3e373aaa1b3fb0df397789b671ca33f1b880bcc5ebc89b9e390b5ebb720e1d0020a2eb1b19e25b90e0089e543dd391ca362f05d01fa6d521d00c35312755c665f0",
    "export_key": "48e39aeec42923ada9a239b231ff290efb1d4d01ccec8cd820a42dde10ff0d09",
    "shared_secret": "a783f8c52f881f276f1c780f21b3fcb4eb36b75daea84b3bb9f7ce0699842864"
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

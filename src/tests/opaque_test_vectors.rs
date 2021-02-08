// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite, errors::*, key_exchange::tripledh::TripleDH, keypair::Key, opaque::*,
    slow_hash::NoOpHash, tests::mock_rng::CycleRng, *,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use serde_json::Value;
use std::convert::TryFrom;

// Tests
// =====

struct Ristretto255Sha512NoSlowHash;
impl CipherSuite for Ristretto255Sha512NoSlowHash {
    type Group = RistrettoPoint;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = NoOpHash;
}

#[derive(PartialEq)]
pub enum EnvelopeMode {
    Base,
    CustomIdentifier,
}

#[allow(non_snake_case)]
pub struct TestVectorParameters {
    pub envelope_mode: EnvelopeMode,
    pub client_public_key: Vec<u8>,
    pub client_private_key: Vec<u8>,
    pub client_keyshare: Vec<u8>,
    pub client_private_keyshare: Vec<u8>,
    pub server_public_key: Vec<u8>,
    pub server_private_key: Vec<u8>,
    pub server_keyshare: Vec<u8>,
    pub server_private_keyshare: Vec<u8>,
    pub client_identity: Vec<u8>,
    pub server_identity: Vec<u8>,
    pub password: Vec<u8>,
    pub blind_registration: Vec<u8>,
    pub oprf_key: Vec<u8>,
    pub envelope_nonce: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub server_nonce: Vec<u8>,
    pub client_info: Vec<u8>,
    pub server_info: Vec<u8>,
    pub registration_request: Vec<u8>,
    pub registration_response: Vec<u8>,
    pub registration_upload: Vec<u8>,
    pub KE1: Vec<u8>,
    pub blind_login: Vec<u8>,
    pub KE2: Vec<u8>,
    pub KE3: Vec<u8>,
    pub export_key: Vec<u8>,
    pub session_key: Vec<u8>,
}

static TEST_VECTORS: &[&str] = &[
    r#"
Group: ristretto255
EnvelopeMode: 01
OPRF: 0001
SlowHash: Identity
Hash: SHA512
server_nonce: a4997137a8fa0d4baf7052a499bf877057f9404e03c889d641a0d7c
807b6a518
oprf_key: 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be03
7e50b
password: 436f7272656374486f72736542617474657279537461706c65
blind_login: ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63
e3263503
server_private_keyshare: 31587dff30b8001d9d43584decc22e358fa7f9d6e606
29fb1223081c3bae7103
client_nonce: 75a1ad27ab77578bc08b44c4318f09b31d53145c9ba3b42abf0ea08
a781277a6
server_info: 6772656574696e677320616c696365
client_info: 68656c6c6f20626f62
client_private_keyshare: fbbf4ad24119f08a35bf999f8ae0c779ed7b3e266bf3
3f793f6bf9ebf4578005
envelope_nonce: 6c6bb9021b9833c788dd25994d3ce7f3811338744fd6dc556e037
585783444c0
server_keyshare: 82be40ef93bf7c6edd43d4ed9f52fa19827649b819de39c52a22
43e985b75d62
blind_registration: c604c785ada70d77a5256ae21767de8c3304115237d262134
f5e46e512cf8e03
client_public_key: b2d1b10f3741a8efef3139f4d2889f2b11f776b79b9aa2c3ef
caba4f1c4ae861
client_private_key: f0f56cfb488649fe28691dd9aa5dc9ff4c0e6028075baa3c5
615398a2cb12304
client_keyshare: 484e47e31b3132f4ee512e41805a1690891111a7b885bc526198
22c14cabf360
server_public_key: 5442a6f57333a332b4c6f07308f6fa846bde3ed27425820cdc
eeeb935924a903
server_private_key: d63d709e3a739a128929a9f289ff263fdcbc457f2f47f7c43
ccafbbfee72290c
auth_key: 22198da4ad73b1d35cd8bb875e64ce1a9fc2edeb073d760e114d1d7a2f8
6d47411caf1787907e2ff96cd3190b14d101101d74cff234259d9f19a18f2cfe29d0b
server_mac_key: 9de28e2f7107afe266570934c033dd6a403fb2b09a9f1a1357a81
9fb072d25e6651626638d77bd7f0adf4b2b715d0a0bee2ac531fd0f7da699aba6e9ed
717466
envelope: 016c6bb9021b9833c788dd25994d3ce7f3811338744fd6dc556e0375857
83444c00022e9b28440a1dc99cca7513e8eb754d427caf8515642b45a92c73838c043
fc316deeb83deface81589bc8e5c2c767b5ab79218834fbf4fa4f87cf23775aa54633
ed75665cd88f451e044cac1b282d890269476d1ac18ff9a4c0cb832e1143ffa7d447a
prk: 732303f65e76c39f30876aec31af1f5bcd8861626c922baa2e842209c7d5bf2e
024912db2d6cac00b1260c437d34ec588a664a55fc7a0a40251915d2b15d8ec9
client_mac_key: 1536168d48218d08dcbed3438e897d98eff566894240d8d136be0
4ba46b2c788883fd165ce7614c52a6a9c926bf55d249e6c29bc4a23d5a1775ad294a7
858922
pseudorandom_pad: e99274b5cd27d14aeeaf16e7aa8d7e7a03071d58229c5dc96d0
46ed57a761ddccdbc
handshake_encrypt_key: c646def7a8ca75282ac1a0ad15630834cba2772837d7a3
a26d00b36923e55b3f5d065679c715e4c799654f261c865f1a55bc94cabc29a6e2e72
296dfc494a984
handshake_secret: cc887e128c28064106d4101ac3de633e9096e170f2c4a9913d3
50f306274b1665a5b251f761672c12db4c403a615c22cee96adb3539fa62662a17f2e
18cd5fed
registration_response: 1867301bcc67bdf8e640b7d6edcbe2a65488446417b50d
30cdba66ccb379e57200205442a6f57333a332b4c6f07308f6fa846bde3ed27425820
cdceeeb935924a903
export_key: 6ca2c344763e5bc9e3d2bbfe3d982b826b709da597e28e85f9594ec54
2a20c697d55de277ccce1d1af7c48ab7fea1467ac1e3a99c71dcf6326a909d280bd2f
6f
registration_upload: 0020b2d1b10f3741a8efef3139f4d2889f2b11f776b79b9a
a2c3efcaba4f1c4ae861016c6bb9021b9833c788dd25994d3ce7f3811338744fd6dc5
56e037585783444c00022e9b28440a1dc99cca7513e8eb754d427caf8515642b45a92
c73838c043fc316deeb83deface81589bc8e5c2c767b5ab79218834fbf4fa4f87cf23
775aa54633ed75665cd88f451e044cac1b282d890269476d1ac18ff9a4c0cb832e114
3ffa7d447a
registration_request: 241b621c417c0705b5ea7a8b7cdd5039fd61e6b63effe2a
44418164c4d49003e
session_key: ee9f1ef224d498858f6c9b3a121016a38bad7816055c452b1c7edf3d
d439c42a4cc78cbd672e985a20910df14f8f1af4ce5793303ffe6954ff5f1a264e3fd
515
KE3: e771daf28bc5e8068dead67c3db19f9ad03ee919e52f6c7a6e79cf1085bd7448
1e76512c77f37762578eb2faff8fe98e4185ca2d01957216c556d33a6fba3028
KE2: e83812f06568d57b8cdfdcc90fe91454e21bd25dd2a1c32dd1599a2e4a4b6c35
00205442a6f57333a332b4c6f07308f6fa846bde3ed27425820cdceeeb935924a9030
16c6bb9021b9833c788dd25994d3ce7f3811338744fd6dc556e037585783444c00022
e9b28440a1dc99cca7513e8eb754d427caf8515642b45a92c73838c043fc316deeb83
deface81589bc8e5c2c767b5ab79218834fbf4fa4f87cf23775aa54633ed75665cd88
f451e044cac1b282d890269476d1ac18ff9a4c0cb832e1143ffa7d447aa4997137a8f
a0d4baf7052a499bf877057f9404e03c889d641a0d7c807b6a51882be40ef93bf7c6e
dd43d4ed9f52fa19827649b819de39c52a2243e985b75d62000f13aed85ae30aee2f8
9ac5e1c5dd53609b890267ef2d765bb56000bc704c2ba4e4256107befee6655cdb084
64e6c75d8b251642e0d721b3fce38f245568b50e7f6c98825d54cc1a26d6eafadcc1d
344
KE1: b68e0e356f8490fa9c3bed952e16cc02db21eda686b3c484f3d9d912caa41f76
75a1ad27ab77578bc08b44c4318f09b31d53145c9ba3b42abf0ea08a781277a600096
8656c6c6f20626f62484e47e31b3132f4ee512e41805a1690891111a7b885bc526198
22c14cabf360
"#,
    r#"
Group: ristretto255
EnvelopeMode: 02
OPRF: 0001
SlowHash: Identity
Hash: SHA512
server_nonce: 0f3a6da8b667bc7a383c987586bee749c5f2787691baca68757e78b
6128b0a0f
oprf_key: 89c61a42c8191a5ca41f2fe959843d333bcf43173b7de4c5c119e0e0d8b
0e707
password: 436f7272656374486f72736542617474657279537461706c65
blind_login: e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd
4171ea02
server_private_keyshare: 70c944dcb7f4dddde168ecb48dd9488c62b6fc7e9bb4
2a16d291afca9dd25b07
client_nonce: 480917b09c6720680b4a7a0ba9f54b69d870f640a4a7994b47ad07d
1a95c984f
server_info: 6772656574696e677320616c696365
server_identity: 5442a6f57333a332b4c6f07308f6fa846bde3ed27425820cdcee
eb935924a903
client_info: 68656c6c6f20626f62
client_private_keyshare: a4ba6cb7e16ab76eccdb4c0b9261eedd426d7863f00b
fc4a0e09476d3121e70c
envelope_nonce: e38fb444afe3df13ae05e6876d10eca7661196375518eb66d7dee
b8cfb42d13f
server_public_key: 5442a6f57333a332b4c6f07308f6fa846bde3ed27425820cdc
eeeb935924a903
client_identity: b2d1b10f3741a8efef3139f4d2889f2b11f776b79b9aa2c3efca
ba4f1c4ae861
blind_registration: 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9db
cec831b8c681a09
client_public_key: b2d1b10f3741a8efef3139f4d2889f2b11f776b79b9aa2c3ef
caba4f1c4ae861
client_private_key: f0f56cfb488649fe28691dd9aa5dc9ff4c0e6028075baa3c5
615398a2cb12304
client_keyshare: 4ae7d50bb80cc8f5034d36c1c27edc30caca0983677a941bc0ac
e5e10b18300a
server_keyshare: a2e9e0809b270a1d5c8208f3498a3188538265e6a9e6b274cb38
c4c5d9b1792d
server_private_key: d63d709e3a739a128929a9f289ff263fdcbc457f2f47f7c43
ccafbbfee72290c
auth_key: 4c7c0ae950ad7e9c518266f953d4a01bd2232695f92fb028aa6c124996e
31a205f621305fd4997edf8a5fce04a51252ba8430227c134b81d7093a58e01c70752
server_mac_key: 974bde939ef1d30ba29f9ec2addcaff1eeb105a1f534e04113f9f
0b5c3b9a0797e3fa5f7006e63dfb2b0ce74d002bd1161767c361507bfb1fa0fed5063
1cdcb7
envelope: 02e38fb444afe3df13ae05e6876d10eca7661196375518eb66d7deeb8cf
b42d13f00227ed4654d4452340f26c6304dceeeb1fddb142fcd91b3b26ecd566d7688
095f9478a721e5a592be9dd3bda76ed97421819aca4a30752813223d33bc7ea443be9
76754605116278c7fffda4de142674ed154f540bd3285080637eb4b929e1378336b11
prk: e3bb74ca5f88a95571578e921489e1b6119b438e4efce6e955ae9b6453f24aa4
e3a34fa22bc5f470cfc134ca0784a9cd7df64be46ff3b325fc19f4009979bf2e
client_mac_key: 1c55ecba64d98dc2db8f45faa72b8fdd63cad8677b8665cc575cf
8ad36ef38ec63c9dfc5552007573215983f55d8f5cfa1651da8417e3f27094dde5254
7f5b89
pseudorandom_pad: 7ef495b828a97c896f381824d3371ba012eb63c3f19bb535676
a3b63b18373255ba3
handshake_encrypt_key: 0852fb826109073be6e7c065b6e2d1f872c16f9977c177
cd2f945b26bb933fe6252f226f40483f7aa52f545f801d1e4430f30f80fd42070494e
a77fdcecd6595
handshake_secret: bfd3bfbe451520880975d0e568cbd3b5155b23c02de504fccb9
dd5a8195266cd94d49d040530b3d6b0a585d542eb24da708a2b6f6dc34dee4652d0c1
c62c4e59
registration_response: 088ac01ebf5700f0c96bc2988509343cb7e2dd6f0df820
d0fb807faa11a26f5600205442a6f57333a332b4c6f07308f6fa846bde3ed27425820
cdceeeb935924a903
export_key: 0effa605dc47ba4fe565c423b782b8b6697b26ee2ede7059b0e17510d
f8b11554ce053409671480a56ffbe77b91edc95205c213caeaf9dcb0841790ff834a0
09
registration_upload: 0020b2d1b10f3741a8efef3139f4d2889f2b11f776b79b9a
a2c3efcaba4f1c4ae86102e38fb444afe3df13ae05e6876d10eca7661196375518eb6
6d7deeb8cfb42d13f00227ed4654d4452340f26c6304dceeeb1fddb142fcd91b3b26e
cd566d7688095f9478a721e5a592be9dd3bda76ed97421819aca4a30752813223d33b
c7ea443be976754605116278c7fffda4de142674ed154f540bd3285080637eb4b929e
1378336b11
registration_request: c8d2e9ba503bf3f8821226653314427edb1ec8a3ecc94a5
dfbbe33d59d07b645
session_key: 8dc21ff264f2774de95955d35544ba314e92d07f4a3b32c89ead5e70
c83ac4c0221deadd34ed11d43fc4d3651aec612d696c63979c96bf1ddd1ee44da5d0c
d68
KE3: c178e45ed9b314653685cdbf5f7730e3e40f8652ceb9b10f47d1c784fdd75dd1
07c4ae3f7683de5a692359178c8f13f41a043fc1dcfc14b1fb7cb411514efc6c
KE2: 5079b16709b195b3b63257b419efb752bd0603170160fa72b828ce9ff9209c0c
00205442a6f57333a332b4c6f07308f6fa846bde3ed27425820cdceeeb935924a9030
2e38fb444afe3df13ae05e6876d10eca7661196375518eb66d7deeb8cfb42d13f0022
7ed4654d4452340f26c6304dceeeb1fddb142fcd91b3b26ecd566d7688095f9478a72
1e5a592be9dd3bda76ed97421819aca4a30752813223d33bc7ea443be976754605116
278c7fffda4de142674ed154f540bd3285080637eb4b929e1378336b110f3a6da8b66
7bc7a383c987586bee749c5f2787691baca68757e78b6128b0a0fa2e9e0809b270a1d
5c8208f3498a3188538265e6a9e6b274cb38c4c5d9b1792d000f5a1a0b34573bf728b
14f53485f3bf62fd91154dc9ca01b21945b2204f96adc87bd80e8283ecf3522b6d893
7527f2e9b9782a94fedab0fa304590d1d4f03d72fb1664fca1523a3be95f6c3a97d0a
2ed
KE1: 7024ca0d5423176294fbb9ca968d8ce3fc879a231f1ceef69e672c89e02ded59
480917b09c6720680b4a7a0ba9f54b69d870f640a4a7994b47ad07d1a95c984f00096
8656c6c6f20626f624ae7d50bb80cc8f5034d36c1c27edc30caca0983677a941bc0ac
e5e10b18300a
"#,
];

macro_rules! parse {
    ( $v:ident, $s:expr ) => {
        match decode(&$v, $s) {
            Some(x) => x,
            None => vec![],
        }
    };
}

macro_rules! rfc_to_params {
    ( $v:ident ) => {
        $v.iter()
            .map(|x| populate_test_vectors(&serde_json::from_str(rfc_to_json(x).as_str()).unwrap()))
            .collect::<Vec<TestVectorParameters>>()
    };
}

fn rfc_to_json(input: &str) -> String {
    let mut json = vec![];
    for line in input.lines() {
        // If line contains colon, then
        if line.contains(":") {
            if json.len() > 0 {
                // Adding closing quote for previous line, comma, and newline
                json.push("\",\n".to_string());
            }

            let mut iter = line.split(":");
            let key = iter.next().unwrap().split_whitespace().next().unwrap();
            let val = iter.next().unwrap().split_whitespace().next().unwrap();

            json.push(format!("    \"{}\": \"{}", key, val));
        } else {
            let s = line.trim().to_string();
            if s.len() > 0 {
                json.push(s);
            }
        }
    }

    format!("{{\n{}\"\n}}", json.join(""))
}

fn decode(values: &Value, key: &str) -> Option<Vec<u8>> {
    values[key]
        .as_str()
        .and_then(|s| hex::decode(&s.to_string()).ok())
}

fn populate_test_vectors(values: &Value) -> TestVectorParameters {
    TestVectorParameters {
        envelope_mode: match values["EnvelopeMode"].as_str() {
            Some("01") => EnvelopeMode::Base,
            Some("02") => EnvelopeMode::CustomIdentifier,
            _ => panic!("Could not match envelope mode"),
        },
        client_public_key: parse!(values, "client_public_key"),
        client_private_key: parse!(values, "client_private_key"),
        client_keyshare: parse!(values, "client_keyshare"),
        client_private_keyshare: parse!(values, "client_private_keyshare"),
        server_public_key: parse!(values, "server_public_key"),
        server_private_key: parse!(values, "server_private_key"),
        server_keyshare: parse!(values, "server_keyshare"),
        server_private_keyshare: parse!(values, "server_private_keyshare"),
        client_identity: parse!(values, "client_identity"),
        server_identity: parse!(values, "server_identity"),
        password: parse!(values, "password"),
        blind_registration: parse!(values, "blind_registration"),
        oprf_key: parse!(values, "oprf_key"),
        envelope_nonce: parse!(values, "envelope_nonce"),
        client_nonce: parse!(values, "client_nonce"),
        server_nonce: parse!(values, "server_nonce"),
        client_info: parse!(values, "client_info"),
        server_info: parse!(values, "server_info"),
        registration_request: parse!(values, "registration_request"),
        registration_response: parse!(values, "registration_response"),
        registration_upload: parse!(values, "registration_upload"),
        KE1: parse!(values, "KE1"),
        KE2: parse!(values, "KE2"),
        KE3: parse!(values, "KE3"),
        blind_login: parse!(values, "blind_login"),
        export_key: parse!(values, "export_key"),
        session_key: parse!(values, "session_key"),
    }
}

fn get_password_file_bytes(parameters: &TestVectorParameters) -> Result<Vec<u8>, ProtocolError> {
    let mut oprf_key_rng = CycleRng::new(parameters.oprf_key.clone());
    let server_registration_start_result =
        ServerRegistration::<Ristretto255Sha512NoSlowHash>::start(
            &mut oprf_key_rng,
            RegistrationRequest::deserialize(&parameters.registration_request[..]).unwrap(),
            &Key::try_from(&parameters.server_public_key[..]).unwrap(),
        )?;

    let password_file = server_registration_start_result
        .state
        .finish(RegistrationUpload::deserialize(&parameters.registration_upload[..]).unwrap())?;

    Ok(password_file.to_bytes())
}

#[test]
fn test_registration_request() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let mut rng = CycleRng::new(parameters.blind_registration.to_vec());
        let client_registration_start_result =
            ClientRegistration::<Ristretto255Sha512NoSlowHash>::start(
                &mut rng,
                &parameters.password,
            )?;
        assert_eq!(
            hex::encode(&parameters.registration_request),
            hex::encode(client_registration_start_result.message.serialize())
        );
    }
    Ok(())
}

#[test]
fn test_registration_response() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let mut oprf_key_rng = CycleRng::new(parameters.oprf_key);
        let server_registration_start_result =
            ServerRegistration::<Ristretto255Sha512NoSlowHash>::start(
                &mut oprf_key_rng,
                RegistrationRequest::deserialize(&parameters.registration_request[..]).unwrap(),
                &Key::try_from(&parameters.server_public_key[..]).unwrap(),
            )?;
        assert_eq!(
            hex::encode(parameters.registration_response),
            hex::encode(server_registration_start_result.message.serialize())
        );
    }
    Ok(())
}

#[test]
fn test_registration_upload() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let mut rng = CycleRng::new(parameters.blind_registration.to_vec());
        let client_registration_start_result =
            ClientRegistration::<Ristretto255Sha512NoSlowHash>::start(
                &mut rng,
                &parameters.password,
            )?;

        let sk_u_and_nonce: Vec<u8> =
            [parameters.client_private_key, parameters.envelope_nonce].concat();
        let mut finish_registration_rng = CycleRng::new(sk_u_and_nonce);
        let result = client_registration_start_result.state.finish(
            &mut finish_registration_rng,
            RegistrationResponse::deserialize(&parameters.registration_response[..]).unwrap(),
            if parameters.envelope_mode == EnvelopeMode::CustomIdentifier {
                ClientRegistrationFinishParameters::WithIdentifiers(
                    parameters.client_identity,
                    parameters.server_identity,
                )
            } else {
                ClientRegistrationFinishParameters::default()
            },
        )?;

        assert_eq!(
            hex::encode(parameters.registration_upload),
            hex::encode(result.message.serialize())
        );
        assert_eq!(
            hex::encode(parameters.export_key),
            hex::encode(result.export_key.to_vec())
        );
    }

    Ok(())
}

#[test]
fn test_ke1() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let client_login_start = [
            parameters.blind_login,
            parameters.client_private_keyshare,
            parameters.client_nonce,
        ]
        .concat();
        let mut client_login_start_rng = CycleRng::new(client_login_start);
        let client_login_start_result = ClientLogin::<Ristretto255Sha512NoSlowHash>::start(
            &mut client_login_start_rng,
            &parameters.password,
            ClientLoginStartParameters::WithInfo(parameters.client_info),
        )?;
        assert_eq!(
            hex::encode(&parameters.KE1),
            hex::encode(client_login_start_result.message.serialize())
        );
    }
    Ok(())
}

#[test]
fn test_ke2() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let password_file_bytes = get_password_file_bytes(&parameters)?;

        let mut server_private_keyshare_and_nonce_rng =
            CycleRng::new([parameters.server_private_keyshare, parameters.server_nonce].concat());
        let server_login_start_result = ServerLogin::<Ristretto255Sha512NoSlowHash>::start(
            &mut server_private_keyshare_and_nonce_rng,
            ServerRegistration::try_from(&password_file_bytes[..]).unwrap(),
            &Key::try_from(&parameters.server_private_key[..]).unwrap(),
            CredentialRequest::<Ristretto255Sha512NoSlowHash>::deserialize(&parameters.KE1[..])
                .unwrap(),
            if parameters.envelope_mode == EnvelopeMode::CustomIdentifier {
                ServerLoginStartParameters::WithInfoAndIdentifiers(
                    parameters.server_info.to_vec(),
                    parameters.client_identity,
                    parameters.server_identity,
                )
            } else {
                ServerLoginStartParameters::WithInfo(parameters.server_info.to_vec())
            },
        )?;
        assert_eq!(
            hex::encode(&parameters.client_info),
            hex::encode(server_login_start_result.plain_info),
        );
        assert_eq!(
            hex::encode(&parameters.KE2),
            hex::encode(server_login_start_result.message.serialize())
        );
    }
    Ok(())
}

#[test]
fn test_ke3() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let client_login_start = [
            parameters.blind_login,
            parameters.client_private_keyshare,
            parameters.client_nonce,
        ]
        .concat();
        let mut client_login_start_rng = CycleRng::new(client_login_start);
        let client_login_start_result = ClientLogin::<Ristretto255Sha512NoSlowHash>::start(
            &mut client_login_start_rng,
            &parameters.password,
            ClientLoginStartParameters::WithInfo(parameters.client_info),
        )?;

        let client_login_finish_result = client_login_start_result.state.finish(
            CredentialResponse::<Ristretto255Sha512NoSlowHash>::deserialize(&parameters.KE2[..])?,
            if parameters.envelope_mode == EnvelopeMode::CustomIdentifier {
                ClientLoginFinishParameters::WithIdentifiers(
                    parameters.client_identity,
                    parameters.server_identity,
                )
            } else {
                ClientLoginFinishParameters::default()
            },
        )?;

        assert_eq!(
            hex::encode(&parameters.server_info),
            hex::encode(&client_login_finish_result.confidential_info)
        );
        assert_eq!(
            hex::encode(&parameters.session_key),
            hex::encode(&client_login_finish_result.session_key)
        );
        assert_eq!(
            hex::encode(&parameters.KE3),
            hex::encode(client_login_finish_result.message.to_bytes())
        );
        assert_eq!(
            hex::encode(&parameters.export_key),
            hex::encode(client_login_finish_result.export_key)
        );
    }
    Ok(())
}

#[test]
fn test_server_login_finish() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let password_file_bytes = get_password_file_bytes(&parameters)?;

        let mut server_private_keyshare_and_nonce_rng =
            CycleRng::new([parameters.server_private_keyshare, parameters.server_nonce].concat());
        let server_login_start_result = ServerLogin::<Ristretto255Sha512NoSlowHash>::start(
            &mut server_private_keyshare_and_nonce_rng,
            ServerRegistration::try_from(&password_file_bytes[..]).unwrap(),
            &Key::try_from(&parameters.server_private_key[..]).unwrap(),
            CredentialRequest::<Ristretto255Sha512NoSlowHash>::deserialize(&parameters.KE1[..])
                .unwrap(),
            if parameters.envelope_mode == EnvelopeMode::CustomIdentifier {
                ServerLoginStartParameters::WithInfoAndIdentifiers(
                    parameters.server_info.to_vec(),
                    parameters.client_identity,
                    parameters.server_identity,
                )
            } else {
                ServerLoginStartParameters::WithInfo(parameters.server_info.to_vec())
            },
        )?;

        let server_login_result = server_login_start_result
            .state
            .finish(CredentialFinalization::try_from(&parameters.KE3[..])?)?;

        assert_eq!(
            hex::encode(parameters.session_key),
            hex::encode(server_login_result.session_key)
        );
    }
    Ok(())
}

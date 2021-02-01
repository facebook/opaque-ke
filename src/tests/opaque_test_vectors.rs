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
EnvelopeMode: 00
OPRF: 0001
SlowHash: Identity
Hash: SHA512
server_nonce: 534a8d6ca099313c73f909ecadd9973644203036913b162134def00
fdf8b8a18
oprf_key: 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be03
7e50b
password: 436f7272656374486f72736542617474657279537461706c65
blind_login: ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63
e3263503
server_private_keyshare: bfd25bddcd9190db01fdc127247eb2461d78281233d8
77b4564a00404cb79700
client_nonce: 1a7c15f8ca50bb7a8d654035ad59488a33758b80fc1cc1fa7cc4d92
50c00f567
server_info: 6772656574696e677320616c696365
client_info: 68656c6c6f20626f62
client_private_keyshare: 1d6078acf052615f1e3206b9aa9aed95cb0f04daa534
0ccb52534871f1158f09
envelope_nonce: ff05735be871d25c4fa25f2a65e26386fad3eda2ba1e093562844
1ed18bbe818
server_keyshare: dcc991d13fa137302cc1adce95e6f9087f503d88e12d90200682
2e6da438ec22
blind_registration: c604c785ada70d77a5256ae21767de8c3304115237d262134
f5e46e512cf8e03
client_public_key: fcca4fd8732b9887f566bbdcdb738c884f5390b360f43b5b3a
4b81b3bb7e060d
client_private_key: 31aca12a23a2a03db43c91fafe6d32589e2d8f09d8004d605
0ec275317cc7f08
client_keyshare: 408c2a2025080d6507b6250f3dc1ac420c37134bf14d7b1be542
c4d8cfd64a52
server_public_key: 76ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf14856
974424a8561115
server_private_key: ccde5849510d7175da028ccccba666e446b9418cf7ba9383b
9530c75474bcb04
auth_key: c0ee18ecc5ae7012bcf641a28c2d21ebc198492f1d75ed7ee7cc60b6c5f
c2a6e5f0ad974fc8f0f48dacfcac765d2b626fce0728f3abbee16d522fe2fa108270c
server_mac_key: 18685231e1442f5547af5f9c965fc6a951428a963f26ef99cea69
53873296df81b71e89c05d9bd4abf6863a1e3215f3fe4a202e33f7164c90d250d00a8
dd4a91
envelope: 00ff05735be871d25c4fa25f2a65e26386fad3eda2ba1e0935628441ed1
8bbe81800228f595ba5f6cf5b9c590bc270cbdc1b46b570b76db941ff14035630294f
b8c42ae21c6d965b5ee07b9a86687941dc9594b3f0c92317b367fd19d168b810d7b08
787319d837367607662e9d545c5e5abecc469e544903a570e2efdb168bbb8603d11c8
prk: ec754de047f914e9adf78a82925d70f90478c0e74ea4124de5ba92e8bd935691
641b6a6ad00ad7d101d232c11fdbe1a578d4795bc62e73fb7e42d6ef234bf2e1
client_mac_key: 1b73e32b32aad3e94a8bfd664532c9cf8c3385d8ec62badd59873
270e02f854436b68ade26d0efa0c6b4b41e4970d950d6e7a5ca292427952730105bba
f89896
pseudorandom_pad: 8f796a0957e5783ef936764c5a26e52b87282940364827144e3
660c568ebd3e69d14
handshake_encrypt_key: 26eea148eeaad14bba63d6d30cac46ddb1d37971f6fe1d
dfc80955271f4d242c0db5824d5df69b3a6f619753733a26640d20e35b8589c6b7448
df7d902155ed4
handshake_secret: 46c0c3d90c38b9cf3a0c3f19248adef96365e059a4a0034b4b2
d36efda24174620e0894bcb0916dcaa79cdb1a7f475e9b809c0f4a072c8bf4b6b4735
87838641
registration_response: 1867301bcc67bdf8e640b7d6edcbe2a65488446417b50d
30cdba66ccb379e572002076ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf14
856974424a8561115
export_key: 39a81bd85c701bcb4396d7d6fad5a67712aff40a4a7d806094f84dbbb
56bf371d8b9b522abba314dc5203cf387c4be187128e3270b151023221c9fc86fff11
4a
registration_upload: 0020fcca4fd8732b9887f566bbdcdb738c884f5390b360f4
3b5b3a4b81b3bb7e060d00ff05735be871d25c4fa25f2a65e26386fad3eda2ba1e093
5628441ed18bbe81800228f595ba5f6cf5b9c590bc270cbdc1b46b570b76db941ff14
035630294fb8c42ae21c6d965b5ee07b9a86687941dc9594b3f0c92317b367fd19d16
8b810d7b08787319d837367607662e9d545c5e5abecc469e544903a570e2efdb168bb
b8603d11c8
registration_request: 241b621c417c0705b5ea7a8b7cdd5039fd61e6b63effe2a
44418164c4d49003e
session_key: f27806d4c588eac72b3da00dba21a2852cf3a91d5164d9ac4dcfa896
a3cbbb2836785a33ba9d5fb193068347b0ed20bcde94a4482e4456d9c5666eb6191de
a47
KE3: bf680d0471ffd1885f050b51c3e57b59e4b3ec31c49dd893644028f30e4bca44
6cf2f047abd75f739bffccac0af3fe24b8255d3391c4899608df9539f97b5c91
KE2: e83812f06568d57b8cdfdcc90fe91454e21bd25dd2a1c32dd1599a2e4a4b6c35
002076ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf14856974424a85611150
0ff05735be871d25c4fa25f2a65e26386fad3eda2ba1e0935628441ed18bbe8180022
8f595ba5f6cf5b9c590bc270cbdc1b46b570b76db941ff14035630294fb8c42ae21c6
d965b5ee07b9a86687941dc9594b3f0c92317b367fd19d168b810d7b08787319d8373
67607662e9d545c5e5abecc469e544903a570e2efdb168bbb8603d11c8534a8d6ca09
9313c73f909ecadd9973644203036913b162134def00fdf8b8a18dcc991d13fa13730
2cc1adce95e6f9087f503d88e12d902006822e6da438ec22000f1e4413f30f38967bd
8c1f3a65da5f825ec34bf0c56f7c50117388593922db7bf53b1f451f6623df88c355a
a7fb7f9464e00c14683bbab1386ee43e59952a44b73af76d7659a81b219270f2543de
fc1
KE1: b68e0e356f8490fa9c3bed952e16cc02db21eda686b3c484f3d9d912caa41f76
1a7c15f8ca50bb7a8d654035ad59488a33758b80fc1cc1fa7cc4d9250c00f56700096
8656c6c6f20626f62408c2a2025080d6507b6250f3dc1ac420c37134bf14d7b1be542
c4d8cfd64a52
"#,
    r#"
Group: ristretto255
EnvelopeMode: 01
OPRF: 0001
SlowHash: Identity
Hash: SHA512
server_nonce: be1b6a9ee06b76c648efd2e57300cae3418a2137ee3abcfa018431e
e50876be4
oprf_key: 89c61a42c8191a5ca41f2fe959843d333bcf43173b7de4c5c119e0e0d8b
0e707
password: 436f7272656374486f72736542617474657279537461706c65
blind_login: e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd
4171ea02
server_private_keyshare: 79450906dc147d9b73edf5c98f7d1970ebcc825c474c
ecddc671f3290038c205
client_nonce: 79a442d9fbebbd244e27fd10ea255dcec9f43e9b2c6a33575eb3377
5b081d77e
server_info: 6772656574696e677320616c696365
server_identity: 76ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf1485697
4424a8561115
client_info: 68656c6c6f20626f62
client_private_keyshare: 46124f54f47fec6b66c53e4154475d27a0e046c5d1c8
54b2f3680defdff14a0e
envelope_nonce: f627cf8e027b5fca94ba970dc06866b79d5914abb16526835bbbd
6c46d705cf2
server_public_key: 76ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf14856
974424a8561115
client_identity: fcca4fd8732b9887f566bbdcdb738c884f5390b360f43b5b3a4b
81b3bb7e060d
blind_registration: 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9db
cec831b8c681a09
client_public_key: fcca4fd8732b9887f566bbdcdb738c884f5390b360f43b5b3a
4b81b3bb7e060d
client_private_key: 31aca12a23a2a03db43c91fafe6d32589e2d8f09d8004d605
0ec275317cc7f08
client_keyshare: 5a7396b6e6e0dbb1690ba3b69061ba864fda0c2c078520f01804
ef15c0b25d56
server_keyshare: ea25f0b5ed03ec29b5eaacf21dde7d4c1fcb4e34ddb2d7c6e4a7
1b6d10e3d870
server_private_key: ccde5849510d7175da028ccccba666e446b9418cf7ba9383b
9530c75474bcb04
auth_key: 3f5312f1c60350f5c46ab368434035f5740eef83a6d5cbc7ed3720fb78a
c32a5ea9fc734296efc9167350492903c449d85ac774b05f37efcc3ea0bcd9c600f55
server_mac_key: 341d064d83d7415f28f9528771f10d768891ac552409d44ee7324
8eed0ed4b58f48ac7406fe8c7fce9cb13029bc30d4e2bc48711fe5932b499a55cb7c1
85ce1b
envelope: 01f627cf8e027b5fca94ba970dc06866b79d5914abb16526835bbbd6c46
d705cf20022ceffb2fded3ff3dfd323ef4411cc213014316463bdd6692907cd4caffd
885530d0d9ceb917641b2550623727461b647b81b1e81ae67fcb0f57ad93175306ff3
26b1ec66433a67ed4da46f1cb54c80c24cf805f3df77a2b81c7f5fda0bcb06f093fa9
prk: 8923bf6277c4593732d3cdfaa559f531acd20e5cbec5bc180ddf6795d7a4d7ab
a39404eed4f94adcf25c84d6e8764fb9bb943db894ac9655fed08b68097de0f9
client_mac_key: 37ffae79ea8bd0b83884ca45e65ce63d4a4210a39d8c158e8772b
31fa96a9e174b6badeb15454a14ac46ce4f758a1c9fe1748b7b598c7cb6c7431dbac4
448b45
pseudorandom_pad: cedf83514c15d07d731e5b788036df5d2669fa4e32dfb1294aa
d1c43dadb42fcafd1
handshake_encrypt_key: 7eec22c81178c6f91176961bc78ccb8a9459f9a54c565b
f44ab8d2445074bd994672f02e8d7a9974722acfca87a56ffbed3d4092d4ef5e8941c
5b117227e07d9
handshake_secret: cc5ce99088b2459ed11e6664e479c19d285878dc0961c47e741
221029f9ca3df00b2cd35b643a263a872e49de7f6bb95d68cb5793d36087b1d6a0b3c
7565f3c8
registration_response: 088ac01ebf5700f0c96bc2988509343cb7e2dd6f0df820
d0fb807faa11a26f56002076ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf14
856974424a8561115
export_key: 38b7c0fc66819d9cd51e0e0051d87e159c2be9829f3e2c2ad42560b12
b7b7950588be9bf8db36bfd9fe26ff55a57e42a5345ee1fa9734f78c8e4e427ede4ee
9e
registration_upload: 0020fcca4fd8732b9887f566bbdcdb738c884f5390b360f4
3b5b3a4b81b3bb7e060d01f627cf8e027b5fca94ba970dc06866b79d5914abb165268
35bbbd6c46d705cf20022ceffb2fded3ff3dfd323ef4411cc213014316463bdd66929
07cd4caffd885530d0d9ceb917641b2550623727461b647b81b1e81ae67fcb0f57ad9
3175306ff326b1ec66433a67ed4da46f1cb54c80c24cf805f3df77a2b81c7f5fda0bc
b06f093fa9
registration_request: c8d2e9ba503bf3f8821226653314427edb1ec8a3ecc94a5
dfbbe33d59d07b645
session_key: db9fa3c0bec6ce623b1b124b843c5b8a8d79f93247396eed72e8c06a
dba2d5389692f988d65e3adb0d59ed477e37fab31633daa514780522ada541eb354d7
d49
KE3: 3e2538f0a28344ba9db33e55270e1db37fedde130e13b088bad31239e3bbf358
7922f8039e205e842f2a012f8db39cb66994b9970363d24f128b882b2b696724
KE2: 5079b16709b195b3b63257b419efb752bd0603170160fa72b828ce9ff9209c0c
002076ba3df8660de4e37dd3ac120bb3f8c9a4d95931b54cf14856974424a85611150
1f627cf8e027b5fca94ba970dc06866b79d5914abb16526835bbbd6c46d705cf20022
ceffb2fded3ff3dfd323ef4411cc213014316463bdd6692907cd4caffd885530d0d9c
eb917641b2550623727461b647b81b1e81ae67fcb0f57ad93175306ff326b1ec66433
a67ed4da46f1cb54c80c24cf805f3df77a2b81c7f5fda0bcb06f093fa9be1b6a9ee06
b76c648efd2e57300cae3418a2137ee3abcfa018431ee50876be4ea25f0b5ed03ec29
b5eaacf21dde7d4c1fcb4e34ddb2d7c6e4a71b6d10e3d870000f853360d8962c60208
1c1a7f11e0ab10b045d752511f9254a95e390e72b9c60f073c85bf789649883a1c712
6b1150e6db4607ac5491833b25f91211ab4e7fc292912562f1397c15e6e91a4972b00
052
KE1: 7024ca0d5423176294fbb9ca968d8ce3fc879a231f1ceef69e672c89e02ded59
79a442d9fbebbd244e27fd10ea255dcec9f43e9b2c6a33575eb33775b081d77e00096
8656c6c6f20626f625a7396b6e6e0dbb1690ba3b69061ba864fda0c2c078520f01804
ef15c0b25d56
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
            Some("00") => EnvelopeMode::Base,
            Some("01") => EnvelopeMode::CustomIdentifier,
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
            hex::encode(&client_login_finish_result.shared_secret)
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
            hex::encode(server_login_result.shared_secret)
        );
    }
    Ok(())
}

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
OPRF: 0001
Hash: SHA512
SlowHash: Identity
EnvelopeMode: 01
Group: ristretto255
Nh: 64
Npk: 32
Nsk: 32
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 8dee75c66f14d8b891c6ba66f1ff8d27ab595186789ca5edf46dd
427b6effb95
client_private_key: 8bcb0b70dac18de24eef12e737d6b28724d3e37774e0b092f
9f70b255defaf04
client_public_key: 360e716c676cfe4d9968d1a352ed3faf17603863e0a7aa1905
df6ea129343b09
server_private_key: f3a0829898a89239dce29ccc98ec8b449a34b255ba1e6f944
829d18e0d589b0f
server_public_key: 66e130c6eb5b41f851b235b03a0eafeaa883f64147bc62cb74
9c22c762389c3c
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 1b42bc94d7f3844a0a284d377fbbe2bdef574d386c9f8b5ead7b7e1
5b151b939
client_nonce: 4b6737c0bb603516ffaad7af55446a4d179187eba9e1b987aabe2be
05397b701
server_keyshare: 5214e3ddc73db786480b79fa2da787f2080b82cbe922c2a9592b
44597d9a702e
client_keyshare: a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e787492
b98265a5e651
server_private_keyshare: c4d002aa4cfcf281657cf36fe562bc60d9133e0e72a7
4432f685b2b6a4b42a0c
client_private_keyshare: de2e98f422bf7b99be19f7da7cac62f1599d35a225ec
6340149a0aaff3102003
blind_registration: 7e5bcbf82a46109ee0d24e9bcab41fc830a6ce8b82fc1e921
3a043b743b95800
blind_login: c4d5a15f0d5ffc354e340454ec779f575e4573a3886ab5e57e4da298
4bdd5306
oprf_key: 080d0a4d352de92672ab709b1ae1888cb48dfabc2d6ca5b914b335512fe
70508
auth_key: 89f76086c4a22a1f9d6c0ab4c7f5b2b4602d756267f8ba7a27aaac1c624
8ec621e16e7935af1b1fa38ca0c389b8e563b8c7e0daa6cfbbc2ad53ea40e006ac243
prk: 159cb43f6d84d9423771010ff0223015870856ac20601876d6d02a9298bd7ec0
ef656d6537420e5d26d768454089389618c6f52c5865c855f2b2684c33c2a225
pseudorandom_pad: dc07da9e15679d4defb299284a029be4878469c905071f2b3d7
08de16c0b1f6e
envelope: 018dee75c66f14d8b891c6ba66f1ff8d27ab595186789ca5edf46dd427b
6effb95002057ccd1eecfa610afa15d8bcf7dd42963a3578abe71e7afb9c48786c431
e4b06ac6906d20d50ea18fe30a05152ac17f34d49cb00567f1cc37d2c7951e00a6c3b
dec25eed743d642c859f48425ecfd695ea27ffe9ee7df6232a8e0bf0b30c774bc
handshake_secret: c7c26c98fe5b164538ce0991e6dc2a3d7e50f78ee4ffac5dc66
48252fc43e10d3574040202417a2199d20841352ec63a25d22dd4e1f33630f2a02836
a9c6f0ce
handshake_encrypt_key: acb381928b2928e92b8780a7ab446e81f1b39545a1a287
bc33693882c5bb202cca4418aa416d955a2309f7663656c48fe63a261c62afa6fbd76
90b031e6d6cc5
server_mac_key: 4f45b1d86815c029d3bca5bf453d693f12bee45a0a71014ab0873
0939eb529ab2b532275887aaa6853866e1fe8ae67a34d555c94726128beb37f4debd9
009407
client_mac_key: ce95ecfcbed2348997e4ef4f232e8448e94f7bfefb9b135a12390
05963c2b6a415a760cb85b44df0da423e32d110e00c42251cb6e7cb19c512a17e28ad
bc6fa3
registration_request: ec9027daa5e9a901d641286a7ded51364142936ac7636e1
42e3f4368b4bd8124
registration_response: 8867d7c8c2c576a6322d49d46078ea32f479aed917c70a
636d3ada4397ea1c0e66e130c6eb5b41f851b235b03a0eafeaa883f64147bc62cb749
c22c762389c3c
registration_upload: 360e716c676cfe4d9968d1a352ed3faf17603863e0a7aa19
05df6ea129343b09018dee75c66f14d8b891c6ba66f1ff8d27ab595186789ca5edf46
dd427b6effb95002057ccd1eecfa610afa15d8bcf7dd42963a3578abe71e7afb9c487
86c431e4b06ac6906d20d50ea18fe30a05152ac17f34d49cb00567f1cc37d2c7951e0
0a6c3bdec25eed743d642c859f48425ecfd695ea27ffe9ee7df6232a8e0bf0b30c774
bc
KE1: e06a32011e1b1704eb686b263e5d132fff4e9f6429cd93b98db107485006792c
4b6737c0bb603516ffaad7af55446a4d179187eba9e1b987aabe2be05397b70100096
8656c6c6f20626f62a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e787492
b98265a5e651
KE2: 66f6b5fa1a4eb6bd7a0c93ed2639a31cba0d02e2df744003641d5a30a4a12364
66e130c6eb5b41f851b235b03a0eafeaa883f64147bc62cb749c22c762389c3c018de
e75c66f14d8b891c6ba66f1ff8d27ab595186789ca5edf46dd427b6effb95002057cc
d1eecfa610afa15d8bcf7dd42963a3578abe71e7afb9c48786c431e4b06ac6906d20d
50ea18fe30a05152ac17f34d49cb00567f1cc37d2c7951e00a6c3bdec25eed743d642
c859f48425ecfd695ea27ffe9ee7df6232a8e0bf0b30c774bc1b42bc94d7f3844a0a2
84d377fbbe2bdef574d386c9f8b5ead7b7e15b151b9395214e3ddc73db786480b79fa
2da787f2080b82cbe922c2a9592b44597d9a702e000ff048b3a462ab243936a4ef2de
87dd0bcd3e7d7f12004b59dc8edeff2885f9dbafa60a55d1d31397b0dd25944ea8b63
842d77720aec60e0708b24cc9a311d424f3880b3ac84a68adc7b5947d5266ec5
KE3: 17ace8fa7c3956f1ea6684fae1bae259e0d8d78214b235e8646904576c17fc43
b7a8eeb6b21b8ee94a31cc075717e8c0b25e8803837238055236ae908010a8e3
export_key: 13af620bbf9cf45da6d4223500d2a9c79b28478d7548cfd52e3708ffc
4d9ddffa9c7735e1958751efbd68c79df6c451ccc48b41dda1748b585c2b5fd7d7f82
64
session_key: 0b51348833b30bfeceab9d13888111c2fcf9c93b6689e1d6c601a26c
a29aa25e19949955ec7d056fce67c24d0fb1b53ea47e27e7966fc267379c3d0c9a738
f54
"#,
    r#"
OPRF: 0001
Hash: SHA512
SlowHash: Identity
EnvelopeMode: 02
Group: ristretto255
Nh: 64
Npk: 32
Nsk: 32
client_identity: 20fa92f2e4b7ea5b5e677ac4930ff3b93b0043481ab70bc613b2
e16a6dde6b05
server_identity: eae9dfa6b8348d34418c32d385e1eac99efbce1af320901f7c8e
de8d6d272c65
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 54cd539b090014c3ac095611ba067be43c8592ddcbcf234f36569
8f964ed836f
client_private_key: dc70a99bbabf1ebe98b192e93cedceb9c0164e95b891bd8bc
81721b83d66b00b
client_public_key: 20fa92f2e4b7ea5b5e677ac4930ff3b93b0043481ab70bc613
b2e16a6dde6b05
server_private_key: 709687a36c94592ab76579f42ce1be6961f0700496e71df80
6ebd5320554720d
server_public_key: eae9dfa6b8348d34418c32d385e1eac99efbce1af320901f7c
8ede8d6d272c65
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 539290dde2ab6046896ff9dfda5d149f5ffbdc7ce165dffaa1c1b03
4a1af27df
client_nonce: ef2e5f21761e7c387a770e6ab729fd31203c29acb18b146da3ba2a7
02cf905ac
server_keyshare: 96a9587e233e67f2397f10fec6355b68102534f1f1b115b4ddf7
485840efcd7c
client_keyshare: 54f35db3a52fb0cf2a97918a6987993231d227e28711eaef19a3
e5033632611a
server_private_keyshare: 6650d64df70618a878504ce73dcca27b1af125c67e48
1e7bd49d0b24709b200f
client_private_keyshare: ebb01c59f99bc955df622548e247f7ef180732909ff3
c5f87ff8c7867b8be704
blind_registration: 308f1d3fa1fea402f3c90b04601274050a3c6f467387c2f48
878823949b0e109
blind_login: 141e21373228a44b09d4c00da9a6bbaf9a5e54a1687c07f327833643
4245510b
oprf_key: b7126967aa0cb69c311b71343843ea041bae30e2bde41b548b8fbd8bced
97604
auth_key: 8e7357bf9c0d2a846452cdd3956d454365df0d307d619cc57e0eefa1aef
31b94e7eaee4402c13f0e508cbcdcc87e9cd1b18e08a258ae185bf74646379468ad0f
prk: b4d69d383cf93c3ea746a668b55de501a574a0aad0a7062e56d5f9942b5dcdf4
7109fb186261a209e7bdd20cde44c15a6095afc36f402cf1e2108783f11b8302
pseudorandom_pad: 1b83a29b29d86d9959b18621522ba3c639cd262236f124d5da5
75817ade23ffd
envelope: 0254cd539b090014c3ac095611ba067be43c8592ddcbcf234f365698f96
4ed836f0020c7f30b0093677327c10014c86ec66d7ff9db68b78e60995e124079af90
848ff6ef0b9e59e3d41ccbe83e08cfaec1124d3e557b8b7ffe4225e5a1f40bee6c077
6238028b6ab6c331534b35afde8806e7e4fb73b2eb255aa1484e6b5b608a3c3ac
handshake_secret: fd4ce6630386646324016ff5e8aff286e8325666ced7df3a39b
cfa200ec5c0d501505af4150439b14101ed540cc58c15e9ed0c6e8d0ae03c1758727a
bd2a20cd
handshake_encrypt_key: 9f13439e483065b0657dd575c30b56382e3fc9adec8e3a
171e3448ad13cb74be64af7968fb6109a3661124fcef29dd3e29f350f6095cdb97dd3
df2fda07c5273
server_mac_key: 70ac95f82f1936b945bd29dcafe19d17e9fd06f27eea1893ed1ad
af7ec596afe478125413cfd510406a8e93ffba72792c432a7cc93b1176c7ac3326882
6b5e60
client_mac_key: c0d5bfd0367a6a09c1b07a61703d2b4cc41e47a2e3a1372472c93
5a0b531f2f0902a038496768deadf5f8cb867c0b59df48682619f4e9a0c7c909ac0d2
cce2a4
registration_request: 3c8b89966e261a5aaf7aeb6dcdd94c87ce311bf197221b8
7ef44632d58f18a05
registration_response: caf9243d7ef3e267815632bf79c85a27a23f218a438815
2a523f6a310949807beae9dfa6b8348d34418c32d385e1eac99efbce1af320901f7c8
ede8d6d272c65
registration_upload: 20fa92f2e4b7ea5b5e677ac4930ff3b93b0043481ab70bc6
13b2e16a6dde6b050254cd539b090014c3ac095611ba067be43c8592ddcbcf234f365
698f964ed836f0020c7f30b0093677327c10014c86ec66d7ff9db68b78e60995e1240
79af90848ff6ef0b9e59e3d41ccbe83e08cfaec1124d3e557b8b7ffe4225e5a1f40be
e6c0776238028b6ab6c331534b35afde8806e7e4fb73b2eb255aa1484e6b5b608a3c3
ac
KE1: 8261a1efd78bea73faf256a23c200d729259886530fa43b875c1ca124b09bc7e
ef2e5f21761e7c387a770e6ab729fd31203c29acb18b146da3ba2a702cf905ac00096
8656c6c6f20626f6254f35db3a52fb0cf2a97918a6987993231d227e28711eaef19a3
e5033632611a
KE2: fa1f33a43a03123ebe35345ef93aa23b57ea8bfbee7022b05a179d60768ba02e
eae9dfa6b8348d34418c32d385e1eac99efbce1af320901f7c8ede8d6d272c650254c
d539b090014c3ac095611ba067be43c8592ddcbcf234f365698f964ed836f0020c7f3
0b0093677327c10014c86ec66d7ff9db68b78e60995e124079af90848ff6ef0b9e59e
3d41ccbe83e08cfaec1124d3e557b8b7ffe4225e5a1f40bee6c0776238028b6ab6c33
1534b35afde8806e7e4fb73b2eb255aa1484e6b5b608a3c3ac539290dde2ab6046896
ff9dfda5d149f5ffbdc7ce165dffaa1c1b034a1af27df96a9587e233e67f2397f10fe
c6355b68102534f1f1b115b4ddf7485840efcd7c000f32cb65026f996c3838716d302
454eee577a049edb36c5d06f9faf4a2eced065c07f4db4767bf3482bdf4014177b963
4f5f419bcb0606835bd417de4b4a2425c7f32faa49c4395aab6192d75d34e9fa
KE3: 734742138587e8553944a16f7e3f12554c54e96d7361e90c909e5de518267c46
676e3b514c68564c6dd60194860f7f425d816042fcf00c0b15ede703216f5fe4
export_key: 5e373cf62e2e1ee77b527e514eeb2844d69285401b5a27a7dfe8fb889
7a56190acfa179f68368ed3bc2068ab05de63670e691a0bbfde9d4bed6e1b57ae008a
ec
session_key: fa3156746b8a70e812aeff1dc50e7587dcc31acb0bf1705827918768
c3e9dbbd893de24e890c341aed9c75a1bef6fbe36f150a2da706ec989013238c3fd94
2a1
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

    Ok(password_file.serialize())
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
            ServerRegistration::deserialize(&password_file_bytes[..]).unwrap(),
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
            hex::encode(client_login_finish_result.message.serialize())
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
            ServerRegistration::deserialize(&password_file_bytes[..]).unwrap(),
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
            .finish(CredentialFinalization::deserialize(&parameters.KE3[..])?)?;

        assert_eq!(
            hex::encode(parameters.session_key),
            hex::encode(server_login_result.session_key)
        );
    }
    Ok(())
}

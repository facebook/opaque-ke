// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    errors::*,
    key_exchange::tripledh::TripleDH,
    keypair::{Key, SizedBytesExt},
    opaque::*,
    slow_hash::NoOpHash,
    tests::mock_rng::CycleRng,
    *,
};
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use curve25519_dalek::ristretto::RistrettoPoint;
use serde_json::Value;

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

// Pulled from "OPAQUE-3DH Test Vector 1" and "OPAQUE-3DH Test Vector 6"
// of https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/
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
envelope_nonce: cc7abb200199d5071c94efa49fb62435d3e70d03cf9573a95da54
20d3eebcd2b
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
server_nonce: 98b8081059f60ffed9336f026fd8e124737205ac73f5348ae5bebdb
49456c70f
client_nonce: 58dc21475ff730342f807bf031c7ae47a11f0d4dfaa63a7feb15d7e
36427ca44
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
auth_key: 7bb7f2b831ee30d3e5cc4012c8f721a4d8f9dd494932d53776e043df9bd
2aa284025b8b006fd8449536446ff50698f46c73fccb53f20d80898f185307d1d39e5
prk: b0aefddbb21d1b97bc40c07b172e0bf172ec740de4f6274f69d46350a447e9b1
b3fb1e4cefc7d8e393ff58a5c45c74d0615ee0eecde116f3d4e744142eb2ee89
pseudorandom_pad: 36a828b3b57bf242c4c47ccd9cb84e5b3cefaffe09629c6b94d
eba0ccec5fa39
envelope: 01cc7abb200199d5071c94efa49fb62435d3e70d03cf9573a95da5420d3
eebcd2bbd6323c36fba7fa08a2b6e2aab6efcdc183c4c897d822cf96d29b129932a55
3d469ffa9999fcbd37a1e8b6c1e579bcf83fed355c9ff413e6158d72d16f3ccd8699e
906027842694b6293b6303bbb7f324e0fccb4ae0f01edb60ee1d32992696e
handshake_secret: 2b041dcf12ac9b75dded88f891c25d76746ce9e2c1a43118ac4
aa5721cdc1bc2f0691e6c012a1ea9eb95ab4899b3e7058d37fe9546c46b0511877e40
f55aac6c
handshake_encrypt_key: ceef10f15d869a4cea8174fa98d0d96c7aaf8602d006fe
0c5274a40173db76cac820138c5890bb63fb974d1e3e925850cc2464e2c10f0a9a776
9a45e80889b1e
server_mac_key: f8fd7fdc349b5ae1339515e05912c89a795f561a117cdc84d8d8b
5f05b05751abfb87fa01c799c5d367244d1e32eab67ff926833c6025c556acffa4af1
f3871a
client_mac_key: 92a30cc82c374c06895aa07e81f0cf5f25309a24b595faefcd225
1f9219b47e47d17da4fe8b572dedefa350ed365f87b217973e90d0b647a2ccf1d796a
8970f6
registration_request: ec9027daa5e9a901d641286a7ded51364142936ac7636e1
42e3f4368b4bd8124
registration_response: 8867d7c8c2c576a6322d49d46078ea32f479aed917c70a
636d3ada4397ea1c0e66e130c6eb5b41f851b235b03a0eafeaa883f64147bc62cb749
c22c762389c3c
registration_upload: 360e716c676cfe4d9968d1a352ed3faf17603863e0a7aa19
05df6ea129343b0901cc7abb200199d5071c94efa49fb62435d3e70d03cf9573a95da
5420d3eebcd2bbd6323c36fba7fa08a2b6e2aab6efcdc183c4c897d822cf96d29b129
932a553d469ffa9999fcbd37a1e8b6c1e579bcf83fed355c9ff413e6158d72d16f3cc
d8699e906027842694b6293b6303bbb7f324e0fccb4ae0f01edb60ee1d32992696e
KE1: e06a32011e1b1704eb686b263e5d132fff4e9f6429cd93b98db107485006792c
58dc21475ff730342f807bf031c7ae47a11f0d4dfaa63a7feb15d7e36427ca4400096
8656c6c6f20626f62a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e787492
b98265a5e651
KE2: 66f6b5fa1a4eb6bd7a0c93ed2639a31cba0d02e2df744003641d5a30a4a12364
66e130c6eb5b41f851b235b03a0eafeaa883f64147bc62cb749c22c762389c3c01cc7
abb200199d5071c94efa49fb62435d3e70d03cf9573a95da5420d3eebcd2bbd6323c3
6fba7fa08a2b6e2aab6efcdc183c4c897d822cf96d29b129932a553d469ffa9999fcb
d37a1e8b6c1e579bcf83fed355c9ff413e6158d72d16f3ccd8699e906027842694b62
93b6303bbb7f324e0fccb4ae0f01edb60ee1d32992696e98b8081059f60ffed9336f0
26fd8e124737205ac73f5348ae5bebdb49456c70f5214e3ddc73db786480b79fa2da7
87f2080b82cbe922c2a9592b44597d9a702e000f72f38a0945819089c44c86820c51d
89cc35f77df03d330101bbed3b2f69066112f32529bdda0998657350fc9f8da4cde73
408ad931f4c2ea6237ccae4696483388b174f50cf96d439139b0f8680c3b
KE3: 9f0e4f73455ca9fe06bb52ad02670b09be5a03db11a73be4422f19963be082b0
eb55871022e8d1d87adc3ab50de7c738058eb659866d091648f2fed12e23fd53
export_key: 66c0b72aa829f13a166fb1a1168f1e26023921f0eed1126def4f81ba0
4924ad6012e42b63656ec199ba27670d1e7f23dc0a927714edc140134dde5a5d2063d
fc
session_key: 951c2bb1b876725fa7d3829db791dddd406a688507b47e24101bd0cc
5d071760b6fba59e8758a6ea6d7e5f51a715b49a47c50fee9a7c8a0451243c3ee837f
d30
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
envelope_nonce: f41e8b3c5a999aa946f9b562a150e5c5e36748a31a79feb241809
0438877888c
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
server_nonce: ef49d83cef5f1411ea30abb82b08bd85423aadb86e2c19df5930b3c
8498b9f97
client_nonce: 4ab1227db632bc079f79c0f5279df2dfa75cfbd4434ab40dcf844d6
77165cd3b
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
auth_key: 9f761a5a56a74269b382403aeba47c1d24b9e200e1839efcb616fb280da
1b6ba7bd71d6455dd3cd979c545608cfbfc1c4e9ba677e1d40848054a00696c4b2589
prk: 30bc3f37a757890ac17ce46043f3c5ed30c96fb8743205e77e84dc167d98e114
6093150ff7b4d002f793bfe717e88d174ed2669abdd9e96af473a7ac82973b0a
pseudorandom_pad: b909f990c94b9c5949a2b8d0874d602f846b7981b331fd79978
b530cc46c8670
envelope: 02f41e8b3c5a999aa946f9b562a150e5c5e36748a31a79feb2418090438
877888c6579500b73f482e7d1132a39bba0ae96447d37140ba040f25f9c72b4f90a36
7bdb425fa1dd4c49e17780f33b821e1e019668fe7f45520e26996ac8cb08e3d2566cc
439c83030464effecb8350e7b1ca31087d87f6a45ed3910c185a24a89d282
handshake_secret: ff89f264f8c3974238f4c8d736af7b0a55f2e4edc487cbf3e5c
7b4bbf21acd7c1d28354c2c8555fba57c4d4b1fbb4b772bfdf909881f67dd517cc9f4
f6ebaeac
handshake_encrypt_key: 3071b181f639062cf70b74d0ffe5ec8fa695da13cd2f00
e74b8b7ef348ae7a5df9c3a32c9f7aeaad5a28379712cf849b9707e221dce124abfad
d0225a8e8e045
server_mac_key: 7c37b344d189cbbeff80bbb4b78e2703d1a80dc28239923094287
62f7ce2a93b11f6e85dd45c02809afe8583d4aad6377e72788773af92eef33c690692
20ae76
client_mac_key: 2c4aff12ba7aa911a51f9e5b7a7c01439d854c97e4b8ec842a9db
d78345760328fd5a72424e49e25ec8fe1b6d9d42f774516f400948bd5a105d995d000
2fc83b
registration_request: 3c8b89966e261a5aaf7aeb6dcdd94c87ce311bf197221b8
7ef44632d58f18a05
registration_response: caf9243d7ef3e267815632bf79c85a27a23f218a438815
2a523f6a310949807beae9dfa6b8348d34418c32d385e1eac99efbce1af320901f7c8
ede8d6d272c65
registration_upload: 20fa92f2e4b7ea5b5e677ac4930ff3b93b0043481ab70bc6
13b2e16a6dde6b0502f41e8b3c5a999aa946f9b562a150e5c5e36748a31a79feb2418
090438877888c6579500b73f482e7d1132a39bba0ae96447d37140ba040f25f9c72b4
f90a367bdb425fa1dd4c49e17780f33b821e1e019668fe7f45520e26996ac8cb08e3d
2566cc439c83030464effecb8350e7b1ca31087d87f6a45ed3910c185a24a89d282
KE1: 8261a1efd78bea73faf256a23c200d729259886530fa43b875c1ca124b09bc7e
4ab1227db632bc079f79c0f5279df2dfa75cfbd4434ab40dcf844d677165cd3b00096
8656c6c6f20626f6254f35db3a52fb0cf2a97918a6987993231d227e28711eaef19a3
e5033632611a
KE2: fa1f33a43a03123ebe35345ef93aa23b57ea8bfbee7022b05a179d60768ba02e
eae9dfa6b8348d34418c32d385e1eac99efbce1af320901f7c8ede8d6d272c6502f41
e8b3c5a999aa946f9b562a150e5c5e36748a31a79feb2418090438877888c6579500b
73f482e7d1132a39bba0ae96447d37140ba040f25f9c72b4f90a367bdb425fa1dd4c4
9e17780f33b821e1e019668fe7f45520e26996ac8cb08e3d2566cc439c83030464eff
ecb8350e7b1ca31087d87f6a45ed3910c185a24a89d282ef49d83cef5f1411ea30abb
82b08bd85423aadb86e2c19df5930b3c8498b9f9796a9587e233e67f2397f10fec635
5b68102534f1f1b115b4ddf7485840efcd7c000f7ebe71d4ab326006a3aeca802435d
c995a38ac6662221f974cb920992d82b8ef8d147c77e29b628a82b5ccb01ea2f7bb60
af94cd1860e1bd974a11a1c9bd827789f663c4758eb71058c244138de0c2
KE3: d81f93397cdba85a43993d4d9afbdc67f147adfa2b223213b19692cb820eef48
5073eda4c8236b2f47702404ad60d9a875d189626fc7b7cc861825385470ae54
export_key: 03192555940b5b42e64e6200bf55cc701f1bace3d402a2f8d83977843
51a1e3fa1f07a471b783b208acb1d92be47903b6fa3a0df9f4d4b7956ee4f431e2950
f6
session_key: 58a7fa98bf3b7b52da21406abfb11d98734354edd47d7b32462c0513
f0617c89824ea6031d4147a86fc9f6c6837ce640c12fb937d764f296d1a9421ad1b2a
5d5
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
            &Key::from_bytes(&parameters.server_public_key[..]).unwrap(),
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
                &Key::from_bytes(&parameters.server_public_key[..]).unwrap(),
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
            hex::encode(client_login_start_result.message.serialize()?)
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
            &Key::from_bytes(&parameters.server_private_key[..]).unwrap(),
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
            hex::encode(server_login_start_result.message.serialize()?)
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
            hex::encode(client_login_finish_result.message.serialize()?)
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
            &Key::from_bytes(&parameters.server_private_key[..]).unwrap(),
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
            hex::encode(&server_login_result.session_key)
        );
    }
    Ok(())
}

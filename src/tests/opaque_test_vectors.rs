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
server_nonce: 0ef5dc5c619b5a58eecb1c8fba63ae5e723e059552bb067bc460efd
910ff58af
oprf_key: 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be03
7e50b
password: 436f7272656374486f72736542617474657279537461706c65
blind_login: ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63
e3263503
server_private_keyshare: ac56b748ee205ea817e823697857b4b40ad758328074
6897e9eb9192636db704
client_nonce: d0298cebb277efb5af53932af6bb10180b2ac35e5f69b55ad4c4191
4d579add6
server_info: 6772656574696e677320616c696365
client_info: 68656c6c6f20626f62
client_private_keyshare: 46244633cd475d25f3db6a6eb8304e2fe02e2a006805
3efee984e49b7f4ff60e
envelope_nonce: 9a87511fa84547961a5467f96caba559fb15f3a203146e4041bb4
b2179e83594
server_keyshare: a83ddbb1abf9e8e8c73fe39d3c18da434dd3f6fd52f01279028f
086126893d7f
blind_registration: c604c785ada70d77a5256ae21767de8c3304115237d262134
f5e46e512cf8e03
client_public_key: dec9d1223019c1aaaaac7397355016f8ea099b949fb5bcf5de
3b9b0b1b298301
client_private_key: f141e91e7006c583b615261f9d13e1807d811f6d108bbbab8
f44ab092c8cb206
client_keyshare: e00213e806c74d73509c68860d75620d09665f1a5030e485ff85
172d8ea54f54
server_public_key: 3881fefba6d687143ecaaec0d8658eb7fa247555f05fedb075
7866d49ea9883e
server_private_key: bc778d1c50714f8f2e7d1378650b5aaf8d61c003f07081ad3
93317506168c004
auth_key: 974ae6360db0593766490b4a95592552ae08fd3e611af028d82be4bde95
b39e2c5a68818fa5ca6be687fb7ec5f26d7c178fd81f7b61056959e88d339a13f560d
server_mac_key: cc7ee1c4d12a2693dc6358b91a1a97bb4e0bffab50bd19aa4a169
9584ed540baea9fa95f2139a0c9aa4d763be5eb5d7984acfecec65363f690c8058e09
5e96f7
envelope: 019a87511fa84547961a5467f96caba559fb15f3a203146e4041bb4b217
9e83594002262a8d608d300886f5a2bd8b9abe76da19af847755fda0541a1729bfd57
e94fbd79be8c03267be7f578b1a017eaff6f23a667f378ac41c516591d04681db9556
09ac4a200b398d0ea88faaa4a74f0291f462119a5cd51491c0935171d75a6421c4b62
prk: c2b586d349c6b573c59d85656958218a187862bd8ae2e06bf3e1e5500182b87d
44e5bb443e6593076934730f9a38a13c5d79f037d9e3e351dbc57f943ac23f29
client_mac_key: b2b2cb96dd005f8b4f52e3bcd9a8258ec39503b371d882ff99e08
7f9860aebfadab51fef9c7edb64318fe3b1bda1250bfd77edd98e8e18a7350ad09b8a
08c45c
pseudorandom_pad: 628827493a1ef8699fa86eac8df8f0b27b783af440b715ca1ad
914b9fce06331cbb8
handshake_encrypt_key: e5a1bc0dffdf22ba837cef7df4db164acc56eab7ba6796
e1a7caab9fce21485560a20f64b217f1c0ebea53b1bde1006860fa9907ca3b8ff1a48
0803664c30458
handshake_secret: 994ae04565986a5b3783488b3e299670a69f55274a6344d6afe
665907dd66750f594e59b40effb99806630766a74bd5bde6a45d26fc4f017d1b73a41
4f523502
registration_response: 1867301bcc67bdf8e640b7d6edcbe2a65488446417b50d
30cdba66ccb379e57200203881fefba6d687143ecaaec0d8658eb7fa247555f05fedb
0757866d49ea9883e
export_key: 93c48fa650a6c2b9fddc27c9697be2f259b0083515b650a7b1520af92
e631c85946fb811b22d636d137ef97380bf9322606b5d97452ca262e9136284d23467
76
registration_upload: 0020dec9d1223019c1aaaaac7397355016f8ea099b949fb5
bcf5de3b9b0b1b298301019a87511fa84547961a5467f96caba559fb15f3a203146e4
041bb4b2179e83594002262a8d608d300886f5a2bd8b9abe76da19af847755fda0541
a1729bfd57e94fbd79be8c03267be7f578b1a017eaff6f23a667f378ac41c516591d0
4681db955609ac4a200b398d0ea88faaa4a74f0291f462119a5cd51491c0935171d75
a6421c4b62
registration_request: 241b621c417c0705b5ea7a8b7cdd5039fd61e6b63effe2a
44418164c4d49003e
session_key: f058bc490684af7833743104168cabe0357ffb648fd0104aae507d59
b9dfdde1a26ab0dc6f7d03a2ea4feb2d2aea04bfc9a1fbd89e309362082c13edc1598
f97
KE3: 290e6fd07a3c225810e88234402879e0d6ed0791f8a3446cf80ac4fbd7e23afc
3b539d926edc9983edacee08c285e82c46b48cb055c983d3cc2c629586dfe99d
KE2: e83812f06568d57b8cdfdcc90fe91454e21bd25dd2a1c32dd1599a2e4a4b6c35
00203881fefba6d687143ecaaec0d8658eb7fa247555f05fedb0757866d49ea9883e0
19a87511fa84547961a5467f96caba559fb15f3a203146e4041bb4b2179e835940022
62a8d608d300886f5a2bd8b9abe76da19af847755fda0541a1729bfd57e94fbd79be8
c03267be7f578b1a017eaff6f23a667f378ac41c516591d04681db955609ac4a200b3
98d0ea88faaa4a74f0291f462119a5cd51491c0935171d75a6421c4b620ef5dc5c619
b5a58eecb1c8fba63ae5e723e059552bb067bc460efd910ff58afa83ddbb1abf9e8e8
c73fe39d3c18da434dd3f6fd52f01279028f086126893d7f000ffa4ba765e84dd8080
c061267b2604326ed135cef21f36407f3bc15609f9693c8eedbe73f2bf8c22c84b295
b3181b074ced2cc9f66a4776401336b7b43d50bed3188593e9e8fb310ff9e6660e44e
d2f
KE1: b68e0e356f8490fa9c3bed952e16cc02db21eda686b3c484f3d9d912caa41f76
d0298cebb277efb5af53932af6bb10180b2ac35e5f69b55ad4c41914d579add600096
8656c6c6f20626f62e00213e806c74d73509c68860d75620d09665f1a5030e485ff85
172d8ea54f54
"#,
    r#"
Group: ristretto255
EnvelopeMode: 02
OPRF: 0001
SlowHash: Identity
Hash: SHA512
server_nonce: 2bf0d250ba1b4ee89929fcb6f91c521551ad52cdd6ef1ab438cc024
e94d6a8c9
oprf_key: 89c61a42c8191a5ca41f2fe959843d333bcf43173b7de4c5c119e0e0d8b
0e707
password: 436f7272656374486f72736542617474657279537461706c65
blind_login: e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd
4171ea02
server_private_keyshare: 7447dd29f57e61d9a67e25cf840b359b605e54eb8bc6
67fcd7fe18fdb47a0100
client_nonce: c1162f56eb58419746bb66e1113d401edb0302d894ee962f7e79ae1
2821bdefd
server_info: 6772656574696e677320616c696365
server_identity: 3881fefba6d687143ecaaec0d8658eb7fa247555f05fedb07578
66d49ea9883e
client_info: 68656c6c6f20626f62
client_private_keyshare: b08950a66fc7f2845f3c0e8f6027a8cd843103c560a2
0e8390457c9a705d1304
envelope_nonce: 6757226024757abf5c42c9d4451a31c90317bcf54741bb9d9e426
41aab0d0fbd
server_public_key: 3881fefba6d687143ecaaec0d8658eb7fa247555f05fedb075
7866d49ea9883e
client_identity: dec9d1223019c1aaaaac7397355016f8ea099b949fb5bcf5de3b
9b0b1b298301
blind_registration: 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9db
cec831b8c681a09
client_public_key: dec9d1223019c1aaaaac7397355016f8ea099b949fb5bcf5de
3b9b0b1b298301
client_private_key: f141e91e7006c583b615261f9d13e1807d811f6d108bbbab8
f44ab092c8cb206
client_keyshare: 9a5fd96f24fea1d99183cfdbaf559a5eb8083ebba2b066bc5d1e
b511896a5417
server_keyshare: 1a6074e0cc3d156865ebecbe371777078d7eccd6ceddae09bec2
65d77f3d0301
server_private_key: bc778d1c50714f8f2e7d1378650b5aaf8d61c003f07081ad3
93317506168c004
auth_key: 8c66139db274252b21b83791f53883406d057b19f75637f9d891d1d982d
ceab86549900fdd3952d3d16ed6c874b15de2229f5d0b6c09e1b42dbb3bb985884e6f
server_mac_key: 64b39a39691023fceb04e5c13c40d50fc4ca5a71d0315e30e86f9
116a4c7edc91398745186155e2ceee26f82c48939c24299263eb1c88644a17536196f
981207
envelope: 026757226024757abf5c42c9d4451a31c90317bcf54741bb9d9e42641aa
b0d0fbd0022b82a0432f3d9c24998d3c74e4b824ea7b835067fedb21d21fafec27968
09853e0d5da9109493ed080c98752f92ecd39353d785a84c63f623920b24f2683f76a
c44ecd0a289b260507d90773502ef3e3fa03ab2e4a6cc54c15eca358ab8ebfc097cb8
prk: cfd0673e7df8668da7873319036876c00d3ca13920318352336cd2a6f9a0b6be
f69a5ad94f42bcf506d7014444fd59b35270131c9383c11199a3cb60c086ffbf
client_mac_key: 106910daa6f98b40af2b99c6e277be37d57cdee8e623e08c04a91
ce77817338976bd9d91c70aa094e7132338c0b86312315a2648dd8be36f46dc85066b
d789fc
pseudorandom_pad: b80af5731ac7b24f5d50715b6d9dd3b459b57bfef2df0daa415
54d3dc300a9b2bf5b
handshake_encrypt_key: 62c52174d46d3ddcb34849d0706b0c08ecbc5b5add858e
d74d037f6696e2fc8fa772ad8871b104f6cddbc72f4b478ef35cc662c1ae5c303fc03
92c288ca87a16
handshake_secret: 5c2dc6c992daa89f2d881a3f0fd56e88a633330134efbe3910f
e7f7c521f0c98f70439acbb0dd3d3ebba735d26ccbdf92299dc95042c4dbd628d3e89
83828712
registration_response: 088ac01ebf5700f0c96bc2988509343cb7e2dd6f0df820
d0fb807faa11a26f5600203881fefba6d687143ecaaec0d8658eb7fa247555f05fedb
0757866d49ea9883e
export_key: 12114bfdd23ba4c7c9abedf72cf068f5bf14a6e8c39c28eb536fe46f3
80fa2276328f15fe89f1147462d84c3114bc734bbbc6acaa240f33d3e230d10c563d1
8b
registration_upload: 0020dec9d1223019c1aaaaac7397355016f8ea099b949fb5
bcf5de3b9b0b1b298301026757226024757abf5c42c9d4451a31c90317bcf54741bb9
d9e42641aab0d0fbd0022b82a0432f3d9c24998d3c74e4b824ea7b835067fedb21d21
fafec2796809853e0d5da9109493ed080c98752f92ecd39353d785a84c63f623920b2
4f2683f76ac44ecd0a289b260507d90773502ef3e3fa03ab2e4a6cc54c15eca358ab8
ebfc097cb8
registration_request: c8d2e9ba503bf3f8821226653314427edb1ec8a3ecc94a5
dfbbe33d59d07b645
session_key: 818d3e379a3ffef7b2707ca760d4b47c91daaa1d67131305116318bf
43266da203b890129a9117da5e1214c537989c3b91cc71549280b55d27e9594e80856
eba
KE3: 3944b13ec8812a9fc9206b215afd6b8f81af4ba85fee2d3ac9c55e088d18f5a0
126c423ac44a1992703d4c68b9784abf2862f80726e1c5d0677e61453f72a108
KE2: 5079b16709b195b3b63257b419efb752bd0603170160fa72b828ce9ff9209c0c
00203881fefba6d687143ecaaec0d8658eb7fa247555f05fedb0757866d49ea9883e0
26757226024757abf5c42c9d4451a31c90317bcf54741bb9d9e42641aab0d0fbd0022
b82a0432f3d9c24998d3c74e4b824ea7b835067fedb21d21fafec2796809853e0d5da
9109493ed080c98752f92ecd39353d785a84c63f623920b24f2683f76ac44ecd0a289
b260507d90773502ef3e3fa03ab2e4a6cc54c15eca358ab8ebfc097cb82bf0d250ba1
b4ee89929fcb6f91c521551ad52cdd6ef1ab438cc024e94d6a8c91a6074e0cc3d1568
65ebecbe371777078d7eccd6ceddae09bec265d77f3d0301000fba6a857cb74713bd0
fd39f363bcc71a6f30218ca78126c553840bb4207237a2379fd803a6e6a25fb77806f
0b05eb477322931cffcad25ac5e78571ac0d2f56627ddb1a136121bea8c01d869266a
435
KE1: 7024ca0d5423176294fbb9ca968d8ce3fc879a231f1ceef69e672c89e02ded59
c1162f56eb58419746bb66e1113d401edb0302d894ee962f7e79ae12821bdefd00096
8656c6c6f20626f629a5fd96f24fea1d99183cfdbaf559a5eb8083ebba2b066bc5d1e
b511896a5417
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

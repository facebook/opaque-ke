// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite, errors::*, key_exchange::tripledh::TripleDH, opaque::*,
    slow_hash::NoOpHash, tests::mock_rng::CycleRng, *,
};
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
    pub credential_identifier: Vec<u8>,
    pub password: Vec<u8>,
    pub blind_registration: Vec<u8>,
    pub oprf_seed: Vec<u8>,
    pub masking_nonce: Vec<u8>,
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
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
EnvelopeMode: 01
Group: ristretto255
oprf_seed: 7bc32c4249689ebdf218d04a2cbfb8d06850d4f1d1acb2b0413b9b3e40
b45b3f9f4647df5bbf6dd32e7d41f7dbc2ddf053f047cbf26a684f2b341ad7459373f
1
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 69f191aeb1af61c1feea7688a7c433a645d0f81c3168b4558b3f1
d83d08b7a25
masking_nonce: 154b361eb3a95bcb64700b8c26898a1e2f78eeb6232b2361b84721
778ca93686
client_private_key: 533c2e6d91c934f919ac218973be55ba0d7b234160a0d4cf3
bddafbda99e2e0c
client_public_key: a07d9609083613e2d7521b8f77f1cd7a07d89ea03aa0045080
775edc37949341
server_private_key: 3af5aec325791592eee4a8860522f8444c8e71ac33af5186a
9706137886dce08
server_public_key: 4c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b
78624cbd10b371
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: a71b6f2ff4c8baae05637f574deec70050dffda1f68d10e8648c838
b696e1918
client_nonce: acd3d4ffff4667b6a6b2d82b95bb8a171caacaa063e102a3a10077a
a6c7ac211
server_keyshare: ca372e52516d51c19763ad5eb1a5b60dafb68c264dcf6bcc692f
667a71c5a617
client_keyshare: 4c415eebd7a9bb5f921cbcfc5863e48c9e79fd2ecc1788e2b616
bea0853f627a
server_private_keyshare: 080d0a4d352de92672ab709b1ae1888cb48dfabc2d6c
a5b914b335512fe70508
client_private_keyshare: 7e5bcbf82a46109ee0d24e9bcab41fc830a6ce8b82fc
1e9213a043b743b95800
blind_registration: 8bcb0b70dac18de24eef12e737d6b28724d3e37774e0b092f
9f70b255defaf04
blind_login: f3a0829898a89239dce29ccc98ec8b449a34b255ba1e6f944829d18e
0d589b0f
oprf_key: f993af4bc97f6e752da6d97eb0a489a68ec1dc2f3327e3f480880f26a2b
73b0a
auth_key: 8ec5878a7d305c1252f11e4c1a5b8219919a4b5b71c85ab3130d0b8cbd9
e5302669a3b1b4275b5ffb67b33db3955eac60b37bea96d3dfad169be702720a00b3b
prk: 2e400d7a64d6abbe9d36a83f9b5a89bbc1cef2fef1094292c4b76b6a3c1d987e
de2228b6d36ae174bc304302af542b6ccb1e7f2fb6bd302b30536112cc11110e
pseudorandom_pad: b21d130015d7f6d33bbf27f8e1ea3d9a7c7c05f94a6f197bc85
1313f4a4f2d2f
envelope: 0169f191aeb1af61c1feea7688a7c433a645d0f81c3168b4558b3f1d83d
08b7a25e1213d6d841ec22a2213067192546820710726b82acfcdb4f38c9e82e3d103
234e3f37b5afd99144411550b9dc3f4f0c920d923cdfb952f5a9050a6c97440230262
4bc5da9563a768f73b195f992741e399cfa9d95eb48b220998b59360b01a3
handshake_secret: 7b416efcce7df41f7b9698c68a6b278286b89d378f5b3fac7f4
d96a0d45f5457e2c4ca2f3bf693325a8710d223a988aedcab7a4deb4892ddb7d13dec
1989d298
handshake_encrypt_key: 122f419c0457e01dda8382e65e92b614015b37cba09666
92c6363f28fad97d00d2a0e6ab112e39a81a11aae074696e2e10b433918c5ffca6114
43a7bea8ad353
server_mac_key: 9aeaacea81de96d2115bc9f86c1bedfe04357afc69a16c4e3c0bc
eb07409d5a9e4f76df2844f5f493feb55c9384af39bb9bd3e928cb796b2c8f1dc03a9
ecf93d
client_mac_key: ee1ccd9c1d66bd6137aec52e323de67c914a35980fc384adeb15e
d10dfea0c389ffaebd889ee36ec4e03253f814e07d93b13e1d8c9a9fe683ea39c6b9d
58e53f
registration_request: 24bbcabb15452642f709cb8567eff38f4cda6044aca3356
87a62b8453d849c18
registration_response: fe8865a1916ad735de5e131930f14922582e3205665cbf
2e9e2f3fbcfb776e2b4c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b7
8624cbd10b371
registration_upload: a07d9609083613e2d7521b8f77f1cd7a07d89ea03aa00450
80775edc379493418183c015b1b27290fc3cf14c963da55f59ed34f70ef871bcc9888
9d53039e5c589b3474f1e3439bfefaf55100334a578ca3d5ec8437d7b06ba02689536
e8b6ae0169f191aeb1af61c1feea7688a7c433a645d0f81c3168b4558b3f1d83d08b7
a25e1213d6d841ec22a2213067192546820710726b82acfcdb4f38c9e82e3d103234e
3f37b5afd99144411550b9dc3f4f0c920d923cdfb952f5a9050a6c974402302624bc5
da9563a768f73b195f992741e399cfa9d95eb48b220998b59360b01a3
KE1: 0e8eeeb2ca0dbf5f690cfe0b76783d7667245f399b874a989f168fdd3e572663
acd3d4ffff4667b6a6b2d82b95bb8a171caacaa063e102a3a10077aa6c7ac21100096
8656c6c6f20626f624c415eebd7a9bb5f921cbcfc5863e48c9e79fd2ecc1788e2b616
bea0853f627a
KE2: 085ab15bca16570dfea48efee2e12d1b13b95c1530a5e9352acb6fc10485353f
154b361eb3a95bcb64700b8c26898a1e2f78eeb6232b2361b84721778ca9368696b92
2224f1082627dcb1912944d5df179fe27633a6deff35649bd8192f6c2012241823265
51d7b485a071b2af1fb86dea63a8e9d3b40cd43bf42e97bb9d1763508478412c1a495
1add4c82e622e2a14b612376364d7fd3a3cdfc1bb36bb789afe1567cbf1c10a006eb8
85ef412395e6d4a1823197254fb5d1a1345228712fd27ed49355735d30dbf548fea57
48cfdc3b58e8062d0060e43e12c6a4b3788682c62a71b6f2ff4c8baae05637f574dee
c70050dffda1f68d10e8648c838b696e1918ca372e52516d51c19763ad5eb1a5b60da
fb68c264dcf6bcc692f667a71c5a617000f723180269119d5c2c2348cabb9ed372e24
70210d9de3ff1970b449d7bac51d0a3b10d58d3f8c58d5698230d6dc102794f658538
7b6b412a9ce973109ebeb62ea444c46180448a3a0af89055786d7ce
KE3: 737427092049117f0a75e42515b81572c9e971687509bf7919950fe078bc6cfd
0cd8e7f32232f6eb296a000c2df29f6b65a4a858229766526380d687eda004d4
export_key: b3816d8a69b2a3f4d15113ae5b474353e99fbad6be7e331376688cc94
6e19e063a604ee3532981e756fe60f0a3822b5881729752e2309ee21072b215e82bd4
25
session_key: 3cf3ce41bd59b6e299aab4f26575f8bb8d4d8b12d2406c0d7a3eed92
11387c363949199665317c5500aef2fb8aa081aa7d74191b92b928382d57b03f13140
9cf
"#,
    r#"
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
EnvelopeMode: 02
Group: ristretto255
client_identity: 36840cc4f3fd4f57bad888ff6e75a120a6ae132b128df738fbc3
16e5bd57356a
server_identity: 3e2651ff8442883bb83ec1b46a76f99a556ab182fd4828da3fe9
65b145a0dc7f
oprf_seed: 258b268d6ec9a468c30e7f009e5d631a31dede64596c8dde12e377d319
3efe2c90e609e135c4bf7d2c7326306ba1f45c510ca9d2dfe4816c680fadfef82bfbe
c
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: e8cd944521ab8459398b39ef6c8b2bc12473281ec34a3220db1c7
88fad2a001b
masking_nonce: 24907c8e1151cae5dfb583a99ec1d74d93166e6ee5089137e7a924
a11d60137b
client_private_key: ed811b4cca7c0e51a886c4343d83c4e5228b87399f1dbf033
ee131fe4ad75c05
client_public_key: 36840cc4f3fd4f57bad888ff6e75a120a6ae132b128df738fb
c316e5bd57356a
server_private_key: 0db27eb7aef2af92c3b297c662a87631531aade91c0558d87
224d922a8573f08
server_public_key: 3e2651ff8442883bb83ec1b46a76f99a556ab182fd4828da3f
e965b145a0dc7f
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ee9675eb495049b7d24c33691d9b150406e646d1f6f2911bf5c665b
cb71e3649
client_nonce: 10603d5ae57cdd698410d49769c00bc248ebba0f5709ba9d6179ab4
42d8a883c
server_keyshare: 264af8bc6a2c78acb503cd838ae3e5e3715df02d19dd4ddfbca9
e4f46b0a0e2d
client_keyshare: 223228d3df70ac6e0b179a48609517304386692952f49cff086e
0bea06f5363f
server_private_keyshare: 94b049e1b0d73ab5b8d914b08dff3e52e62ea8898d35
b2862d28ff4c2bb1a607
client_private_keyshare: 362f233a8a73971925abc79daa9fcc06f6d3acf12df8
2de919be4937fe716a03
blind_registration: 9b53af4cbdb352b0a2016e5e5f6c0bee4a642526ef9910289
315b71feff26f0f
blind_login: 275e46a6aea42c40b78bd2f1281617519f3f790c8d0f42eacce68456
380b8405
oprf_key: 09da9c8c1ff925937a04c07b613a8bcdf1335db32e11db0a4ee45bfc297
2380f
auth_key: 20e401aeb76dac20c8f5054685d2531aa3ebe53569b5a50d9d34d19b93b
e7488d7e7b6f0ae0f5c36a876464ac0b69aa2199438d7ac1be69059dea6394dcbe067
prk: 91a4c98e88faa5f30fd0bdc2fb2f0cc808d6808822d079e251bef46a399e4a25
6bd3c6207bd01b22bdd713ca3c2c3e1945bfddbbce193e5073c9f47b29928279
pseudorandom_pad: c08e7bb57b5b4e6c866119a8d29c51f4f97378e938342f596ff
56075bb06dcf0
envelope: 02e8cd944521ab8459398b39ef6c8b2bc12473281ec34a3220db1c788fa
d2a001b2d0f60f9b127403d2ee7dd9cef1f9511dbf8ffd0a729905a5114518bf1d180
f5023e24c1dba1c8940220cf5475fb7d73419a4896096b37403ccdec1da295365cad4
a423674850602e44a524ca3ecf7a3364ab106350e29cfae3937489b30601c
handshake_secret: 54a0b775fda0a405c3e2b585ffd427f8002ff6ed14fb13dbb2f
c2597984e14b40830c131a6c72035fd40a0c0ac7a24ace5682d73ac1e3a2dff0d36b3
75cd3146
handshake_encrypt_key: 2ecbf7901784137571505028bcd2c119c77038ed024d87
20810c50e076fbf01be82326df2d3c52a5fa2da623603c65caa078002abb9c9d0d5f7
07c5fcade01bf
server_mac_key: fc7bafe7c51426b18bee3fa7cd895c145ba36481946f4fa7b4355
3746331ec201891eb3b3cf28590569e3f7d0863da5542ff728c31282bba2ebcc642be
533fa2
client_mac_key: da7cb58102085bb05de9e175a004e862c653aac24a529f416b33e
3308cf9a9cd9d15e655c02f44d24f8e8e257a27e4db82049ba1eaa456a4f0ba73cfc4
ef1ef4
registration_request: 1e026d981ad38a4c03e5785f151fc42cf932ec153a1134a
3e6f7f3cb9b2c632d
registration_response: d4d75537ab05e41746c6ed5de6d985e8d08e47a433f04e
9b97f0be760dc870093e2651ff8442883bb83ec1b46a76f99a556ab182fd4828da3fe
965b145a0dc7f
registration_upload: 36840cc4f3fd4f57bad888ff6e75a120a6ae132b128df738
fbc316e5bd57356a1008b12b8ab4c890f937b961554635298ea2696433c7a285c7df2
46da4bef777cc3b4b1004222263792be00050b20385c6f22abd40dc61bcfa823e3c83
4f4fa702e8cd944521ab8459398b39ef6c8b2bc12473281ec34a3220db1c788fad2a0
01b2d0f60f9b127403d2ee7dd9cef1f9511dbf8ffd0a729905a5114518bf1d180f502
3e24c1dba1c8940220cf5475fb7d73419a4896096b37403ccdec1da295365cad4a423
674850602e44a524ca3ecf7a3364ab106350e29cfae3937489b30601c
KE1: be5993d16412c8452d6b320ea8025a8f0b405a0d62dce14bee5dda17c3ef2645
10603d5ae57cdd698410d49769c00bc248ebba0f5709ba9d6179ab442d8a883c00096
8656c6c6f20626f62223228d3df70ac6e0b179a48609517304386692952f49cff086e
0bea06f5363f
KE2: a2668282db653a9ed70e46556a78381bba08a8163a71463afc499289a2bf9632
24907c8e1151cae5dfb583a99ec1d74d93166e6ee5089137e7a924a11d60137b6e10b
ed0e73a37ea9617af60b3d295d6bd0761c2acdaae6a88614bd10f2ce5cd5dcec97b3e
bdd1508e8aebdb48f86bec27dc21aaf6e0aaf67cd44b62a28b4377b4dee4634922bfb
7b30550fafd287d00c3a2776f4c31f5a568b2d564cc9281b9cb2fea2ec45feba2d7f0
0fe1f595647a515b8f7178139f668720de10c8e5d41169a79f7809d120ebe8b156855
4ebc9cf4b85454bdfca44cb1d4552871e0ffb1373ee9675eb495049b7d24c33691d9b
150406e646d1f6f2911bf5c665bcb71e3649264af8bc6a2c78acb503cd838ae3e5e37
15df02d19dd4ddfbca9e4f46b0a0e2d000f5e02b66c4e83b9933b4ff5dc10a8e5e064
3cbf26f738bca0d25b0db9740dcbabbeb23e54c59deec56dab96bc96daa727aa0b730
bf81e15d82641f49bc5d4c998c2bd0416f27de631f445c93e43522f
KE3: 01be33d72a3d430b0bf3d5e3ef3450652c23354e818460b315a644635882899f
4f6746efabb3da6a5a8a645bbeba96d32d133e8d6e0ec13e96af61c74fe814f5
export_key: 3d4d4d6c586ef538d08756f5a1a04cc190aee59e8dea997d0aaff89a8
da58ac712fb5002666d8fb09b18a4f46a54a858592dc3c0b683a37a06d5a29728349b
91
session_key: eaa0057dde12425c05b185fc490579987638a9a2d56dece67db5acc3
b526241174635a7ffff2c2ad6359a82eff279cc23c8f6768dcbffc801420fbfd6f147
ae2
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
        credential_identifier: parse!(values, "credential_identifier"),
        password: parse!(values, "password"),
        blind_registration: parse!(values, "blind_registration"),
        oprf_seed: parse!(values, "oprf_seed"),
        masking_nonce: parse!(values, "masking_nonce"),
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
    let password_file = ServerRegistration::<Ristretto255Sha512NoSlowHash>::finish(
        RegistrationUpload::deserialize(&parameters.registration_upload[..]).unwrap(),
    );

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
        let server_setup = ServerSetup::<Ristretto255Sha512NoSlowHash>::deserialize(
            &[
                &parameters.oprf_seed[..],
                &parameters.server_private_key[..],
            ]
            .concat(),
        )?;
        let server_registration_start_result =
            ServerRegistration::<Ristretto255Sha512NoSlowHash>::start(
                &server_setup,
                RegistrationRequest::deserialize(&parameters.registration_request[..]).unwrap(),
                &parameters.credential_identifier,
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
        let server_setup = ServerSetup::<Ristretto255Sha512NoSlowHash>::deserialize(
            &[
                &parameters.oprf_seed[..],
                &parameters.server_private_key[..],
            ]
            .concat(),
        )?;
        let password_file_bytes = get_password_file_bytes(&parameters)?;

        let mut server_private_keyshare_and_nonce_rng = CycleRng::new(
            [
                parameters.masking_nonce,
                parameters.server_private_keyshare,
                parameters.server_nonce,
            ]
            .concat(),
        );
        let server_login_start_result = ServerLogin::<Ristretto255Sha512NoSlowHash>::start(
            &mut server_private_keyshare_and_nonce_rng,
            &server_setup,
            Some(ServerRegistration::deserialize(&password_file_bytes[..]).unwrap()),
            CredentialRequest::<Ristretto255Sha512NoSlowHash>::deserialize(&parameters.KE1[..])
                .unwrap(),
            &parameters.credential_identifier,
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
        let server_setup = ServerSetup::<Ristretto255Sha512NoSlowHash>::deserialize(
            &[
                &parameters.oprf_seed[..],
                &parameters.server_private_key[..],
            ]
            .concat(),
        )?;
        let password_file_bytes = get_password_file_bytes(&parameters)?;

        let mut server_private_keyshare_and_nonce_rng = CycleRng::new(
            [
                parameters.masking_nonce,
                parameters.server_private_keyshare,
                parameters.server_nonce,
            ]
            .concat(),
        );
        let server_login_start_result = ServerLogin::<Ristretto255Sha512NoSlowHash>::start(
            &mut server_private_keyshare_and_nonce_rng,
            &server_setup,
            Some(ServerRegistration::deserialize(&password_file_bytes[..]).unwrap()),
            CredentialRequest::<Ristretto255Sha512NoSlowHash>::deserialize(&parameters.KE1[..])
                .unwrap(),
            &parameters.credential_identifier,
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

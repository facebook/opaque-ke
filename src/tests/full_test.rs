// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

#![allow(unsafe_code)]

use core::ops::Add;
use std::string::String;
use std::vec::Vec;
use std::{format, println, ptr, vec};

use digest::core_api::{BlockSizeUser, CoreProxy};
use digest::{Output, OutputSizeUser};
use generic_array::typenum::{IsLess, IsLessOrEqual, Le, NonZero, Sum, Unsigned, U256};
use generic_array::ArrayLength;
use rand::rngs::OsRng;
use serde_json::Value;
use subtle::ConstantTimeEq;
use voprf::Group;

use crate::ciphersuite::{CipherSuite, OprfGroup, OprfHash};
use crate::envelope::EnvelopeLen;
use crate::errors::*;
use crate::hash::{Hash, OutputSize, ProxyHash};
use crate::key_exchange::group::KeGroup;
use crate::key_exchange::traits::{Ke1MessageLen, Ke1StateLen, Ke2MessageLen};
use crate::key_exchange::tripledh::{NonceLen, TripleDh};
use crate::keypair::SecretKey;
use crate::ksf::Identity;
use crate::messages::{
    CredentialRequestLen, CredentialResponseLen, CredentialResponseWithoutKeLen,
    RegistrationResponseLen, RegistrationUploadLen,
};
use crate::opaque::*;
use crate::tests::mock_rng::CycleRng;
use crate::*;

// Tests
// =====

#[cfg(feature = "ristretto255")]
struct Ristretto255;

#[cfg(feature = "ristretto255")]
impl CipherSuite for Ristretto255 {
    type OprfCs = crate::Ristretto255;
    type KeGroup = crate::Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

struct P256;

impl CipherSuite for P256 {
    type OprfCs = p256::NistP256;
    type KeGroup = p256::NistP256;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

#[cfg(all(feature = "curve25519", feature = "ristretto255"))]
struct Curve25519Ristretto255;

#[cfg(all(feature = "curve25519", feature = "ristretto255"))]
impl CipherSuite for Curve25519Ristretto255 {
    type OprfCs = crate::Ristretto255;
    type KeGroup = crate::Curve25519;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

#[cfg(feature = "curve25519")]
struct Curve25519P256;

#[cfg(feature = "curve25519")]
impl CipherSuite for Curve25519P256 {
    type OprfCs = p256::NistP256;
    type KeGroup = crate::Curve25519;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
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

// To regenerate these test vectors, run:
// cargo test --features curve25519-u64 -- --nocapture generate_test_vectors
#[cfg(feature = "ristretto255")]
static TEST_VECTOR_RISTRETTO255: &str = r#"
{

    "client_s_pk": "dcddc4b2e2880d52e5e7feb1a960483279ec01322a9459a38617fe279328ea73",
    "client_s_sk": "0429abf73dd54603a2517d43963092191b3bfa703d6f96e5c3ab07032af09306",
    "client_e_pk": "f4078829250cbe512a46d47f607bcbd11f55d257c2758968f0a2fe052f153f23",
    "client_e_sk": "44effcb2a3e3cdf444c73964afc454513b42b19b5fe9de78bafec9d6d152b808",
    "server_s_pk": "d20495860077399f2ae24565bfafb29f41602805bda05323663a1b9a2f74532e",
    "server_s_sk": "c40c8d1af35aa1aeb16539eda98e17dc2eecfa9e21938c286eb5c04d03a3d90c",
    "server_e_pk": "3868e17fa3a9ea40b8099b94265b41f6989a7790b99525a6ebe6d8da02151517",
    "server_e_sk": "6f11607b6c7493cb14935f2af3ea6d35368564840d3e13d0b8b85619ce5cb309",
    "fake_sk": "d027dc1c2c5fd2abe413d4603a31c5f5af7798dcb8a349ddff1dba22619e3106",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "2f4d3b99b3239f14c02937cd9c5928b72e792923c392f32259d38db66b378c09",
    "oprf_seed": "a4fd682676da261afc2d1f6c2b4d173bee9b591de7b6a125a95cd6a129c582abfb47c58cb8519300c41993c4f65f3bc998857839782e81853a9b4222bbd0af51",
    "masking_nonce": "84fee2957ecedff1f417fb7b9cc033a27cc2f23f346c22933121ec902c563d8ebe92eec260c4c48f11f560a20896334f11598174313af77b6c06b5aebe4dc8bc",
    "envelope_nonce": "52cf21f9aa91b105dbacbf986c2f2ffc18c2c876ebbe753991eeb6018986c25d",
    "client_nonce": "61c78d68faafff73962fe5938a6e51cf0d142f682055c6935da551d9c0c1f5e0",
    "server_nonce": "3803f1c7e9fc0859f9d82c0a5dc853191c9cc7ecb4b8901d5eae9cb545210dbd",
    "context": "636f6e74657874",
    "registration_request": "0029a6bfe36ad951c8180cd030870a8eaac946d7a0a8f6838b90273cd363553f",
    "registration_response": "a2ff5ff073aa3ae6e8c1341cb10d0fe6822c902f254b40648523c456ce511f60d20495860077399f2ae24565bfafb29f41602805bda05323663a1b9a2f74532e",
    "registration_upload": "94ddf2dd8051a97accbff76b961f475be5499153176c4e7673009f5471e82d452e44248ec8495c0622e895633ee23ab365a99eb86c422095b5e6687922b436cc23397830983684f1b7e0a6c828b4be843416ea3d666751741446a17b798836220429abf73dd54603a2517d43963092191b3bfa703d6f96e5c3ab07032af0930630f910034ee42f3650979f34c60116c8df87ab2014a8028719b7af16933757a1364a0a8dba5e31702d4ecd8bb0089963c8c7c806633106ec01f21d2c1f0e7c6d",
    "credential_request": "0029a6bfe36ad951c8180cd030870a8eaac946d7a0a8f6838b90273cd363553f61c78d68faafff73962fe5938a6e51cf0d142f682055c6935da551d9c0c1f5e0f4078829250cbe512a46d47f607bcbd11f55d257c2758968f0a2fe052f153f23",
    "credential_response": "a2ff5ff073aa3ae6e8c1341cb10d0fe6822c902f254b40648523c456ce511f6084fee2957ecedff1f417fb7b9cc033a27cc2f23f346c22933121ec902c563d8e6611595c09b73c4d0b376bff1e0f6170e741932a2fcc46eea41f0a25fcbc9b3776b3cd7caf89abb4e12051add84020e78bf66fdf085bf7bece614996aab5e003572942c0d2adb246190bac44854418aa91b97f21676ee6081cc392fbfa69a8b4310231dbdcc334d7236c3b29c1e68c6053694c70636941db4773f0de31b807d66f11607b6c7493cb14935f2af3ea6d35368564840d3e13d0b8b85619ce5cb309224143ae3d5f41168405da956adf330323607e9cfeccf142344926bfc456d221363994a0ad737282c8130e3e695f119bb549a0a1d4bcfe43877badbd1376c22d2357648f2c5d10eb4871ce565caa12943390ab4c4f39e8a21ef8dd58325d80c6",
    "credential_finalization": "8d9d27b4b02011d4fd0c0712a66d870ff1477f564459fdb9710778129f7415fa1ffdf878838bd5886482a8fad35e7fe76f072fd58d755a3b417ab3b5546d8db7",
    "client_registration_state": "2f4d3b99b3239f14c02937cd9c5928b72e792923c392f32259d38db66b378c090029a6bfe36ad951c8180cd030870a8eaac946d7a0a8f6838b90273cd363553f",
    "client_login_state": "2f4d3b99b3239f14c02937cd9c5928b72e792923c392f32259d38db66b378c090029a6bfe36ad951c8180cd030870a8eaac946d7a0a8f6838b90273cd363553f61c78d68faafff73962fe5938a6e51cf0d142f682055c6935da551d9c0c1f5e0f4078829250cbe512a46d47f607bcbd11f55d257c2758968f0a2fe052f153f2344effcb2a3e3cdf444c73964afc454513b42b19b5fe9de78bafec9d6d152b80861c78d68faafff73962fe5938a6e51cf0d142f682055c6935da551d9c0c1f5e0",
    "server_login_state": "a1ea9f94d030c645d25fa27e6b5c711cb392878042639ad7c3b14bdc8030ab6bfbbf1dd7b20dad15f07ac6a1cd62f13aa34eb903984d0836dc1de6a8cb66058920841cdfd8f3e28d52a50964109166b049f624b492879313ee506599d96962048872e2fa61c711e9f37f37b984048b3a29969e8686b9e21f1ce0a4e151e6f1a1f72c738d5eab793d8e9d2ec660bf49fff9a4faff5a984a10607caa260e4b94f767d47e9336d554b778ca41671d498d262f36c8874b035ecc954ed3baa8031ac7",
    "password_file": "94ddf2dd8051a97accbff76b961f475be5499153176c4e7673009f5471e82d452e44248ec8495c0622e895633ee23ab365a99eb86c422095b5e6687922b436cc23397830983684f1b7e0a6c828b4be843416ea3d666751741446a17b798836220429abf73dd54603a2517d43963092191b3bfa703d6f96e5c3ab07032af0930630f910034ee42f3650979f34c60116c8df87ab2014a8028719b7af16933757a1364a0a8dba5e31702d4ecd8bb0089963c8c7c806633106ec01f21d2c1f0e7c6d",
    "export_key": "69b3d2fa20b4b93b18fdb8dae139af6a5a210a8d40ed107fe0d76bd76aedc1d791c6c948eba8aa1750217c3021e7c07657569152120d4dd9928a22f4d904fbf8",
    "session_key": "f72c738d5eab793d8e9d2ec660bf49fff9a4faff5a984a10607caa260e4b94f767d47e9336d554b778ca41671d498d262f36c8874b035ecc954ed3baa8031ac7"
}
"#;

static TEST_VECTOR_P256: &str = r#"
{
    "client_s_pk": "024233c7da16965cf8dd009c16d6da1fb30678e1a77a8bed62ee4ab0ff19398df8",
    "client_s_sk": "7b37ca3a844e38d48f199a982cf584b8377a06c3b0d82075da71c29d7d067a15",
    "client_e_pk": "028a5cfff38ac26a0287940c0d0ca4cca86c2de48a0371cb668e4a47047ee407f2",
    "client_e_sk": "3b97e770cbf587cfdedcc07d4ed0ee393645c36ee4505d13542061fd1e4075b1",
    "server_s_pk": "03e5fd5f2d9a767013c18a9f3848c187ce4b832419420019289888fff4ccd3e105",
    "server_s_sk": "344ad6c7f5426b17b06816601d61d2b828d9193d0ac71d4ff457b927d713f61a",
    "server_e_pk": "03361978ce9712ef7b94b42b58d9ea705b3f846ca63c0f99375aaff06b995bc04b",
    "server_e_sk": "9b226d6b94f4df66246f1fdc57a77333bf29e28b561343a747845a83c89d9974",
    "fake_sk": "ec7f397fa39804a8be9559ebe5666c583813b5c0d199150a308408b5cc7d1ad3",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "7f765e59c9005b407dd9d9c80c9b6870bf34d723b463c9ef1bf37062f3a32932",
    "oprf_seed": "6e2dbc907c0e8e6ac9b25e9786bce93b2b7c611efbbfe8f0ac6cc49a367f1b53",
    "masking_nonce": "fc65e1213c391fc03baabad6f4fb2435d1f4143fd55362a77f6505a848198e72790e68a3d7e699187e7765b018e29330b1aa559c4b01681e3f9f1a122c88cfc7",
    "envelope_nonce": "990e155dcd76335a870f03898bc52ce7c206d2a9fba98023d524c9e5eaeeb8f1",
    "client_nonce": "1c5ac2e0c8134298298d6fbb27e2a30161548e0ab40b3e1f93fd048893290823",
    "server_nonce": "28fb86796e386659fc1be72ecc9452928c864dae3c0bc407694c15b97303b8fd",
    "context": "636f6e74657874",
    "registration_request": "02626e2a7d0a3a65c5ce26319ffdcd8f12749597288d5a3f056a85061d440b3134",
    "registration_response": "024881b1756686787aa2c9379842b3c043be2bc2160f8399388566df186aca076203e5fd5f2d9a767013c18a9f3848c187ce4b832419420019289888fff4ccd3e105",
    "registration_upload": "02b2c2080e85eb9be5fce9af315ebbd582b97a888bc38db41eb3ff89d150094c4ee1897cecbb1eb404c07cb336778480ce59b45be07417b62c6065509d743081bd7b37ca3a844e38d48f199a982cf584b8377a06c3b0d82075da71c29d7d067a15290f38d81d8afca3b0b9f8fd39d43695c3ff00c9cc65dffa80c81d4346c4c231",
    "credential_request": "02626e2a7d0a3a65c5ce26319ffdcd8f12749597288d5a3f056a85061d440b31341c5ac2e0c8134298298d6fbb27e2a30161548e0ab40b3e1f93fd048893290823028a5cfff38ac26a0287940c0d0ca4cca86c2de48a0371cb668e4a47047ee407f2",
    "credential_response": "024881b1756686787aa2c9379842b3c043be2bc2160f8399388566df186aca0762fc65e1213c391fc03baabad6f4fb2435d1f4143fd55362a77f6505a848198e725bc35e08a2b8eca1fd54f864f551bbb26aca647e8a7fa7865d9da84c3cb9aa9e7c88a0643d3c2d83f722bc0f961bcfbe08b041e6010fd42e070411df6a00032b38a649251a11fcdade4133d9392a83163150617d97f66304bd2cd82b8dea34003b9b226d6b94f4df66246f1fdc57a77333bf29e28b561343a747845a83c89d997402dd41500c28354a2b4c2e99723d4e2c663032803766576eca885ba1e16c141093e3f50476135f37f2f0973be22ab0723f264bc54b48c8b7814f578c20145b1a62",
    "credential_finalization": "4a4dc7da190d96ca9a464e97fd87caac8a6a8284dca988723392c4ff55e9ee19",
    "client_registration_state": "7f765e59c9005b407dd9d9c80c9b6870bf34d723b463c9ef1bf37062f3a3293202626e2a7d0a3a65c5ce26319ffdcd8f12749597288d5a3f056a85061d440b3134",
    "client_login_state": "7f765e59c9005b407dd9d9c80c9b6870bf34d723b463c9ef1bf37062f3a3293202626e2a7d0a3a65c5ce26319ffdcd8f12749597288d5a3f056a85061d440b31341c5ac2e0c8134298298d6fbb27e2a30161548e0ab40b3e1f93fd048893290823028a5cfff38ac26a0287940c0d0ca4cca86c2de48a0371cb668e4a47047ee407f23b97e770cbf587cfdedcc07d4ed0ee393645c36ee4505d13542061fd1e4075b11c5ac2e0c8134298298d6fbb27e2a30161548e0ab40b3e1f93fd048893290823",
    "server_login_state": "c084be73543caee016de23f6987e9d9db9ce8a39490127388f7cfc8d73f7c37ba5ebebd95e175ba698748629e95da35b2750f870919bdeb0a80b5ac8988517f366adf6480ea66dec3384cf202fa979bb3501e0cc4c8cea8a268d5561cd45ce95",
    "password_file": "02b2c2080e85eb9be5fce9af315ebbd582b97a888bc38db41eb3ff89d150094c4ee1897cecbb1eb404c07cb336778480ce59b45be07417b62c6065509d743081bd7b37ca3a844e38d48f199a982cf584b8377a06c3b0d82075da71c29d7d067a15290f38d81d8afca3b0b9f8fd39d43695c3ff00c9cc65dffa80c81d4346c4c231",
    "export_key": "d8e44930ad9ae7e1e5d83dbc9b5fd51b814280864aa10e39e62aa07c72458c86",
    "session_key": "66adf6480ea66dec3384cf202fa979bb3501e0cc4c8cea8a268d5561cd45ce95"
}
"#;

#[cfg(all(feature = "curve25519", feature = "ristretto255"))]
static TEST_VECTOR_CURVE25519_RISTRETTO255: &str = r#"
{
    "client_s_pk": "f535ff1f431781ebdf247ba474600b35900c78bae062b78bca336f93125fae78",
    "client_s_sk": "a2965d641d8faac6d78929faaea9d849260374dfbc48fcd8508d619e91549e0f",
    "client_e_pk": "41b9b9e40898537c1afc044ea4362a91b0688841a2f8ac7576799ea554b9955c",
    "client_e_sk": "3462f1906981bf3849bdda9e4fb11f227aa1ce36715fbab787137d9293877804",
    "server_s_pk": "c3bb58d0ab702a78cd49c49ed666445715a3a9031352988fa3b8b5354f234555",
    "server_s_sk": "66db13a9043ba998acf4c025817c212a679998aca94e284d92d7a3e624918405",
    "server_e_pk": "092c508e525c26d207f26e08f31bc3d3da93280260b959a2b422f61365336266",
    "server_e_sk": "a45b6ec2746a0930da83e7be61fec440b8101a6da0057684d552495818945a08",
    "fake_sk": "b58d23d86aa0cdc9baf29cf03f6d1362e96980ea2e33b0407dc8e213ef31f40e",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "ddd58385737d8c20704c0cb1a3a966bf34e74f0110fed80f1beff71b5f595c0c",
    "oprf_seed": "a73d9a1a8258fb9e07525bc7ec95ec099b781674b1b8af4293062f5f8929ba600ce3e430a1604a6264eb234b6380bcaf7ebfe8c094c6ad512a66d90465ea1b24",
    "masking_nonce": "75c3c3c4131c481038ed136f2aa8f73cb721336e8932aec3a4afa7a807bb80b9064711750bf956f5c87b0fbb2237e4a8dce44c5b5a556ee7c9878fff08a7703c",
    "envelope_nonce": "2a19eea1b3a01bd1654e550c248e376280920e1512109d6193e6d384d4b9c78a",
    "client_nonce": "e211715a5e81960e9645812027b02eb2bf1a29fc7c40706fbf7d89372bdcfff4",
    "server_nonce": "d7b113083e27e038199d4d8e536a16d9cacded41a1ab1baf861ee2bbb3c64a08",
    "context": "636f6e74657874",
    "registration_request": "1e7066e92f802e894edc3383c84a30d9941dff5ae4bae093aac6249d7307fb4f",
    "registration_response": "4ac42b2850dfa252c98ddf441ad4f2d39d195fa6d966326a971a917d9bf2a83dc3bb58d0ab702a78cd49c49ed666445715a3a9031352988fa3b8b5354f234555",
    "registration_upload": "18a37ef21ebff958b228f6b0a4aa66764a20b438393a380833dc73bf05da8c4043a1d396008b10207c4a2c6c6c2a1bd1fff443741102e6884eb58236cd27c2c09626b7c2df397a8473337cfb760d4dbdfe8f50a26696d6c41f9f4c2086ab0957a2965d641d8faac6d78929faaea9d849260374dfbc48fcd8508d619e91549e0f1f13d125c3dc2fc99a3fa879d3a914202afae68113902a60a44266febeca8521fab72bcb5fddd144768fc59bcbe759e328b09aeffbfb906627ddfe670342a358",
    "credential_request": "1e7066e92f802e894edc3383c84a30d9941dff5ae4bae093aac6249d7307fb4fddd58385737d8c20704c0cb1a3a966bf34e74f0110fed80f1beff71b5f595c0ce3c5ca3e5d685c064f212bdeba8f58804cc2b7c3732cf87f9c541444f1629970",
    "credential_response": "4ac42b2850dfa252c98ddf441ad4f2d39d195fa6d966326a971a917d9bf2a83d75c3c3c4131c481038ed136f2aa8f73cb721336e8932aec3a4afa7a807bb80b9d2ce565f318da629a658c9b653853e649ccbe4ce9cd46a904f4352a67140bc9e44ccfb5823a385fd29f7ce9d4711fe8e4b4e050c62c7e041ec2c6bf82e84371c802a360dbdbc9614363ac2830c60624ab77d1de45eef3b15326a988a6862b0315dd5a0a966130f724c2265db5b04a8bf772fb57a5643c05f88daf3b89a6fb0c7d7b113083e27e038199d4d8e536a16d9cacded41a1ab1baf861ee2bbb3c64a084f2de1632c9028867527905d5a84a3dea08ba32b61db5cbc17c104ac09386d7a6b6483a41e1649ec4925eebb3b3f145c4b5abd046f49fd28c6345cb7c81b93aa73f57fcf10b04ad118e6cb532c522547aa379556d0a5f81125c1028a680de0ec",
    "credential_finalization": "f9310bbda0fe43f1b6a66ab862ae57e27a7e0753c5039da335e44da00beaab2108c02286fe673ebad2f04ed66d0d891a9f493166af1b1bcddd5950fa9a5d2d73",
    "client_registration_state": "ddd58385737d8c20704c0cb1a3a966bf34e74f0110fed80f1beff71b5f595c0c1e7066e92f802e894edc3383c84a30d9941dff5ae4bae093aac6249d7307fb4f",
    "client_login_state": "ddd58385737d8c20704c0cb1a3a966bf34e74f0110fed80f1beff71b5f595c0c1e7066e92f802e894edc3383c84a30d9941dff5ae4bae093aac6249d7307fb4fddd58385737d8c20704c0cb1a3a966bf34e74f0110fed80f1beff71b5f595c0ce3c5ca3e5d685c064f212bdeba8f58804cc2b7c3732cf87f9c541444f1629970ba6394b0b2570047a038334a0186080289ba294018dd8cc1c8c2d2010e1b4303ddd58385737d8c20704c0cb1a3a966bf34e74f0110fed80f1beff71b5f595c0c",
    "server_login_state": "4c1dc1603f7568dd19dacea6938a2eb0847f365e3733f1d94068648fed318d72dfb05320144e8b25aff7cdaf1ff2f6e23aace1b1d2b48eab23e0bbf315044c54dde886c08fc1bad2f87e6445d2938e4405211e141948a98f8693d3a044a78cc94c0c0f44848825a6a65f6555599c6c133b8cd7e6cd71d0f8f661f10cfd1afbd41c8edc5902c6500ff5529b3fef4a3eeb902a98da7b542f80dbc449b1eaa42bda5c8a5a4486395ca5d34b13312fedba5aaca2039185f514eff22c598b4aecb5c2",
    "password_file": "18a37ef21ebff958b228f6b0a4aa66764a20b438393a380833dc73bf05da8c4043a1d396008b10207c4a2c6c6c2a1bd1fff443741102e6884eb58236cd27c2c09626b7c2df397a8473337cfb760d4dbdfe8f50a26696d6c41f9f4c2086ab0957a2965d641d8faac6d78929faaea9d849260374dfbc48fcd8508d619e91549e0f1f13d125c3dc2fc99a3fa879d3a914202afae68113902a60a44266febeca8521fab72bcb5fddd144768fc59bcbe759e328b09aeffbfb906627ddfe670342a358",
    "export_key": "42635c7e79ad5b9d3c7c3d60c233a26c0f2c4081c2698a0fde7f40597705c6fd10265d227a6d74f6b77a731945777d19b38e73d53adee9337cb89eb197a08553",
    "session_key": "1c8edc5902c6500ff5529b3fef4a3eeb902a98da7b542f80dbc449b1eaa42bda5c8a5a4486395ca5d34b13312fedba5aaca2039185f514eff22c598b4aecb5c2"
}
"#;

#[cfg(feature = "curve25519")]
static TEST_VECTOR_CURVE25519_P256: &str = r#"
{
    "client_s_pk": "984c4d0154f43c559a6e9c11e53899796c14df117333d23415e6271694fad424",
    "client_s_sk": "2b3e92c34952a4c3deb75b18f9096d22256f54819f608e181720da0d48590108",
    "client_e_pk": "679d88f27a93d9a53ff507f56fd9ef726605e5b62f6584fe62b88115c30fec42",
    "client_e_sk": "2f56650f9b56744b174e5ac45714559d515ed4487e71c5da7608015adc2cde09",
    "server_s_pk": "9a90ad9a25286cdde32ee8028538f4a83cedcca0fc9a3e53412a0454926e834d",
    "server_s_sk": "d327ef3da05a7f92e2a60c43194b124f0b8e4d7aa2cfb9d94b66ed19021b8409",
    "server_e_pk": "4962df96cfa3cadf6dbf7ac56e2e5a7d6e8515645df41bf01e479c6298a19002",
    "server_e_sk": "d9fec8c73c59b5f9ceea74cf32a3de88cbc0c31e6b769137d876053aa0800d04",
    "fake_sk": "0e0289c3530bfd4c79ca732b87e71227b8dcb36a552c652bf601da293887710a",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "9c0bc8990211537292deb41e9fcd040961d49091fbe65d1bb59e383277bb25eb",
    "oprf_seed": "1bc1978fa716b5f9034f63d04aed6721e1671d862e482a7b8ec24e9911972d6a",
    "masking_nonce": "ea49e91d388abfde7a79628609ca387ec24d1566ed95044aba000db31c97e8f432462af38aa60e5ce7c32d34604e5c121cefc8297671bdf71a966ecdb3bc5a2f",
    "envelope_nonce": "997f10d36ebeffa5083d8b534794a62e957764ddb3c09825a68133d33df3c661",
    "client_nonce": "1d191eb4375568db766e64b378df66f7076b642a46cf708919e5deab6b48d236",
    "server_nonce": "f861a3400dd011365ef09f2634290d5268b9d45fc8da91b0ed815e623a688529",
    "context": "636f6e74657874",
    "registration_request": "02cadf5b02d05f65bf053761947c54ff9c52a32e64d8ba40d406eee86f86ac8f63",
    "registration_response": "027746a0843ddcf383f24981d1605c354d69d6434149a3396caf667d816bc581c59a90ad9a25286cdde32ee8028538f4a83cedcca0fc9a3e53412a0454926e834d",
    "registration_upload": "eb59650e50b056798293da46391143455a5c97ebff75d221976f32c150eb3e3f2ee763032e75976fba490d56539e7d29106024c262c7c08135ddb378392189142b3e92c34952a4c3deb75b18f9096d22256f54819f608e181720da0d48590108e9cc437cb299cf10fc8de53172ba891cf9c094b1b339dbd8a18282ef98137765",
    "credential_request": "02cadf5b02d05f65bf053761947c54ff9c52a32e64d8ba40d406eee86f86ac8f639c0bc8990211537292deb41e9fcd040961d49091fbe65d1bb59e383277bb25ebc9bab2dbddaa4984ee8669b527b4edd2a56fa187a457480088c37e75f1835903",
    "credential_response": "027746a0843ddcf383f24981d1605c354d69d6434149a3396caf667d816bc581c5ea49e91d388abfde7a79628609ca387ec24d1566ed95044aba000db31c97e8f436bcf21522e3fb43d01f3916cb7af262cbb7a87836f4b75eeae64c861c12eddb6fbe7448b8c87db4916fd6e2807c21429ab04495d3b48aeb36a03335e2c66bc01e4aa1e32c4974a016f065daab0cc0facd3ed7bf955eb2882f1e8016ae8a31dcf861a3400dd011365ef09f2634290d5268b9d45fc8da91b0ed815e623a688529dd126f42ce1494ebf2ece4f509d111a8ff72a1e7ca2ac15478069901c51a4a1db4aaba8cc5b9ef025dc650a5b07d8db9fd060cbf27b8b4640e2e6bca872d4380",
    "credential_finalization": "923474270342f186a41a23e5572c2583f5387f8e847381a5fd94917aa33a3655",
    "client_registration_state": "9c0bc8990211537292deb41e9fcd040961d49091fbe65d1bb59e383277bb25eb02cadf5b02d05f65bf053761947c54ff9c52a32e64d8ba40d406eee86f86ac8f63",
    "client_login_state": "9c0bc8990211537292deb41e9fcd040961d49091fbe65d1bb59e383277bb25eb02cadf5b02d05f65bf053761947c54ff9c52a32e64d8ba40d406eee86f86ac8f639c0bc8990211537292deb41e9fcd040961d49091fbe65d1bb59e383277bb25ebc9bab2dbddaa4984ee8669b527b4edd2a56fa187a457480088c37e75f1835903583c4e5353c1cfc928a4975d1423ec85b72a06bc4d728ecfff81c501c5fbfc069c0bc8990211537292deb41e9fcd040961d49091fbe65d1bb59e383277bb25eb",
    "server_login_state": "3c6cc54d29f32745040e127c8c5e606f431cdefccf214452d30182850d50300061c4876da2632558184289431e51e81a2ed1defe4460fa621f4169ff0e0fdd90c315d7a845a902fd4146c13d228d7a0e3d0cf138bd42969fae5e7b0e032e5f4e",
    "password_file": "eb59650e50b056798293da46391143455a5c97ebff75d221976f32c150eb3e3f2ee763032e75976fba490d56539e7d29106024c262c7c08135ddb378392189142b3e92c34952a4c3deb75b18f9096d22256f54819f608e181720da0d48590108e9cc437cb299cf10fc8de53172ba891cf9c094b1b339dbd8a18282ef98137765",
    "export_key": "5e8338e5f129bddb19dd5d85494c8b6fe25d0f739c6c38b1c71a183832e8120f",
    "session_key": "c315d7a845a902fd4146c13d228d7a0e3d0cf138bd42969fae5e7b0e032e5f4e"
}
"#;

fn decode(values: &Value, key: &str) -> Option<Vec<u8>> {
    values[key].as_str().and_then(|s| hex::decode(s).ok())
}

fn populate_test_vectors(values: &Value) -> TestVectorParameters {
    TestVectorParameters {
        client_s_pk: decode(values, "client_s_pk").unwrap(),
        client_s_sk: decode(values, "client_s_sk").unwrap(),
        client_e_pk: decode(values, "client_e_pk").unwrap(),
        client_e_sk: decode(values, "client_e_sk").unwrap(),
        server_s_pk: decode(values, "server_s_pk").unwrap(),
        server_s_sk: decode(values, "server_s_sk").unwrap(),
        server_e_pk: decode(values, "server_e_pk").unwrap(),
        server_e_sk: decode(values, "server_e_sk").unwrap(),
        fake_sk: decode(values, "fake_sk").unwrap(),
        credential_identifier: decode(values, "credential_identifier").unwrap(),
        id_u: decode(values, "id_u").unwrap(),
        id_s: decode(values, "id_s").unwrap(),
        password: decode(values, "password").unwrap(),
        blinding_factor: decode(values, "blinding_factor").unwrap(),
        oprf_seed: decode(values, "oprf_seed").unwrap(),
        masking_nonce: decode(values, "masking_nonce").unwrap(),
        envelope_nonce: decode(values, "envelope_nonce").unwrap(),
        client_nonce: decode(values, "client_nonce").unwrap(),
        server_nonce: decode(values, "server_nonce").unwrap(),
        context: decode(values, "context").unwrap(),
        registration_request: decode(values, "registration_request").unwrap(),
        registration_response: decode(values, "registration_response").unwrap(),
        registration_upload: decode(values, "registration_upload").unwrap(),
        credential_request: decode(values, "credential_request").unwrap(),
        credential_response: decode(values, "credential_response").unwrap(),
        credential_finalization: decode(values, "credential_finalization").unwrap(),
        client_registration_state: decode(values, "client_registration_state").unwrap(),
        client_login_state: decode(values, "client_login_state").unwrap(),
        server_login_state: decode(values, "server_login_state").unwrap(),
        password_file: decode(values, "password_file").unwrap(),
        export_key: decode(values, "export_key").unwrap(),
        session_key: decode(values, "session_key").unwrap(),
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

fn generate_parameters<CS: CipherSuite>() -> Result<TestVectorParameters, ProtocolError>
where
    <OprfHash<CS> as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
    OprfHash<CS>: Hash,
    <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
    <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // ClientRegistration: KgSk + KgPk
    <OprfGroup<CS> as Group>::ScalarLen: Add<<OprfGroup<CS> as Group>::ElemLen>,
    ClientRegistrationLen<CS>: ArrayLength<u8>,
    // RegistrationResponse: KgPk + KePk
    <OprfGroup<CS> as Group>::ElemLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
    RegistrationResponseLen<CS>: ArrayLength<u8>,
    // Envelope: Nonce + Hash
    NonceLen: Add<OutputSize<OprfHash<CS>>>,
    EnvelopeLen<CS>: ArrayLength<u8>,
    // RegistrationUpload: (KePk + Hash) + Envelope
    <CS::KeGroup as KeGroup>::PkLen: Add<OutputSize<OprfHash<CS>>>,
    Sum<<CS::KeGroup as KeGroup>::PkLen, OutputSize<OprfHash<CS>>>:
        ArrayLength<u8> + Add<EnvelopeLen<CS>>,
    RegistrationUploadLen<CS>: ArrayLength<u8>,
    // ServerRegistration = RegistrationUpload
    // Ke1Message: Nonce + KePk
    NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
    Ke1MessageLen<CS>: ArrayLength<u8>,
    // CredentialRequest: KgPk + Ke1Message
    <OprfGroup<CS> as Group>::ElemLen: Add<Ke1MessageLen<CS>>,
    CredentialRequestLen<CS>: ArrayLength<u8>,
    // ClientLogin: KgSk + CredentialRequest + Ke1State
    <OprfGroup<CS> as Group>::ScalarLen: Add<CredentialRequestLen<CS>>,
    Sum<<OprfGroup<CS> as Group>::ScalarLen, CredentialRequestLen<CS>>:
        ArrayLength<u8> + Add<Ke1StateLen<CS>>,
    ClientLoginLen<CS>: ArrayLength<u8>,
    // MaskedResponse: (Nonce + Hash) + KePk
    NonceLen: Add<OutputSize<OprfHash<CS>>>,
    Sum<NonceLen, OutputSize<OprfHash<CS>>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
    MaskedResponseLen<CS>: ArrayLength<u8>,
    // CredentialResponseWithoutKeLen: (KgPk + Nonce) + MaskedResponse
    <OprfGroup<CS> as Group>::ElemLen: Add<NonceLen>,
    Sum<<OprfGroup<CS> as Group>::ElemLen, NonceLen>: ArrayLength<u8> + Add<MaskedResponseLen<CS>>,
    CredentialResponseWithoutKeLen<CS>: ArrayLength<u8>,
    // Ke2Message: (Nonce + KePk) + Hash
    NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
    Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>: ArrayLength<u8> + Add<OutputSize<OprfHash<CS>>>,
    Ke2MessageLen<CS>: ArrayLength<u8>,
    // CredentialResponse: CredentialResponseWithoutKeLen + Ke2Message
    CredentialResponseWithoutKeLen<CS>: Add<Ke2MessageLen<CS>>,
    CredentialResponseLen<CS>: ArrayLength<u8>,
{
    use rand::RngCore;

    use crate::keypair::KeyPair;

    let mut rng = OsRng;

    // Inputs
    let server_s_kp = KeyPair::<CS::KeGroup>::generate_random(&mut rng);
    let server_e_kp = KeyPair::<CS::KeGroup>::generate_random(&mut rng);
    let client_s_kp = KeyPair::<CS::KeGroup>::generate_random(&mut rng);
    let client_e_kp = KeyPair::<CS::KeGroup>::generate_random(&mut rng);
    let fake_kp = KeyPair::<CS::KeGroup>::generate_random(&mut rng);
    let credential_identifier = b"credIdentifier";
    let id_u = b"idU";
    let id_s = b"idS";
    let password = b"password";
    let context = b"context";
    let mut oprf_seed = Output::<OprfHash<CS>>::default();
    rng.fill_bytes(&mut oprf_seed);
    let mut masking_nonce = [0u8; 64];
    rng.fill_bytes(&mut masking_nonce);
    let mut envelope_nonce = [0u8; 32];
    rng.fill_bytes(&mut envelope_nonce);
    let mut client_nonce = [0u8; NonceLen::USIZE];
    rng.fill_bytes(&mut client_nonce);
    let mut server_nonce = [0u8; NonceLen::USIZE];
    rng.fill_bytes(&mut server_nonce);

    let fake_sk: Vec<u8> = fake_kp.private().serialize().to_vec();
    let server_setup = ServerSetup::<CS>::deserialize(
        &[
            oprf_seed.as_ref(),
            &server_s_kp.private().serialize(),
            &fake_sk,
        ]
        .concat(),
    )
    .unwrap();

    let blinding_factor = <OprfGroup<CS> as Group>::random_scalar(&mut rng);
    let blinding_factor_bytes = OprfGroup::<CS>::serialize_scalar(blinding_factor);

    let mut blinding_factor_registration_rng = CycleRng::new(blinding_factor_bytes.to_vec());
    let client_registration_start_result =
        ClientRegistration::<CS>::start(&mut blinding_factor_registration_rng, password).unwrap();
    let blinding_factor_bytes_returned = OprfGroup::<CS>::serialize_scalar(
        client_registration_start_result
            .state
            .oprf_client
            .get_blind(),
    );
    assert_eq!(
        hex::encode(&blinding_factor_bytes),
        hex::encode(&blinding_factor_bytes_returned)
    );

    let registration_request_bytes = client_registration_start_result.message.serialize();
    let client_registration_state = client_registration_start_result.state.serialize();

    let server_registration_start_result = ServerRegistration::<CS>::start(
        &server_setup,
        client_registration_start_result.message,
        credential_identifier,
    )
    .unwrap();
    let registration_response_bytes = server_registration_start_result.message.serialize();

    let mut client_s_sk_and_nonce: Vec<u8> = Vec::new();
    client_s_sk_and_nonce.extend_from_slice(&client_s_kp.private().serialize());
    client_s_sk_and_nonce.extend_from_slice(&envelope_nonce);

    let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
    let client_registration_finish_result = client_registration_start_result
        .state
        .finish(
            &mut finish_registration_rng,
            password,
            server_registration_start_result.message,
            ClientRegistrationFinishParameters::new(
                Identifiers {
                    client: Some(id_u),
                    server: Some(id_s),
                },
                None,
            ),
        )
        .unwrap();
    let registration_upload_bytes = client_registration_finish_result.message.serialize();

    let password_file = ServerRegistration::finish(client_registration_finish_result.message);
    let password_file_bytes = password_file.serialize();

    let mut client_login_start: Vec<u8> = Vec::new();
    client_login_start.extend_from_slice(&blinding_factor_bytes);
    client_login_start.extend_from_slice(&client_e_kp.private().serialize());
    client_login_start.extend_from_slice(&client_nonce);

    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let client_login_start_result =
        ClientLogin::<CS>::start(&mut client_login_start_rng, password).unwrap();
    let credential_request_bytes = client_login_start_result.message.serialize();
    let client_login_state = client_login_start_result.state.serialize().to_vec();

    let mut server_e_sk_and_nonce_rng = CycleRng::new(
        [
            masking_nonce.to_vec(),
            server_e_kp.private().serialize().to_vec(),
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
        ServerLoginStartParameters {
            context: Some(context),
            identifiers: Identifiers {
                client: Some(id_u),
                server: Some(id_s),
            },
        },
    )
    .unwrap();
    let credential_response_bytes = server_login_start_result.message.serialize();
    let server_login_state = server_login_start_result.state.serialize();

    let client_login_finish_result = client_login_start_result
        .state
        .finish(
            password,
            server_login_start_result.message,
            ClientLoginFinishParameters::new(
                Some(context),
                Identifiers {
                    client: Some(id_u),
                    server: Some(id_s),
                },
                None,
            ),
        )
        .unwrap();
    let credential_finalization_bytes = client_login_finish_result.message.serialize();

    Ok(TestVectorParameters {
        client_s_pk: client_s_kp.public().serialize().to_vec(),
        client_s_sk: client_s_kp.private().serialize().to_vec(),
        client_e_pk: client_e_kp.public().serialize().to_vec(),
        client_e_sk: client_e_kp.private().serialize().to_vec(),
        server_s_pk: server_s_kp.public().serialize().to_vec(),
        server_s_sk: server_s_kp.private().serialize().to_vec(),
        server_e_pk: server_e_kp.public().serialize().to_vec(),
        server_e_sk: server_e_kp.private().serialize().to_vec(),
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
        registration_request: registration_request_bytes.to_vec(),
        registration_response: registration_response_bytes.to_vec(),
        registration_upload: registration_upload_bytes.to_vec(),
        credential_request: credential_request_bytes.to_vec(),
        credential_response: credential_response_bytes.to_vec(),
        credential_finalization: credential_finalization_bytes.to_vec(),
        password_file: password_file_bytes.to_vec(),
        client_registration_state: client_registration_state.to_vec(),
        client_login_state,
        server_login_state: server_login_state.to_vec(),
        session_key: client_login_finish_result.session_key.to_vec(),
        export_key: client_registration_finish_result.export_key.to_vec(),
    })
}

#[test]
fn generate_test_vectors() -> Result<(), ProtocolError> {
    #[cfg(feature = "ristretto255")]
    {
        let parameters = generate_parameters::<Ristretto255>()?;
        println!("Ristretto255: {}", stringify_test_vectors(&parameters));
    }

    let parameters = generate_parameters::<P256>()?;
    println!("P-256: {}", stringify_test_vectors(&parameters));

    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    {
        let parameters = generate_parameters::<Curve25519Ristretto255>()?;
        println!(
            "Curve25519 Ristretto255: {}",
            stringify_test_vectors(&parameters)
        );
    }

    #[cfg(feature = "curve25519")]
    {
        let parameters = generate_parameters::<Curve25519P256>()?;
        println!("Curve25519 P-256: {}", stringify_test_vectors(&parameters));
    }

    Ok(())
}

#[test]
fn test_registration_request() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // ClientRegistration: KgSk + KgPk
        <OprfGroup<CS> as Group>::ScalarLen: Add<<OprfGroup<CS> as Group>::ElemLen>,
        ClientRegistrationLen<CS>: ArrayLength<u8>,
    {
        let parameters = populate_test_vectors(&serde_json::from_str(test_vector).unwrap());
        let mut rng = CycleRng::new(parameters.blinding_factor.to_vec());
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut rng, &parameters.password)?;
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

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>(TEST_VECTOR_RISTRETTO255)?;
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>(TEST_VECTOR_CURVE25519_RISTRETTO255)?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>(TEST_VECTOR_CURVE25519_P256)?;

    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn test_serialization() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let parameters = populate_test_vectors(&serde_json::from_str(test_vector).unwrap());
        let mut rng = CycleRng::new(parameters.blinding_factor.to_vec());
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut rng, &parameters.password)?;

        // Test the bincode serialization (binary).
        let registration_request =
            bincode::serialize(&client_registration_start_result.message).unwrap();
        assert_eq!(
            registration_request.len(),
            RegistrationRequestLen::<CS>::USIZE
        );
        let registration_request: RegistrationRequest<CS> =
            bincode::deserialize(&registration_request).unwrap();
        assert_eq!(
            hex::encode(client_registration_start_result.message.serialize()),
            hex::encode(registration_request.serialize()),
        );

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>(TEST_VECTOR_RISTRETTO255)?;
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>(TEST_VECTOR_CURVE25519_RISTRETTO255)?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>(TEST_VECTOR_CURVE25519_P256)?;

    Ok(())
}

#[test]
fn test_registration_response() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // RegistrationResponse: KgPk + KePk
        <OprfGroup<CS> as Group>::ElemLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
        RegistrationResponseLen<CS>: ArrayLength<u8>,
    {
        let parameters = populate_test_vectors(
            &serde_json::from_str(test_vector).map_err(|_| ProtocolError::SerializationError)?,
        );

        let server_setup = ServerSetup::<CS>::deserialize(
            &[
                parameters.oprf_seed,
                parameters.server_s_sk,
                parameters.fake_sk,
            ]
            .concat(),
        )?;

        let server_registration_start_result = ServerRegistration::<CS>::start(
            &server_setup,
            RegistrationRequest::deserialize(&parameters.registration_request)?,
            &parameters.credential_identifier,
        )?;
        assert_eq!(
            hex::encode(parameters.registration_response),
            hex::encode(server_registration_start_result.message.serialize())
        );
        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>(TEST_VECTOR_RISTRETTO255)?;
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>(TEST_VECTOR_CURVE25519_RISTRETTO255)?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>(TEST_VECTOR_CURVE25519_P256)?;

    Ok(())
}

#[test]
fn test_registration_upload() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <CS::KeGroup as KeGroup>::PkLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<EnvelopeLen<CS>>,
        RegistrationUploadLen<CS>: ArrayLength<u8>,
    {
        let parameters = populate_test_vectors(
            &serde_json::from_str(test_vector).map_err(|_| ProtocolError::SerializationError)?,
        );

        let client_s_sk_and_nonce: Vec<u8> =
            [parameters.client_s_sk, parameters.envelope_nonce].concat();
        let mut finish_registration_rng = CycleRng::new(client_s_sk_and_nonce);
        let result = ClientRegistration::<CS>::deserialize(&parameters.client_registration_state)?
            .finish(
                &mut finish_registration_rng,
                &parameters.password,
                RegistrationResponse::deserialize(&parameters.registration_response)?,
                ClientRegistrationFinishParameters::new(
                    Identifiers {
                        client: Some(&parameters.id_u),
                        server: Some(&parameters.id_s),
                    },
                    None,
                ),
            )?;

        assert_eq!(
            hex::encode(parameters.registration_upload),
            hex::encode(result.message.serialize())
        );
        assert_eq!(
            hex::encode(parameters.export_key),
            hex::encode(result.export_key)
        );

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>(TEST_VECTOR_RISTRETTO255)?;
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>(TEST_VECTOR_CURVE25519_RISTRETTO255)?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>(TEST_VECTOR_CURVE25519_P256)?;

    Ok(())
}

#[test]
fn test_password_file() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <CS::KeGroup as KeGroup>::PkLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<EnvelopeLen<CS>>,
        RegistrationUploadLen<CS>: ArrayLength<u8>,
        // ServerRegistration = RegistrationUpload
    {
        let parameters = populate_test_vectors(&serde_json::from_str(test_vector).unwrap());

        let password_file = ServerRegistration::finish(RegistrationUpload::<CS>::deserialize(
            &parameters.registration_upload,
        )?);

        assert_eq!(
            hex::encode(parameters.password_file),
            hex::encode(password_file.serialize())
        );
        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>(TEST_VECTOR_RISTRETTO255)?;
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>(TEST_VECTOR_CURVE25519_RISTRETTO255)?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>(TEST_VECTOR_CURVE25519_P256)?;

    Ok(())
}

#[test]
fn test_credential_request() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // CredentialRequest: KgPk + Ke1Message
        <OprfGroup<CS> as Group>::ElemLen: Add<Ke1MessageLen<CS>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
        // ClientLogin: KgSk + CredentialRequest + Ke1State
        <OprfGroup<CS> as Group>::ScalarLen: Add<CredentialRequestLen<CS>>,
        Sum<<OprfGroup<CS> as Group>::ScalarLen, CredentialRequestLen<CS>>:
            ArrayLength<u8> + Add<Ke1StateLen<CS>>,
        ClientLoginLen<CS>: ArrayLength<u8>,
    {
        let parameters = populate_test_vectors(&serde_json::from_str(test_vector).unwrap());

        let client_login_start_rng = [
            parameters.blinding_factor,
            parameters.client_e_sk,
            parameters.client_nonce,
        ]
        .concat();
        let mut client_login_start_rng = CycleRng::new(client_login_start_rng);
        let client_login_start_result =
            ClientLogin::<CS>::start(&mut client_login_start_rng, &parameters.password)?;
        assert_eq!(
            hex::encode(&parameters.credential_request),
            hex::encode(client_login_start_result.message.serialize())
        );
        assert_eq!(
            hex::encode(&parameters.client_login_state),
            hex::encode(client_login_start_result.state.serialize())
        );
        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>(TEST_VECTOR_RISTRETTO255)?;
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>(TEST_VECTOR_CURVE25519_RISTRETTO255)?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>(TEST_VECTOR_CURVE25519_P256)?;

    Ok(())
}

#[test]
fn test_credential_response() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<NonceLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
        // CredentialResponseWithoutKeLen: (KgPk + Nonce) + MaskedResponse
        <OprfGroup<CS> as Group>::ElemLen: Add<NonceLen>,
        Sum<<OprfGroup<CS> as Group>::ElemLen, NonceLen>:
            ArrayLength<u8> + Add<MaskedResponseLen<CS>>,
        CredentialResponseWithoutKeLen<CS>: ArrayLength<u8>,
        // CredentialResponse: CredentialResponseWithoutKeLen + Ke2Message
        CredentialResponseWithoutKeLen<CS>: Add<Ke2MessageLen<CS>>,
        CredentialResponseLen<CS>: ArrayLength<u8>,
    {
        let parameters = populate_test_vectors(&serde_json::from_str(test_vector).unwrap());

        let server_setup = ServerSetup::<CS>::deserialize(
            &[
                parameters.oprf_seed,
                parameters.server_s_sk,
                parameters.fake_sk,
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
        let server_login_start_result = ServerLogin::<CS>::start(
            &mut server_e_sk_and_nonce_rng,
            &server_setup,
            Some(ServerRegistration::deserialize(&parameters.password_file)?),
            CredentialRequest::<CS>::deserialize(&parameters.credential_request)?,
            &parameters.credential_identifier,
            ServerLoginStartParameters {
                context: Some(&parameters.context),
                identifiers: Identifiers {
                    client: Some(&parameters.id_u),
                    server: Some(&parameters.id_s),
                },
            },
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

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>(TEST_VECTOR_RISTRETTO255)?;
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>(TEST_VECTOR_CURVE25519_RISTRETTO255)?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>(TEST_VECTOR_CURVE25519_P256)?;

    Ok(())
}

#[test]
fn test_credential_finalization() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<NonceLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
    {
        let parameters = populate_test_vectors(&serde_json::from_str(test_vector).unwrap());

        let client_login_finish_result =
            ClientLogin::<CS>::deserialize(&parameters.client_login_state)?.finish(
                &parameters.password,
                CredentialResponse::<CS>::deserialize(&parameters.credential_response)?,
                ClientLoginFinishParameters::new(
                    Some(&parameters.context),
                    Identifiers {
                        client: Some(&parameters.id_u),
                        server: Some(&parameters.id_s),
                    },
                    None,
                ),
            )?;

        assert_eq!(
            hex::encode(&parameters.server_s_pk),
            hex::encode(&client_login_finish_result.server_s_pk.serialize())
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

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>(TEST_VECTOR_RISTRETTO255)?;
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>(TEST_VECTOR_CURVE25519_RISTRETTO255)?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>(TEST_VECTOR_CURVE25519_P256)?;

    Ok(())
}

#[test]
fn test_server_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let parameters = populate_test_vectors(&serde_json::from_str(test_vector).unwrap());

        let server_login_result = ServerLogin::<CS>::deserialize(&parameters.server_login_state)?
            .finish(CredentialFinalization::deserialize(
            &parameters.credential_finalization,
        )?)?;

        assert_eq!(
            hex::encode(parameters.session_key),
            hex::encode(&server_login_result.session_key)
        );

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>(TEST_VECTOR_RISTRETTO255)?;
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>(TEST_VECTOR_CURVE25519_RISTRETTO255)?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>(TEST_VECTOR_CURVE25519_P256)?;

    Ok(())
}

fn test_complete_flow<CS: CipherSuite>(
    registration_password: &[u8],
    login_password: &[u8],
) -> Result<(), ProtocolError>
where
    <OprfHash<CS> as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
    OprfHash<CS>: Hash,
    <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
    <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // MaskedResponse: (Nonce + Hash) + KePk
    NonceLen: Add<OutputSize<OprfHash<CS>>>,
    Sum<NonceLen, OutputSize<OprfHash<CS>>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
    MaskedResponseLen<CS>: ArrayLength<u8>,
{
    let credential_identifier = b"credentialIdentifier";
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<CS>::new(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<CS>::start(&mut client_rng, registration_password)?;
    let server_registration_start_result = ServerRegistration::<CS>::start(
        &server_setup,
        client_registration_start_result.message,
        credential_identifier,
    )?;
    let client_registration_finish_result = client_registration_start_result.state.finish(
        &mut client_rng,
        registration_password,
        server_registration_start_result.message,
        ClientRegistrationFinishParameters::default(),
    )?;
    let p_file = ServerRegistration::finish(client_registration_finish_result.message);
    let client_login_start_result = ClientLogin::<CS>::start(&mut client_rng, login_password)?;
    let server_login_start_result = ServerLogin::<CS>::start(
        &mut server_rng,
        &server_setup,
        Some(p_file),
        client_login_start_result.message,
        credential_identifier,
        ServerLoginStartParameters::default(),
    )?;

    let client_login_result = client_login_start_result.state.finish(
        login_password,
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
        assert!(matches!(
            client_login_result,
            Err(ProtocolError::InvalidLoginError)
        ));
    }

    Ok(())
}

#[test]
fn test_complete_flow_success() -> Result<(), ProtocolError> {
    #[cfg(feature = "ristretto255")]
    test_complete_flow::<Ristretto255>(b"good password", b"good password")?;
    test_complete_flow::<P256>(b"good password", b"good password")?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    test_complete_flow::<Curve25519Ristretto255>(b"good password", b"good password")?;
    #[cfg(feature = "curve25519")]
    test_complete_flow::<Curve25519P256>(b"good password", b"good password")?;

    Ok(())
}

#[test]
fn test_complete_flow_fail() -> Result<(), ProtocolError> {
    #[cfg(feature = "ristretto255")]
    test_complete_flow::<Ristretto255>(b"good password", b"bad password")?;
    test_complete_flow::<P256>(b"good password", b"bad password")?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    test_complete_flow::<Curve25519Ristretto255>(b"good password", b"bad password")?;
    #[cfg(feature = "curve25519")]
    test_complete_flow::<Curve25519P256>(b"good password", b"bad password")?;

    Ok(())
}

// Zeroize tests

#[test]
fn test_zeroize_client_registration_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let mut client_rng = OsRng;
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;

        let mut state = client_registration_start_result.state;
        unsafe { ptr::drop_in_place(&mut state) };
        for byte in state.to_vec() {
            assert_eq!(byte, 0);
        }

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    inner::<P256>()?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>()?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_client_registration_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let mut client_rng = OsRng;
        let mut server_rng = OsRng;
        let server_setup = ServerSetup::<CS>::new(&mut server_rng);
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;
        let server_registration_start_result = ServerRegistration::<CS>::start(
            &server_setup,
            client_registration_start_result.message,
            STR_CREDENTIAL_IDENTIFIER.as_bytes(),
        )?;
        let client_registration_finish_result = client_registration_start_result.state.finish(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
            server_registration_start_result.message,
            ClientRegistrationFinishParameters::default(),
        )?;

        let mut state = client_registration_finish_result.state;
        unsafe { ptr::drop_in_place(&mut state) };
        for byte in state.to_vec() {
            assert_eq!(byte, 0);
        }

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    inner::<P256>()?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>()?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_server_registration_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <CS::KeGroup as KeGroup>::PkLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<EnvelopeLen<CS>>,
        RegistrationUploadLen<CS>: ArrayLength<u8>,
        // ServerRegistration = RegistrationUpload
    {
        let mut client_rng = OsRng;
        let mut server_rng = OsRng;
        let server_setup = ServerSetup::<CS>::new(&mut server_rng);
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;
        let server_registration_start_result = ServerRegistration::<CS>::start(
            &server_setup,
            client_registration_start_result.message,
            STR_CREDENTIAL_IDENTIFIER.as_bytes(),
        )?;
        let client_registration_finish_result = client_registration_start_result.state.finish(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
            server_registration_start_result.message,
            ClientRegistrationFinishParameters::default(),
        )?;
        let p_file = ServerRegistration::finish(client_registration_finish_result.message);

        let mut state = p_file;
        util::drop_manually(&mut state);
        util::test_zeroized(&mut state.0.envelope.mode);
        util::test_zeroized(&mut state.0.masking_key);

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    inner::<P256>()?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>()?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_client_login_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite<KeyExchange = TripleDh>>() -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // CredentialRequest: KgPk + Ke1Message
        <OprfGroup<CS> as Group>::ElemLen: Add<Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
        // Ke1State: KeSk + Nonce
        <CS::KeGroup as KeGroup>::SkLen: Add<NonceLen>,
        Sum<<CS::KeGroup as KeGroup>::SkLen, NonceLen>: ArrayLength<u8>,
        // Ke1Message: Nonce + KePk
        NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
        Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>: ArrayLength<u8>,
        // Ke2State: (Hash + Hash) + Hash
        OutputSize<OprfHash<CS>>: Add<OutputSize<OprfHash<CS>>>,
        Sum<OutputSize<OprfHash<CS>>, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<OutputSize<OprfHash<CS>>>,
        Sum<Sum<OutputSize<OprfHash<CS>>, OutputSize<OprfHash<CS>>>, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8>,
        // Ke2Message: (Nonce + KePk) + Hash
        NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
        Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>:
            ArrayLength<u8> + Add<OutputSize<OprfHash<CS>>>,
        Sum<Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8>,
    {
        let mut client_rng = OsRng;
        let client_login_start_result =
            ClientLogin::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;

        let mut state = client_login_start_result.state;
        util::drop_manually(&mut state);
        util::test_zeroized(&mut state.oprf_client);
        util::test_zeroized(&mut state.ke1_state);
        util::test_zeroized(&mut state.credential_request.ke1_message.client_nonce);

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    inner::<P256>()?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>()?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_server_login_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<NonceLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
    {
        let mut client_rng = OsRng;
        let mut server_rng = OsRng;
        let server_setup = ServerSetup::<CS>::new(&mut server_rng);
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;
        let server_registration_start_result = ServerRegistration::<CS>::start(
            &server_setup,
            client_registration_start_result.message,
            STR_CREDENTIAL_IDENTIFIER.as_bytes(),
        )?;
        let client_registration_finish_result = client_registration_start_result.state.finish(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
            server_registration_start_result.message,
            ClientRegistrationFinishParameters::default(),
        )?;
        let p_file = ServerRegistration::finish(client_registration_finish_result.message);
        let client_login_start_result =
            ClientLogin::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;
        let server_login_start_result = ServerLogin::<CS>::start(
            &mut server_rng,
            &server_setup,
            Some(p_file),
            client_login_start_result.message,
            STR_CREDENTIAL_IDENTIFIER.as_bytes(),
            ServerLoginStartParameters::default(),
        )?;

        let mut state = server_login_start_result.state;
        unsafe { ptr::drop_in_place(&mut state) };
        for byte in state.serialize() {
            assert_eq!(byte, 0);
        }

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    inner::<P256>()?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>()?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_client_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite<KeyExchange = TripleDh>>() -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<NonceLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
        // CredentialRequest: KgPk + Ke1Message
        <OprfGroup<CS> as Group>::ElemLen: Add<Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
        // Ke1State: KeSk + Nonce
        <CS::KeGroup as KeGroup>::SkLen: Add<NonceLen>,
        Sum<<CS::KeGroup as KeGroup>::SkLen, NonceLen>: ArrayLength<u8>,
        // Ke1Message: Nonce + KePk
        NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
        Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>: ArrayLength<u8>,
        // Ke2State: (Hash + Hash) + Hash
        OutputSize<OprfHash<CS>>: Add<OutputSize<OprfHash<CS>>>,
        Sum<OutputSize<OprfHash<CS>>, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<OutputSize<OprfHash<CS>>>,
        Sum<Sum<OutputSize<OprfHash<CS>>, OutputSize<OprfHash<CS>>>, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8>,
        // Ke2Message: (Nonce + KePk) + Hash
        NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
        Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>:
            ArrayLength<u8> + Add<OutputSize<OprfHash<CS>>>,
        Sum<Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8>,
    {
        let mut client_rng = OsRng;
        let mut server_rng = OsRng;
        let server_setup = ServerSetup::<CS>::new(&mut server_rng);
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;
        let server_registration_start_result = ServerRegistration::<CS>::start(
            &server_setup,
            client_registration_start_result.message,
            STR_CREDENTIAL_IDENTIFIER.as_bytes(),
        )?;
        let client_registration_finish_result = client_registration_start_result.state.finish(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
            server_registration_start_result.message,
            ClientRegistrationFinishParameters::default(),
        )?;
        let p_file = ServerRegistration::finish(client_registration_finish_result.message);
        let client_login_start_result =
            ClientLogin::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;
        let server_login_start_result = ServerLogin::<CS>::start(
            &mut server_rng,
            &server_setup,
            Some(p_file),
            client_login_start_result.message,
            STR_CREDENTIAL_IDENTIFIER.as_bytes(),
            ServerLoginStartParameters::default(),
        )?;
        let client_login_finish_result = client_login_start_result.state.finish(
            STR_PASSWORD.as_bytes(),
            server_login_start_result.message,
            ClientLoginFinishParameters::default(),
        )?;

        let mut state = client_login_finish_result.state;
        util::drop_manually(&mut state);
        util::test_zeroized(&mut state.oprf_client);
        util::test_zeroized(&mut state.ke1_state);
        util::test_zeroized(&mut state.credential_request.ke1_message.client_nonce);

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    inner::<P256>()?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>()?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_server_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<NonceLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
    {
        let mut client_rng = OsRng;
        let mut server_rng = OsRng;
        let server_setup = ServerSetup::<CS>::new(&mut server_rng);
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;
        let server_registration_start_result = ServerRegistration::<CS>::start(
            &server_setup,
            client_registration_start_result.message,
            STR_CREDENTIAL_IDENTIFIER.as_bytes(),
        )?;
        let client_registration_finish_result = client_registration_start_result.state.finish(
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
            server_registration_start_result.message,
            ClientRegistrationFinishParameters::default(),
        )?;
        let p_file = ServerRegistration::finish(client_registration_finish_result.message);
        let client_login_start_result =
            ClientLogin::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;
        let server_login_start_result = ServerLogin::<CS>::start(
            &mut server_rng,
            &server_setup,
            Some(p_file),
            client_login_start_result.message,
            STR_CREDENTIAL_IDENTIFIER.as_bytes(),
            ServerLoginStartParameters::default(),
        )?;
        let client_login_finish_result = client_login_start_result.state.finish(
            STR_PASSWORD.as_bytes(),
            server_login_start_result.message,
            ClientLoginFinishParameters::default(),
        )?;
        let server_login_finish_result = server_login_start_result
            .state
            .finish(client_login_finish_result.message)?;

        let mut state = server_login_finish_result.state;
        unsafe { ptr::drop_in_place(&mut state) };
        for byte in state.serialize() {
            assert_eq!(byte, 0);
        }

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    inner::<P256>()?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>()?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>()?;

    Ok(())
}

#[test]
fn test_scalar_always_nonzero() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        // Start out with a bunch of zeros to force resampling of scalar
        let mut client_registration_rng = CycleRng::new([vec![0u8; 128], vec![1u8; 128]].concat());
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut client_registration_rng, STR_PASSWORD.as_bytes())?;

        assert!(!bool::from(
            OprfGroup::<CS>::identity_elem().ct_eq(
                &client_registration_start_result
                    .message
                    .get_blinded_element_for_testing()
                    .value(),
            )
        ));

        // Start out with a bunch of zeros to force resampling of scalar
        let mut client_login_rng = CycleRng::new([vec![0u8; 128], vec![1u8; 128]].concat());
        let client_login_start_result =
            ClientLogin::<CS>::start(&mut client_login_rng, STR_PASSWORD.as_bytes())?;

        assert!(!bool::from(
            OprfGroup::<CS>::identity_elem().ct_eq(
                &client_login_start_result
                    .message
                    .get_blinded_element_for_testing()
                    .value(),
            )
        ));

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    inner::<P256>()?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>()?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>()?;

    Ok(())
}

#[test]
fn test_reflected_value_error_registration() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let credential_identifier = b"credentialIdentifier";
        let password = b"password";
        let mut client_rng = OsRng;
        let mut server_rng = OsRng;
        let server_setup = ServerSetup::<CS>::new(&mut server_rng);
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut client_rng, password)?;
        let alpha = client_registration_start_result
            .message
            .get_blinded_element_for_testing()
            .value();
        let server_registration_start_result = ServerRegistration::<CS>::start(
            &server_setup,
            client_registration_start_result.message,
            credential_identifier,
        )?;

        let reflected_registration_response = server_registration_start_result
            .message
            .set_evaluation_element_for_testing(alpha);

        let client_registration_finish_result = client_registration_start_result.state.finish(
            &mut client_rng,
            password,
            reflected_registration_response,
            ClientRegistrationFinishParameters::default(),
        );

        assert!(matches!(
            client_registration_finish_result,
            Err(ProtocolError::ReflectedValueError)
        ));

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    inner::<P256>()?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>()?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>()?;

    Ok(())
}

#[test]
fn test_reflected_value_error_login() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <OprfHash<CS> as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<OprfHash<CS> as BlockSizeUser>::BlockSize>,
        OprfHash<CS>: Hash,
        <OprfHash<CS> as CoreProxy>::Core: ProxyHash,
        <<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<OprfHash<CS> as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<NonceLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
    {
        let credential_identifier = b"credentialIdentifier";
        let password = b"password";
        let mut client_rng = OsRng;
        let mut server_rng = OsRng;
        let server_setup = ServerSetup::<CS>::new(&mut server_rng);
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut client_rng, password)?;
        let server_registration_start_result = ServerRegistration::<CS>::start(
            &server_setup,
            client_registration_start_result.message,
            credential_identifier,
        )?;
        let client_registration_finish_result = client_registration_start_result.state.finish(
            &mut client_rng,
            password,
            server_registration_start_result.message,
            ClientRegistrationFinishParameters::default(),
        )?;
        let p_file = ServerRegistration::finish(client_registration_finish_result.message);
        let client_login_start_result = ClientLogin::<CS>::start(&mut client_rng, password)?;
        let alpha = client_login_start_result
            .message
            .get_blinded_element_for_testing()
            .value();
        let server_login_start_result = ServerLogin::<CS>::start(
            &mut server_rng,
            &server_setup,
            Some(p_file),
            client_login_start_result.message,
            credential_identifier,
            ServerLoginStartParameters::default(),
        )?;

        let reflected_credential_response = server_login_start_result
            .message
            .set_evaluation_element_for_testing(alpha);

        let client_login_result = client_login_start_result.state.finish(
            password,
            reflected_credential_response,
            ClientLoginFinishParameters::default(),
        );

        assert!(matches!(
            client_login_result,
            Err(ProtocolError::ReflectedValueError)
        ));
        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    inner::<P256>()?;
    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    inner::<Curve25519Ristretto255>()?;
    #[cfg(feature = "curve25519")]
    inner::<Curve25519P256>()?;

    Ok(())
}

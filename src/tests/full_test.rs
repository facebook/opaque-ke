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
use crate::key_exchange::tripledh::{NonceLen, TripleDH};
use crate::keypair::SecretKey;
use crate::messages::{
    CredentialRequestLen, CredentialResponseLen, CredentialResponseWithoutKeLen,
    RegistrationResponseLen, RegistrationUploadLen,
};
use crate::opaque::*;
use crate::slow_hash::NoOpHash;
use crate::tests::mock_rng::CycleRng;
use crate::*;

// Tests
// =====

#[cfg(feature = "ristretto255")]
struct Ristretto255;

#[cfg(feature = "ristretto255")]
impl CipherSuite for Ristretto255 {
    type OprfGroup = crate::Ristretto255;
    type KeGroup = crate::Ristretto255;
    type KeyExchange = TripleDH;
    type SlowHash = NoOpHash;
}

struct P256;

impl CipherSuite for P256 {
    type OprfGroup = p256::NistP256;
    type KeGroup = p256::NistP256;
    type KeyExchange = TripleDH;
    type SlowHash = NoOpHash;
}

#[cfg(all(feature = "x25519", feature = "ristretto255"))]
struct X25519Ristretto255;

#[cfg(all(feature = "x25519", feature = "ristretto255"))]
impl CipherSuite for X25519Ristretto255 {
    type OprfGroup = crate::Ristretto255;
    type KeGroup = crate::X25519;
    type KeyExchange = TripleDH;
    type SlowHash = NoOpHash;
}

#[cfg(feature = "x25519")]
struct X25519P256;

#[cfg(feature = "x25519")]
impl CipherSuite for X25519P256 {
    type OprfGroup = p256::NistP256;
    type KeGroup = crate::X25519;
    type KeyExchange = TripleDH;
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

// To regenerate, run: cargo test -- --nocapture generate_test_vectors
#[cfg(feature = "ristretto255")]
static TEST_VECTOR_RISTRETTO255: &str = r#"
{
    "client_s_pk": "8cc7c9eb1d0f5803fd02f13ffc91175bd2a4ea0395913c7d6414431a05dda94c",
    "client_s_sk": "b30044efeb2c90127e35389c2d025dccbe90c03c102ea38388e362320c6e570f",
    "client_e_pk": "5ac74ef87ac50c960c56fdcd46daf12ef7d88739c8654937e7a4d8996d60ed22",
    "client_e_sk": "1d78d5ffe9b3ad5bb467da13232805cbbdff0473ed47da7738f7a05d2f35c603",
    "server_s_pk": "34dacc7158463c3d29aa780baab28624b1c71df0468e134bde085cdc8f4e941b",
    "server_s_sk": "966ee3f6f3ece48d37ca5394f113dad2fc3afe2923fc20f769a185de1bea9905",
    "server_e_pk": "387e1dff8d671ac91665bb0268478ec518d2db28d0cf71041696e65c14c04562",
    "server_e_sk": "5f7bed95ef1efd306e3144f30381593a85adb98e632552b0e87644d46cbcc002",
    "fake_sk": "a85ac8f4eee6bb688c3ae7d7b6d995da2038645ba34ceadf8467e56d175bc008",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "ae7bd2be7bcbeafcf4c26f92e4ab37b174c93126cdb0b6321a511c92f3cecb0f",
    "oprf_seed": "4f31cd5f5ddbc39da5d354b0d5bdae1c0f57aa549aaca4eba8138156c387473ed050329b97631d9fca895c60afb1855e30f2426043cd2dd242707bf664082c87",
    "masking_nonce": "97a321a4a2946fcacbae9d80d78ac1c06d9f7e39e426b367be57398957938bbc5a18264ee75b6976b2abc8fccc702010196cb1c90fbfcab60363acc3d503c968",
    "envelope_nonce": "4745c52d41faa7c697d3fb3374c087966b8e44da7519e0f7c561a0ee0f3a6180",
    "client_nonce": "781fbdffc567af01253fb0d53839842a7255fd36371dde1b05979691c0bca067",
    "server_nonce": "1f5fc6d4f55c092245bdb150c2db4189ad8fca9c8df5218a0876cb11c8114a39",
    "context": "636f6e74657874",
    "registration_request": "083b7dfada0e53c78f9d32ddcb88ec50144cf361fd202d73581eeeb944113715",
    "registration_response": "760fdf28216493a9a9b9f268c33d7a22f059f16ab6f3b9559f3165874453414834dacc7158463c3d29aa780baab28624b1c71df0468e134bde085cdc8f4e941b",
    "registration_upload": "5c60129a5003992493977306a309188b373fb806a9f0668279ca21806081cc7d21a180fba338aa1477038a9b41623dc5feb69445f9f48e342a63eb7a45b6522fa4f1555d1729fcb15fb2d1e761c7583c0b5ce704c032e3804aa3c2ca16e6bd26b30044efeb2c90127e35389c2d025dccbe90c03c102ea38388e362320c6e570f4992b64df766073034f49e77eddf22f6a6418408cc29a11357871e9c41663ee71958443f36fa81c3ff2d487dcfcdd28695e2f0dfbb84201e968a8f9111a68a28",
    "credential_request": "083b7dfada0e53c78f9d32ddcb88ec50144cf361fd202d73581eeeb944113715781fbdffc567af01253fb0d53839842a7255fd36371dde1b05979691c0bca0675ac74ef87ac50c960c56fdcd46daf12ef7d88739c8654937e7a4d8996d60ed22",
    "credential_response": "760fdf28216493a9a9b9f268c33d7a22f059f16ab6f3b9559f3165874453414897a321a4a2946fcacbae9d80d78ac1c06d9f7e39e426b367be57398957938bbcb095ee31bf57672fab06716b53c69cbfefc2907064a8fbf284cd02adda3add3c43706e059634ea372ecb2718103ca2fc83a7b060194a804dc2b4339ee5d5d228d38d21e16c61424bbc3ff8fd599e5f1e928935983ee3b0226a1beeb182777a0c0053859554b5bde0f9f52f5a8c82831e866891cfa1907f2906b55d0432f0c30b5f7bed95ef1efd306e3144f30381593a85adb98e632552b0e87644d46cbcc002d023f69a86ba2b2ec3d6e75350f2ac1f780a899e6eb658a41dd773c440dc2b4a4f4281f8a049d3ed483db43274d30e89220e693e4027259ab1b037ff543935d973772ca255fc128d114c338100c49a86906c8deed99fd49a9c481beeb689154d",
    "credential_finalization": "90861a832ee7aa11c865d37c011443fb0bc66852484d41f7ee712ceb4a61a580b368c08b7a3d1b133f63a54db5368b47e28e59740697336d9855da3b72d26e83",
    "client_registration_state": "ae7bd2be7bcbeafcf4c26f92e4ab37b174c93126cdb0b6321a511c92f3cecb0f083b7dfada0e53c78f9d32ddcb88ec50144cf361fd202d73581eeeb944113715",
    "client_login_state": "ae7bd2be7bcbeafcf4c26f92e4ab37b174c93126cdb0b6321a511c92f3cecb0f083b7dfada0e53c78f9d32ddcb88ec50144cf361fd202d73581eeeb944113715781fbdffc567af01253fb0d53839842a7255fd36371dde1b05979691c0bca0675ac74ef87ac50c960c56fdcd46daf12ef7d88739c8654937e7a4d8996d60ed221d78d5ffe9b3ad5bb467da13232805cbbdff0473ed47da7738f7a05d2f35c603781fbdffc567af01253fb0d53839842a7255fd36371dde1b05979691c0bca067",
    "server_login_state": "877f235cde56f884c971e137dbfec8dc6fbb00656cbf6e20d032f6fba598ed0ad6ff7fc2d52b76e57eb72037c6976491ee045472b35204513b909cafc3ac5e3bac4fab5f4dce3c8de85481d899ee644fd8af2c30b8756746ef97bdfb82d9a081bad64d83fa726404f7af042b49ba79049e6ed825e40180ac08407ff18d44f11d828933d78f17e6360881ec80e8696507892dd1072958b8e1566ea2a68b0ed227593a19f2c5266d5c456338d7142126543bfb38bfe7209e84778eda944774832b",
    "password_file": "5c60129a5003992493977306a309188b373fb806a9f0668279ca21806081cc7d21a180fba338aa1477038a9b41623dc5feb69445f9f48e342a63eb7a45b6522fa4f1555d1729fcb15fb2d1e761c7583c0b5ce704c032e3804aa3c2ca16e6bd26b30044efeb2c90127e35389c2d025dccbe90c03c102ea38388e362320c6e570f4992b64df766073034f49e77eddf22f6a6418408cc29a11357871e9c41663ee71958443f36fa81c3ff2d487dcfcdd28695e2f0dfbb84201e968a8f9111a68a28",
    "export_key": "c37b2ce98f5822c578236405dba3b17d42e3ae452ec2bb667442bbfc39774827bfeff20ec0c98c4b2d131880425455f0e12cd09b5112dc6e8609eb3be07bb396",
    "session_key": "828933d78f17e6360881ec80e8696507892dd1072958b8e1566ea2a68b0ed227593a19f2c5266d5c456338d7142126543bfb38bfe7209e84778eda944774832b"
}
"#;

static TEST_VECTOR_P256: &str = r#"
{
    "client_s_pk": "02ec5dd688a3aa66022860d4bfed2dcb01a5da07a0b4ff0c84d9f8749bd478c293",
    "client_s_sk": "4982f91037e2e498ea3b7fe8f72c35d00a9b952c8ce4fb0563a49071d599390c",
    "client_e_pk": "027f8c859ded40011655cd5314f5dc3b42ed95c11da3ad181a70d911fadb818415",
    "client_e_sk": "efeb2242f4068b651e29917611a295033e8369ee14c1091678f0327383997289",
    "server_s_pk": "0231a120b62158db8b182afba15361f32870c17d09675fb2b751fab99a55b7f29b",
    "server_s_sk": "04a0d9eae979c3e0a7be44d723fdabafd4a2c2bd0d2bef4d1134a61358e1d3d6",
    "server_e_pk": "022ef1078479c8d69e08d94d682aca2c63a293193ef8d45d0508cc13d64d5dc3b4",
    "server_e_sk": "304ada96918e021ec1595981ac41711853bd7a271bf3aa6c01e57ebdd18b50ed",
    "fake_sk": "668017c4eb69093ca24e877fb258df8de386a136af9a08fb5c3c52c52267a03c",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "7c4a996eaac89d9cea984623277a142b52b63c6546ef426227922dec19d00a87",
    "oprf_seed": "cdeef0e45c5c592bcc00d9ac8f094d43463165f886c4102f5a293ef8aa319de8",
    "masking_nonce": "1d8e692fc6911170cfa00dbe665fa0d5db76a672245d111432b2fe35733d04f86b3d1ba79b08430b7fcad140a0d3067bcb2dd90fb3c3376cfc50660477454ae4",
    "envelope_nonce": "18774499e68269ff9cc98e6b74438d00378b11886e93b34dfe61fb0912be6faa",
    "client_nonce": "4a66273ed0c375274d59eb5d29f2f579c282dce9853401c9c7bdefe4018ed016",
    "server_nonce": "e11586209869eb4ac351ebc8c1e348a7f7bdd4cccf747b8ccd6b7028a57a1692",
    "context": "636f6e74657874",
    "registration_request": "0240132c056e840d76432376499866bc24cbcc421352f97876e3db730eaf93c9a3",
    "registration_response": "02aaf5d179cbd839043f1a5bb0b9d548240f83ba04fdf20bde2c4eb6c8cbd9af190231a120b62158db8b182afba15361f32870c17d09675fb2b751fab99a55b7f29b",
    "registration_upload": "02d4231d770ef9ae965843a1675ad74199326c45903ba01740fb78802b3c513a94dadfe6d48822c9afb0180a8c153d05ec8165f12a65c5a4cdc4dd3319d1771d014982f91037e2e498ea3b7fe8f72c35d00a9b952c8ce4fb0563a49071d599390c13dd1bc302ed8244f467ae4efeffed774664d64a23e3be0526ca1a97bd0e184d",
    "credential_request": "0240132c056e840d76432376499866bc24cbcc421352f97876e3db730eaf93c9a34a66273ed0c375274d59eb5d29f2f579c282dce9853401c9c7bdefe4018ed016027f8c859ded40011655cd5314f5dc3b42ed95c11da3ad181a70d911fadb818415",
    "credential_response": "02aaf5d179cbd839043f1a5bb0b9d548240f83ba04fdf20bde2c4eb6c8cbd9af191d8e692fc6911170cfa00dbe665fa0d5db76a672245d111432b2fe35733d04f82b04c06b790ba4255130b98aff3a2f1fd6a0527cd9c8013b21eaf416292ce31f7f0cc1265563c461b5b201321c9aff0e33ebcbb3c378d44abe339070ee98d9c4273424602fe6defccedf46622f024f9d43569cb168ffde5f83ce2627e4b3033502304ada96918e021ec1595981ac41711853bd7a271bf3aa6c01e57ebdd18b50ed03a2fc14b586b9875732238ef1c8964ca168781c3002a0dd1b301aa692525cb86023db579c0d130a7272e9e43f0ae71cc585146f0c547f4d903b0e85fb5c855dc0",
    "credential_finalization": "d721a8860a39f2f0b454a1721c3edef13bd9d2d1dc850624b4375e9824ab04ce",
    "client_registration_state": "7c4a996eaac89d9cea984623277a142b52b63c6546ef426227922dec19d00a870240132c056e840d76432376499866bc24cbcc421352f97876e3db730eaf93c9a3",
    "client_login_state": "7c4a996eaac89d9cea984623277a142b52b63c6546ef426227922dec19d00a870240132c056e840d76432376499866bc24cbcc421352f97876e3db730eaf93c9a34a66273ed0c375274d59eb5d29f2f579c282dce9853401c9c7bdefe4018ed016027f8c859ded40011655cd5314f5dc3b42ed95c11da3ad181a70d911fadb818415efeb2242f4068b651e29917611a295033e8369ee14c1091678f03273839972894a66273ed0c375274d59eb5d29f2f579c282dce9853401c9c7bdefe4018ed016",
    "server_login_state": "b652d371e96e1b4afc79137d6f6fbdb7c98a254f2547f3fab2423ea2213a188c2884cb33441cb38a5d0d63e3d914de117781df0573022dd326766effb07e3cce5b812234056fefc56980a25a8d0a2614cd638594fae2b25cd17b456f2046c724",
    "password_file": "02d4231d770ef9ae965843a1675ad74199326c45903ba01740fb78802b3c513a94dadfe6d48822c9afb0180a8c153d05ec8165f12a65c5a4cdc4dd3319d1771d014982f91037e2e498ea3b7fe8f72c35d00a9b952c8ce4fb0563a49071d599390c13dd1bc302ed8244f467ae4efeffed774664d64a23e3be0526ca1a97bd0e184d",
    "export_key": "bcb1ed54d1baebf8c0ee5542623b1867cd3f9257a67fac4a456af55a9fd9e02a",
    "session_key": "5b812234056fefc56980a25a8d0a2614cd638594fae2b25cd17b456f2046c724"
}
"#;

#[cfg(all(feature = "x25519", feature = "ristretto255"))]
static TEST_VECTOR_X25519_RISTRETTO255: &str = r#"
{
    "client_s_pk": "4df1ab49521829e233f34b412d48598d046afa20156f117898b7809b070ab526",
    "client_s_sk": "9055cba6082b86d8856b8ac3720c16a7ca07ff3303874149a0b5656e391bb05a",
    "client_e_pk": "9bbea5c768383168e385d895007f3eba4ecfbcadef26305449a76b2440465e3d",
    "client_e_sk": "388fac72f9c2e9aeeb189963015f7af1692a4a31fefaf06b4ecb66d066d9fe43",
    "server_s_pk": "f2f02607a409b5de08ee6e1e51ae674462397997682ea7c48c2d3c762378075b",
    "server_s_sk": "c06fed7591d65aa5f6a23cda5d53bde59707bc2d62c2ba61382380b77cae497a",
    "server_e_pk": "ee5251c72b241bfa4d926fed7d5082ee31a406e622731550912ac0fce105515f",
    "server_e_sk": "b018aa7067155ce9bb6d2fdbc163e706888d8e0cdff1e47f45073556abc8da5a",
    "fake_sk": "b8c3c7caec7ef8985a8c84dc183d98e2dbc9c30bd13b86e9c37c810fa0e1cc5e",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "d36ed47358b72a28796b5b0fc4f9301a294659da94d394f227e6e9b8ea277c0b",
    "oprf_seed": "b430182519702493f1991bbf7506c335b5e6e3899e5f1266a7f4c99dd16bf2efab3355a7e75423c2d0e54ee7cc1c16d3fc8975e47946f4bea95a77a06bfeea7c",
    "masking_nonce": "ce8202d2438b73cfe23d5f7bccc172ee6a354d690c1770ef07f4f269978bb0dbd6df845d9d9cb969ec8bf41dadef3835ba1d1dd4360b15ba5ad6cb77b9a53879",
    "envelope_nonce": "04c9e2914f5874089839e78eb29d342d3c472c0bdb62e1abedf74bbf505fec79",
    "client_nonce": "c01061951b0f6acc314a0cfa2f45b8f2e2125e0f1896fa63c1d97d8f74245c16",
    "server_nonce": "50fe3f0de7db78443da1eadb15d36d6645ea3f94ffcc57b862befda2a9bd10a5",
    "context": "636f6e74657874",
    "registration_request": "b889d6957f21a33951637b12f12007efc50d7b87811c96b8cc0072a605f1d24c",
    "registration_response": "200bcd11d44e9a10541a465ed3b130d4d10632dd7433965578e33d181e321113f2f02607a409b5de08ee6e1e51ae674462397997682ea7c48c2d3c762378075b",
    "registration_upload": "79d14f4164e722a8dcabffd4a341104e217d1597eeb414d4e4597d7c4376bf3b23ed2104a05b3ff4a12160f73172bbb195a3a399489bc4092e471e181a524b6c7fb6f955cacb8f8d0db54b89287b496e48b34b1a6204960925469d712c793bd89055cba6082b86d8856b8ac3720c16a7ca07ff3303874149a0b5656e391bb05a9490086c367c3705a0a46a497c797de7e67c0c7d1803e17e1cfd78d949c7b8558fa46da9fb3445bdef5e285a561e04518919387726a1b73660e687bda8a14256",
    "credential_request": "b889d6957f21a33951637b12f12007efc50d7b87811c96b8cc0072a605f1d24cc01061951b0f6acc314a0cfa2f45b8f2e2125e0f1896fa63c1d97d8f74245c169bbea5c768383168e385d895007f3eba4ecfbcadef26305449a76b2440465e3d",
    "credential_response": "200bcd11d44e9a10541a465ed3b130d4d10632dd7433965578e33d181e321113ce8202d2438b73cfe23d5f7bccc172ee6a354d690c1770ef07f4f269978bb0dbcc6f726f243b5a331e2a5b420866413d0e8b82f391bc4183361508a9f6c1b700e5f182630556f732e466976c2797cc5b05163ee4bb6ce39b1db500f03fe365009e359199926fad26726e438722c45f11beccc0e32e45fc24732f85d1aa9543e1d7c30248a20aad34efe89f8af3e8578071aa362564b5faba808fba9a66a78a26b018aa7067155ce9bb6d2fdbc163e706888d8e0cdff1e47f45073556abc8da5a3b9470912a8c10a2bede335ddbc1198d706acca69ae6ff0a72e195d2575f5b27b32d6099439ef55837e6e817def5ee8230ffb6fcd66d0f23f7169ab49eecfa8d134f2d6db9de03c51034b3a129f84c261234429cc34dfb7afdf3e392b7962b78",
    "credential_finalization": "f4133b65451a2b8f7a9cbfaca3f7c06211912fc669ffbe7cd554905b9f4e82a0e841cc97c70c8b964e02d6f665a136db0ad83b249d4f36be4c4944c4596ac696",
    "client_registration_state": "d36ed47358b72a28796b5b0fc4f9301a294659da94d394f227e6e9b8ea277c0bb889d6957f21a33951637b12f12007efc50d7b87811c96b8cc0072a605f1d24c",
    "client_login_state": "d36ed47358b72a28796b5b0fc4f9301a294659da94d394f227e6e9b8ea277c0bb889d6957f21a33951637b12f12007efc50d7b87811c96b8cc0072a605f1d24cc01061951b0f6acc314a0cfa2f45b8f2e2125e0f1896fa63c1d97d8f74245c169bbea5c768383168e385d895007f3eba4ecfbcadef26305449a76b2440465e3d388fac72f9c2e9aeeb189963015f7af1692a4a31fefaf06b4ecb66d066d9fe43c01061951b0f6acc314a0cfa2f45b8f2e2125e0f1896fa63c1d97d8f74245c16",
    "server_login_state": "b87047afce3cb9166d7f96a992d423f3eebb931413775c5373dc18abd6a42f919de37ca5643454b07d84440d77d364c7dd4c9029fb481aa7e34d91f061c38c2b5ba9c3260c4eb1bdfd6ef65e1415b8e227631985d979f0c5860d3076bd8f22a0e009dd6efb4359c414257678101fe91560f15b16461ca79618c09d26f346b0e9776d5589e16dc1d9466d5aa901db05d5cbeb73c2672da3b954046b170f514ce50282b8bccc1d542e902af8486fd37f886f555e56b2f34cc91d658996651eb8b8",
    "password_file": "79d14f4164e722a8dcabffd4a341104e217d1597eeb414d4e4597d7c4376bf3b23ed2104a05b3ff4a12160f73172bbb195a3a399489bc4092e471e181a524b6c7fb6f955cacb8f8d0db54b89287b496e48b34b1a6204960925469d712c793bd89055cba6082b86d8856b8ac3720c16a7ca07ff3303874149a0b5656e391bb05a9490086c367c3705a0a46a497c797de7e67c0c7d1803e17e1cfd78d949c7b8558fa46da9fb3445bdef5e285a561e04518919387726a1b73660e687bda8a14256",
    "export_key": "9b728dbe104caf7ea3d52a167c74408770b89f883c4ee280ee053fd9ad5aabc62bbe78cbc6bc9230819819ea75d40b8411f914095d4101c1e0d92c71b4e5b29f",
    "session_key": "776d5589e16dc1d9466d5aa901db05d5cbeb73c2672da3b954046b170f514ce50282b8bccc1d542e902af8486fd37f886f555e56b2f34cc91d658996651eb8b8"
}
"#;

#[cfg(feature = "x25519")]
static TEST_VECTOR_X25519_P256: &str = r#"
{
    "client_s_pk": "54ad295308e561e9549d2662a79a18228784bca512b50a6fd161595dbfa18f54",
    "client_s_sk": "20f9d6b90a9463e8432780c647b2dd7f4becf8d174c92a8023f395d01f16515b",
    "client_e_pk": "07cb52b7d96fcdcdec4ec1da39dab5210c6abca838af870886a391caf1cc9d7a",
    "client_e_sk": "20bdb5e9d5d98fcd9ba5634e03eba34fc728753369ce0234c9826aa88047c259",
    "server_s_pk": "4923a63bd059263cb2a69fd3a528191986d9c1f470bfe240d470af628adec277",
    "server_s_sk": "88b9fbacb0d38394f61c35408fe05c6734a1a63c5e6a16684095d9cc2f82cb4d",
    "server_e_pk": "e8a420fd6ff116cf865035321f91e211609b4a0f013ffd0798ea68bd04267c7a",
    "server_e_sk": "20eed40939abf897bdba6d7649893a617762fb3b94e04c247a086dc48448f361",
    "fake_sk": "4847b46ae57fa21f9bdf38bb4ee08ed12f64141b21707743ce3bf203cf36416b",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "1ca386b0d0a0c390c68d8eab341787260fa3ee2a94059d7887ec687eba80ceee",
    "oprf_seed": "b78f0138ef05a3df5aef410e7dda3b4972600e4d9f1e3ffa9376778cf31337ad",
    "masking_nonce": "669d7a5f0b410805b4a48d81d86e821d925341c5a634581d43225b1f0820d3c13a3633d70a1eb6982b12dbca41db7718f12db87a0896034bc4c3c7c54ac4d647",
    "envelope_nonce": "b57ed3206fb154fcfccb1e5effd873e9bce098af031674524c24572116061cc1",
    "client_nonce": "f7e2cf7311f3bd310e331dc24a94f319c0dc5f1ae2d3a039b5da60bac9ef6099",
    "server_nonce": "daad4ea374a85431b05253e53c5c69f67e0fc8067eaa1d492f8ff045659fe377",
    "context": "636f6e74657874",
    "registration_request": "023741a9f45d763159b728738cde140058e6bc3ead289e74b9df6cf2317dc50a36",
    "registration_response": "023e084f135edff464f60468dcc18c779ea7cea99daec254499ed082ed086bfe7d4923a63bd059263cb2a69fd3a528191986d9c1f470bfe240d470af628adec277",
    "registration_upload": "fee1e2438d269807b7e8b07c5b078f553bab065deb2943ac95119ec04857dc2a8a2e3934463798e276d13a0b3456eb2a98c87968d90c4ae0a51d311fe1655d5f20f9d6b90a9463e8432780c647b2dd7f4becf8d174c92a8023f395d01f16515bc4ddd82e83589cbe9c3b6fdea12acedef29aa7784a2ce0b65685dc352b66c142",
    "credential_request": "023741a9f45d763159b728738cde140058e6bc3ead289e74b9df6cf2317dc50a36f7e2cf7311f3bd310e331dc24a94f319c0dc5f1ae2d3a039b5da60bac9ef609907cb52b7d96fcdcdec4ec1da39dab5210c6abca838af870886a391caf1cc9d7a",
    "credential_response": "023e084f135edff464f60468dcc18c779ea7cea99daec254499ed082ed086bfe7d669d7a5f0b410805b4a48d81d86e821d925341c5a634581d43225b1f0820d3c15a700199e8446adf51b7f027b5c59ef0847b6e43ab72a6d6de4cf0eb3fe3a2093bdf8d3a50013795f094d651dcd7e9f597904e4940a3629166c2f3f4905e88c3e1f6db8f5244feebd435e5664bd395e9ba78aa93bd7e93863aa052765d4911b420eed40939abf897bdba6d7649893a617762fb3b94e04c247a086dc48448f3618e2b6d1e406e0695a0a7f32f296e45990186c54ab76a3562e7d70faf66ff99759118020c29faab346283f6e0221f7de81def8dc79c6904b5075b098a35c6a50e",
    "credential_finalization": "4a6e76c08153d2c07ab695030c6fd3a6f531338e3dc85f75b0af56ee54874e2e",
    "client_registration_state": "1ca386b0d0a0c390c68d8eab341787260fa3ee2a94059d7887ec687eba80ceee023741a9f45d763159b728738cde140058e6bc3ead289e74b9df6cf2317dc50a36",
    "client_login_state": "1ca386b0d0a0c390c68d8eab341787260fa3ee2a94059d7887ec687eba80ceee023741a9f45d763159b728738cde140058e6bc3ead289e74b9df6cf2317dc50a36f7e2cf7311f3bd310e331dc24a94f319c0dc5f1ae2d3a039b5da60bac9ef609907cb52b7d96fcdcdec4ec1da39dab5210c6abca838af870886a391caf1cc9d7a20bdb5e9d5d98fcd9ba5634e03eba34fc728753369ce0234c9826aa88047c259f7e2cf7311f3bd310e331dc24a94f319c0dc5f1ae2d3a039b5da60bac9ef6099",
    "server_login_state": "a4177b3ddccd8634ea0ad95dc9d7287f701fc5354ff53c84cb6205bff831fdeb49b5196d9330ab791ca1eb475a8eb04937430ef87776a7d1c7c4102231e7a1a89c599288d589338b0c99688a2db39f693d5d6f57cee46dc77f3d66af027fed3e",
    "password_file": "fee1e2438d269807b7e8b07c5b078f553bab065deb2943ac95119ec04857dc2a8a2e3934463798e276d13a0b3456eb2a98c87968d90c4ae0a51d311fe1655d5f20f9d6b90a9463e8432780c647b2dd7f4becf8d174c92a8023f395d01f16515bc4ddd82e83589cbe9c3b6fdea12acedef29aa7784a2ce0b65685dc352b66c142",
    "export_key": "fae7cd4aa438eeaa5f83b0a181ce29d18c9de4eecfd778a42511014c8b536f89",
    "session_key": "9c599288d589338b0c99688a2db39f693d5d6f57cee46dc77f3d66af027fed3e"
}
"#;

fn decode(values: &Value, key: &str) -> Option<Vec<u8>> {
    values[key].as_str().and_then(|s| hex::decode(&s).ok())
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
        client_s_pk: client_s_kp.public().to_bytes().to_vec(),
        client_s_sk: client_s_kp.private().serialize().to_vec(),
        client_e_pk: client_e_kp.public().to_bytes().to_vec(),
        client_e_sk: client_e_kp.private().serialize().to_vec(),
        server_s_pk: server_s_kp.public().to_bytes().to_vec(),
        server_s_sk: server_s_kp.private().serialize().to_vec(),
        server_e_pk: server_e_kp.public().to_bytes().to_vec(),
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

    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    {
        let parameters = generate_parameters::<X25519Ristretto255>()?;
        println!(
            "X25519 Ristretto255: {}",
            stringify_test_vectors(&parameters)
        );
    }

    #[cfg(feature = "x25519")]
    {
        let parameters = generate_parameters::<X25519P256>()?;
        println!("X25519 P-256: {}", stringify_test_vectors(&parameters));
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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn test_serialization() -> Result<(), ProtocolError> {
    use core::mem;

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
            RegistrationRequestLen::<CS>::USIZE + mem::size_of::<usize>()
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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

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
            hex::encode(&client_login_finish_result.server_s_pk.to_bytes())
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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    test_complete_flow::<X25519Ristretto255>(b"good password", b"good password")?;
    #[cfg(feature = "x25519")]
    test_complete_flow::<X25519P256>(b"good password", b"good password")?;

    Ok(())
}

#[test]
fn test_complete_flow_fail() -> Result<(), ProtocolError> {
    #[cfg(feature = "ristretto255")]
    test_complete_flow::<Ristretto255>(b"good password", b"bad password")?;
    test_complete_flow::<P256>(b"good password", b"bad password")?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    test_complete_flow::<X25519Ristretto255>(b"good password", b"bad password")?;
    #[cfg(feature = "x25519")]
    test_complete_flow::<X25519P256>(b"good password", b"bad password")?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>()?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>()?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_client_login_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite<KeyExchange = TripleDH>>() -> Result<(), ProtocolError>
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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>()?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_client_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite<KeyExchange = TripleDH>>() -> Result<(), ProtocolError>
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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>()?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>()?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>()?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>()?;

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
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(feature = "x25519")]
    inner::<X25519P256>()?;

    Ok(())
}

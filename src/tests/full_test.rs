// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

#![allow(unsafe_code)]

use core::ops::Add;
use std::string::{String, ToString};
use std::vec::Vec;
use std::{format, println, vec};

use digest::core_api::{BlockSizeUser, CoreProxy};
use digest::Output;
use generic_array::typenum::{IsLess, Le, NonZero, Sum, Unsigned, U256};
use generic_array::ArrayLength;
use rand::rngs::OsRng;
use serde_json::Value;
use subtle::ConstantTimeEq;
use voprf::Group;
use zeroize::Zeroize;

use crate::ciphersuite::CipherSuite;
use crate::envelope::EnvelopeLen;
use crate::errors::*;
use crate::hash::{OutputSize, ProxyHash};
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
    type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
    type KeGroup = crate::Ristretto255;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = NoOpHash;
}

#[cfg(feature = "p256")]
struct P256;
#[cfg(feature = "p256")]
impl CipherSuite for P256 {
    type OprfGroup = p256::ProjectivePoint;
    type KeGroup = p256::NistP256;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha256;
    type SlowHash = NoOpHash;
}

#[cfg(all(feature = "x25519", feature = "ristretto255"))]
struct X25519Ristretto255;
#[cfg(all(feature = "x25519", feature = "ristretto255"))]
impl CipherSuite for X25519Ristretto255 {
    type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
    type KeGroup = crate::X25519;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = NoOpHash;
}

#[cfg(all(feature = "x25519", feature = "p256"))]
struct X25519P256;
#[cfg(all(feature = "x25519", feature = "p256"))]
impl CipherSuite for X25519P256 {
    type OprfGroup = p256::ProjectivePoint;
    type KeGroup = crate::X25519;
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

#[cfg(feature = "p256")]
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
    "client_s_pk": "d6ea34b61fa4625c1197f8f9fd51bc7023d4dfb0e17a95cf0ec38488ffff072c",
    "client_s_sk": "f8fe7d4c525bd238c501c78a7b6ab26e076bb22c6b409ca08e34875ee4055850",
    "client_e_pk": "7b0d1002539befa86f0cdf2a281f538842ec685bad21e9057a92390846ca0047",
    "client_e_sk": "30e51bf7c5734fd3d1465b20affb65dc342f06513df999822832aa464aa29c5a",
    "server_s_pk": "b6791c7cad7775b6cbc0bfa580319a1de159981771c59b0b86afeeff2767365a",
    "server_s_sk": "68bfdb4e00e93059fb35e90db641ae1ef7af0fc8a7e013e2990431cf4c708563",
    "server_e_pk": "c68d13eacc23578e731d78d2ccc37e2ff8e7cfdac3f76ee54d9ae40dd1167325",
    "server_e_sk": "68b6d213f11d303e61929d299ca2424947e136d5a56b1400dda6286eaf5e4278",
    "fake_sk": "c8f71d7e7864a25ee4e786744c5059ca268b7cf7a7610b4b3d763f368fae6972",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "fa0bbeb200bef1802f3317c0e6b92590d9431fb6f5cb7f579d0865950172e40f",
    "oprf_seed": "8bbe6e550d125d9169342b5683b085be3aee7e6414fe2a4f6db2aa3493b16a9b75f109725d6d92c13f3f2814dec17f83e2fd20cf8b922ca1d928e8bf476f8154",
    "masking_nonce": "885aa518b13d78757415f8839e1505a4ae8b5f04b6904ce9aff6de6d156d94756f3cb40352bbdafe521da49bf9a57bcde3597114161b023cfbf3b79051d2ee0d",
    "envelope_nonce": "e5c5bb34123bb9b08eb961c6f3a94c6b627f1c5bcd3527d46a1652f662e078ac",
    "client_nonce": "7fb4b8f81eefe57a8b1cf5d75465d557e04b21ed7800356713ecc63b0ebbfca5",
    "server_nonce": "9e3f8ceb7174fdd7ceb2f1e37d4cd483e28e18fa60457416d2d5c468ae7501e7",
    "context": "636f6e74657874",
    "registration_request": "8eda5caa002e6574e677636eeba5967ec25505a125ea12d9857c0d8c3beb3551",
    "registration_response": "ecf14ba8fb208a8d5b263170ffd84a9d21751810f52e539938ed22e71f66cb02b6791c7cad7775b6cbc0bfa580319a1de159981771c59b0b86afeeff2767365a",
    "registration_upload": "020689ce9ffba0f198d9e63e23902ff1600656fdd604aa47c289d5d073cc472354e891e7c4f89058fd270813d320e0cb97a745722eb8038eec062e5aed5e6b40b88148d43e68b7f457c352c3b6523e0bc79795f651487d007574cbaf7dba317ff8fe7d4c525bd238c501c78a7b6ab26e076bb22c6b409ca08e34875ee4055850ea0fcb59720fdb42fcbddbccbaed60a0aec01d72403c63075468e8a03c9efc25206776154291cbce05d7567a82a10d8303f991b8689643c5727b1886c478a9b8",
    "credential_request": "8eda5caa002e6574e677636eeba5967ec25505a125ea12d9857c0d8c3beb35517fb4b8f81eefe57a8b1cf5d75465d557e04b21ed7800356713ecc63b0ebbfca57b0d1002539befa86f0cdf2a281f538842ec685bad21e9057a92390846ca0047",
    "credential_response": "ecf14ba8fb208a8d5b263170ffd84a9d21751810f52e539938ed22e71f66cb02885aa518b13d78757415f8839e1505a4ae8b5f04b6904ce9aff6de6d156d94756060ede0b8a8d061eaa376b4578fd39ec064f9f36c7a0602894690da72727b427148a2970ce50d06d93ed74dde1143f7d092f19541e8738c509dd5d34f4411d753959bc295083bc96a0b6e1d9a12a369c83fc2a50fab84276f83a2a63e5d5ba6dbb0b23752b7819c238123f0e69cbccc777fa6c35484608f324a3c30b307ad6068b6d213f11d303e61929d299ca2424947e136d5a56b1400dda6286eaf5e4278549bc184dd7a99b0749dfb1acb8ca862b649567d04b056c0530755d453e4c466d5728608562883eea4c922c313455999720cbbf3c6511d3666365132e39c1b6f094d05e73a75e15fb0869661337c3569fcfca75a9373d8fac9ff29c61be49a0d",
    "credential_finalization": "6061b34bc847481034908047ded2b7e08450793091f96b9a425e4e4e24e65810596b2556e1ea1ae57e3f6bf234ba33fc393fe4fa98de984760df870a454fcdc9",
    "client_registration_state": "fa0bbeb200bef1802f3317c0e6b92590d9431fb6f5cb7f579d0865950172e40f8eda5caa002e6574e677636eeba5967ec25505a125ea12d9857c0d8c3beb3551",
    "client_login_state": "fa0bbeb200bef1802f3317c0e6b92590d9431fb6f5cb7f579d0865950172e40f8eda5caa002e6574e677636eeba5967ec25505a125ea12d9857c0d8c3beb35517fb4b8f81eefe57a8b1cf5d75465d557e04b21ed7800356713ecc63b0ebbfca57b0d1002539befa86f0cdf2a281f538842ec685bad21e9057a92390846ca004730e51bf7c5734fd3d1465b20affb65dc342f06513df999822832aa464aa29c5a7fb4b8f81eefe57a8b1cf5d75465d557e04b21ed7800356713ecc63b0ebbfca5",
    "server_login_state": "d58815ef0bd83afafea536fe17c23f5292a5484d5748e7164b678bb4edbbfd99a31fc1b8e78ce8aab0908db29832e2c9644b4af4e3a167ab9a4f5e82c0a068eb8df23068244e4c7256c48abb28bc02529c3fbc2217c042fcc7f54e50f1516dde8f9f25c694e34604c9bea4b94090c3c911c22db5c74a79abbecf0354dc8d475575d17a1f85b7efdc2dd8b6e2fa9529bfe49d7cfa2563451fe6b9d5cd7344377c3730e197b550030c012b01466b142c9022b869fe5ea7c59412e5b6685db19997",
    "password_file": "020689ce9ffba0f198d9e63e23902ff1600656fdd604aa47c289d5d073cc472354e891e7c4f89058fd270813d320e0cb97a745722eb8038eec062e5aed5e6b40b88148d43e68b7f457c352c3b6523e0bc79795f651487d007574cbaf7dba317ff8fe7d4c525bd238c501c78a7b6ab26e076bb22c6b409ca08e34875ee4055850ea0fcb59720fdb42fcbddbccbaed60a0aec01d72403c63075468e8a03c9efc25206776154291cbce05d7567a82a10d8303f991b8689643c5727b1886c478a9b8",
    "export_key": "0527421cb5c31aeba8fddff1af3a673e94cbd7af57999eaed47e23ea3562d68362416d69afb3bcf450db76b4fea504d5d065e0a104d9a1848f20e64ff04f3cfd",
    "session_key": "75d17a1f85b7efdc2dd8b6e2fa9529bfe49d7cfa2563451fe6b9d5cd7344377c3730e197b550030c012b01466b142c9022b869fe5ea7c59412e5b6685db19997"
}
"#;

#[cfg(all(feature = "x25519", feature = "p256"))]
static TEST_VECTOR_X25519_P256: &str = r#"
{
    "client_s_pk": "ee6282a908e24291fcd1e7ce0a6fc244cf9b6371889e31a908d1919cdd756776",
    "client_s_sk": "785f65307f77f78cc4b20565a42c1954a30763d881528749f376b90a13ca2b73",
    "client_e_pk": "c6e0310d186d3c869b384418a6574cd9fff826e3a91ac46d05ce0ab56e25b978",
    "client_e_sk": "e889400a32d355cd203d6a1ee195a787217db28075de794d0c39ca29c44f1776",
    "server_s_pk": "1c840f081ecaa88b6eff81536d28b3220cc7101e6e90b998461cc80ead285808",
    "server_s_sk": "10138ce9d5660b1b23aaf520e1ec948bd1f318b571356aa3f9becf3db34daf7a",
    "server_e_pk": "152d47f6ac15e7c2c11f29bd513d182db4eed09ef3974a6e4438b72ec9aa2d0c",
    "server_e_sk": "589db8b32e957d97134b10f8b2fa107b908f88eb2a4620f2ae25d61107bf9e6f",
    "fake_sk": "088a857c0f23ea4896cb067420a5264e8ea22f13d6b471cc4518cdf520de817b",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "40b461844231f2f890fc68aa0da838e25f40af01ec1b212fdf6bad07db170757",
    "oprf_seed": "b25a0265e824656034824b935d49d7f844d26acf1a7d8c6c40d635543a2e6d33",
    "masking_nonce": "005cf982b3ddbb28ee252d729c83c4b9d74a54ac72f25325f7f21824530649fbf165383559cce8a4734d6fcd56e45f866828008d3d4c56dd57659c80bc3e094f",
    "envelope_nonce": "0c9954390a2bac0bf09c083a2152bfce397281e7a5408c08b0b18d56c0ec686c",
    "client_nonce": "b389ed08bf4bfbf895ea6706c3d967b5ec7c4af96c207ebe816c50b9615ab06e",
    "server_nonce": "a920b7dbb1607caea2a3d7577531fb30173d0123a2353cf4151bea9e71caaab2",
    "context": "636f6e74657874",
    "registration_request": "02c1f758572663d7bb1fa5dbc8cf426b867a9936bc741e9acc8a31b18bf0e5bd33",
    "registration_response": "03068d5d3fe0d6b3361c2c728b85dce104df42d3d11c2079392ab894ace50ff4001c840f081ecaa88b6eff81536d28b3220cc7101e6e90b998461cc80ead285808",
    "registration_upload": "f49b790e8f2e36ca511957263868d1ee897b2936b1ae4922ac2ad0b7a0e38f3c2606360d0008b6ed33e4ca48d31f3992875445e3a53f42e4eee661aad96e2c50785f65307f77f78cc4b20565a42c1954a30763d881528749f376b90a13ca2b7374d474b4232682bf9033067a42d35f2b9936822372cd9ea4f9b8c38b14948ff5",
    "credential_request": "02c1f758572663d7bb1fa5dbc8cf426b867a9936bc741e9acc8a31b18bf0e5bd33b389ed08bf4bfbf895ea6706c3d967b5ec7c4af96c207ebe816c50b9615ab06ec6e0310d186d3c869b384418a6574cd9fff826e3a91ac46d05ce0ab56e25b978",
    "credential_response": "03068d5d3fe0d6b3361c2c728b85dce104df42d3d11c2079392ab894ace50ff400005cf982b3ddbb28ee252d729c83c4b9d74a54ac72f25325f7f21824530649fbed3e1ab6eb243095958829896b0286515a108213900d019d88d8578eb7919aec225c95400fd737bdfa72a8dfcfc12958fb794383b8da8f49d13cd554569097e0f9ed325ae363061f593e3cf7a2d28ac87e5e0d2a2f344e7286cf7f38e006908b589db8b32e957d97134b10f8b2fa107b908f88eb2a4620f2ae25d61107bf9e6f3691d795831920a6728252782da676dc34b5d069d92af4d306f8b13a81185b5e8f648ff448ba49b2fbe98d0cac15fce9f60b965e79e0903bdee7528549d4241b",
    "credential_finalization": "1e7f17932a85f0d16ca1a40c1233695dd23a087f17f470df4eb51e9ff24cbe43",
    "client_registration_state": "40b461844231f2f890fc68aa0da838e25f40af01ec1b212fdf6bad07db17075702c1f758572663d7bb1fa5dbc8cf426b867a9936bc741e9acc8a31b18bf0e5bd33",
    "client_login_state": "40b461844231f2f890fc68aa0da838e25f40af01ec1b212fdf6bad07db17075702c1f758572663d7bb1fa5dbc8cf426b867a9936bc741e9acc8a31b18bf0e5bd33b389ed08bf4bfbf895ea6706c3d967b5ec7c4af96c207ebe816c50b9615ab06ec6e0310d186d3c869b384418a6574cd9fff826e3a91ac46d05ce0ab56e25b978e889400a32d355cd203d6a1ee195a787217db28075de794d0c39ca29c44f1776b389ed08bf4bfbf895ea6706c3d967b5ec7c4af96c207ebe816c50b9615ab06e",
    "server_login_state": "9a2ccb3a4690792ee4c290ae12a84049b941ac7d6c5288c300f3af40b34fef6dc40347b218e9f65fe3c67d07173dcc9d73b7bcd5e2a128e7565e4c2fcaada2c631b54a2472ce398831783222437e916804e19a67771d900cde8733e890305ce3",
    "password_file": "f49b790e8f2e36ca511957263868d1ee897b2936b1ae4922ac2ad0b7a0e38f3c2606360d0008b6ed33e4ca48d31f3992875445e3a53f42e4eee661aad96e2c50785f65307f77f78cc4b20565a42c1954a30763d881528749f376b90a13ca2b7374d474b4232682bf9033067a42d35f2b9936822372cd9ea4f9b8c38b14948ff5",
    "export_key": "2b867ad9909d31946cb3c3738fb1c1e51ba09d768e83d6b03eb909e0e4298003",
    "session_key": "31b54a2472ce398831783222437e916804e19a67771d900cde8733e890305ce3"
}
"#;

fn decode(values: &Value, key: &str) -> Option<Vec<u8>> {
    values[key]
        .as_str()
        .and_then(|s| hex::decode(&s.to_string()).ok())
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
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // ClientRegistration: KgSk + KgPk
    <CS::OprfGroup as Group>::ScalarLen: Add<<CS::OprfGroup as Group>::ElemLen>,
    ClientRegistrationLen<CS>: ArrayLength<u8>,
    // RegistrationResponse: KgPk + KePk
    <CS::OprfGroup as Group>::ElemLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
    RegistrationResponseLen<CS>: ArrayLength<u8>,
    // Envelope: Nonce + Hash
    NonceLen: Add<OutputSize<CS::Hash>>,
    EnvelopeLen<CS>: ArrayLength<u8>,
    // RegistrationUpload: (KePk + Hash) + Envelope
    <CS::KeGroup as KeGroup>::PkLen: Add<OutputSize<CS::Hash>>,
    Sum<<CS::KeGroup as KeGroup>::PkLen, OutputSize<CS::Hash>>:
        ArrayLength<u8> + Add<EnvelopeLen<CS>>,
    RegistrationUploadLen<CS>: ArrayLength<u8>,
    // ServerRegistration = RegistrationUpload
    // Ke1Message: Nonce + KePk
    NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
    Ke1MessageLen<CS>: ArrayLength<u8>,
    // CredentialRequest: KgPk + Ke1Message
    <CS::OprfGroup as Group>::ElemLen: Add<Ke1MessageLen<CS>>,
    CredentialRequestLen<CS>: ArrayLength<u8>,
    // ClientLogin: KgSk + CredentialRequest + Ke1State
    <CS::OprfGroup as Group>::ScalarLen: Add<CredentialRequestLen<CS>>,
    Sum<<CS::OprfGroup as Group>::ScalarLen, CredentialRequestLen<CS>>:
        ArrayLength<u8> + Add<Ke1StateLen<CS>>,
    ClientLoginLen<CS>: ArrayLength<u8>,
    // MaskedResponse: (Nonce + Hash) + KePk
    NonceLen: Add<OutputSize<CS::Hash>>,
    Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
    MaskedResponseLen<CS>: ArrayLength<u8>,
    // CredentialResponseWithoutKeLen: (KgPk + Nonce) + MaskedResponse
    <CS::OprfGroup as Group>::ElemLen: Add<NonceLen>,
    Sum<<CS::OprfGroup as Group>::ElemLen, NonceLen>: ArrayLength<u8> + Add<MaskedResponseLen<CS>>,
    CredentialResponseWithoutKeLen<CS>: ArrayLength<u8>,
    // Ke2Message: (Nonce + KePk) + Hash
    NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
    Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>: ArrayLength<u8> + Add<OutputSize<CS::Hash>>,
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
    let mut oprf_seed = Output::<CS::Hash>::default();
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

    let blinding_factor = CS::OprfGroup::random_nonzero_scalar(&mut rng);
    let blinding_factor_bytes = CS::OprfGroup::scalar_as_bytes(blinding_factor);

    let mut blinding_factor_registration_rng = CycleRng::new(blinding_factor_bytes.to_vec());
    let client_registration_start_result =
        ClientRegistration::<CS>::start(&mut blinding_factor_registration_rng, password).unwrap();
    let blinding_factor_bytes_returned = CS::OprfGroup::scalar_as_bytes(
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
    #[cfg(feature = "p256")]
    {
        let parameters = generate_parameters::<P256>()?;
        println!("P-256: {}", stringify_test_vectors(&parameters));
    }
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    {
        let parameters = generate_parameters::<X25519Ristretto255>()?;
        println!(
            "X25519 Ristretto255: {}",
            stringify_test_vectors(&parameters)
        );
    }
    #[cfg(all(feature = "x25519", feature = "p256"))]
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
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // ClientRegistration: KgSk + KgPk
        <CS::OprfGroup as Group>::ScalarLen: Add<<CS::OprfGroup as Group>::ElemLen>,
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
    #[cfg(feature = "p256")]
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn test_serialization() -> Result<(), ProtocolError> {
    use core::mem;

    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
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
    #[cfg(feature = "p256")]
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

    Ok(())
}

#[test]
fn test_registration_response() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // RegistrationResponse: KgPk + KePk
        <CS::OprfGroup as Group>::ElemLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
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
    #[cfg(feature = "p256")]
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

    Ok(())
}

#[test]
fn test_registration_upload() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<CS::Hash>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <CS::KeGroup as KeGroup>::PkLen: Add<OutputSize<CS::Hash>>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, OutputSize<CS::Hash>>:
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
            hex::encode(result.export_key.to_vec())
        );

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>(TEST_VECTOR_RISTRETTO255)?;
    #[cfg(feature = "p256")]
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

    Ok(())
}

#[test]
fn test_password_file() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<CS::Hash>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <CS::KeGroup as KeGroup>::PkLen: Add<OutputSize<CS::Hash>>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, OutputSize<CS::Hash>>:
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
    #[cfg(feature = "p256")]
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

    Ok(())
}

#[test]
fn test_credential_request() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // CredentialRequest: KgPk + Ke1Message
        <CS::OprfGroup as Group>::ElemLen: Add<Ke1MessageLen<CS>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
        // ClientLogin: KgSk + CredentialRequest + Ke1State
        <CS::OprfGroup as Group>::ScalarLen: Add<CredentialRequestLen<CS>>,
        Sum<<CS::OprfGroup as Group>::ScalarLen, CredentialRequestLen<CS>>:
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
    #[cfg(feature = "p256")]
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

    Ok(())
}

#[test]
fn test_credential_response() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<CS::Hash>>,
        Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
        // CredentialResponseWithoutKeLen: (KgPk + Nonce) + MaskedResponse
        <CS::OprfGroup as Group>::ElemLen: Add<NonceLen>,
        Sum<<CS::OprfGroup as Group>::ElemLen, NonceLen>:
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
    #[cfg(feature = "p256")]
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

    Ok(())
}

#[test]
fn test_credential_finalization() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<CS::Hash>>,
        Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
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
            hex::encode(&client_login_finish_result.server_s_pk.to_bytes().to_vec())
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
    #[cfg(feature = "p256")]
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

    Ok(())
}

#[test]
fn test_server_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
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
    #[cfg(feature = "p256")]
    inner::<P256>(TEST_VECTOR_P256)?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>(TEST_VECTOR_X25519_RISTRETTO255)?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>(TEST_VECTOR_X25519_P256)?;

    Ok(())
}

fn test_complete_flow<CS: CipherSuite>(
    registration_password: &[u8],
    login_password: &[u8],
) -> Result<(), ProtocolError>
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    // MaskedResponse: (Nonce + Hash) + KePk
    NonceLen: Add<OutputSize<CS::Hash>>,
    Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
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
    #[cfg(feature = "p256")]
    test_complete_flow::<P256>(b"good password", b"good password")?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    test_complete_flow::<X25519Ristretto255>(b"good password", b"good password")?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    test_complete_flow::<X25519P256>(b"good password", b"good password")?;

    Ok(())
}

#[test]
fn test_complete_flow_fail() -> Result<(), ProtocolError> {
    #[cfg(feature = "ristretto255")]
    test_complete_flow::<Ristretto255>(b"good password", b"bad password")?;
    #[cfg(feature = "p256")]
    test_complete_flow::<P256>(b"good password", b"bad password")?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    test_complete_flow::<X25519Ristretto255>(b"good password", b"bad password")?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    test_complete_flow::<X25519P256>(b"good password", b"bad password")?;

    Ok(())
}

// Zeroize tests

#[test]
fn test_zeroize_client_registration_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let mut client_rng = OsRng;
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;

        let mut state = client_registration_start_result.state;
        Zeroize::zeroize(&mut state);
        for byte in state.to_vec() {
            assert_eq!(byte, 0);
        }

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_client_registration_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
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
        Zeroize::zeroize(&mut state);
        for byte in state.to_vec() {
            assert_eq!(byte, 0);
        }

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_server_registration_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<CS::Hash>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <CS::KeGroup as KeGroup>::PkLen: Add<OutputSize<CS::Hash>>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, OutputSize<CS::Hash>>:
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
    #[cfg(feature = "p256")]
    inner::<P256>()?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_client_login_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite<KeyExchange = TripleDH>>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // CredentialRequest: KgPk + Ke1Message
        <CS::OprfGroup as Group>::ElemLen: Add<Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
        // Ke1State: KeSk + Nonce
        <CS::KeGroup as KeGroup>::SkLen: Add<NonceLen>,
        Sum<<CS::KeGroup as KeGroup>::SkLen, NonceLen>: ArrayLength<u8>,
        // Ke1Message: Nonce + KePk
        NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
        Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>: ArrayLength<u8>,
        // Ke2State: (Hash + Hash) + Hash
        OutputSize<CS::Hash>: Add<OutputSize<CS::Hash>>,
        Sum<OutputSize<CS::Hash>, OutputSize<CS::Hash>>:
            ArrayLength<u8> + Add<OutputSize<CS::Hash>>,
        Sum<Sum<OutputSize<CS::Hash>, OutputSize<CS::Hash>>, OutputSize<CS::Hash>>: ArrayLength<u8>,
        // Ke2Message: (Nonce + KePk) + Hash
        NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
        Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>: ArrayLength<u8> + Add<OutputSize<CS::Hash>>,
        Sum<Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>, OutputSize<CS::Hash>>: ArrayLength<u8>,
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
    #[cfg(feature = "p256")]
    inner::<P256>()?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_server_login_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<CS::Hash>>,
        Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
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
        Zeroize::zeroize(&mut state);
        for byte in state.serialize() {
            assert_eq!(byte, 0);
        }

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_client_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite<KeyExchange = TripleDH>>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<CS::Hash>>,
        Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
        // CredentialRequest: KgPk + Ke1Message
        <CS::OprfGroup as Group>::ElemLen: Add<Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
        // Ke1State: KeSk + Nonce
        <CS::KeGroup as KeGroup>::SkLen: Add<NonceLen>,
        Sum<<CS::KeGroup as KeGroup>::SkLen, NonceLen>: ArrayLength<u8>,
        // Ke1Message: Nonce + KePk
        NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
        Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>: ArrayLength<u8>,
        // Ke2State: (Hash + Hash) + Hash
        OutputSize<CS::Hash>: Add<OutputSize<CS::Hash>>,
        Sum<OutputSize<CS::Hash>, OutputSize<CS::Hash>>:
            ArrayLength<u8> + Add<OutputSize<CS::Hash>>,
        Sum<Sum<OutputSize<CS::Hash>, OutputSize<CS::Hash>>, OutputSize<CS::Hash>>: ArrayLength<u8>,
        // Ke2Message: (Nonce + KePk) + Hash
        NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
        Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>: ArrayLength<u8> + Add<OutputSize<CS::Hash>>,
        Sum<Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>, OutputSize<CS::Hash>>: ArrayLength<u8>,
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
    #[cfg(feature = "p256")]
    inner::<P256>()?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>()?;

    Ok(())
}

#[test]
fn test_zeroize_server_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<CS::Hash>>,
        Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
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
        Zeroize::zeroize(&mut state);
        for byte in state.serialize() {
            assert_eq!(byte, 0);
        }

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>()?;

    Ok(())
}

#[test]
fn test_scalar_always_nonzero() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        // Start out with a bunch of zeros to force resampling of scalar
        let mut client_registration_rng = CycleRng::new([vec![0u8; 128], vec![1u8; 128]].concat());
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut client_registration_rng, STR_PASSWORD.as_bytes())?;

        assert!(!bool::from(
            CS::OprfGroup::identity().ct_eq(
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
            CS::OprfGroup::identity().ct_eq(
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
    #[cfg(feature = "p256")]
    inner::<P256>()?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>()?;

    Ok(())
}

#[test]
fn test_reflected_value_error_registration() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
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
    #[cfg(feature = "p256")]
    inner::<P256>()?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>()?;

    Ok(())
}

#[test]
fn test_reflected_value_error_login() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<CS::Hash>>,
        Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
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
    #[cfg(feature = "p256")]
    inner::<P256>()?;
    #[cfg(all(feature = "x25519", feature = "ristretto255"))]
    inner::<X25519Ristretto255>()?;
    #[cfg(all(feature = "x25519", feature = "p256"))]
    inner::<X25519P256>()?;

    Ok(())
}

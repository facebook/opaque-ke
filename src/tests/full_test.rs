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

#[cfg(all(feature = "x25519", feature = "ristretto255"))]
struct X25519Ristretto255;

#[cfg(all(feature = "x25519", feature = "ristretto255"))]
impl CipherSuite for X25519Ristretto255 {
    type OprfCs = crate::Ristretto255;
    type KeGroup = crate::X25519;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

#[cfg(feature = "x25519")]
struct X25519P256;

#[cfg(feature = "x25519")]
impl CipherSuite for X25519P256 {
    type OprfCs = p256::NistP256;
    type KeGroup = crate::X25519;
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

// To regenerate, run: cargo test -- --nocapture generate_test_vectors
#[cfg(feature = "ristretto255")]
static TEST_VECTOR_RISTRETTO255: &str = r#"
{
    "client_s_pk": "462bcbb0f1f303eaa919ab66e5c19a94052b84e2cbc40645cde46df2a68b0c7a",
    "client_s_sk": "d2b04e26c274b67ec381dad0a4ddaa72801cc41ff53e94262a8bc817c9491304",
    "client_e_pk": "febdfdb6a812769e8c63f013ddda42e0ca0d5a388136241d9bd8059bc7933051",
    "client_e_sk": "fb61820e78aa5512f0da07d231c6644a8111fd4c72561b7329e72e6e5c848005",
    "server_s_pk": "58f645872da0f3f487584dea46be982c1557b9d392422c4795e48ce05d5b374d",
    "server_s_sk": "7df714f8df702dad7d38a714e58fb18820d2da1c41e3252e961a70566fac2f0e",
    "server_e_pk": "089dd523fa969d424e7d5e2af4f9c712cb02f47173a8381db4c7fc69ad10b362",
    "server_e_sk": "b3a1709e4c291d9d727822e148346aa192d29575c33362d33d457bdc0e13cb06",
    "fake_sk": "844666460d91813f25f07ee484ff9ec7cd9eacbd55f462a93b0da868f39ea70d",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "2189fa0524efc945e096e591acaf741c6af03ea514e3c9aea44ad7a56847be03",
    "oprf_seed": "5e162cd641cfb826427569ec676b43bf038e1274b0d9bdd4cb76ac56f8472fd538e7ac4e34702325a3daaf3609f3a7246f6673bc5caaeca02c067aa8ede3f8dd",
    "masking_nonce": "b98330c71a2d82674dea6e0aa7cb18087de3883295fcd0ff6c45cd80a4681eba8f5562ac122850ec933455c3c6c25f42138bb425d591cb38bd765f53b7a01b96",
    "envelope_nonce": "423b6c1c4666ed8f8640d59bc165783709b36c9b4ae1b42a547ae351b5d57d05",
    "client_nonce": "1189d05e799fa6c56d9d72a7a8c93b891ed35736010f71eb64cf1220ce27c338",
    "server_nonce": "a218c4e22ea27ba74f8cf3f09fd428d6587897d76f6f5b4a63d3e0cb6e299ae3",
    "context": "636f6e74657874",
    "registration_request": "ec3f63d15a8959e86f5664d4c409b71a4993e1d49fcd6ee51ad9f983220e3237",
    "registration_response": "3ee77a8a4d491f9fd746ddc536f5e5bbc2898067263a3b34e1e591b783462c4a58f645872da0f3f487584dea46be982c1557b9d392422c4795e48ce05d5b374d",
    "registration_upload": "40c78fe33dd3a50c99bcbaf260c790c63b192f8fdab6777ade1c4b16d8c5381840c62980f9a3931f4d0c68ddece8b87d3bf4d4a56ccb4a0b88af37cbd457dd5ab2b8c633b898e7a8e18b024090894615363e039055fe735da12ba9cc68d4f982d2b04e26c274b67ec381dad0a4ddaa72801cc41ff53e94262a8bc817c9491304d9eafd0bacdc61e6da750116fd9388a65e2a574934f65d2e957d8d05e1d4d4ee9c23a87d8d60e93936da683363469b5c0bf234891204cd93f84ec8531fc32acc",
    "credential_request": "ec3f63d15a8959e86f5664d4c409b71a4993e1d49fcd6ee51ad9f983220e32371189d05e799fa6c56d9d72a7a8c93b891ed35736010f71eb64cf1220ce27c338febdfdb6a812769e8c63f013ddda42e0ca0d5a388136241d9bd8059bc7933051",
    "credential_response": "3ee77a8a4d491f9fd746ddc536f5e5bbc2898067263a3b34e1e591b783462c4ab98330c71a2d82674dea6e0aa7cb18087de3883295fcd0ff6c45cd80a4681eba6942d2635f21656760a29dd64fc0d7eb2202eacd698993203e2b93ed69a904ea555e62c861ed0b05c61f5f9dbc80cf4a68f7788e5ab423fd707a25eb985e0f206a66d41514f40dd3afed0c0f5d33cc86072df0a6c0bb95a1f7acb2a195451795133fef323da255177d94dd9f338f4727e2ec464c895edd1891f4ca28e005fa86b3a1709e4c291d9d727822e148346aa192d29575c33362d33d457bdc0e13cb06da2bd185020cd964cf518873336f2f00a0440a975e8ff1e29912770d415d0c1747e79bae72037aabe86af57181b4f9d3964061da83e60b6a216becb025cbd805c52ecf6ed69b44a7309bd643ceb37a926459b8b2dd9dded7fc2daf58a72b789e",
    "credential_finalization": "8240d4d8bde9bd911581b7c3d48d760368add71d789f7917b7f3b97f12ba88fb1dd8a99e301ef5716e1baf76b0f374c41c4bce2b9a015d49fa0c6e305196e3bd",
    "client_registration_state": "2189fa0524efc945e096e591acaf741c6af03ea514e3c9aea44ad7a56847be03ec3f63d15a8959e86f5664d4c409b71a4993e1d49fcd6ee51ad9f983220e3237",
    "client_login_state": "2189fa0524efc945e096e591acaf741c6af03ea514e3c9aea44ad7a56847be03ec3f63d15a8959e86f5664d4c409b71a4993e1d49fcd6ee51ad9f983220e32371189d05e799fa6c56d9d72a7a8c93b891ed35736010f71eb64cf1220ce27c338febdfdb6a812769e8c63f013ddda42e0ca0d5a388136241d9bd8059bc7933051fb61820e78aa5512f0da07d231c6644a8111fd4c72561b7329e72e6e5c8480051189d05e799fa6c56d9d72a7a8c93b891ed35736010f71eb64cf1220ce27c338",
    "server_login_state": "4d72816b73b51d687b129808e5eb2bba359da1ed16c4422f66ea240fa64019a494c119e432a05e6c73f6e5b09e460cf46d321547003c1f1d1d31f58b77b366b4a3f58ad498a297b3d1e00d90e9c0dad467219542bd1e9c79418669ea759b981968b475818fdfa415faea89e01be55f7a7dc63d8bc2a0f146da08410c8f2e2ae6866d64ba0fcd85ab9377f367428a16813f43e042d7da9f499847a6cdc5718f5e39cb0cd74bc6ed73e709f21d567e9506acc1dbec8881cc7bf4995306df3ac7d9",
    "password_file": "40c78fe33dd3a50c99bcbaf260c790c63b192f8fdab6777ade1c4b16d8c5381840c62980f9a3931f4d0c68ddece8b87d3bf4d4a56ccb4a0b88af37cbd457dd5ab2b8c633b898e7a8e18b024090894615363e039055fe735da12ba9cc68d4f982d2b04e26c274b67ec381dad0a4ddaa72801cc41ff53e94262a8bc817c9491304d9eafd0bacdc61e6da750116fd9388a65e2a574934f65d2e957d8d05e1d4d4ee9c23a87d8d60e93936da683363469b5c0bf234891204cd93f84ec8531fc32acc",
    "export_key": "4072224aa93c097b12d3bfe4df74ddb337d2424c8e63881a0feaadb1dc1e856e32420893c1d136c7abc6faf55d464bb1669dad232c038c145c6edeb1b723a557",
    "session_key": "866d64ba0fcd85ab9377f367428a16813f43e042d7da9f499847a6cdc5718f5e39cb0cd74bc6ed73e709f21d567e9506acc1dbec8881cc7bf4995306df3ac7d9"
}
"#;

static TEST_VECTOR_P256: &str = r#"
{
    "client_s_pk": "023260fcb7915e53cdd3a1164c3fbb02105669f6652fc7f04afbee9c41fc70e6ce",
    "client_s_sk": "dfa3fccf6ef36714a1dcf5085c38a3f007842579bc3bede124e0dfd994f173c0",
    "client_e_pk": "02af274d7a94c8e33e8c374e39991ab7fe078c87cdaa1a0334ad33b8308cae1298",
    "client_e_sk": "62b5b89b4daac1e2db00d12a993c18af4f69083526c51f4428ec9072264e5184",
    "server_s_pk": "03baaee6e122a55c05860cae3795e6662a879e8308983fe55905dbe363883a0e4a",
    "server_s_sk": "df3a9c42ef25ac2319c5fa32e4ed124ef8f829c890ac1eb4abb3c2cd3b0fa071",
    "server_e_pk": "022361f1cce383b29175f58673b2f9f941234b63709b621bcc7097c0b62e20f758",
    "server_e_sk": "3f822df5e690807c585bc42e1ca604770c2f9bbd017d366561d8de90e06628dd",
    "fake_sk": "f7c75629f0fc954d321b186c2a8a1e8230735ec90a86c96435d740533f9de641",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "c4eb21db1dbcac484e768fed47395a8274efdf7a6bb0b51650158a4f20fa9962",
    "oprf_seed": "9cbb7e45eca257600aee9f80a73999f6a043464ef8373ff05692a2c2a78ad7e9",
    "masking_nonce": "75980b06670edc94d3bec1cd50a234b5ae5a80ab0d35751d088db4bc716f7749f116e9de81908f5c552b89311aeb14f39e83edfc72c675898aebb33f670c47c5",
    "envelope_nonce": "f7c268c385a2357f9bdc375e2ed01b14ed8a4d5da7f73a7637a1e1d1b870d5aa",
    "client_nonce": "5e91a3321f75b640d8fc8fb8087d7207e5c45b2b63d1fb9a111797ace5973509",
    "server_nonce": "59320205db3abe90453078cd87defdca26ed9106c87e86b23b3d973ce493e74c",
    "context": "636f6e74657874",
    "registration_request": "03efeab933855855df6309184b1f38e72253a30da135e8a5247f487e84da0e2038",
    "registration_response": "038208b3367f5f2037ebe633a3a496ca91253b51ddf3da27ce160aa32cadd894f003baaee6e122a55c05860cae3795e6662a879e8308983fe55905dbe363883a0e4a",
    "registration_upload": "02bdac72f70ee3dec77c6f827a74262c35d166f0f219dc34990563a791cfa6d52e6fe49ac269f3f0ff9ff149827df28a706651d47d83587642ec1d26cb94eb8921dfa3fccf6ef36714a1dcf5085c38a3f007842579bc3bede124e0dfd994f173c04982a39a7878cac19db2bfcfc20e7e523ff07d29a77c12def7eece9ed0489d01",
    "credential_request": "03efeab933855855df6309184b1f38e72253a30da135e8a5247f487e84da0e20385e91a3321f75b640d8fc8fb8087d7207e5c45b2b63d1fb9a111797ace597350902af274d7a94c8e33e8c374e39991ab7fe078c87cdaa1a0334ad33b8308cae1298",
    "credential_response": "038208b3367f5f2037ebe633a3a496ca91253b51ddf3da27ce160aa32cadd894f075980b06670edc94d3bec1cd50a234b5ae5a80ab0d35751d088db4bc716f774974578203a277492803925adc16a48d007b69fc31f4c48efefd43b81280bfb3cab9abf5fa0156d12191811f948ac311e0279f47279ceba64c46bfa12f4cc0fb99364395e6d57307c00ba4b1330d98b85db8a8e09729ef79376e40a8adc1428da58e3f822df5e690807c585bc42e1ca604770c2f9bbd017d366561d8de90e06628dd0226810c8030327817b74d2d3a05be5ff4966b16912a372e8d2722c24c14121ec21024966125998398c81fdfc25b8018a8ee641f485663996ef336c4521b85f6e7",
    "credential_finalization": "b32b0472968a844fb681f4a1ac61e33763d74d39b711db71b8f5d27e90e271f8",
    "client_registration_state": "c4eb21db1dbcac484e768fed47395a8274efdf7a6bb0b51650158a4f20fa996203efeab933855855df6309184b1f38e72253a30da135e8a5247f487e84da0e2038",
    "client_login_state": "c4eb21db1dbcac484e768fed47395a8274efdf7a6bb0b51650158a4f20fa996203efeab933855855df6309184b1f38e72253a30da135e8a5247f487e84da0e20385e91a3321f75b640d8fc8fb8087d7207e5c45b2b63d1fb9a111797ace597350902af274d7a94c8e33e8c374e39991ab7fe078c87cdaa1a0334ad33b8308cae129862b5b89b4daac1e2db00d12a993c18af4f69083526c51f4428ec9072264e51845e91a3321f75b640d8fc8fb8087d7207e5c45b2b63d1fb9a111797ace5973509",
    "server_login_state": "b6ac93a918062c080a4b1de8fd268294c6bd94bf4a7858c73307816abaaa6ac1316f2c7fa3580a84d4e8d0f7f5985ba2b4b655c0a190d3810f5c5ffe3db178cab8e1bf50c444bae5ed713df3460eaa2987fb378a4a7eda0a2b426636ce34a797",
    "password_file": "02bdac72f70ee3dec77c6f827a74262c35d166f0f219dc34990563a791cfa6d52e6fe49ac269f3f0ff9ff149827df28a706651d47d83587642ec1d26cb94eb8921dfa3fccf6ef36714a1dcf5085c38a3f007842579bc3bede124e0dfd994f173c04982a39a7878cac19db2bfcfc20e7e523ff07d29a77c12def7eece9ed0489d01",
    "export_key": "0a3f9daef4c6ce2d7853b140bca06b89288f45c90a68697ad4f5f65181838ac7",
    "session_key": "b8e1bf50c444bae5ed713df3460eaa2987fb378a4a7eda0a2b426636ce34a797"
}
"#;

#[cfg(all(feature = "x25519", feature = "ristretto255"))]
static TEST_VECTOR_X25519_RISTRETTO255: &str = r#"
{
    "client_s_pk": "fd9421aabf489c202c0c73692d191e8f90dd9c3d33d8f9d7098b68037a0d7018",
    "client_s_sk": "743049eab865ebf6bd680586629c99bb27350c391a8badd2cd3072046ccf7909",
    "client_e_pk": "3d6ea92c272d085a4343ef0057938f0049a01716d263539a2ce11b00d8776767",
    "client_e_sk": "2320c9b2022c31960dee0081793d7e2192d88d62b91279ecb23090381017770a",
    "server_s_pk": "86fc83e93faefe37539af2c66f283de69589496b9c24c1afeade5293548beb51",
    "server_s_sk": "7a707d042be8b8572e22553d37c5956b0ab1bfa4ee11e35b54b70915638aa60a",
    "server_e_pk": "83e5937afa666054f398733915dad7e0fed785e97eb1a6d4a869368a7225e32e",
    "server_e_sk": "f0dbcb5c09a2083ee0b4d829a60c9b08a802ccb963a7b4903bc16d7152641f02",
    "fake_sk": "9c76aea51fcc052fb3f34f27f70a3a8fbf63788d156e4e0c0a7d625865f34b05",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "c54a7234fcc8eda29e08c80a0c3062cfa42725a7befc0038be5c9447082c300d",
    "oprf_seed": "39ee741b2d1286785db8f020da65495dd49676c74fd6060e9bad6365a006294399a91cf7d89e52133fec92243794667fef7a41c50fd41b269d2c7bb7c2caf118",
    "masking_nonce": "4b1c8057992d51b72890e653ae56ca2f5a2c2fb983c61a25084bcb0c42ef50a310e290e0e25f4026e29ce78ba72d4e617acefd30d439c120209c1e9f3394fe51",
    "envelope_nonce": "f686b0b38da88128bab866bb8a271491fe4d31f7f6c468b2410b3f7d13f81c21",
    "client_nonce": "66681cf8abba1f60f4b45c4df681f053af152c85afd070a87ea0963c82208fba",
    "server_nonce": "2b7b31d669643feaaa398f9107b3cc31ccf8059c260364d02f81af5609c253da",
    "context": "636f6e74657874",
    "registration_request": "947c08180d7ee11962a475408e34db1cf36153ad565efbaaa2003c8ddb873742",
    "registration_response": "22db969f065d6270719d52678b3b5a8505df865347befe4a2ca23c305698375886fc83e93faefe37539af2c66f283de69589496b9c24c1afeade5293548beb51",
    "registration_upload": "811c9b5fff64f79dd1c58230f6afd5686b64aa2bf2645e53efcbce5258c5e501dae567fe81428ed227caf290d4286806733fe4b28373cdf98f75cbee2a26a285d51289636e0277b8b547a12c4444d6c138ad1f312e290d8cb268392cdc532557743049eab865ebf6bd680586629c99bb27350c391a8badd2cd3072046ccf7909099d944a610d38ef9a48314cc6cf4bc7eb336a12eac42e4cf21db2b05bd09bf2e82f1c63396804455281cc67d85cb95301024104b911362c14a3d3c03bdcc897",
    "credential_request": "947c08180d7ee11962a475408e34db1cf36153ad565efbaaa2003c8ddb873742c54a7234fcc8eda29e08c80a0c3062cfa42725a7befc0038be5c9447082c300d62de25755c11a72834d1aba572e3efcce0ba30924ad487ff996e287e78196916",
    "credential_response": "22db969f065d6270719d52678b3b5a8505df865347befe4a2ca23c30569837584b1c8057992d51b72890e653ae56ca2f5a2c2fb983c61a25084bcb0c42ef50a3c3db1e1b9843739d36c04702c4701316815f52f3df2bf7fab1aab7adbaf8491e8b5b7dafb6e4db3f9a5c76c3eea24ecd81ed430f47f0b67cb78048462f9816b376feb3d77a907c2839f05ae7cd770524e77672294d9d91e648137ae9f87c8a923a2181e19fb231ffc11a2c530536193675a977b9d8e3ca2f20272194ec79cb8a2b7b31d669643feaaa398f9107b3cc31ccf8059c260364d02f81af5609c253da5df4034fc05556580243652e4ca2beaf23d710299ddfb55545930e3a474bae44edd162d8c4de17bd7a345dc5976f3a48e15865963785b013e91d0def39058a1f4525d88367fad2a74e3b9e7651966b7b16decaa585b67086bab580d6924b3933",
    "credential_finalization": "d6a968e5ef62448d4fab1ee40e4e719e56e2977c5f43ecfe6cabdbbf7c66df0cb9e2e5ecba7d69b2cd78ca6707a23bc243f38385ef08b03ac29299b2c810011c",
    "client_registration_state": "c54a7234fcc8eda29e08c80a0c3062cfa42725a7befc0038be5c9447082c300d947c08180d7ee11962a475408e34db1cf36153ad565efbaaa2003c8ddb873742",
    "client_login_state": "c54a7234fcc8eda29e08c80a0c3062cfa42725a7befc0038be5c9447082c300d947c08180d7ee11962a475408e34db1cf36153ad565efbaaa2003c8ddb873742c54a7234fcc8eda29e08c80a0c3062cfa42725a7befc0038be5c9447082c300d62de25755c11a72834d1aba572e3efcce0ba30924ad487ff996e287e7819691621328157ed777d9ed99dc915e9c05aef779537e93ec33b859592c3167d317509c54a7234fcc8eda29e08c80a0c3062cfa42725a7befc0038be5c9447082c300d",
    "server_login_state": "225c04cdf34d68b6a5e328da6d0820f831c0a6747359ba04f5c363a590c2881125c94cfcbb52dedb23e63c67a29889925dd8d14570a060570b7d1f599730ad9d6693aea75639e20b161f0b814cfacefbb0ccfb294c04c7fef55f7515fa75f11ae56d6649219048c3d307cf026e4b9d88afa0db5779243437d05202b01b46b4a5fcb72639f47ce5017784bb1cf5a95ea2aa10f4071fc83eca962424086d0dd4df2fd315e39ac6f95795dd47fb8b6df8749e049fcc6065346b615c7732ac917d89",
    "password_file": "811c9b5fff64f79dd1c58230f6afd5686b64aa2bf2645e53efcbce5258c5e501dae567fe81428ed227caf290d4286806733fe4b28373cdf98f75cbee2a26a285d51289636e0277b8b547a12c4444d6c138ad1f312e290d8cb268392cdc532557743049eab865ebf6bd680586629c99bb27350c391a8badd2cd3072046ccf7909099d944a610d38ef9a48314cc6cf4bc7eb336a12eac42e4cf21db2b05bd09bf2e82f1c63396804455281cc67d85cb95301024104b911362c14a3d3c03bdcc897",
    "export_key": "cd38ef9ca81fb3bdb6ae0c9ace0a3574755030a89a6a104d55f2066d81d5fe64089a7d73e06c3c00adabbc1ed755426fd4d04aee09023b111e1224487738cbac",
    "session_key": "fcb72639f47ce5017784bb1cf5a95ea2aa10f4071fc83eca962424086d0dd4df2fd315e39ac6f95795dd47fb8b6df8749e049fcc6065346b615c7732ac917d89"
}
"#;

#[cfg(feature = "x25519")]
static TEST_VECTOR_X25519_P256: &str = r#"
{
    "client_s_pk": "753ed6bb950b75a9070b13ef93b4dcc99919addb4b6bcceb1f843e902b078a74",
    "client_s_sk": "e49b6199b4fee342db063928a80d1a2f129d7402f70a00615e349a5bc7402109",
    "client_e_pk": "27c883a8e09ed4f8854e8a4d788c79f947e7ef7d9508294a3c93394f39daff4b",
    "client_e_sk": "ea9695fedac154e8432b3b7d3da908b2e594e5eccbf53b29e94492312aaa630f",
    "server_s_pk": "66369d74ab45914fb8fc53520b6915561ce2c3a14c93adb2bf5cdf714feace76",
    "server_s_sk": "093c818970ed2f9056a6a29cc4683c4c5f8bda343cdd891c99ecb63ba11f2001",
    "server_e_pk": "6576ff437de71bdcc39dd78fceec0bc7afb0ad1f10e1b0f991795c996daead78",
    "server_e_sk": "2da54527ace3bfa2a79dd6dfe8e24d814e9f4c3d888ee1b1eae80435eb03ad03",
    "fake_sk": "fbc4817729c76924c0f2a254856d56ef58616e8366a512d51145e5d6bab65609",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "18a4203efc82b58ba0931b86966fb32c2ba9fefb8b20f53d2cf2e8eb3cbef538",
    "oprf_seed": "9a17b1000c68e3b3befe6f2461c327435fdfaefcbce3945e3898002591cc200f",
    "masking_nonce": "a55af67cbd406f7e8629bb563890fd0e031efa9ea179b423cd05d475444485053f682c99350fb7b96b564d7e8ef27c3ae2c282f5a60008f18caf3274ca69aab7",
    "envelope_nonce": "3ee31dcd5be16563a1be31c1916d813fbb2df6e7a8174de9fbe970268a38f1ff",
    "client_nonce": "2d8c52a01ddb0afe916fa6320ac924fdafd3a086dd15d7d8b8b849e1a6b5598c",
    "server_nonce": "c2c4292207fdb5c70a083ffa3265665b47320f49e5830213fc0a7be465e250ac",
    "context": "636f6e74657874",
    "registration_request": "029ea801c63cfef8082b9d90bec2bc73223ffbb58a4efafc92a558758cc6499007",
    "registration_response": "02cb947d77ba412d051844f71c0e3f3ea76f37675986c224b8c3cc98d3c15901e966369d74ab45914fb8fc53520b6915561ce2c3a14c93adb2bf5cdf714feace76",
    "registration_upload": "c87c3864bf4d08de1dcb54e391861e6c9a3952ce32138437b97ca8ba7ecce17da4199e5b514468f8ca0df74939ab0882b29494e6719e5f82aca17b1b473d4cbae49b6199b4fee342db063928a80d1a2f129d7402f70a00615e349a5bc7402109ae22d994c188e1f074d36667f86328a2846d36b02d439cece7ffe513d943b008",
    "credential_request": "029ea801c63cfef8082b9d90bec2bc73223ffbb58a4efafc92a558758cc649900718a4203efc82b58ba0931b86966fb32c2ba9fefb8b20f53d2cf2e8eb3cbef538a7b8272a9235017ef28a8b2dc55e75eb509b4687834a84d8502d5223e0213a0e",
    "credential_response": "02cb947d77ba412d051844f71c0e3f3ea76f37675986c224b8c3cc98d3c15901e9a55af67cbd406f7e8629bb563890fd0e031efa9ea179b423cd05d475444485053dc3294947f945d405b034c8381df98395567633d32c373b3ef38382e8edc453b2adf3be2ca9c6397e2ad4a835493395d9c04a5b2185ae18bfd9e11301c3cbf2b613048a9cbe81fcc0e1bc558f8975e26769ae243b0c279e744b8891020b4fa2c2c4292207fdb5c70a083ffa3265665b47320f49e5830213fc0a7be465e250ac0fd0d98ac8aa06c6bf1e30acf462fcb2f5fdc12b39a8606609a9ca49f751413b7bee901e53032e54ac992da96a1d181ccf5af5c99ba3097454c5f0ef3c390414",
    "credential_finalization": "149fc8cea95f8691c4a5a5c23c5fa7dfc374359ff387a1f0818a9781e03d5572",
    "client_registration_state": "18a4203efc82b58ba0931b86966fb32c2ba9fefb8b20f53d2cf2e8eb3cbef538029ea801c63cfef8082b9d90bec2bc73223ffbb58a4efafc92a558758cc6499007",
    "client_login_state": "18a4203efc82b58ba0931b86966fb32c2ba9fefb8b20f53d2cf2e8eb3cbef538029ea801c63cfef8082b9d90bec2bc73223ffbb58a4efafc92a558758cc649900718a4203efc82b58ba0931b86966fb32c2ba9fefb8b20f53d2cf2e8eb3cbef538a7b8272a9235017ef28a8b2dc55e75eb509b4687834a84d8502d5223e0213a0ebcb52188b5c59f7a62b5a3cbaa4d91df52f62dd508802d3813192fb933dcbe0218a4203efc82b58ba0931b86966fb32c2ba9fefb8b20f53d2cf2e8eb3cbef538",
    "server_login_state": "62719f8b13444f9cb407ba8588221a4ccadab4e23bd9b53562982b70c10dd76549f8e5e06f9c67dda3b2cbbc04e611251114d0ec75814448ec31735e256de8375661696067914036a03e84148db7dc7cb80a119b76b1a4b1cacfae8a51261cde",
    "password_file": "c87c3864bf4d08de1dcb54e391861e6c9a3952ce32138437b97ca8ba7ecce17da4199e5b514468f8ca0df74939ab0882b29494e6719e5f82aca17b1b473d4cbae49b6199b4fee342db063928a80d1a2f129d7402f70a00615e349a5bc7402109ae22d994c188e1f074d36667f86328a2846d36b02d439cece7ffe513d943b008",
    "export_key": "d01fdced2b0342d693da9290e6a8d3fe4aa5ff5bacbdced310fb137ba95e7349",
    "session_key": "5661696067914036a03e84148db7dc7cb80a119b76b1a4b1cacfae8a51261cde"
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

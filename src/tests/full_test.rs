// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

#![allow(unsafe_code)]

use crate::{
    ciphersuite::CipherSuite,
    envelope::EnvelopeLen,
    errors::*,
    hash::{OutputSize, ProxyHash},
    key_exchange::{
        group::KeGroup,
        traits::{Ke1MessageLen, Ke2MessageLen},
        tripledh::{NonceLen, TripleDH},
    },
    messages::{
        CredentialRequestLen, CredentialResponseLen, CredentialResponseWithoutKeLen,
        RegistrationResponseLen, RegistrationUploadLen,
    },
    opaque::*,
    slow_hash::NoOpHash,
    tests::mock_rng::CycleRng,
    *,
};
use alloc::string::ToString;
use alloc::vec::Vec;
use core::ops::Add;
use digest::core_api::{BlockSizeUser, CoreProxy};
use digest::Output;
use generic_array::typenum::{IsLess, Le, NonZero, Sum, Unsigned, U256};
use generic_array::ArrayLength;
use rand::rngs::OsRng;
use serde_json::Value;
use subtle::ConstantTimeEq;
use voprf::Group;
use zeroize::Zeroize;

// Tests
// =====

#[cfg(feature = "ristretto255")]
struct Ristretto255;
#[cfg(feature = "ristretto255")]
impl CipherSuite for Ristretto255 {
    type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
    type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = NoOpHash;
}

#[cfg(feature = "p256")]
struct P256;
#[cfg(feature = "p256")]
impl CipherSuite for P256 {
    type OprfGroup = p256_::ProjectivePoint;
    type KeGroup = p256_::PublicKey;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha256;
    type SlowHash = NoOpHash;
}

#[cfg(all(feature = "x25519", feature = "ristretto255"))]
struct X25519Ristretto255;
#[cfg(all(feature = "x25519", feature = "ristretto255"))]
impl CipherSuite for X25519Ristretto255 {
    type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
    type KeGroup = x25519_dalek::PublicKey;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = NoOpHash;
}

#[cfg(all(feature = "x25519", feature = "p256"))]
struct X25519P256;
#[cfg(all(feature = "x25519", feature = "p256"))]
impl CipherSuite for X25519P256 {
    type OprfGroup = p256_::ProjectivePoint;
    type KeGroup = x25519_dalek::PublicKey;
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
    "client_s_pk": "7ebcdedff3f85d655a8125fc47a6f36690b136b5b7709855d285ee82afd1b378",
    "client_s_sk": "8a415e955c9fa050db9d05771f682964757ea447b50776381115f7be021f8803",
    "client_e_pk": "a4c51f00ccfe015c8e7c5ab796c0b16ca585dedc103cd2b2e9ceb787c2c9fc07",
    "client_e_sk": "f8be9d08044e44e5f881234135bcf24ea0c80f54c7319480f37f3fadfa2c420c",
    "server_s_pk": "1cdee00ea6617b06c423ac8a6b0c332f953bf085a3bfa4f8c8170e4d9f260f1b",
    "server_s_sk": "49696b9d4c8d6143fcc6444437210fa3e3c602f0379fcce5d267e66cf7ef7a09",
    "server_e_pk": "b80463806ca903964436214f2373d94a9b4a15bb2ef7f6ffacd40237a8324549",
    "server_e_sk": "05bba963634348852262cf8510daa85e1c5d9677e8a124fb9c96c6888663ca06",
    "fake_sk": "dfd81e92f213dcc4311b9a4a191c5ed41cfb0db06ce0d7b6aa11a2157f347c0f",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "00cf35388a20eb5fc4f574fcbe5157eddb08955fd035e9339271f9f2e7a8e00c",
    "oprf_seed": "7af88d6bb52f5e85ab246682d031170bc3bdba958b81dd011e93b6cb3a730ed73ed677d0efd7814b78ae97249ec14276756a47bcd8b300f341785495c2feb3fc",
    "masking_nonce": "560c0f0a47e4629ceb215c386e71a5206824f38568946152e464f52007252d43270f8f5d4cc3fa0a35532794403e726042f6ebf7341452c01706e56d6acbcd4e",
    "envelope_nonce": "2dad0f495e212b5effd57d11c366829990d417314967504e4ea9e279e2de2215",
    "client_nonce": "03de3557f48dd52f5dcd79301b28b75dbaaed0890e8a08007922e0111ea2d68a",
    "server_nonce": "c70bfa05cf16ebfd9783b550400fd6b64c1767bf3d5a05ff6933c44e669c5119",
    "context": "636f6e74657874",
    "registration_request": "3277cb1711244616ea8adbe2653fbd68ef9c05985df9ad81e81154eb4598d209",
    "registration_response": "2276444e5e9b946725779f47e8954a148476021d7f71334b9099a6e7c86ead561cdee00ea6617b06c423ac8a6b0c332f953bf085a3bfa4f8c8170e4d9f260f1b",
    "registration_upload": "d446929e9559d4baaebe013b5b122892a32784e197e95e0710a3f7d87bb73c122b4487c56bc3d12e080db368afd8d3f8fe72c3d3de446a2e11d6124c7fbdecedd2ae4d29f63b16b92406c845f525a817c9a1ee19525e5ad15204f56ec5fe61bf8a415e955c9fa050db9d05771f682964757ea447b50776381115f7be021f880396d445d281e5e3b83555b40f7bef6e43c553c1c6064f88e1e76de861339dc492dbab1f60450fd8d869561888d426d6f9beb21d51a2ac7ed0e14d8e13f09a4581",
    "credential_request": "3277cb1711244616ea8adbe2653fbd68ef9c05985df9ad81e81154eb4598d20903de3557f48dd52f5dcd79301b28b75dbaaed0890e8a08007922e0111ea2d68aa4c51f00ccfe015c8e7c5ab796c0b16ca585dedc103cd2b2e9ceb787c2c9fc07",
    "credential_response": "2276444e5e9b946725779f47e8954a148476021d7f71334b9099a6e7c86ead56560c0f0a47e4629ceb215c386e71a5206824f38568946152e464f52007252d4335e4a5a3de4e7ee06d3e2365b9d25a2ff13d72651e042e75c635443eb923d607ba071b23e0f6bea1b33cfe25332c4e00d1dc2cc849b382a09cb743ab3aa48a6d60fc16a22f24684ed52dc4113d55c1a75789a9c57b39016f0bd2f38fd47c00929c5cedde147cf58c2a2707bbba14a2d7b3b2aeb39df038ab2c1415398f877c3705bba963634348852262cf8510daa85e1c5d9677e8a124fb9c96c6888663ca060a2ae5e4278f4e8f0957e681a1ff6cad0c1ef0b0c8c3b03191877350662bd940ba9653099777f6c760c41e7ebc8b6b1af38387be9d108d694027a73f61869e008e1cb4629a7c3b588c0514bc97ef0ed662e58589723f390dea6578d43e04e05f",
    "credential_finalization": "b452e46d4922e2a8f49c79653efcf4ec5b9a2dc019b491e0a80dddd7e8d57f835e0bdde192d4d3fbcabdff616e551906a3a992afa75f347e56063d192972c409",
    "client_registration_state": "002000cf35388a20eb5fc4f574fcbe5157eddb08955fd035e9339271f9f2e7a8e00c00203277cb1711244616ea8adbe2653fbd68ef9c05985df9ad81e81154eb4598d209",
    "client_login_state": "002000cf35388a20eb5fc4f574fcbe5157eddb08955fd035e9339271f9f2e7a8e00c00603277cb1711244616ea8adbe2653fbd68ef9c05985df9ad81e81154eb4598d20903de3557f48dd52f5dcd79301b28b75dbaaed0890e8a08007922e0111ea2d68aa4c51f00ccfe015c8e7c5ab796c0b16ca585dedc103cd2b2e9ceb787c2c9fc070040f8be9d08044e44e5f881234135bcf24ea0c80f54c7319480f37f3fadfa2c420c03de3557f48dd52f5dcd79301b28b75dbaaed0890e8a08007922e0111ea2d68a",
    "server_login_state": "7735737f2b6a9933f2f727167d7fd1d68f055404aab302f63331708b01f92fbf4dae2d1872b2fd778b5eb314820582ffb37e5f8a56aadd0237b1e88b19b03a5c53a5b627b7c330ce6a14ac13afb78e8de0c0a7d7b1e743e41c04f7556ab20407c6e3ab2f9a7f7163e39ec5944b011977c81c3918cff5da193307016c921a0b2efa8f52170ea42318fe54cb945ca833e163b9c8ed6bbb37d13f4dd89351be7141b88c04b8cc5ad31caa8e59468f50d30eb54e5d776e4bd4a6d6ce65f5e187e6fa",
    "password_file": "d446929e9559d4baaebe013b5b122892a32784e197e95e0710a3f7d87bb73c122b4487c56bc3d12e080db368afd8d3f8fe72c3d3de446a2e11d6124c7fbdecedd2ae4d29f63b16b92406c845f525a817c9a1ee19525e5ad15204f56ec5fe61bf8a415e955c9fa050db9d05771f682964757ea447b50776381115f7be021f880396d445d281e5e3b83555b40f7bef6e43c553c1c6064f88e1e76de861339dc492dbab1f60450fd8d869561888d426d6f9beb21d51a2ac7ed0e14d8e13f09a4581",
    "export_key": "839f3da6c08d4be3db8c07ab92d1b374fa247f4de4ca204fdbe075e539e7ab0e0814506417ce6b2257487472fbc87f32704c5bc18872b6cd9693245a7d9d060f",
    "session_key": "fa8f52170ea42318fe54cb945ca833e163b9c8ed6bbb37d13f4dd89351be7141b88c04b8cc5ad31caa8e59468f50d30eb54e5d776e4bd4a6d6ce65f5e187e6fa"
}
"#;

#[cfg(feature = "p256")]
static TEST_VECTOR_P256: &str = r#"
{
    "client_s_pk": "02cfdf8d73ff6923f64367e5d47ecb0d4ec235e9ac5c37a2eeba2965d288e4379a",
    "client_s_sk": "133536d17f9f606be08764749eb56faea117d3bbaaed858b044180b363dcdfeb",
    "client_e_pk": "036d56181f0b67f7c6c55f1905072eca62bc081eada24671cfe6a30895e18c86fc",
    "client_e_sk": "89e0d6a457895418b46f6e90c389d6fbe6d08fcd144a23a0f3aa7cc435989c76",
    "server_s_pk": "02072fc775218863509d8608972333f0f3ce15e3b8c64029bb329268fc735c169b",
    "server_s_sk": "b6c15cf376230cca2640a9b6a56afd9a410f50f0d4646a910a74ee9773d11d69",
    "server_e_pk": "0206fe7ff5c1820514068d1f50811c2ac6f29c620ec632f40768eb6f3bc99a235c",
    "server_e_sk": "4492467b6128c25074c27b43fc3c2cd1a0680fcdadd6a215919ff32a2141e2af",
    "fake_sk": "4caeb6d8a9eb1b821caf6b724afcf3e99ce994195f0e19250d27eadc294bc4a1",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "566ba0b0c560c47305a6d18f004e45d7c0ffbb0ca7d70298a46ac4dc06fe04de",
    "oprf_seed": "1faf2da896fd12a989a766913d4fe5ad2f18effecb8d19cd9cb799958d352ac0",
    "masking_nonce": "755396e85ad2a9db2d1f268c8b82d19ecf7fd894c9b7a5d55abfc984e94d3fc4a55bada9379763b8fcbbc5c9c0c43f8c986f93f41efd6b643af6abcaa16472ab",
    "envelope_nonce": "44c87a05249a9ee146d796b92e4daf83580817b24fe71f8c2833ac78f502a9ed",
    "client_nonce": "158a7151344e033fda674cf0e9ea589eceead5633abb280d9621779ceeb4ef7f",
    "server_nonce": "70cc74bf8d84fd478d790a7c3a27c9918d5455b97d455db32e7880716df41c3a",
    "context": "636f6e74657874",
    "registration_request": "03eeecb3a5fa5bf46117a9373982bdc03718abc980dda6895eba271f6c1cfdf87d",
    "registration_response": "02edd9313283905183f1ee8f3ce9c251c068ca7d328dcfbeb5a004194b2c3655a002072fc775218863509d8608972333f0f3ce15e3b8c64029bb329268fc735c169b",
    "registration_upload": "03165d66d02346a775750a65c5f6bb0fcf30d1f6791c8cd0851a35088041a2ced89d4eadfcc71134774ddde5f32e48d8156f55579ef4051d7b20470f43f81a1541133536d17f9f606be08764749eb56faea117d3bbaaed858b044180b363dcdfebcc284276a24a186559e782aa8735347d69825cb0737711e52e76aa93679329a9",
    "credential_request": "03eeecb3a5fa5bf46117a9373982bdc03718abc980dda6895eba271f6c1cfdf87d158a7151344e033fda674cf0e9ea589eceead5633abb280d9621779ceeb4ef7f036d56181f0b67f7c6c55f1905072eca62bc081eada24671cfe6a30895e18c86fc",
    "credential_response": "02edd9313283905183f1ee8f3ce9c251c068ca7d328dcfbeb5a004194b2c3655a0755396e85ad2a9db2d1f268c8b82d19ecf7fd894c9b7a5d55abfc984e94d3fc464daba0917b58cc1bc8e563c1ac137b00bf9d9962f192df6659707966acea1a475aa7d02f21d3e53edc088e076f871d1e7aea4ba9128db8782fb4bd7f3f1c25bed6b88ff196ef9dae93873cc1fd2521efe6e5719d6afc0608f4357888f51257aa84492467b6128c25074c27b43fc3c2cd1a0680fcdadd6a215919ff32a2141e2af03f01cd237fa1dd5ab9d5103c0ccfcbeb7241491fbce5a9f4dfd9642ccb6db447d630c05899e308e9b6f57fec287646f825ec72425a9b9df9d757b596d867eb09f",
    "credential_finalization": "d95dc6ffd5da777f21ffe270e24e6031890cc11d3eae13a5b6b39f98b3dc6235",
    "client_registration_state": "0020566ba0b0c560c47305a6d18f004e45d7c0ffbb0ca7d70298a46ac4dc06fe04de002103eeecb3a5fa5bf46117a9373982bdc03718abc980dda6895eba271f6c1cfdf87d",
    "client_login_state": "0020566ba0b0c560c47305a6d18f004e45d7c0ffbb0ca7d70298a46ac4dc06fe04de006203eeecb3a5fa5bf46117a9373982bdc03718abc980dda6895eba271f6c1cfdf87d158a7151344e033fda674cf0e9ea589eceead5633abb280d9621779ceeb4ef7f036d56181f0b67f7c6c55f1905072eca62bc081eada24671cfe6a30895e18c86fc004089e0d6a457895418b46f6e90c389d6fbe6d08fcd144a23a0f3aa7cc435989c76158a7151344e033fda674cf0e9ea589eceead5633abb280d9621779ceeb4ef7f",
    "server_login_state": "95cccef78efea9edc490fb4dbeb343a997245897344a77729ca6c3c0eb54933df0a8297057bada1a0fd84de5d5027284635249855c1c4c9b96418f90ab9618428d625c84b2d4d95254eeeb180d15c3c05624057d2d859e17e422565a0f3ab556",
    "password_file": "03165d66d02346a775750a65c5f6bb0fcf30d1f6791c8cd0851a35088041a2ced89d4eadfcc71134774ddde5f32e48d8156f55579ef4051d7b20470f43f81a1541133536d17f9f606be08764749eb56faea117d3bbaaed858b044180b363dcdfebcc284276a24a186559e782aa8735347d69825cb0737711e52e76aa93679329a9",
    "export_key": "22d8b5b573b5c4369a134e93e0e212a9133e7ff3c140e432f47365c298477e04",
    "session_key": "8d625c84b2d4d95254eeeb180d15c3c05624057d2d859e17e422565a0f3ab556"
}
"#;

#[cfg(all(feature = "x25519", feature = "ristretto255"))]
static TEST_VECTOR_X25519_RISTRETTO255: &str = r#"
{
    "client_s_pk": "a5c05ebbc722b686fa4c6d566bfc44d74e2fc8e8ea4896324331a841865b0a3b",
    "client_s_sk": "18b3ca6b79d753880f3f1279cbdc61223999a33b0b87e516465b68045731697d",
    "client_e_pk": "43a3c909cc80a393768a1a45455fc9fbd3350c77e00ad9976a274ca3fa615f6c",
    "client_e_sk": "40eb129cbe5e0eef5ae8ef988bd82c7e8554ae9ee24e9058eac905adb168cf49",
    "server_s_pk": "63355261f337200c3bbbc431a5f54d1d9b5c8ba9c5874c4cc976ec884c88d93e",
    "server_s_sk": "4047cc79b02a47036b6b9d38c0914dc1ed94e83c036be89aba59fa18b57df04a",
    "server_e_pk": "20aaa63e2f953dcb523e9163d82070b8bb20d79c98356545dcdc3da1eabe7b31",
    "server_e_sk": "70547132b4209ed76f79aaa5b024528b173b82156089bac33aa6bc0f65b1114a",
    "fake_sk": "b8ad45827bcc4d8001866e40e252a93c40cfede36929ea79e4bf483184f05861",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "9cf11320eaf981ececa309f4a9155ea97581af83d31323456c5904952ac0ac01",
    "oprf_seed": "42ed621bae9cc161c6ff480799faabe1c8e37afb7f8a7a090b2c4c817aef12f128964fceae3fdcfc29833410420d32fcf7af2a261f61559cf203078098144385",
    "masking_nonce": "7696aabec815d249c9c9027978b60ec2184d5538cd5b79a0e8bf96cdf26bf75c78ec3b1ddea4cc7563391a912dd6cac66a4ffe8f87fecf9b893e6cc847193e99",
    "envelope_nonce": "4efc855a6b690cbb8e4fa8bc94677c559ac14e623e6653194645eab44b76ce3c",
    "client_nonce": "8b6e2808feca07a7ad9e5732441b31870aa093279f8f5a797cacef5b03273a7d",
    "server_nonce": "cb0e029a84a789a313ab1aedc80d41e848c4349dfe675dab3f79d16f64e1a4e1",
    "context": "636f6e74657874",
    "registration_request": "d820d2f1dcdb05827e6a3fb574cdd8682c1b6dc86a51e95a1a99e9c032eb0337",
    "registration_response": "4c8515fe262e5b5f74ac859bb6c2e3fa1351e9508239f721f9cf12f2dd370b1d63355261f337200c3bbbc431a5f54d1d9b5c8ba9c5874c4cc976ec884c88d93e",
    "registration_upload": "1117c9105075dc9777eb5898ce1d61eeb2ce32f543fdf5ba69d88923bc3531450efa6e6246e0745fa5a3c061ec267158b90f50496b208fd276026adeabd989bef46bfb136043f26870aae76135b21e6203317fe41e792d615d99e0f75fadcdc618b3ca6b79d753880f3f1279cbdc61223999a33b0b87e516465b68045731697d70c517117dc57a92c71c3d8a8c6f66ebd8717b466f4a1e2573f3a0f77ff035917de17aab4c7222d2cdc16a7a556dbd9ea7c6a10a0cd7e7154ac51cdd4d74d8f8",
    "credential_request": "d820d2f1dcdb05827e6a3fb574cdd8682c1b6dc86a51e95a1a99e9c032eb03378b6e2808feca07a7ad9e5732441b31870aa093279f8f5a797cacef5b03273a7d43a3c909cc80a393768a1a45455fc9fbd3350c77e00ad9976a274ca3fa615f6c",
    "credential_response": "4c8515fe262e5b5f74ac859bb6c2e3fa1351e9508239f721f9cf12f2dd370b1d7696aabec815d249c9c9027978b60ec2184d5538cd5b79a0e8bf96cdf26bf75c03f6d8167d48c86a5a46189ebe36e7b996d9c955c4d756f85853217eec1c32edc6d445aaa236afa509d045ba0f205a01698827b4d9d48eda5a3a92d153c78a186edc2a152b0ca310528804c6ed4873a9ab1fbe5808f13b0aa886f0dbe0ac05dbb899591d2850b758e2a36239aaceeb5e2b72acfac26fe80d6c7bd464ff50ac0270547132b4209ed76f79aaa5b024528b173b82156089bac33aa6bc0f65b1114aa78b3b35e660f9706c6855ee9d48cd8efa62f861e17ac9f5954548cee713e6349f9e7308abc991dfcbbb7fdff3a985ec45a9a6b6f2ca678c086fb65382f4cf3d0c7115fcf771140da3bfff7d500f92a3e361e4469e24a03746ca384b7d06d4db",
    "credential_finalization": "60af28e12a0d2c9e3946820abe2ebbba29cf6e5b09053853d28654d1ade1dd17b9a84a48871f992b148529e785fdd8f24d21dd8ebc4fecbbc6dfae2ced20777e",
    "client_registration_state": "00209cf11320eaf981ececa309f4a9155ea97581af83d31323456c5904952ac0ac010020d820d2f1dcdb05827e6a3fb574cdd8682c1b6dc86a51e95a1a99e9c032eb0337",
    "client_login_state": "00209cf11320eaf981ececa309f4a9155ea97581af83d31323456c5904952ac0ac010060d820d2f1dcdb05827e6a3fb574cdd8682c1b6dc86a51e95a1a99e9c032eb03378b6e2808feca07a7ad9e5732441b31870aa093279f8f5a797cacef5b03273a7d43a3c909cc80a393768a1a45455fc9fbd3350c77e00ad9976a274ca3fa615f6c004040eb129cbe5e0eef5ae8ef988bd82c7e8554ae9ee24e9058eac905adb168cf498b6e2808feca07a7ad9e5732441b31870aa093279f8f5a797cacef5b03273a7d",
    "server_login_state": "bbb12324c0e182a54a432b82ff00ae0ce4ab135772aa09c9a81c9c80d85b25c3bef7be6e2b3b0dceab098034927f05615179b9a1485965bc263d69d31ad2155c8a5a104595d9888f33867d811352bd520a5acd678154e37d4b9e9241f3e9660f185680c94383a036c1aa4f44784b94faecdc6316f40efbbdb5dcf9a6edaad9bb4ac112225e423d09e6f275bdeb8ff7eb7bef36b948c0251b226c4d0629758236cc53a47a94d262ce1a4eb22568a6c5a83ef617057cf846fe020e3c51a673a683",
    "password_file": "1117c9105075dc9777eb5898ce1d61eeb2ce32f543fdf5ba69d88923bc3531450efa6e6246e0745fa5a3c061ec267158b90f50496b208fd276026adeabd989bef46bfb136043f26870aae76135b21e6203317fe41e792d615d99e0f75fadcdc618b3ca6b79d753880f3f1279cbdc61223999a33b0b87e516465b68045731697d70c517117dc57a92c71c3d8a8c6f66ebd8717b466f4a1e2573f3a0f77ff035917de17aab4c7222d2cdc16a7a556dbd9ea7c6a10a0cd7e7154ac51cdd4d74d8f8",
    "export_key": "dd0eee2e2be41c3de1c30dc10201ba4e6fd9c3c35fbac6b92e69c9bc3009793d0592ec691fbf153dd0c1ab7981f838a7857d15119510d264d3867e333d7a2fd8",
    "session_key": "4ac112225e423d09e6f275bdeb8ff7eb7bef36b948c0251b226c4d0629758236cc53a47a94d262ce1a4eb22568a6c5a83ef617057cf846fe020e3c51a673a683"
}
"#;

#[cfg(all(feature = "x25519", feature = "p256"))]
static TEST_VECTOR_X25519_P256: &str = r#"
{
    "client_s_pk": "7ddc3080300348a75a952b4d2eeb486679b291e0afe62e92d0f7d8daac0d9c04",
    "client_s_sk": "304bfc6ac14ba9ff4bcce293f6bc4018f5ace430b73c441b5285bcee7f914f6b",
    "client_e_pk": "4cd8867133016f2da6682a941e754d3cc117f9a379a54a6d4032c7ca33bf8971",
    "client_e_sk": "70044c1595a385aac9c8717de01cfb467ec79730974aaab152af9c7bc81c6362",
    "server_s_pk": "a20a638ff49314fe1a12fba617a71db074a31e13b8b527082f73dfa8e698814f",
    "server_s_sk": "809437ea751bc8e080df6b287d4a17a898ee8b667d26d306ce6475b6ea17b653",
    "server_e_pk": "0d9802b608ef2a508e40789ab788ffffcaeb473404f86ce165c40b329e115e26",
    "server_e_sk": "b84391e35793b4342134d5b27cc295eccbfd9cb30b6204af49c564be5d7fc96b",
    "fake_sk": "6805cec76fb42273793898583a4b5337f83200a3e743c4a9a625eb228cdf034e",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "45a86fc13ab5e0f5640f4107cd9a779de17d70b21c7c1cb67d3a31eec98dc393",
    "oprf_seed": "c812748c4d8612898cf341a64330bd15bf3698cace57b056e6e9dde7b85b3d02",
    "masking_nonce": "21a2c07dbb280173d3c52de4928db8dbdb5e08ab63cc41e50120f3f59dadc0e27439b375baefe512c9549207c80e32b80c9eb3fcb14f3b8475e28606dd93b92a",
    "envelope_nonce": "bef3f1619710d6ef7106b9fb34ea91d63e7d4353abea3187af58733e3bee4b90",
    "client_nonce": "7d38f8a1e0611328fee58c56505e93aae540898f6b1d5114f36bb6580b7b15d5",
    "server_nonce": "65c26fbd58ca2aa7f422c7a43f46f90e600b5da3164b560fb30bbee2e3208df5",
    "context": "636f6e74657874",
    "registration_request": "03cccab9c2f978372a7d399eb6673f869b84e43a2983cb58df79a7e52edbaaf4d8",
    "registration_response": "02276d3a9d08018fbdb517e8ce96285813bb4ea8d75e387c2042dc4baf700b5eb4a20a638ff49314fe1a12fba617a71db074a31e13b8b527082f73dfa8e698814f",
    "registration_upload": "2aa1abc021cf39cf81dd3a572087235f2e85bab3fb481ab5bf8584cc0ce3b45958eeb87b8088b1f986cc607e41f1be68cfb9fba8c2d8cd8e719ff13320c29853304bfc6ac14ba9ff4bcce293f6bc4018f5ace430b73c441b5285bcee7f914f6bed46e88d2cedb44272383b47f1a9f1f3642e511bd9348ba2eb654f2340599f1e",
    "credential_request": "03cccab9c2f978372a7d399eb6673f869b84e43a2983cb58df79a7e52edbaaf4d87d38f8a1e0611328fee58c56505e93aae540898f6b1d5114f36bb6580b7b15d54cd8867133016f2da6682a941e754d3cc117f9a379a54a6d4032c7ca33bf8971",
    "credential_response": "02276d3a9d08018fbdb517e8ce96285813bb4ea8d75e387c2042dc4baf700b5eb421a2c07dbb280173d3c52de4928db8dbdb5e08ab63cc41e50120f3f59dadc0e2926e1c5ab5d87d62b297cba83187f43236f2cebf28365f1bda456198e7fc7f2d619843118f8b5b3478edfbb10b71c84fc19984b68504f80a265ca6efed1094c92c4cfa68f2407a3c47d59536aa28f3a75b97c0cb8f6c9600c775dcd144ccc4b9b84391e35793b4342134d5b27cc295eccbfd9cb30b6204af49c564be5d7fc96bd781656288e2efd01b055dd54c3e5cf9bc1619be6c3ce233494d371338b7565c51042a0192ca2696977f9a216c7ede85cc9f934311c41dabe3543e2a5108d892",
    "credential_finalization": "e7f1dcededf267cef1e2cd34249bc031aaa40270e1699c65a992e0a133e25d51",
    "client_registration_state": "002045a86fc13ab5e0f5640f4107cd9a779de17d70b21c7c1cb67d3a31eec98dc393002103cccab9c2f978372a7d399eb6673f869b84e43a2983cb58df79a7e52edbaaf4d8",
    "client_login_state": "002045a86fc13ab5e0f5640f4107cd9a779de17d70b21c7c1cb67d3a31eec98dc393006103cccab9c2f978372a7d399eb6673f869b84e43a2983cb58df79a7e52edbaaf4d87d38f8a1e0611328fee58c56505e93aae540898f6b1d5114f36bb6580b7b15d54cd8867133016f2da6682a941e754d3cc117f9a379a54a6d4032c7ca33bf8971004070044c1595a385aac9c8717de01cfb467ec79730974aaab152af9c7bc81c63627d38f8a1e0611328fee58c56505e93aae540898f6b1d5114f36bb6580b7b15d5",
    "server_login_state": "af0e6995bf454d54d9d8aed0a3151df128abeb03c127e261c225e72a65622394b2b830cad7bb1113ccca8321e3047f0adf2060bf2b8be341a28af70f07710400fe18ab0443a44ef5cea7af48443510c45e20361d9d55a535160d4e601ab68a2d",
    "password_file": "2aa1abc021cf39cf81dd3a572087235f2e85bab3fb481ab5bf8584cc0ce3b45958eeb87b8088b1f986cc607e41f1be68cfb9fba8c2d8cd8e719ff13320c29853304bfc6ac14ba9ff4bcce293f6bc4018f5ace430b73c441b5285bcee7f914f6bed46e88d2cedb44272383b47f1a9f1f3642e511bd9348ba2eb654f2340599f1e",
    "export_key": "8089b4587c260f0b5bfd467a1083a0b811e81f27fabf1625ed72c00713d3d2af",
    "session_key": "fe18ab0443a44ef5cea7af48443510c45e20361d9d55a535160d4e601ab68a2d"
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

fn stringify_test_vectors(p: &TestVectorParameters) -> alloc::string::String {
    let mut s = alloc::string::String::new();
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
    use crate::keypair::KeyPair;
    use rand::RngCore;

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

    let fake_sk: Vec<u8> = fake_kp.private().to_vec();
    let server_setup = ServerSetup::<CS>::deserialize(
        &[
            oprf_seed.as_ref(),
            &server_s_kp.private().to_arr(),
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
    let client_registration_state = client_registration_start_result.state.serialize()?;

    let server_registration_start_result = ServerRegistration::<CS>::start(
        &server_setup,
        client_registration_start_result.message,
        credential_identifier,
    )
    .unwrap();
    let registration_response_bytes = server_registration_start_result.message.serialize();

    let mut client_s_sk_and_nonce: Vec<u8> = Vec::new();
    client_s_sk_and_nonce.extend_from_slice(&client_s_kp.private().to_arr());
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
    client_login_start.extend_from_slice(&client_e_kp.private().to_arr());
    client_login_start.extend_from_slice(&client_nonce);

    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let client_login_start_result =
        ClientLogin::<CS>::start(&mut client_login_start_rng, password).unwrap();
    let credential_request_bytes = client_login_start_result.message.serialize();
    let client_login_state = client_login_start_result
        .state
        .serialize()
        .unwrap()
        .to_vec();

    let mut server_e_sk_and_nonce_rng = CycleRng::new(
        [
            masking_nonce.to_vec(),
            server_e_kp.private().to_arr().to_vec(),
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
        client_s_pk: client_s_kp.public().to_arr().to_vec(),
        client_s_sk: client_s_kp.private().to_arr().to_vec(),
        client_e_pk: client_e_kp.public().to_arr().to_vec(),
        client_e_sk: client_e_kp.private().to_arr().to_vec(),
        server_s_pk: server_s_kp.public().to_arr().to_vec(),
        server_s_sk: server_s_kp.private().to_arr().to_vec(),
        server_e_pk: server_e_kp.public().to_arr().to_vec(),
        server_e_sk: server_e_kp.private().to_arr().to_vec(),
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
        client_registration_state,
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
            hex::encode(client_registration_start_result.state.serialize()?)
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
            hex::encode(client_login_start_result.state.serialize()?)
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
            hex::encode(&client_login_finish_result.server_s_pk.to_arr().to_vec())
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
fn test_zeroize_client_login_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // CredentialRequest: KgPk + Ke1Message
        <CS::OprfGroup as Group>::ElemLen: Add<Ke1MessageLen<CS>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
    {
        let mut client_rng = OsRng;
        let client_login_start_result =
            ClientLogin::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;

        let mut state = client_login_start_result.state;
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
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<CS::Hash>>,
        Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
        // CredentialRequest: KgPk + Ke1Message
        <CS::OprfGroup as Group>::ElemLen: Add<Ke1MessageLen<CS>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
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

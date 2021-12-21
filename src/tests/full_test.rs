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
use digest::{Digest, FixedOutput};
use generic_array::typenum::{Sum, Unsigned};
use generic_array::{ArrayLength, GenericArray};
use rand::rngs::OsRng;
use serde_json::Value;
use subtle::ConstantTimeEq;
use voprf::group::Group;
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
    type KeGroup = p256_::ProjectivePoint;
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
    "client_s_pk": "181bbea01a5e444390c4b335f8bcb9a846a1c60042669ce6d731af4587960c06",
    "client_s_sk": "2f21529b9fb27c8c12770b765dc36750c4a51c5ccaf2f83d0182504a85a22c0b",
    "client_e_pk": "58a16b672e100b18069d0716715a9a8d9a643954bb24c0887e46d542eab9e417",
    "client_e_sk": "c1a4db9d650ce1700e05fbd472d30c13e0a4c6926b114e7ca11e2e9f397c5005",
    "server_s_pk": "dc8c66b6dcf4731836a0cdb336985c77a6321ffb75db6bb1aef20974c141dd3c",
    "server_s_sk": "410ef173f972994eeabb2cb39fd5db907e39a1abd6b36c9f514ab903d9d16305",
    "server_e_pk": "68630597c4593cb8158f398ab6ff956a1d87232be4300be1f96a6860663d9461",
    "server_e_sk": "155452c6b08b889b31d5a810925136adfb2d363eee4ccaed0ef15b594fb88b04",
    "fake_sk": "b009e67b83c418f0ae271b8790d6c5e06ea3874fa5a9e66752b5ebdbec953b04",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "544ce97b02dff0201282a44cf73171a62a76e2a113d40dce8950f31bf4339403",
    "oprf_seed": "f929fa161a065bec163bea6dbab6d6eccd960666951fc7fd3da7cf2b6baf20a2763598aba89a4e5bcaa57096c66cfded26d683e07ab1a3b37a7c82706dfaee81",
    "masking_nonce": "4c0099b7067c7c243ed804def0fd490babd577abcd7b05a1f24a05d2d1cc344e079a75936ed36b89a3056661a2dc981a6628edde6a86da2714cce71659d84f8d",
    "envelope_nonce": "9888ba54ffc1e1be5deb23a2efa5432f318f9a17d681d1273e909ca3bf1b2fea",
    "client_nonce": "652a39daf155cc9b5a005b67951f19c2ccdf4667cf7bcd39f941a87565ed4c29",
    "server_nonce": "5e2f19069ea9791d6b346b676d8d8aaf45536148ca0357a595f330c7aed107d2",
    "context": "636f6e74657874",
    "registration_request": "f05048bb39f3f5a3a414f50254c425b36f842162a630bf73456df453351cb33d",
    "registration_response": "2c6f5ba3de9af2719529e9a993097e8c0ecd5110a24471414e4225950189cc46dc8c66b6dcf4731836a0cdb336985c77a6321ffb75db6bb1aef20974c141dd3c",
    "registration_upload": "08a51d9973140af4f911f235d4910e9536503157bfaffefaeaa11f69d723cc54d35d9ae50d6a0a7ab38614e571a81821cfbfec36ed9fd46e397e173252d02ff623287035e190153e9fb88509da1c225765bb200ed59249cbfd6201656d1672db2f21529b9fb27c8c12770b765dc36750c4a51c5ccaf2f83d0182504a85a22c0b19e07582aea6c5e782b15ff18f6188203f54ea62dfb1efb77d641f030b86062c9f0d1bc3c39b7f824fe81df456c702ea4fa084eba803fea7e5a80d2284c2ff15",
    "credential_request": "f05048bb39f3f5a3a414f50254c425b36f842162a630bf73456df453351cb33d652a39daf155cc9b5a005b67951f19c2ccdf4667cf7bcd39f941a87565ed4c2958a16b672e100b18069d0716715a9a8d9a643954bb24c0887e46d542eab9e417",
    "credential_response": "2c6f5ba3de9af2719529e9a993097e8c0ecd5110a24471414e4225950189cc464c0099b7067c7c243ed804def0fd490babd577abcd7b05a1f24a05d2d1cc344e4100aea1aa461bed485d0e441c275d0d04388e1b6b739379cd9ebabe6a53ca025375487ea73cc17ea884fb3fd91d05a8970628459ab7996e9e20aacdc613a669a687c95479814b866c43cde2ca225f43a44035ba921b5986877589013acd8eba3f4e00bd4c5e83756651c5faa0319487e4b80bcedfef82b9e46c3cace5b4aa8e155452c6b08b889b31d5a810925136adfb2d363eee4ccaed0ef15b594fb88b04605c82fb3bb14125d8274619e5ceef90151b6309610aa35c2c0a004337c44b50162d27726ed40aca064e88cff1413d7098f81b16567919ca8d9c425b8b3445684e2ad7e7d8d14475c2ca1ace56a5949199fb836f9f343d46994098955bb9f129",
    "credential_finalization": "e13284ada3e78eed48047934115ce7e6c2cdff0c3012e9ba2d423759c4000ddf11ecd186dd7f0740ee3413ff0d253e2437eced56f3717e45c071b170d12db1dd",
    "client_registration_state": "0028544ce97b02dff0201282a44cf73171a62a76e2a113d40dce8950f31bf433940370617373776f72640020f05048bb39f3f5a3a414f50254c425b36f842162a630bf73456df453351cb33d",
    "client_login_state": "0028544ce97b02dff0201282a44cf73171a62a76e2a113d40dce8950f31bf433940370617373776f72640060f05048bb39f3f5a3a414f50254c425b36f842162a630bf73456df453351cb33d652a39daf155cc9b5a005b67951f19c2ccdf4667cf7bcd39f941a87565ed4c2958a16b672e100b18069d0716715a9a8d9a643954bb24c0887e46d542eab9e4170040c1a4db9d650ce1700e05fbd472d30c13e0a4c6926b114e7ca11e2e9f397c5005652a39daf155cc9b5a005b67951f19c2ccdf4667cf7bcd39f941a87565ed4c29",
    "server_login_state": "2a009e5881454a2b42fb8c039762f78828c5b4ba7008d2e57b16ffdc937ee846b56461f9cda751b2a1c2b03793d72d5ca8c482adf8009880779323e64e12eb1d4c0cf45ec665be918cb9d655f9eca974494f0f4c0f6e714c6ddcca37b547c122cf7419984e123fa4c7981212e5171b01bfd6f8ac88e7964c8da4a88b5df4f2c85da5318465cef76fbddd389ff36be66c693cfc6feecbcf43bf16a22c97de8430e824b2812449934d13fb666b24de78a007f1fc06064304b0abfae3fc5caba7f6",
    "password_file": "08a51d9973140af4f911f235d4910e9536503157bfaffefaeaa11f69d723cc54d35d9ae50d6a0a7ab38614e571a81821cfbfec36ed9fd46e397e173252d02ff623287035e190153e9fb88509da1c225765bb200ed59249cbfd6201656d1672db2f21529b9fb27c8c12770b765dc36750c4a51c5ccaf2f83d0182504a85a22c0b19e07582aea6c5e782b15ff18f6188203f54ea62dfb1efb77d641f030b86062c9f0d1bc3c39b7f824fe81df456c702ea4fa084eba803fea7e5a80d2284c2ff15",
    "export_key": "ea8d1f871a3c8ad5d2a7a2d647e020105a33f8b8534055c56ab4bae2b8467d22806968159f918d9c31098602790fcad3e5969f1d8ff0b90b48c26b4132877ed4",
    "session_key": "5da5318465cef76fbddd389ff36be66c693cfc6feecbcf43bf16a22c97de8430e824b2812449934d13fb666b24de78a007f1fc06064304b0abfae3fc5caba7f6"
}
"#;

// To regenerate, run: cargo test -- --nocapture generate_test_vectors
#[cfg(feature = "p256")]
static TEST_VECTOR_P256: &str = r#"
{
    "client_s_pk": "022bb70342affe88f4f3c5d5fc4991bfc1f4758651d59d50c25815ffc4d13eeae3",
    "client_s_sk": "ee7beaaed8110b155efac3af2bb97a7a45262fa5702de4721c90ebcfb098b596",
    "client_e_pk": "02faf2a785a7de0d59c240b235ab7559820f682a7930fb546ecabddee2de091043",
    "client_e_sk": "755577ce43627c5201af2bd35bc17bb7a4c9945acbadbb08962a0236a860ce80",
    "server_s_pk": "025e6c524abf252eadf812d3ef46dd7afbeb2f65d76269d1a1288fb0be82b378cb",
    "server_s_sk": "5f044f77db085dd5ebeb0ffbe69166057c586719f5ff277a4488b3202c720258",
    "server_e_pk": "039e7fc9dcf8e9f50405d228a70c1d9bf5eb283b7e156774125b876819d0349630",
    "server_e_sk": "5158264e39bd1234ab785701b47d697b07db92eb4f5dc0f206607edf69f66476",
    "fake_sk": "402eaf9bf6d4b1501a2eae8ebb76d4970060decd43944c4bd601602c23a23093",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "a383673cc3fc95652d0fd6fdfaaff8c2db97c0cb55706499a7e719a28f93ba49",
    "oprf_seed": "84618864bc307f9c178cb5c156865094c8f3737e6ea4e46dc965ddbd4b2332f2",
    "masking_nonce": "ec5bb47a34e050136fb97a513ddf182ccc498ffb7d70d94954cc013db934c2716f35c5a1adb5c220194bbb1e8159bbfbcabeb7d94215476bdf29e5dad3919b2c",
    "envelope_nonce": "a9a9de9d77fae996ffa597928b12c83ff44e56b2e7d4f79dd561132800d63a2c",
    "client_nonce": "51710b892007ef555ffd08452d9f9078165c2e7fd3695ad8020d74a8c20bb8b1",
    "server_nonce": "68f4bc84db8af9940f41e8e91a5d39800e1eacdecd124918d24dc5eb8d5ed840",
    "context": "636f6e74657874",
    "registration_request": "0397d002bed42dfd7a104348c29e82c0bab8a5871846d8c6159e511d3c681fc2be",
    "registration_response": "0357c5ca3794429f3111026c79925ffa597c7e518ac787ed49fe152d083d07c846025e6c524abf252eadf812d3ef46dd7afbeb2f65d76269d1a1288fb0be82b378cb",
    "registration_upload": "03dd5bbddab150cf7cd793d6702741e529ee13ab4ce4cfad731dd77fc13c2310e5d82ca5e29fa03deff3ed1d8eb1353389b02a78bd48fa256915314dac55cf5e74ee7beaaed8110b155efac3af2bb97a7a45262fa5702de4721c90ebcfb098b5964788cdaf2a92a5a161a819c2aa84985f5a8ea6fbedf01c87ddaa8be23fc16721",
    "credential_request": "0397d002bed42dfd7a104348c29e82c0bab8a5871846d8c6159e511d3c681fc2be51710b892007ef555ffd08452d9f9078165c2e7fd3695ad8020d74a8c20bb8b102faf2a785a7de0d59c240b235ab7559820f682a7930fb546ecabddee2de091043",
    "credential_response": "0357c5ca3794429f3111026c79925ffa597c7e518ac787ed49fe152d083d07c846ec5bb47a34e050136fb97a513ddf182ccc498ffb7d70d94954cc013db934c27117a3467e180aa4144edd4122e53e2f9fe4d1c1363796e5820d92489e94c5fcabda33f5e886cfee0da967b28cc2a06674cf5d050125ac1136a44284520fcde7f7de6af0ab5f26f57d682c5d389298d5ebd38e7ca7f8bf5456ed0ac9f9ac6f4b7cbe5158264e39bd1234ab785701b47d697b07db92eb4f5dc0f206607edf69f66476039cb032462240ab63f406935a398ef593655ed0617147a952a249ca81bfda7d4ad872b9829967987a74514454b1ee3776debcae819c526ac33f838a81edb234b3",
    "credential_finalization": "35395199a2e317c5f08f55f67f9f5565d1d0c856572876b1b4e447925a36eb60",
    "client_registration_state": "0028a383673cc3fc95652d0fd6fdfaaff8c2db97c0cb55706499a7e719a28f93ba4970617373776f726400210397d002bed42dfd7a104348c29e82c0bab8a5871846d8c6159e511d3c681fc2be",
    "client_login_state": "0028a383673cc3fc95652d0fd6fdfaaff8c2db97c0cb55706499a7e719a28f93ba4970617373776f726400620397d002bed42dfd7a104348c29e82c0bab8a5871846d8c6159e511d3c681fc2be51710b892007ef555ffd08452d9f9078165c2e7fd3695ad8020d74a8c20bb8b102faf2a785a7de0d59c240b235ab7559820f682a7930fb546ecabddee2de0910430040755577ce43627c5201af2bd35bc17bb7a4c9945acbadbb08962a0236a860ce8051710b892007ef555ffd08452d9f9078165c2e7fd3695ad8020d74a8c20bb8b1",
    "server_login_state": "5c2ec839d40694328ed6133cc12b8da7ec4300589849eb193eb673d35e4645c8bce86cbd880012967dae7c0f1ac2a90a4d6ea9f3ee5c521c77a20600de4528ee89699ffdb9e8ba62442184bd4a696c6c5832801a425446869aefa2544260d618",
    "password_file": "03dd5bbddab150cf7cd793d6702741e529ee13ab4ce4cfad731dd77fc13c2310e5d82ca5e29fa03deff3ed1d8eb1353389b02a78bd48fa256915314dac55cf5e74ee7beaaed8110b155efac3af2bb97a7a45262fa5702de4721c90ebcfb098b5964788cdaf2a92a5a161a819c2aa84985f5a8ea6fbedf01c87ddaa8be23fc16721",
    "export_key": "35a93c215dc618dc3acbacc08d16e4879bf2054349facf2a33bc061dee57d787",
    "session_key": "89699ffdb9e8ba62442184bd4a696c6c5832801a425446869aefa2544260d618"
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
    // RegistrationResponse: KgPk + KePk
    <CS::OprfGroup as Group>::ElemLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
    RegistrationResponseLen<CS>: ArrayLength<u8>,
    // Envelope: Nonce + Hash
    NonceLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
    EnvelopeLen<CS>: ArrayLength<u8>,
    // RegistrationUpload: (KePk + Hash) + Envelope
    <CS::KeGroup as KeGroup>::PkLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
    Sum<<CS::KeGroup as KeGroup>::PkLen, <CS::Hash as FixedOutput>::OutputSize>:
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
    NonceLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
    Sum<NonceLen, <CS::Hash as FixedOutput>::OutputSize>:
        ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
    MaskedResponseLen<CS>: ArrayLength<u8>,
    // CredentialResponseWithoutKeLen: (KgPk + Nonce) + MaskedResponse
    <CS::OprfGroup as Group>::ElemLen: Add<NonceLen>,
    Sum<<CS::OprfGroup as Group>::ElemLen, NonceLen>: ArrayLength<u8> + Add<MaskedResponseLen<CS>>,
    CredentialResponseWithoutKeLen<CS>: ArrayLength<u8>,
    // Ke2Message: (Nonce + KePk) + Hash
    NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
    Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>:
        ArrayLength<u8> + Add<<CS::Hash as FixedOutput>::OutputSize>,
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
    let mut oprf_seed = GenericArray::<_, <CS::Hash as Digest>::OutputSize>::default();
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
        println!("P256: {}", stringify_test_vectors(&parameters));
    }

    Ok(())
}

#[test]
fn test_registration_request() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError> {
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

    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn test_serialization() -> Result<(), ProtocolError> {
    use core::mem;

    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError> {
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

    Ok(())
}

#[test]
fn test_registration_response() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
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

    Ok(())
}

#[test]
fn test_registration_upload() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        // Envelope: Nonce + Hash
        NonceLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <CS::KeGroup as KeGroup>::PkLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, <CS::Hash as FixedOutput>::OutputSize>:
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

    Ok(())
}

#[test]
fn test_password_file() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        // Envelope: Nonce + Hash
        NonceLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <CS::KeGroup as KeGroup>::PkLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, <CS::Hash as FixedOutput>::OutputSize>:
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

    Ok(())
}

#[test]
fn test_credential_request() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
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

    Ok(())
}

#[test]
fn test_credential_response() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
        Sum<NonceLen, <CS::Hash as FixedOutput>::OutputSize>:
            ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
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

    Ok(())
}

#[test]
fn test_credential_finalization() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
        Sum<NonceLen, <CS::Hash as FixedOutput>::OutputSize>:
            ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
    {
        let parameters = populate_test_vectors(&serde_json::from_str(test_vector).unwrap());

        let client_login_finish_result =
            ClientLogin::<CS>::deserialize(&parameters.client_login_state)?.finish(
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

    Ok(())
}

#[test]
fn test_server_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError> {
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

    Ok(())
}

fn test_complete_flow<CS: CipherSuite>(
    registration_password: &[u8],
    login_password: &[u8],
) -> Result<(), ProtocolError>
where
    // MaskedResponse: (Nonce + Hash) + KePk
    NonceLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
    Sum<NonceLen, <CS::Hash as FixedOutput>::OutputSize>:
        ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
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

    Ok(())
}

#[test]
fn test_complete_flow_fail() -> Result<(), ProtocolError> {
    #[cfg(feature = "ristretto255")]
    test_complete_flow::<Ristretto255>(b"good password", b"bad password")?;
    #[cfg(feature = "p256")]
    test_complete_flow::<P256>(b"good password", b"bad password")?;

    Ok(())
}

// Zeroize tests

#[test]
fn test_zeroize_client_registration_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError> {
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

    Ok(())
}

#[test]
fn test_zeroize_client_registration_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError> {
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

    Ok(())
}

#[test]
fn test_zeroize_server_registration_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        // Envelope: Nonce + Hash
        NonceLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <CS::KeGroup as KeGroup>::PkLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, <CS::Hash as FixedOutput>::OutputSize>:
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

    Ok(())
}

#[test]
fn test_zeroize_client_login_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
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

    Ok(())
}

#[test]
fn test_zeroize_server_login_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
        Sum<NonceLen, <CS::Hash as FixedOutput>::OutputSize>:
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

    Ok(())
}

#[test]
fn test_zeroize_client_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
        Sum<NonceLen, <CS::Hash as FixedOutput>::OutputSize>:
            ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
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

    Ok(())
}

#[test]
fn test_zeroize_server_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
        Sum<NonceLen, <CS::Hash as FixedOutput>::OutputSize>:
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

    Ok(())
}

#[test]
fn test_scalar_always_nonzero() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError> {
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

    Ok(())
}

#[test]
fn test_reflected_value_error_registration() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError> {
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

    Ok(())
}

#[test]
fn test_reflected_value_error_login() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<<CS::Hash as FixedOutput>::OutputSize>,
        Sum<NonceLen, <CS::Hash as FixedOutput>::OutputSize>:
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

    Ok(())
}

// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

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

#[cfg(feature = "ristretto255")]
struct Ristretto255P256;

#[cfg(feature = "ristretto255")]
impl CipherSuite for Ristretto255P256 {
    type OprfCs = p256::NistP256;
    type KeGroup = crate::Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

#[cfg(feature = "ristretto255")]
struct Ristretto255P384;

#[cfg(feature = "ristretto255")]
impl CipherSuite for Ristretto255P384 {
    type OprfCs = p384::NistP384;
    type KeGroup = crate::Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

#[cfg(feature = "ristretto255")]
struct Ristretto255P521;

#[cfg(feature = "ristretto255")]
impl CipherSuite for Ristretto255P521 {
    type OprfCs = p521::NistP521;
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

struct P256P384;

impl CipherSuite for P256P384 {
    type OprfCs = p384::NistP384;
    type KeGroup = p256::NistP256;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

struct P256P521;

impl CipherSuite for P256P521 {
    type OprfCs = p521::NistP521;
    type KeGroup = p256::NistP256;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

#[cfg(feature = "ristretto255")]
struct P256Ristretto255;

#[cfg(feature = "ristretto255")]
impl CipherSuite for P256Ristretto255 {
    type OprfCs = crate::Ristretto255;
    type KeGroup = p256::NistP256;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

struct P384;

impl CipherSuite for P384 {
    type OprfCs = p384::NistP384;
    type KeGroup = p384::NistP384;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

struct P384P256;

impl CipherSuite for P384P256 {
    type OprfCs = p256::NistP256;
    type KeGroup = p384::NistP384;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

struct P384P521;

impl CipherSuite for P384P521 {
    type OprfCs = p521::NistP521;
    type KeGroup = p384::NistP384;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

#[cfg(feature = "ristretto255")]
struct P384Ristretto255;

#[cfg(feature = "ristretto255")]
impl CipherSuite for P384Ristretto255 {
    type OprfCs = crate::Ristretto255;
    type KeGroup = p384::NistP384;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

struct P521;

impl CipherSuite for P521 {
    type OprfCs = p521::NistP521;
    type KeGroup = p521::NistP521;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

struct P521P256;

impl CipherSuite for P521P256 {
    type OprfCs = p256::NistP256;
    type KeGroup = p521::NistP521;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

struct P521P384;

impl CipherSuite for P521P384 {
    type OprfCs = p384::NistP384;
    type KeGroup = p521::NistP521;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

#[cfg(feature = "ristretto255")]
struct P521Ristretto255;

#[cfg(feature = "ristretto255")]
impl CipherSuite for P521Ristretto255 {
    type OprfCs = crate::Ristretto255;
    type KeGroup = p521::NistP521;
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

#[cfg(feature = "curve25519")]
struct Curve25519P384;

#[cfg(feature = "curve25519")]
impl CipherSuite for Curve25519P384 {
    type OprfCs = p384::NistP384;
    type KeGroup = crate::Curve25519;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

#[cfg(feature = "curve25519")]
struct Curve25519P521;

#[cfg(feature = "curve25519")]
impl CipherSuite for Curve25519P521 {
    type OprfCs = p521::NistP521;
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
// cargo test --features curve25519 -- --nocapture generate_test_vectors
#[cfg(feature = "ristretto255")]
static TEST_VECTOR_RISTRETTO255: &str = r#"
{
    "client_s_pk": "26716bbe69e8a0f5af491ee125ebcf1ba570fded8429a5efe3a411572046f168",
    "client_s_sk": "f4a4b1f3c2c54257b91a0d87db527505428cbee4b6139e653160d44418f2110c",
    "client_e_pk": "6ef6b77b5640a9edc6f70c51498008113d616abcaecb93665184f960d109fe52",
    "client_e_sk": "e2ea723e5c50da359eb157b61305ceba76e782def7900f49c4d6710255dab502",
    "server_s_pk": "88a0a8d7d4af520eed596ed1ba0f559ef3938e0760ba4dc0edda61516f786c34",
    "server_s_sk": "119d9d4d6a0d346b32bd098545374bb13d3c62292ee46244ad198388e33d7d0c",
    "server_e_pk": "bc7cc5a25ae069bda90f1c7dd1171025ab795f27e45b78839f6991f29a56e052",
    "server_e_sk": "5b7e3196121b14d54f326ad51849264aeaeef95ea4f4bfde96b31266df92200b",
    "fake_sk": "45caf0bf77b445fedbac477bde6b4302122c29c572b8a4b0760e25c7ae992d0a",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "4c590eff6854bda8024117051aa86c838b5d37bf408714a6004c671e7f72fb03",
    "oprf_seed": "77b3fa30df8c1a6cf848a3cd747f5e28dae23b522e80b9ed67d4d06f09f53136dbc44bbb511b56fec4de8780572bac59b2647c1a71f080e42e70e573f10c6e8a",
    "masking_nonce": "586157850ffa2085e7f857a27b5c942f5419331ca8f9d7467dfd2825e1ec6a3cf85ec715b14eeaadc89615d07c8d49d6859940ff84649df740f97ecaef168f9b",
    "envelope_nonce": "21946497a938b40c9bdeb84d286fc7e9b3ef1e6d150660bd2330e400eac5c5bc",
    "client_nonce": "d49d84dcfdde7c09eecf7b6ddaab79c3269a9d2511ba72d01d363fae862b5a83",
    "server_nonce": "1e5a5cc267d99866ea30678c1ee43c53400b78e4a27b7dcf2b4521667b78c3b3",
    "context": "636f6e74657874",
    "registration_request": "70815fce02606dcb4a45ac1b3e312e201501d5cada02691953297e982e1f9b32",
    "registration_response": "9e2ae845f8f4bd555c4c8df2b5bcff75fa6d1f0650011c422ad349b8d16edc3788a0a8d7d4af520eed596ed1ba0f559ef3938e0760ba4dc0edda61516f786c34",
    "registration_upload": "66723c5c39695106d654570842a1edab79711a36ea4f34f65078b8c35731ea494d10c64e8239e9ed8a476faf6a4df44dd60a58fb0036ef65d5241541c7ca87aa050a7ea198c68d490d02f23419d0e002c7819805f8c9a6517a062d67a2de8b4df4a4b1f3c2c54257b91a0d87db527505428cbee4b6139e653160d44418f2110cedf21caa38e4cfbef0a7e5254082231d0b0dd056ff9014f2fa313e2107925dd8e69e45c126b8dae8c00567da34d09c8658aa7acab6e2fcb43359b263b4642773",
    "credential_request": "70815fce02606dcb4a45ac1b3e312e201501d5cada02691953297e982e1f9b32d49d84dcfdde7c09eecf7b6ddaab79c3269a9d2511ba72d01d363fae862b5a83306781008374dd7ae51f6ea634f742c5db39774daed51d781e1a2e155a804666",
    "credential_response": "9e2ae845f8f4bd555c4c8df2b5bcff75fa6d1f0650011c422ad349b8d16edc37586157850ffa2085e7f857a27b5c942f5419331ca8f9d7467dfd2825e1ec6a3c0e282fab682070fe5f5eaac1c4c01607c753263d6089bec28cf159483d9d8d3bae87a9ae56d6234b34187cd59740eb5e1cbcfe14e048f04ddd020b223365877b175ec2778d8cb0b427ea592751b1456d7f0c7295bc35bc70803e1a69e9ef0039b805f52c349b47ac42896152b738cd2babd230633a30d005fbfdae4a62b168f55b7e3196121b14d54f326ad51849264aeaeef95ea4f4bfde96b31266df92200bfe12195f75aa85845eb390e4eec3ee3594370f9fde7f3864dac00fb5c967dd00f198994831bc346a4b558e0570302b653436f9ecba165dc1f2ac3137f0a0df68aa209353dbf8539a39a4f9d7ff289195b2df5c5e84cb8ff02bbe552c384009f1",
    "credential_finalization": "5f944d84bb4b92fa2a2ae5719eb7f3c486f4dc3c9622d8b23b8512383b2e9be96ecf3540c7a343a519a447ddd74bf651602dbaa54e6b41e44d24fbe00e4888d3",
    "client_registration_state": "4c590eff6854bda8024117051aa86c838b5d37bf408714a6004c671e7f72fb0370815fce02606dcb4a45ac1b3e312e201501d5cada02691953297e982e1f9b32",
    "client_login_state": "4c590eff6854bda8024117051aa86c838b5d37bf408714a6004c671e7f72fb0370815fce02606dcb4a45ac1b3e312e201501d5cada02691953297e982e1f9b32d49d84dcfdde7c09eecf7b6ddaab79c3269a9d2511ba72d01d363fae862b5a83306781008374dd7ae51f6ea634f742c5db39774daed51d781e1a2e155a8046668d4d5de82f0c234b84eb97934b87f2d43960fae1b6bd5d3d6944caf5154d6308d49d84dcfdde7c09eecf7b6ddaab79c3269a9d2511ba72d01d363fae862b5a83",
    "server_login_state": "30234f3b8cead1e011aa7dfeaae19b64913115daaa46f3cfd033c2a64fdd0a3959e62584463cf961b0471a6aff255eb0537edafef843dd59145ae1a96536b42476799bfed1b5332d0547740d550554fdf83b2fa13ef9850c8664a6932e7da165b629fb87a8993b3dca588a96199e5e5d5454e4597d60482390925ecece9f62fd87a6422c13f1ed7bc5b844ebb29f7b35a2230d9a4d798763d91feb7f2be228b6c46277fd8d9589066c3c656d7daf75c71ce257ff9c7b7c8d017cc5dc766858c1",
    "password_file": "66723c5c39695106d654570842a1edab79711a36ea4f34f65078b8c35731ea494d10c64e8239e9ed8a476faf6a4df44dd60a58fb0036ef65d5241541c7ca87aa050a7ea198c68d490d02f23419d0e002c7819805f8c9a6517a062d67a2de8b4df4a4b1f3c2c54257b91a0d87db527505428cbee4b6139e653160d44418f2110cedf21caa38e4cfbef0a7e5254082231d0b0dd056ff9014f2fa313e2107925dd8e69e45c126b8dae8c00567da34d09c8658aa7acab6e2fcb43359b263b4642773",
    "export_key": "f529f81953f783863c758dc677dc5673d39e3b17508c5ccff96a3bb8dc29b3d09966c6b8cb11afe53ac1784b3768d8789d47c85a300ec2431a4b48b63d0724fc",
    "session_key": "87a6422c13f1ed7bc5b844ebb29f7b35a2230d9a4d798763d91feb7f2be228b6c46277fd8d9589066c3c656d7daf75c71ce257ff9c7b7c8d017cc5dc766858c1"
}
"#;

#[cfg(feature = "ristretto255")]
static TEST_VECTOR_RISTRETTO255_P256: &str = r#"
{
    "client_s_pk": "96860d1458e14e8724abc569401bcd1b6bcfeddf09742103d760a6014804cc73",
    "client_s_sk": "0daf879c98ee31788e0014af07cebe6ff594ea3c4f6e308abcc2bb878b8fa605",
    "client_e_pk": "5a049d36bf732157b108dbfc9230a9e67fea0020f16035856c10ca81d8930f07",
    "client_e_sk": "b1683ccba5ced8986407ca6f6047749a239418ebe1bde10c793db752e6980c06",
    "server_s_pk": "12396a13fddef61cf0134aa4c2a6aaf3d1be57cb13ea4f4b9838d71fc54ee80c",
    "server_s_sk": "0f383b8fc12a075e1625771cb0e5dbe415f11f5bf1782b890c72c079214db30d",
    "server_e_pk": "922dc5a69f7cad85dd41191458f4964176c47dd563d02bfd49c3023329b3ec6c",
    "server_e_sk": "02ea163c9f6e9178774981e0c1e85f15279bfedc3dda8e6d61d29a3a6cb7100c",
    "fake_sk": "85dd0108f49dfba87cc20ddbf26e50fa2f75617eadd79f981166918dd46d0b07",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "0c4bce66bf65a8546ef873df3753d1d7be8b03c7117e4db915db6c39e8e2ba3c",
    "oprf_seed": "189debd660e17b3e4bf4e867d341715e9106d1c8fe50f1c7494b844f84581520",
    "masking_nonce": "cf06408b0fb43754f84212958c57c9f1f80ee9c286f09f4a8abb0df17a34f5c7fb0678eb323d4c08bf48261066876c41e552f0fa0597bcf72723745084074c33",
    "envelope_nonce": "48485d8f1020b7a37c39b1d30b32a8e1627f090602bc6d252210feced34f5380",
    "client_nonce": "2299b1cbada1e9f1aab6ae243db020674b38e3c3d9d48c09a77e68cb5a3dbc89",
    "server_nonce": "e930041050fbfe8ee81dc9769d9b70ef4bc1aa214fcc816566a94c216dd25a1b",
    "context": "636f6e74657874",
    "registration_request": "03bd2e315c39a7f0262844c53d8474cf45ff0eb1702b583f190b902b80dd636211",
    "registration_response": "0295b6e042acf53567b5e0c33f6ef78867387f97be9cfa032d63dd59b0a3bbe69612396a13fddef61cf0134aa4c2a6aaf3d1be57cb13ea4f4b9838d71fc54ee80c",
    "registration_upload": "1cbf711b9e1dff7c2aaf72a2b6f1539575829b8810bfe226e24fbbefbcd2894dc919828b717bfe9b990b34447ae288e858d92188d447aeed5e567d22145b3d4c0daf879c98ee31788e0014af07cebe6ff594ea3c4f6e308abcc2bb878b8fa6052b8c9a902bbc1e1ebc7ddfe5bc8d8f0373643ebc8aa14068cfd59023c08a9c2b",
    "credential_request": "03bd2e315c39a7f0262844c53d8474cf45ff0eb1702b583f190b902b80dd6362112299b1cbada1e9f1aab6ae243db020674b38e3c3d9d48c09a77e68cb5a3dbc898e49984d760ede86d52699fa452d5297c4939007ce7aa197374e1048a6035d46",
    "credential_response": "0295b6e042acf53567b5e0c33f6ef78867387f97be9cfa032d63dd59b0a3bbe696cf06408b0fb43754f84212958c57c9f1f80ee9c286f09f4a8abb0df17a34f5c7537e2b0fddecff2140a12fff250cf71dc909d80397aef7ef4b127762dcfcc718c7023064997840e593afea87022470bdee8954a0640992403f8ec4a14b7c845d49010dae5bf99c6db15c34fb354c3c385c7dc45853ec9b1dcf9afab48281a8cb02ea163c9f6e9178774981e0c1e85f15279bfedc3dda8e6d61d29a3a6cb7100caa4daad8755b1ffb28695e317278215428bd4d1ecd969e62059a93fba1af40018caf3978ca1456277ec344116a4f189a32c91fd28c1d23cc7be0e80e10a57422",
    "credential_finalization": "4db5e4b91877f7bcee7d63b015793559fc788e7196b3c53f34b63ff8bf9bb91d",
    "client_registration_state": "0c4bce66bf65a8546ef873df3753d1d7be8b03c7117e4db915db6c39e8e2ba3c03bd2e315c39a7f0262844c53d8474cf45ff0eb1702b583f190b902b80dd636211",
    "client_login_state": "0c4bce66bf65a8546ef873df3753d1d7be8b03c7117e4db915db6c39e8e2ba3c03bd2e315c39a7f0262844c53d8474cf45ff0eb1702b583f190b902b80dd6362112299b1cbada1e9f1aab6ae243db020674b38e3c3d9d48c09a77e68cb5a3dbc898e49984d760ede86d52699fa452d5297c4939007ce7aa197374e1048a6035d46f62b5e93fa459dcdf3ee17e3e2447f0809e85f15b17e46d06f8894baa3c0e20a2299b1cbada1e9f1aab6ae243db020674b38e3c3d9d48c09a77e68cb5a3dbc89",
    "server_login_state": "3a31ecc4fdee405375e58df2e9f4fe25965859cb6173d7e6709fb24fd2698d53933d8bc443c8860da1d4096d8b2ea2a5c651d744a22da9b2c9f73ff0ad17fc0b5c0df6a11fedcc36dcd1173ab7e55f3f2627d399e464ec29671cee7566d6d912",
    "password_file": "1cbf711b9e1dff7c2aaf72a2b6f1539575829b8810bfe226e24fbbefbcd2894dc919828b717bfe9b990b34447ae288e858d92188d447aeed5e567d22145b3d4c0daf879c98ee31788e0014af07cebe6ff594ea3c4f6e308abcc2bb878b8fa6052b8c9a902bbc1e1ebc7ddfe5bc8d8f0373643ebc8aa14068cfd59023c08a9c2b",
    "export_key": "e785a045278a7fa931ef1f8910d0ba85dc3d6c7537dfe5a9f4bd7bfa317e1762",
    "session_key": "5c0df6a11fedcc36dcd1173ab7e55f3f2627d399e464ec29671cee7566d6d912"
}
"#;

#[cfg(feature = "ristretto255")]
static TEST_VECTOR_RISTRETTO255_P384: &str = r#"
{
    "client_s_pk": "4e2c60441878e85783c9800406ebd5e7e881dff80616d03b567947b82e5c7a57",
    "client_s_sk": "dce2e0634b405f06caf29c1265fe223cb534535bb7c27cdf2e12f6291b39c00a",
    "client_e_pk": "5e49aef294f9dce3c6522d66805d864337dc0fadfe88fe2e0f037c32c105a82d",
    "client_e_sk": "dfb45d06440e1cbcdda340d9582de46237c44413f05b40339a6187115bfcc404",
    "server_s_pk": "543f5a039f83eacc40c62fc5c5acecfd4650873dce4d6dbceb04a327baf86f2f",
    "server_s_sk": "0c0d7c18c7ff0860f5d6648d5ebea2fec4a3cff45d436f3be5aa680608e7f605",
    "server_e_pk": "e063a148282a82945d5ea35b9bcbc4fdacc175f73bee2ba4d0f72e7b3aec1338",
    "server_e_sk": "a50f4953424642bcfc681fd4b6f8f9c71bd4a052bbc5f46047d22727da26af0b",
    "fake_sk": "4305d00aa1b28f5fa20a4c939c97ce51150b948f87307191d5febc66ea2ea606",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "ebb318997438ae2f5e3238f03b75b975c15574221dc5366b28fd9f3401230420fbdaea1919df12380f986f7c6dcaee4d",
    "oprf_seed": "f28b12958dfe452b0819cc0df743666cb27c9f7d5b07818de0c79b21bbc8a3987257a81a1c57c21bccebd2af0e6fbe94",
    "masking_nonce": "cbe822a5e60816a19d6b707308876147e4c0be5436e0658802c88d257f9523f873c3c248f599aa0854a047ff227676b2ef036e847aad26113df99cf494ada455",
    "envelope_nonce": "f5af3d4e880da0abaf85dfb4da5b7b23549c83c90bffbce20fc84d8a22014b00",
    "client_nonce": "97cb195111c2bd433a1d1cafed854d9039936ae9559942cc701dafcb9dd51524",
    "server_nonce": "4b15d916d5fb9bfc3e0a110dfcade484e4c98f6bebd9860f7b7956880a806efe",
    "context": "636f6e74657874",
    "registration_request": "0335ded8e0d44b32ef46a01d530365171b4a0656bc97362c731e5228c8d82cc66a7be5bbb4af2df2c69fab5946951bddba",
    "registration_response": "037afbd911baaeaf20b8f81a323b9394b0483b622b92a02d19c6956b229264f645b2c82d42207a43c14445c9b77d5812d1543f5a039f83eacc40c62fc5c5acecfd4650873dce4d6dbceb04a327baf86f2f",
    "registration_upload": "f0009445fd1d418db028788a28b21992786ad8b697a2a8baebe30547733f9143bdb7d21117484fed96d101d15e148c5a63623687e4844834c2d22a48913aaf0feeeb831dfb5ca91a91be5d2d7d46680fdce2e0634b405f06caf29c1265fe223cb534535bb7c27cdf2e12f6291b39c00a659cfc677db765aa62682b8095a1ab39dcd73ddbe49b668eb63f7bd5f4396f6e6b40ad646ebbb1af13b3589b73d69371",
    "credential_request": "0335ded8e0d44b32ef46a01d530365171b4a0656bc97362c731e5228c8d82cc66a7be5bbb4af2df2c69fab5946951bddba97cb195111c2bd433a1d1cafed854d9039936ae9559942cc701dafcb9dd51524962707435be9a80153f6e4ec9ebc2440163ba73c232a418c958e25e77aa85863",
    "credential_response": "037afbd911baaeaf20b8f81a323b9394b0483b622b92a02d19c6956b229264f645b2c82d42207a43c14445c9b77d5812d1cbe822a5e60816a19d6b707308876147e4c0be5436e0658802c88d257f9523f8020480a4ed9d375068b49232966147564a442f1dfe5cab652453c60a29d384863194bfb106012b50ca488869460200f16360b01a1337cfe3f03e118eb48bbba6ccd4c56eb181539277bc2b72f1dc15afabecd59885ca66fe42595382d085692bbd0278b83759deb8230883bf2c3181eea50f4953424642bcfc681fd4b6f8f9c71bd4a052bbc5f46047d22727da26af0b3405b452e6d6dabfe98ba19092987ebbfae106116b40a0f65dacbd709ac4f7756c3e6d1965246cca600fc88be6abd548299f728d756bc966b3021c2fb1a8c43a0b53a886a9594c93b3975536e59c71e1",
    "credential_finalization": "4adf8d88cfd65aeec5b01e53cb0c791fba6239a7140994105b2d43c30d1921e9f3510d03c6f097f1d170cb7ae665e7cf",
    "client_registration_state": "ebb318997438ae2f5e3238f03b75b975c15574221dc5366b28fd9f3401230420fbdaea1919df12380f986f7c6dcaee4d0335ded8e0d44b32ef46a01d530365171b4a0656bc97362c731e5228c8d82cc66a7be5bbb4af2df2c69fab5946951bddba",
    "client_login_state": "ebb318997438ae2f5e3238f03b75b975c15574221dc5366b28fd9f3401230420fbdaea1919df12380f986f7c6dcaee4d0335ded8e0d44b32ef46a01d530365171b4a0656bc97362c731e5228c8d82cc66a7be5bbb4af2df2c69fab5946951bddba97cb195111c2bd433a1d1cafed854d9039936ae9559942cc701dafcb9dd51524962707435be9a80153f6e4ec9ebc2440163ba73c232a418c958e25e77aa85863dea54ac07a062a89450b947cd563d9b3c7bbec1460212b78c21d509f45f1310997cb195111c2bd433a1d1cafed854d9039936ae9559942cc701dafcb9dd51524",
    "server_login_state": "ed32e9f19429767a8297ece379a7f2ca317543fa601f9d575577c4004a22240814814df482a466fb9456f2a8ea175f61d589b838e49246593d6fa7e2f41335961f0d890be0ff0f196d6c54b0ea909e9833cce7f57c20cdde215c23d0107bb32173700ee1021612393ecb5a619d95774b74ac82c7a2243ea01091aa34059bb6b93763af9e3270d17e15d31e2c36a22c1d",
    "password_file": "f0009445fd1d418db028788a28b21992786ad8b697a2a8baebe30547733f9143bdb7d21117484fed96d101d15e148c5a63623687e4844834c2d22a48913aaf0feeeb831dfb5ca91a91be5d2d7d46680fdce2e0634b405f06caf29c1265fe223cb534535bb7c27cdf2e12f6291b39c00a659cfc677db765aa62682b8095a1ab39dcd73ddbe49b668eb63f7bd5f4396f6e6b40ad646ebbb1af13b3589b73d69371",
    "export_key": "d610a300a933f98e70927f01cd97b7aead44e98b1405c40b42c15e25e20dc0ce237eca5cc623d2f7f185aa3db7846cf1",
    "session_key": "73700ee1021612393ecb5a619d95774b74ac82c7a2243ea01091aa34059bb6b93763af9e3270d17e15d31e2c36a22c1d"
}
"#;

#[cfg(feature = "ristretto255")]
static TEST_VECTOR_RISTRETTO255_P521: &str = r#"
{
    "client_s_pk": "2077405e985ad5bf0089c6b3dd78f85b36c1e01a67d3f36c8c0d0a1c5aac0938",
    "client_s_sk": "9df2f24beaa7e529640b970ac597d6e3456ec9b7d36a2b890a97ab802ca90e05",
    "client_e_pk": "78d7f3173e896f289a86d7c0180bf1bb8acc05d8ff615d643709e4aa410d697f",
    "client_e_sk": "e8b675d6e47400715562781ba47471f4600c113ef313137e2ba04052af1fe301",
    "server_s_pk": "ceb112c998aab8a83098be0e488827919ced0386595c4e598c088daab9500c0f",
    "server_s_sk": "b3deb77be0f7431eb8c9658b7be5d2680629b69f605e72f4faeddc23e6ad3f06",
    "server_e_pk": "8aa2e0e651a2ea09d6d648f3370307b142b5ac1076840983267af4d436febf6f",
    "server_e_sk": "139a6f95f63c6e3cb8e461e442f6ec04e2aa1afe4279a7e4bce4f4a4bc9bc607",
    "fake_sk": "b4b60e9eabe6239493fed00fe73cee20806fa99d602de5cf7eda5f0f715a8a0d",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "010c7b8374e35b248945cb1a86effd5884bec434ab18fe4ade26d9b558db0d38a1520fb5f644013595a21bf94e76a334aa31002779e40bf7e9e714d727262db38a17",
    "oprf_seed": "c16596e94bd594eb328ee761e0a1887bd78fd720c7ca3c5c051372c99d81dc7876d942ea2ff06a350f923435a9c6f477e118f6d4d457435525453851d8d6c183",
    "masking_nonce": "c9a63bd144989b19235a95f287bcec34b3205d56665cf1150e6f284176c08e35116524ea6c2fdcace39cec4da3a7cff8badb0ed2d7b69b09f60d17c0c975ab40",
    "envelope_nonce": "d6bf1ed3a9a7a01117601c9ee895b920796c37277e88aae79e5c82283ba9b144",
    "client_nonce": "9e338a60e944810d17531826051dc6e37924c212827139254b69a0c865dcd068",
    "server_nonce": "c84b844b04286f186b2aeebc4103807f557787bdab9b0c753b6cc4f8bcce2ac9",
    "context": "636f6e74657874",
    "registration_request": "03013da5403d8197b44fb2511fc40b268d4a2a52a418fab3547a1faef30ca5b3f99e8656c431938a3ca130401081bcde4c283a222bc4750990c1a9780cb3a5b8b07604",
    "registration_response": "03018762c323bed064ffa56ce959b15a7ecf460a2d683fa9a77a4a3a9d750bf078e00a2d2655adff6445095c9923d430748c18df1d58b6983b77e90f777cb7be43bf6bceb112c998aab8a83098be0e488827919ced0386595c4e598c088daab9500c0f",
    "registration_upload": "9412c7cd4602e95843873e81641acb7d7d848f296e8bd13e2aabe2b6f765e057e57249cd9e4a3933b6e041ee23d5343de013c8125abad89b3cfab53b3d814acff0b7ad644545cb5577014c9563e9103ae0f945dabc9851ad8c5f619e6d1bd9d89df2f24beaa7e529640b970ac597d6e3456ec9b7d36a2b890a97ab802ca90e054a6eda0c3fd684af13828a9d98fcd636784bc6d73b969bd5cfc926e89846a14b8d71d342d5f573fb1c05a88849292c1bdf4d93577e7a2529ae169283dd4ea6d1",
    "credential_request": "03013da5403d8197b44fb2511fc40b268d4a2a52a418fab3547a1faef30ca5b3f99e8656c431938a3ca130401081bcde4c283a222bc4750990c1a9780cb3a5b8b076049e338a60e944810d17531826051dc6e37924c212827139254b69a0c865dcd068544557ef4fc18374150778acd6c7ad3626ca7616858e4e523cdf7472acf1aa5a",
    "credential_response": "03018762c323bed064ffa56ce959b15a7ecf460a2d683fa9a77a4a3a9d750bf078e00a2d2655adff6445095c9923d430748c18df1d58b6983b77e90f777cb7be43bf6bc9a63bd144989b19235a95f287bcec34b3205d56665cf1150e6f284176c08e35afaa80b5a0b5aae20ca99f6552c27341906a796b668b21882317fd46008d3e34b60ecec015fc91d71639d55f0070c4d2f748b152e72e1b17400b0dc266c188940b3c6c86fbe086ac2c28bef718ecb050c6c56317a71913fc5f193ccebc5a1d881302115f3589b7c1788d33c81f63d839012660e48f7b942ecf7e909899a0593f139a6f95f63c6e3cb8e461e442f6ec04e2aa1afe4279a7e4bce4f4a4bc9bc607166ebcf6d93a36e8e2c0069c0c90e07ce34b49863dfd94e4d7cfa0ff1591bb11cbcd464e2b09cb09e3ea01cbc45ace33f673029cfd0692f974b66441bd7daba26ff9e877ac26a8bebb00b281c5d6299f1a4da87da6ec2585dcffa4c0b0273b06",
    "credential_finalization": "a7ea907ae7aef2265a82138a49d2c818f6bc5702989c2932a4336ab4138497f0aac9fcfc94edd4f686d8e693c11dd0351fb8c88514c93f2373f04f73bbf5bf94",
    "client_registration_state": "010c7b8374e35b248945cb1a86effd5884bec434ab18fe4ade26d9b558db0d38a1520fb5f644013595a21bf94e76a334aa31002779e40bf7e9e714d727262db38a1703013da5403d8197b44fb2511fc40b268d4a2a52a418fab3547a1faef30ca5b3f99e8656c431938a3ca130401081bcde4c283a222bc4750990c1a9780cb3a5b8b07604",
    "client_login_state": "010c7b8374e35b248945cb1a86effd5884bec434ab18fe4ade26d9b558db0d38a1520fb5f644013595a21bf94e76a334aa31002779e40bf7e9e714d727262db38a1703013da5403d8197b44fb2511fc40b268d4a2a52a418fab3547a1faef30ca5b3f99e8656c431938a3ca130401081bcde4c283a222bc4750990c1a9780cb3a5b8b076049e338a60e944810d17531826051dc6e37924c212827139254b69a0c865dcd068544557ef4fc18374150778acd6c7ad3626ca7616858e4e523cdf7472acf1aa5a10bf3935bdc04f2133d0eb17c6a84ff0d901431c95450328ba1692b5f80ea0049e338a60e944810d17531826051dc6e37924c212827139254b69a0c865dcd068",
    "server_login_state": "1095ed5a9ff61d8633914d4f47003116b72b73738e274dcee2a8c5e71abb3365d19da34866a5ab3781e48fc340a0cbaf83872646ead0284eba6629b4a6591dbca924a83fe5c6b3cf0e7a9377f12af861ca7666c4506d91bed3093cb7ecec78e4dbf36aecdde558a819965ae22f2b82d3d26eb27bbd4b7ee679100ae4b228d7079871a24403fc269146c1600a6820334b444cacdac99c1217de12502bc15500b95bb77c290148aeaa71dcae5ef921773128b69f94e1d981cacea36e2898bc612a",
    "password_file": "9412c7cd4602e95843873e81641acb7d7d848f296e8bd13e2aabe2b6f765e057e57249cd9e4a3933b6e041ee23d5343de013c8125abad89b3cfab53b3d814acff0b7ad644545cb5577014c9563e9103ae0f945dabc9851ad8c5f619e6d1bd9d89df2f24beaa7e529640b970ac597d6e3456ec9b7d36a2b890a97ab802ca90e054a6eda0c3fd684af13828a9d98fcd636784bc6d73b969bd5cfc926e89846a14b8d71d342d5f573fb1c05a88849292c1bdf4d93577e7a2529ae169283dd4ea6d1",
    "export_key": "fa596949b4dd6d8ddf9d75f9298904422b034b9e9bbcbaa977e7cb70d93373cee465c92a0a2897aa60f166ec15706efd73dd00a0d53375e135cf8e760a659965",
    "session_key": "9871a24403fc269146c1600a6820334b444cacdac99c1217de12502bc15500b95bb77c290148aeaa71dcae5ef921773128b69f94e1d981cacea36e2898bc612a"
}
"#;

static TEST_VECTOR_P256: &str = r#"
{
    "client_s_pk": "02c2e8f49855c9f783a851dcefbd8987ce90d8e85cf191c7aa475950c771a1a392",
    "client_s_sk": "5ae546ad6e00e6434492285305f0a087a2c0fd4c70d867c87e59aa18df7168d1",
    "client_e_pk": "039f4ec8755bb55f7b815f08fdda9da51a05edbc22025a3d4f5ff7b6ddcdecf847",
    "client_e_sk": "efaaaad9104f1eaf18014d70ac70a61073cb1cf471b02b89dc16f6a338c9aac5",
    "server_s_pk": "03923edfe871973dc0e549692526eeed3967fec567cd4ccba30ea3696614e5c9d6",
    "server_s_sk": "21cbcff4c92ceb1acade2eccf301c7defe655f55d7354d1326a1259de4f6afc9",
    "server_e_pk": "037ae15922e04a5e1d288494176932c8b4defae649eae82dd40876e9bc5afe7236",
    "server_e_sk": "6162bef0095725abad6b72a7e3e64599fc1b5df9064e7ce40766fb0ac7e7964e",
    "fake_sk": "da212727cf2f6f38c536014c883c22c35cb9efc4a27228563d364ab4d12ec5fa",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "9d781bd63f99a84b819c99c7ce497e6288f9122834048945997f2d76147efde4",
    "oprf_seed": "b09d533d8960cb471b05a36882927adbcbe7ef600ba74e1af31d1486230e8adf",
    "masking_nonce": "2590367466a06ccc880d11398181d1c302144c05e4ac5a0528ef3336fc26e4f13e45edf9d43d0d4e9c6ec08536895968111c4d23f6f9ecc6734999e7466ae9c5",
    "envelope_nonce": "aacb6bb400ab28256d2e54d9eca742857f6d5e29c92b7b0044c95215b6db4892",
    "client_nonce": "27e8fe90451e2934e8dc358fe30ba07d15175e2c70a6fda88b1bab732e80c140",
    "server_nonce": "fefe1c85ec03f03f8ab66d4037a661f677954cda1695765381fe56ee553275bf",
    "context": "636f6e74657874",
    "registration_request": "03493e2bda2f5ce79408178469ddb1424bd6880b796945caf97eca254091493c4f",
    "registration_response": "03f66c48699b84e856f2110cb770c46c59fd75831d5fe0a4b1c164a2b13272798503923edfe871973dc0e549692526eeed3967fec567cd4ccba30ea3696614e5c9d6",
    "registration_upload": "033975e189b8c31851993d7b38abf30c0fc666ab8fb93e5ad8581a035fbeb60283bf546c8d3d8f1759d16dd4db3653c45248c8420703beba195304e1f5600cded75ae546ad6e00e6434492285305f0a087a2c0fd4c70d867c87e59aa18df7168d107ed74db82d4ef8d7268bc2dbcb146681347aafd7ed9bb8e78399766d753688f",
    "credential_request": "03493e2bda2f5ce79408178469ddb1424bd6880b796945caf97eca254091493c4f27e8fe90451e2934e8dc358fe30ba07d15175e2c70a6fda88b1bab732e80c140026a65dd93748b6d545fe24839cdcba11db412e3649d704e88a0a24b3600671a77",
    "credential_response": "03f66c48699b84e856f2110cb770c46c59fd75831d5fe0a4b1c164a2b1327279852590367466a06ccc880d11398181d1c302144c05e4ac5a0528ef3336fc26e4f1fc2abe70c70551c2922019c4e8aa092a32492dd50e0be8aaa44913d2c7253c8255ffec37fd5612b651b7ac26e5f2aeebb0caeddae68e8dd49aa0ee522dce90900da3537d718ae15954a5b5c2678d6efa31c846f6bd46605b56fdf70a448c3143c46162bef0095725abad6b72a7e3e64599fc1b5df9064e7ce40766fb0ac7e7964e03f609f0b7575cf87465a11900d2ac4e91f8097f34c5668b974e55af50ae1ddf4895d3f8760cfd8699c9bf6ea54fdaaa7af049e2ec205505ab33fad7c0ce680c14",
    "credential_finalization": "e6aa42333906d3294b5f6f153c746974bfbb3f9d6eee94fabff2757994ae0828",
    "client_registration_state": "9d781bd63f99a84b819c99c7ce497e6288f9122834048945997f2d76147efde403493e2bda2f5ce79408178469ddb1424bd6880b796945caf97eca254091493c4f",
    "client_login_state": "9d781bd63f99a84b819c99c7ce497e6288f9122834048945997f2d76147efde403493e2bda2f5ce79408178469ddb1424bd6880b796945caf97eca254091493c4f27e8fe90451e2934e8dc358fe30ba07d15175e2c70a6fda88b1bab732e80c140026a65dd93748b6d545fe24839cdcba11db412e3649d704e88a0a24b3600671a77d406726833e0a9451751dbb50af5764e45187906840cdfe814282d5aa0efa95527e8fe90451e2934e8dc358fe30ba07d15175e2c70a6fda88b1bab732e80c140",
    "server_login_state": "dab1a874a0f1db74fa0c9526e6b55b2c4843f26d181b410278b76f1a5a65b0b960e1c6fa8b17cca50f4dc45d53a7f5ef975e31406b31418b87d2d9cab0991e2326ca86363e475842c54ce152c8075b5d633ce3d44f3123bccfbb9a444833f6ed",
    "password_file": "033975e189b8c31851993d7b38abf30c0fc666ab8fb93e5ad8581a035fbeb60283bf546c8d3d8f1759d16dd4db3653c45248c8420703beba195304e1f5600cded75ae546ad6e00e6434492285305f0a087a2c0fd4c70d867c87e59aa18df7168d107ed74db82d4ef8d7268bc2dbcb146681347aafd7ed9bb8e78399766d753688f",
    "export_key": "5b8816c59a360431bf7afe5d93644136617c2d25bd67673785cc593cc40b1e35",
    "session_key": "26ca86363e475842c54ce152c8075b5d633ce3d44f3123bccfbb9a444833f6ed"
}
"#;

static TEST_VECTOR_P256_P384: &str = r#"
{
    "client_s_pk": "0300ffa27e9e1c07e726f3446303fd6e169a824e938be7142c5d57c966c41f48cd",
    "client_s_sk": "63bcffa26f32783271d78d3b84dbdefda3a4533bc11d7ce73de145c6a80ea659",
    "client_e_pk": "03f46e7129db840987843f76ec3c1521c7c753740bcb22f00b37b2cf52a9dc5974",
    "client_e_sk": "502bd0e6474522e6c0572f81e4d7ba6cb87430aa34bad5eb7509d0dd5f2aa01e",
    "server_s_pk": "02ec3bb6cdaa17e7e0872a57e2c89e2647983bced0b86ffd0d7fcdfa304f90e03f",
    "server_s_sk": "47965063ae881466b08ba9e96cf1fc48d6bfb7e23d0a6bac30498b114dfc5a54",
    "server_e_pk": "0304fc747fa5640c258d4846be2f6529ad35d61782f3e45a48efd6d6dbd1cedf07",
    "server_e_sk": "1bdbabc050b6f5d59d01b02a03d187b0954c8a9341b696cb60c49a8511ab9712",
    "fake_sk": "cf19797c598f15e3cddc5e01388999e85ca49ef729dc2e8ac10d8f10ff59d2c7",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "ef8bb36f1ad0921181910a8a1a497e18c1192264c5389f4e2cdc270d322e0a0c9b74284ee2af3d476cc7893fe7597d01",
    "oprf_seed": "1f9b1338fb64584fdd2ef104c15a15a75cd9b922dedcdc4037409c4dd69c5aee2ecada1652d380f3335352baf92974c0",
    "masking_nonce": "889e0b260347814b97b922fca5c96f89e3974776f2d6486399d17f7634d90d3a7fe5cecf435269a054b3b24d968c20c586ead3fe3b529b7a129f2cd75bb11645",
    "envelope_nonce": "df7b5518d79f0c5748cbe6ba671786680e895ab470e8a8399018ab4a245e308d",
    "client_nonce": "ed8e76fe71017d89879ec9580cbee48e1dff47f05d52e4e7655ea65a813897a5",
    "server_nonce": "92fd03780d2b4035ebe83915fe37fa650477ac7d20a8d83b553d43a569beb584",
    "context": "636f6e74657874",
    "registration_request": "03f98a111741a24c1ad90f15985ac345636e631cddde1d05dd8d7f5fc00e57483c5504f390e8bda613345aa89d3493bed0",
    "registration_response": "029daa00653cd0b4f9ac0b9e5640e6c6b608543e02955a40de853bcc530f3180bdd52991e528e570e650a6c50d6ed06b5602ec3bb6cdaa17e7e0872a57e2c89e2647983bced0b86ffd0d7fcdfa304f90e03f",
    "registration_upload": "020b1901303ffe1ea63379d6e310d39712521ca43609a8bcfa4db28866411355862282ab14133a5a1c095c9af7b4ffc61aa5371b3ed762a24f94448e6ca0bb87b7c0ce558dce762c73aeb6ba1f4b56681363bcffa26f32783271d78d3b84dbdefda3a4533bc11d7ce73de145c6a80ea659033f437455f7be8b3ed47fd871057beb6e30785364bb586c074c0c4b475d17129383f531042647448933a17914cc2b61",
    "credential_request": "03f98a111741a24c1ad90f15985ac345636e631cddde1d05dd8d7f5fc00e57483c5504f390e8bda613345aa89d3493bed0ed8e76fe71017d89879ec9580cbee48e1dff47f05d52e4e7655ea65a813897a5027204ea166787e2d7766ae8101143be5283f79ba8107b33f8db03339d72970597",
    "credential_response": "029daa00653cd0b4f9ac0b9e5640e6c6b608543e02955a40de853bcc530f3180bdd52991e528e570e650a6c50d6ed06b56889e0b260347814b97b922fca5c96f89e3974776f2d6486399d17f7634d90d3a68490a295fd49a787786c1db2bb1e31e38b56e8151e958f8770041746fb5496696be499beb470f04a2ea7074502918277c024cd785b534de8ced805918a2a0bce17eded3cf11e6fc2e54d67d641632fe1d2fb56bf641540c34a023d32913fa9eddfad0aadd9fddfbe1c9af4a96da04887b1bdbabc050b6f5d59d01b02a03d187b0954c8a9341b696cb60c49a8511ab971202d56b40e364d4947215d3befb46b114cedd8ae3f75f9d38767a7cc87315e3473d94ca79a51b45a5bdc935be80d9bf697d384ded48d5d5b9bdb85432e3d85ee5aba8729d55ec530313d28ca3208090ce11",
    "credential_finalization": "6ab06573cb9bb92a5e4ae2c6623bffc5463f94b81c2d38c1416e4dce35c32e49d2225ac5957a9913e1badcab819f35af",
    "client_registration_state": "ef8bb36f1ad0921181910a8a1a497e18c1192264c5389f4e2cdc270d322e0a0c9b74284ee2af3d476cc7893fe7597d0103f98a111741a24c1ad90f15985ac345636e631cddde1d05dd8d7f5fc00e57483c5504f390e8bda613345aa89d3493bed0",
    "client_login_state": "ef8bb36f1ad0921181910a8a1a497e18c1192264c5389f4e2cdc270d322e0a0c9b74284ee2af3d476cc7893fe7597d0103f98a111741a24c1ad90f15985ac345636e631cddde1d05dd8d7f5fc00e57483c5504f390e8bda613345aa89d3493bed0ed8e76fe71017d89879ec9580cbee48e1dff47f05d52e4e7655ea65a813897a5027204ea166787e2d7766ae8101143be5283f79ba8107b33f8db03339d72970597de1f1c0591eaeacea4eaddf441e4f78007347895f79775d836aeef03269ef260ed8e76fe71017d89879ec9580cbee48e1dff47f05d52e4e7655ea65a813897a5",
    "server_login_state": "4af2c9dc93a9681293550723eccabed75aec6fc72b688bca2c68d8bdd8fe21c66b94753b04b4f9b9d1dfb3661397ca712f8990baea7679888d3045640cf0f17c98a6704146f5e4f6cfa2c764532fa1bfe78bfdbda526213af50d2c6b8dbd83eeb78c21b07ad43485cacaa2bb6743962ea4d450fab27f9d3848b4d4f5a50ecea2ce3fcf3007867d8e708182d76f97ba2a",
    "password_file": "020b1901303ffe1ea63379d6e310d39712521ca43609a8bcfa4db28866411355862282ab14133a5a1c095c9af7b4ffc61aa5371b3ed762a24f94448e6ca0bb87b7c0ce558dce762c73aeb6ba1f4b56681363bcffa26f32783271d78d3b84dbdefda3a4533bc11d7ce73de145c6a80ea659033f437455f7be8b3ed47fd871057beb6e30785364bb586c074c0c4b475d17129383f531042647448933a17914cc2b61",
    "export_key": "f79bdebcf6534e9fbb727a295edb160e952a8bda27b0e1d3f2379ece6bde6fc5d0d4486e2a37ef41d2fd1d0fe1719fc9",
    "session_key": "b78c21b07ad43485cacaa2bb6743962ea4d450fab27f9d3848b4d4f5a50ecea2ce3fcf3007867d8e708182d76f97ba2a"
}
"#;

static TEST_VECTOR_P256_P521: &str = r#"
{
    "client_s_pk": "026ace2e49b33570703571fc51510894ac20a900fbec77b9384053bf6953d80f7a",
    "client_s_sk": "93193996fc683bc53bc810c2e6347be88b58537175b40c9350d876327d834699",
    "client_e_pk": "026000d38af4e10ca2ff27b6705b5088289e67a7665fa28a2461e002d1e3b2d171",
    "client_e_sk": "ca36f9168931b0ef649e9096404d6c3937158e71ab3c7fc9d1072cc7103c8d4c",
    "server_s_pk": "0380d85bc1efc536b509143d572de289762daf71860433451581ca32a62f709cdb",
    "server_s_sk": "8fc0c570b66d932d9dea28dba6d0f2d81e88620bdc8f56508224a43d0024f011",
    "server_e_pk": "02322cff1c6011018298628d2ecaca4f73ba1fc1c11233cf56e1524c948a29096b",
    "server_e_sk": "2ba0d48065ff3610831535fb5b5f3ce1d153b7e4512cd2f8a59b343235fa911e",
    "fake_sk": "1f034fa4e14f44ae1d40af052d1adef642f6e389680ee655cf42191a7aacff63",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "006c59fb00b2b9e8c0cca65798ff2509b47eb38da1ba33c06262e8430f3a905198b2f7cc1e7bb1211ca7503b17fb566843990798f8b6210eadc32699a12565348717",
    "oprf_seed": "092cd0f16c4ad4c7ee1e6ab605f4008d3dae6cff6f4769791cbedb13945f9654ef854dc5e9b20ccd5fda5f94a71637f1948d217d19fd3891572db046753c943d",
    "masking_nonce": "cee3d0942b4ea18897d4193c6f5b3d9b66681e29485c7187f7a4b1c7907461da52913d00dcd654803bc2b93b10bb0bfd4ecdb81a7895c7e63e3f6f75f2fdb5f3",
    "envelope_nonce": "fb978c35cf73e93d041bad8ab733f7a8858ea749bef09d96c49da4e806d57792",
    "client_nonce": "fdaac5db3c4711ef0735776dc16567b7319b4e86bcf21f547db420bbe3d01934",
    "server_nonce": "ba8c5c8acdcc7205afe3fca2fee68359252ed71028be3a5e3f84c915ff7d26ad",
    "context": "636f6e74657874",
    "registration_request": "0300509a38e769a55f6ceb689b4459556992c37a6f7f89eef42a49d8d5c0f00e68af2f1c6b044e2237230b8366412800f9866f14165070a471248845ff6c6a480565fa",
    "registration_response": "0200f35180d7f7dabb1be52925409fbb9678212f1193f5e256aef0c369a1db8820d97efab733d734504482443c9f562414e3681fd966f8195c75880bd3bb79a46db6120380d85bc1efc536b509143d572de289762daf71860433451581ca32a62f709cdb",
    "registration_upload": "0318f78494899a7c291aaaedc7fbf05d19332aef15264174174cb734e922e7cc2390dc220ae3f36299752baf772327cdbd93d33894ba6236e9b2e3c2edf23e2664d73df7e901a5afde0ca7c808177469d12ac927f69c5b52a4aa7828f0ce106fce93193996fc683bc53bc810c2e6347be88b58537175b40c9350d876327d8346990cb18f0477ab23dcf468b9377f9772aa2f6328c32b8414fcba19a81cf61220f6f7e7cc321552abb3b2eda29a79500fb805fb1cf6abc02c0d633cc5393ad982e3",
    "credential_request": "0300509a38e769a55f6ceb689b4459556992c37a6f7f89eef42a49d8d5c0f00e68af2f1c6b044e2237230b8366412800f9866f14165070a471248845ff6c6a480565fafdaac5db3c4711ef0735776dc16567b7319b4e86bcf21f547db420bbe3d0193402b9e5cffa20267c414487855a45878c37f1fb32523354c1939a2bb4e1d65ce19c",
    "credential_response": "0200f35180d7f7dabb1be52925409fbb9678212f1193f5e256aef0c369a1db8820d97efab733d734504482443c9f562414e3681fd966f8195c75880bd3bb79a46db612cee3d0942b4ea18897d4193c6f5b3d9b66681e29485c7187f7a4b1c7907461da501d40c5438bade885fd9299d0ae51f131db73d1ff9f326bb02347a797910c20e0970b564f9cdb53f02a83cd8053ecf292bb4d55e8c6bef7f36fdc0e2ec4e7870195984eea5981b1d2adfc7de049964fbe0b1b81e0acacd58de67578364d3b7ac54e2dbb317351645fbee01b2e1a4423205766cf757b753f3b7dc71c283f3a286d2ba0d48065ff3610831535fb5b5f3ce1d153b7e4512cd2f8a59b343235fa911e02246522dbfcd7f638635e8ca6be8a8478bb099d3cfd5a84530e63511e2f7db261ed063eef80d616cde31cc32f1ad06ca519fbbd627955ec3559ad957204fd8e55498254852ef0b047af6f1c2ae0d67c5e5d764df846446eb6da09500252cb0991",
    "credential_finalization": "7f5422d1964671bda089ef02f1c71bb491edcae1a03eb1076c09364eec7fddebf86a2fa7e029f8e50ec2bd0021dcbccdc26ca57b060af6c29165120223253924",
    "client_registration_state": "006c59fb00b2b9e8c0cca65798ff2509b47eb38da1ba33c06262e8430f3a905198b2f7cc1e7bb1211ca7503b17fb566843990798f8b6210eadc32699a125653487170300509a38e769a55f6ceb689b4459556992c37a6f7f89eef42a49d8d5c0f00e68af2f1c6b044e2237230b8366412800f9866f14165070a471248845ff6c6a480565fa",
    "client_login_state": "006c59fb00b2b9e8c0cca65798ff2509b47eb38da1ba33c06262e8430f3a905198b2f7cc1e7bb1211ca7503b17fb566843990798f8b6210eadc32699a125653487170300509a38e769a55f6ceb689b4459556992c37a6f7f89eef42a49d8d5c0f00e68af2f1c6b044e2237230b8366412800f9866f14165070a471248845ff6c6a480565fafdaac5db3c4711ef0735776dc16567b7319b4e86bcf21f547db420bbe3d0193402b9e5cffa20267c414487855a45878c37f1fb32523354c1939a2bb4e1d65ce19cf48ba9205760a2ccf7038a73aba91ae78f52e7b611563ca4df9f0b12369124c5fdaac5db3c4711ef0735776dc16567b7319b4e86bcf21f547db420bbe3d01934",
    "server_login_state": "fde310fff92b130ee7f4f19d3bbc573726bf486a921a66a9fd5ae1d7ade3d832631cd04d0f63b0ad38854c4dd55f73c999aa8a3c7a5a4a5780174ac427cd690d56add666e24869df0f8356c662cf3b66c234d8318294ce5c46175db05fbc8d06ccd092c247a299685f603046ea43ce6dc0193a059a7c5e8ae3fd1a01eb2554b5862a1d39e424f021ba5a20c779b29ce8dc379eac186133ec9a5a74ceee9da4e0097f4fb6627a44241d699dfef7e43908a8a456740133bc14e3b5df98fb65613b",
    "password_file": "0318f78494899a7c291aaaedc7fbf05d19332aef15264174174cb734e922e7cc2390dc220ae3f36299752baf772327cdbd93d33894ba6236e9b2e3c2edf23e2664d73df7e901a5afde0ca7c808177469d12ac927f69c5b52a4aa7828f0ce106fce93193996fc683bc53bc810c2e6347be88b58537175b40c9350d876327d8346990cb18f0477ab23dcf468b9377f9772aa2f6328c32b8414fcba19a81cf61220f6f7e7cc321552abb3b2eda29a79500fb805fb1cf6abc02c0d633cc5393ad982e3",
    "export_key": "2f3130294835703f7412386eb2ff101c391a6d22ddf2e831f932da6e0d2cbcf40092276f4c23fe2edc54e45828acd762c9aeb451aeae3a70f9c1bf37a4dcd87a",
    "session_key": "862a1d39e424f021ba5a20c779b29ce8dc379eac186133ec9a5a74ceee9da4e0097f4fb6627a44241d699dfef7e43908a8a456740133bc14e3b5df98fb65613b"
}
"#;

#[cfg(feature = "ristretto255")]
static TEST_VECTOR_P256_RISTRETTO255: &str = r#"
{
    "client_s_pk": "026a80b08688346c0a5d884119239af863b0729ef14bf8b86b285b5751b6e2b067",
    "client_s_sk": "8ea03094d56fdfd7937b9a4b8b89e2b09f8a2a493d6409d39dfec1f4612a4fdf",
    "client_e_pk": "0326c437e32e7a5604807b24f92385cd732e6b70f70793fd59022d9470e6579622",
    "client_e_sk": "4fe1d7f5159e429d35bb4d3c66ca20f50b133893f1e1712e89d9edd34c044612",
    "server_s_pk": "02267105ddf0f2a9531a0875ab315f1c831766134af1b7e4ad9c4f298ce0536eea",
    "server_s_sk": "8871c04d141df9881e3ef15210660112c164cc32867f3ec0bd67d68cbbd87424",
    "server_e_pk": "03315305fc11f61944bc790a112f01e1020df7a830479618e7a42dd2204d30075b",
    "server_e_sk": "225599a7b01f047bee6fba835c86f271410b786b3933cd7542abc8c58afb10f8",
    "fake_sk": "61ea20ed0bde67756fe11072c5a8aa3103085a293d60bcbb0b5c5e09920d07d8",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "269627e7fb86bc28052c4538cd8a4a8cf30ed530196e0e2d99a8382a78c21f00",
    "oprf_seed": "3abaf808e5435b5fb9929d98dc3060827fe627bbaefdaeb9205b9cdf2037a625ce8a687ab3f85c0a70629f94c1f23212f8d67b3dd0fc422c5f65a600350267b2",
    "masking_nonce": "093ba9502b07a9a838f28bd2bfb9699315549db299ef6196fa32233acdfaabf9b97a0dd265db7ff52ca1b1f3fadedfa9dca26751b166972e6ab6569ff08ff5b5",
    "envelope_nonce": "d7e0137e8adf2de3b00cd9e0c888f36ecba2ee18f92e51b7298fbaa654d286ba",
    "client_nonce": "1186e18b135739cd36cde4a2dd72ce5d1c4a92a96da279ead6f54813f84d9d86",
    "server_nonce": "9589f0bbec5cc2c68b98684158b8ef40f81f7f0fb8b2197e90d8e3666cfd1682",
    "context": "636f6e74657874",
    "registration_request": "f28816d64e1d4f17a0f36830ed92349d29de1e0444f21147a23d1952a4355573",
    "registration_response": "7c734fdd7907d3aeef3fd17a8bb1d08642ab04f36c1eca4d8e6b10147c8a505f02267105ddf0f2a9531a0875ab315f1c831766134af1b7e4ad9c4f298ce0536eea",
    "registration_upload": "03ce990fb3f9331bccd12eeadcf92f938dcf3acb07ec660c2936f8adc34554d7c7ecb4d45aa36908729dc4ca3e7c6e0a4a605fef0e7aa9c84de814e304a27dae2b8738f10785f2a1005d906a37f12b259b83a9f8406b6d6783180ba471e27393858ea03094d56fdfd7937b9a4b8b89e2b09f8a2a493d6409d39dfec1f4612a4fdfaa6224b035117cd28adba5aeba7c4733b66b44fa47052f2f50fd68b02360a769157fbd7e00af377f755d2ae0d1f6042eeb8e45c0c870eb7a985c8cd867aad53e",
    "credential_request": "f28816d64e1d4f17a0f36830ed92349d29de1e0444f21147a23d1952a43555731186e18b135739cd36cde4a2dd72ce5d1c4a92a96da279ead6f54813f84d9d8603eb66e9a64dd24d6aa1a89dc0002e3e12f01b3dc6d9005bd72a03ef934377f23b",
    "credential_response": "7c734fdd7907d3aeef3fd17a8bb1d08642ab04f36c1eca4d8e6b10147c8a505f093ba9502b07a9a838f28bd2bfb9699315549db299ef6196fa32233acdfaabf92bdd08e08a4ac46f690d1dc4ad05eb4323770753adbf0c354f7fe215200c3091b4342949f456fb3d0e2d6a59ce9da891930dde787b9b6943446bebf9b029a82e878e2ca9412df818403c9a8b817985f9697219d1319bd90b57793a64472995b72b0f15551d35c1f90db203b8dbfc3448fe35982b350349255b4d1a8bc100d0f280225599a7b01f047bee6fba835c86f271410b786b3933cd7542abc8c58afb10f8027a0c4c39a84d38b39f2b54c62c20b312fd37090e841337483b27047c143b94a1d57a81fed7757d80845053b83cb02890e60ec0f48d241965f752dbc826b88753d2d256b76e8c181f48d7c24351da7b2bad1c41790c20776db86c654bf48cb9ae",
    "credential_finalization": "643a6547dc003d7caa81adadfb74be774853e0a422bf58fc61e5918a3dff35e9854b4150c73ddea93283deb6aa4216437fad406fdea480ec229fcdae3c83d6da",
    "client_registration_state": "269627e7fb86bc28052c4538cd8a4a8cf30ed530196e0e2d99a8382a78c21f00f28816d64e1d4f17a0f36830ed92349d29de1e0444f21147a23d1952a4355573",
    "client_login_state": "269627e7fb86bc28052c4538cd8a4a8cf30ed530196e0e2d99a8382a78c21f00f28816d64e1d4f17a0f36830ed92349d29de1e0444f21147a23d1952a43555731186e18b135739cd36cde4a2dd72ce5d1c4a92a96da279ead6f54813f84d9d8603eb66e9a64dd24d6aa1a89dc0002e3e12f01b3dc6d9005bd72a03ef934377f23bd8fabb81cc58414997e3c76aba160146183de4cc966657e5b1def258df81ff6b1186e18b135739cd36cde4a2dd72ce5d1c4a92a96da279ead6f54813f84d9d86",
    "server_login_state": "13bab355577815ab29a0571bc571f6911d88f92cc64d6e930872674364b7400cacb5cab973263ca4da8687f36f894c06fb8939e96a7c6d1d4bed17dc1e00a12878b01cb72645993a5186b124808b8604a24b63aa3d934424dc78f9e56d02b506941b0af906d06edec7ab2eed07847fa424b5881e71282aa306d223902b37c354ed6f8a57a79a4433771a1b3aec9ab490df027ac3383a42cf7d09bed5c35e1dd1e092354e18d809935e1c19929906398286669f2603153de7026674823149fed0",
    "password_file": "03ce990fb3f9331bccd12eeadcf92f938dcf3acb07ec660c2936f8adc34554d7c7ecb4d45aa36908729dc4ca3e7c6e0a4a605fef0e7aa9c84de814e304a27dae2b8738f10785f2a1005d906a37f12b259b83a9f8406b6d6783180ba471e27393858ea03094d56fdfd7937b9a4b8b89e2b09f8a2a493d6409d39dfec1f4612a4fdfaa6224b035117cd28adba5aeba7c4733b66b44fa47052f2f50fd68b02360a769157fbd7e00af377f755d2ae0d1f6042eeb8e45c0c870eb7a985c8cd867aad53e",
    "export_key": "2fe20c906ff2656ba5c9c4bb313788f88395ef86281e4448462d5b1f5438d4afc91d2ccf9b8f340c0434db96a1996bc90cfa8a378c349c18e4291e793277e31f",
    "session_key": "ed6f8a57a79a4433771a1b3aec9ab490df027ac3383a42cf7d09bed5c35e1dd1e092354e18d809935e1c19929906398286669f2603153de7026674823149fed0"
}
"#;

static TEST_VECTOR_P384: &str = r#"
{
    "client_s_pk": "027ad019b16564c074d6f2ae68bdf20a738d7d2e9839a0abfa438a760d0c06c16048fcb8fd4f1dd115a7dfc3fea5f09b58",
    "client_s_sk": "834a110fe6c0e7b6cea98c3bc534a928d6a842116774a1e01b513584405cd2e31970f765d7bf0db0ade9bf27fcd9cd0c",
    "client_e_pk": "036a8b6a879e4b771b980f60263761fe7fe8ea7caf25f72093e4e7becaaea14a11a6acdc9ff156f0f9663623e17738a541",
    "client_e_sk": "44760cfc351b43df634d788300fe8a21d3a1045654421a0c7db0e4def8a4f95f78900b61e9ceeff021f381270cdb5418",
    "server_s_pk": "02f66681149226426db92504e9c0604e8f9fdbfc5f36f399e77d2a9b1383a00d693a04e3549bf909acbbd700162cefbca9",
    "server_s_sk": "5dc037810ae1265de50fe0262b18f9f494866dfd9e8b10d7cd9126e513de0f3248510c8af60e8e61d875eb702610a010",
    "server_e_pk": "0345d90f8c96cdec81eaaeb147250f54e25824b5fa9df6a333fa932cc73e3768228f3ba8b81a1480c1c8cd705775ea9761",
    "server_e_sk": "c82bf9be4884f55e97240bb1fddf2c21cb9d44ea208a6448dcd0dfa25b4500b60990c58e8de1041a10068c8b1390353c",
    "fake_sk": "c75ce826bfcfaa3328fbf6ca2060c5f80313048082da3bbe9b81654c4f6bdf87374e15ad49594315e973e0cd289c6bf9",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "bc8fd9384462ca535b97649453851e7d053165c1d813f88f168e91deadbd58ff2f1ce08628948d75db1ae9ddca1d5b97",
    "oprf_seed": "b06de4f6d4a0dd8efe8afb46f51d197a3e098d0af21b52b4a5117d4980ca8fcd90c629400a43476271e89291d6618096",
    "masking_nonce": "5469703e134b2b70a9ad0aad851cdd22038fce9291147198b87d5731ec1ab5000ebf49eacbb3b90e6ea84bc1ec0032b233b9edf505289298db7ef65720e1f2aa",
    "envelope_nonce": "f4320d83faae12c799f3ceca6a84c4aabc9bc1896b11b217087a9b820c6ff075",
    "client_nonce": "4edb4057671642bb7630028923812954abdd34f57bf6f62ad4f24568680bc0be",
    "server_nonce": "aa49c4593ad1ff89776852ab9f555a68eba4b5d86c7ec7f39577cdb04684e24f",
    "context": "636f6e74657874",
    "registration_request": "0305632a043103148c0c50187844d031dc33aa81ab6b9d13919469b317703774ee3eea7c7b4b63445fb446ce2c4bde9173",
    "registration_response": "03f878aaf28a28fbce8805a11b0feccf82233c46a75f7c8513c47a23bba92bced8f95d97c795c70a7755ac3c5b290a14a302f66681149226426db92504e9c0604e8f9fdbfc5f36f399e77d2a9b1383a00d693a04e3549bf909acbbd700162cefbca9",
    "registration_upload": "03499599951aa81858e10fd6394610cdceee52195ca2f5eab241fb8a30d24f4f6ce3f33839c025bf5ebbc056d489e55797cab6175299333799ad308b718815a97d3326c82311f380dbc3d3f3bbb1c9922fa75b4eb2125fa386b75b610a07c2f639834a110fe6c0e7b6cea98c3bc534a928d6a842116774a1e01b513584405cd2e360093806a0701ac9820c29ac81ab66b91d12243b036b20309c2dab1a473869c03efadc490a20af8f3e5dec0f5643a621",
    "credential_request": "0305632a043103148c0c50187844d031dc33aa81ab6b9d13919469b317703774ee3eea7c7b4b63445fb446ce2c4bde91734edb4057671642bb7630028923812954abdd34f57bf6f62ad4f24568680bc0be025cbaa73207a363589d904f9ccc29197ddad82e32580db1e4fcc26eaee9e202cb40e8b0a08b5d1f1240e835f9da08d0e2",
    "credential_response": "03f878aaf28a28fbce8805a11b0feccf82233c46a75f7c8513c47a23bba92bced8f95d97c795c70a7755ac3c5b290a14a35469703e134b2b70a9ad0aad851cdd22038fce9291147198b87d5731ec1ab5003eff2203d3b86ee028fe1889fd24b6459a3ed00fda3cf90bfbb9508ce62367a185609ec407a7765a2cdfb9d4558c984bc3c235451a584c133ca70c57ef5573f3dcf29dfdce332106e53d4778331e8dcf4f807f3f13c41748fd251c5af002f64efc48cfbd7243d78ab451b9c9cc0dad4fca77583abe51538f2f42cb198cb698b7fccb9d44ea208a6448dcd0dfa25b4500b60990c58e8de1041a10068c8b1390353c021e31dcaffe65a256f1b32c8e91fda21d475a4b4fe06c961a6e23a7aca49214846a5d999db011e5de464859ee8d023cf96d3c35ef24a969602bc8b9346dc55a5a4fcb14aa9f42932986885a79317945d277e9601dc4ccdb5fee028f17fb33f14e",
    "credential_finalization": "4d9dd316ad4c575ef6c6a26f90e72f26672d8740e03c9d8808c95449f3279ec8709c5d2f1fc1cf14270d3919ee952e86",
    "client_registration_state": "bc8fd9384462ca535b97649453851e7d053165c1d813f88f168e91deadbd58ff2f1ce08628948d75db1ae9ddca1d5b970305632a043103148c0c50187844d031dc33aa81ab6b9d13919469b317703774ee3eea7c7b4b63445fb446ce2c4bde9173",
    "client_login_state": "bc8fd9384462ca535b97649453851e7d053165c1d813f88f168e91deadbd58ff2f1ce08628948d75db1ae9ddca1d5b970305632a043103148c0c50187844d031dc33aa81ab6b9d13919469b317703774ee3eea7c7b4b63445fb446ce2c4bde91734edb4057671642bb7630028923812954abdd34f57bf6f62ad4f24568680bc0be025cbaa73207a363589d904f9ccc29197ddad82e32580db1e4fcc26eaee9e202cb40e8b0a08b5d1f1240e835f9da08d0e2e546cb8ed99c8d3ad4c1f32c4cf19ce4da1e2a13700df0a0a1eed43f251261f6e7edb92cb124f652241186604c5f1cdb4edb4057671642bb7630028923812954abdd34f57bf6f62ad4f24568680bc0be",
    "server_login_state": "2e33ed0981c481b9141212ab38ca6e8ed1cbc132f8b96c70c2268b6b10aca88c38411cae2cf819b786922785bb2b7019e20c7da8c330d03e251b1fb4555995389964ad78cda9a6ea30c9b0e5b3733656c40cdf92f31ad08331baddf5c98a4ff6641618b739a79bd6a29f917505c30ca462b3d43b762fd7cfc8181fe439055f4f151e5ea1796bcc0f146305e9712c6376",
    "password_file": "03499599951aa81858e10fd6394610cdceee52195ca2f5eab241fb8a30d24f4f6ce3f33839c025bf5ebbc056d489e55797cab6175299333799ad308b718815a97d3326c82311f380dbc3d3f3bbb1c9922fa75b4eb2125fa386b75b610a07c2f639834a110fe6c0e7b6cea98c3bc534a928d6a842116774a1e01b513584405cd2e360093806a0701ac9820c29ac81ab66b91d12243b036b20309c2dab1a473869c03efadc490a20af8f3e5dec0f5643a621",
    "export_key": "4e00ea96339443ec9427a94d5ffc38faf7abfe49bc45f33a2b8893ca05266eb7c3d9dda533244384656e3595e589d4d0",
    "session_key": "641618b739a79bd6a29f917505c30ca462b3d43b762fd7cfc8181fe439055f4f151e5ea1796bcc0f146305e9712c6376"
}
"#;

static TEST_VECTOR_P384_P256: &str = r#"
{
    "client_s_pk": "03aa7fcc3a2b13ed9080a84f4c73ef1e8431cb0f981911d8e9b1bbf6d1b13a97c6b4230bfeb638d960f2deea221c699e80",
    "client_s_sk": "e465935788fc3d6f16cdef00c912f9e032a6aa4d9452c86cbbf2549217f390b0a81faffdca2b752ec7bfdee0dbcda7a5",
    "client_e_pk": "020c105b40758cf0d0c596644d387eaf598dc215652fb8c7ae3f9cab07b72ca87feb3385ede83ca6792df13959ca866650",
    "client_e_sk": "a5c0e6f2080c4952fefdb7e50753942e8f46ed5dcd16925d976a6919d601721e7d2bd75f89b07e4a48cb7e9a5afdd450",
    "server_s_pk": "0295c88cdbfefcacbab08754dd36b58abc72026e761a6e0337b4feee1392dd4dd0f2ac6817bb1e12df2c6020a790343695",
    "server_s_sk": "82aaee1871a785361798e2b78179a333ae3c4da7fb8d537534e244f889c2bbc51f92c4505b24bef69dbb5028cf87653e",
    "server_e_pk": "03363da7ae2f5ebf0ae9e3d98fe6c7ecc41fec55afa834959e71a61d848d850cf50f2636c877f78e8a7a3d525408dd79ef",
    "server_e_sk": "a271eb33e9b9ec5f8bc797a66596bf477cbf8d4b7fbe69b18509dfe633f4159cbd3a5e92d3bd0fd2de81a7d9bb6499f5",
    "fake_sk": "90574e2a941462615a8958064f02cfd2070ee0c2f12761eb77e70d6b5f5eb8417843b6812c89b6841ff7bdbbd2db33cc",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "48408a664deda29200696fdb750224da0210d17f45a0b59de34162e63b57b994",
    "oprf_seed": "94b2ded5dc7b7bf787234c8deaa2107d2522b51125d2e58b331e36b6329ad4c1",
    "masking_nonce": "2b7d2d7e3e856bb56a1b52b0e2caf2b166b72f3542dd96913979eec031ffe9dacce0484db3069adde7e122d145a993c31bb0f6f663c178e1f95fafc7a0be8a58",
    "envelope_nonce": "e2476436fb2d0a4fbb17821008da5e16650a8fa03f68138b733a5d200e6c2983",
    "client_nonce": "3bd63f9517a75441ea79144e4f6b050b815cb05211737902a074ae83c6aeb2f8",
    "server_nonce": "cbbb2b55ef928799ec4007730505e0cf2189d5e60c5d914948d32e4a02ca4488",
    "context": "636f6e74657874",
    "registration_request": "0350999de8c8a3dfb259b5ce85966712c2989449758ac6ac14076c93c8abf3e656",
    "registration_response": "03138b9a92582ac291858e1954b2dff11098c89fae57c2ff137400ba95b901a39a0295c88cdbfefcacbab08754dd36b58abc72026e761a6e0337b4feee1392dd4dd0f2ac6817bb1e12df2c6020a790343695",
    "registration_upload": "03808b6fa408dc690f92e06196131aad15dff9164e10e11991d1cdcc763f979cfb4577cf766164fa6ffc75a67b13ac2a910b878ac6b600b274baa71d8eb97323ccf45443577c62faf1222bf0fe017d983ae465935788fc3d6f16cdef00c912f9e032a6aa4d9452c86cbbf2549217f390b0d55fc01d6e91ea395a9233165418b5584f38f31175083cccfae69578e85758b1",
    "credential_request": "0350999de8c8a3dfb259b5ce85966712c2989449758ac6ac14076c93c8abf3e6563bd63f9517a75441ea79144e4f6b050b815cb05211737902a074ae83c6aeb2f802386993c958a9a14fc3a788d73f89fc932930a077c86d3222d9c40f07e3f0795d9f5c7191118978242bb722f72a082ac7",
    "credential_response": "03138b9a92582ac291858e1954b2dff11098c89fae57c2ff137400ba95b901a39a2b7d2d7e3e856bb56a1b52b0e2caf2b166b72f3542dd96913979eec031ffe9da93db2760bead8c6834ed76bade81fe8cb849f92f957991ff9f41d1ecb7fa4eeb82acab5ba32fdbeff970a50986e16c069a230989b18a6d2488f096a52949a6e4c824f25e803253cd8498991c3707cb1ee9edc14c5b4b8b4d2e03b4059c075a785bcba61873a9d3994029e98580a55437d67cbf8d4b7fbe69b18509dfe633f4159cbd3a5e92d3bd0fd2de81a7d9bb6499f5039cf64cf96647d66faf21348683a4d80ee69fcbd8cb6545dc8a13aa52e226c77389c0f1a7bb2396bee9a6807ec566835041259eb94980ac4c5634dde99c9d0f5124e2653102170a34626f32907745e5c3",
    "credential_finalization": "4fe1618a77247445239c7733cb0d25380fc728d86f5785fd08bbe13419fd94f5",
    "client_registration_state": "48408a664deda29200696fdb750224da0210d17f45a0b59de34162e63b57b9940350999de8c8a3dfb259b5ce85966712c2989449758ac6ac14076c93c8abf3e656",
    "client_login_state": "48408a664deda29200696fdb750224da0210d17f45a0b59de34162e63b57b9940350999de8c8a3dfb259b5ce85966712c2989449758ac6ac14076c93c8abf3e6563bd63f9517a75441ea79144e4f6b050b815cb05211737902a074ae83c6aeb2f802386993c958a9a14fc3a788d73f89fc932930a077c86d3222d9c40f07e3f0795d9f5c7191118978242bb722f72a082ac76bcd42cbe5150c7632326bf7b038ac8fd5cb09530c144cdfe798847035a7f14c82849c114e13883295de509a7a9a15d73bd63f9517a75441ea79144e4f6b050b815cb05211737902a074ae83c6aeb2f8",
    "server_login_state": "882a3c1a309a19a32907ed72540b465f308380cb9adcb3e1d906d6e0c255f91de5ff8b87edbe0af9daa50908efb34a9a8da444ced5f1b0e2bfce8ffd4947e1e64d169ed4727febf302256f84ee462e2219c5217236da8749c8e3aec996eedf2e",
    "password_file": "03808b6fa408dc690f92e06196131aad15dff9164e10e11991d1cdcc763f979cfb4577cf766164fa6ffc75a67b13ac2a910b878ac6b600b274baa71d8eb97323ccf45443577c62faf1222bf0fe017d983ae465935788fc3d6f16cdef00c912f9e032a6aa4d9452c86cbbf2549217f390b0d55fc01d6e91ea395a9233165418b5584f38f31175083cccfae69578e85758b1",
    "export_key": "7c242005347a90ed8a263e0963f554d1c0fc2d0df3b3bdb4a818e94569da2cfa",
    "session_key": "4d169ed4727febf302256f84ee462e2219c5217236da8749c8e3aec996eedf2e"
}
"#;

static TEST_VECTOR_P384_P521: &str = r#"
{
    "client_s_pk": "02dc23c166e9c1c2ea87c53067b21851732c6c811263e0ac28b04f861bdf6081a422394ca7d0c6d415a0534cb98a5d4747",
    "client_s_sk": "2a0f646176250a4d6887498f415a7ec9c6b092c335d32103403e898b473dd0177bdd82f503c3ef2803c546ceeecc5cf1",
    "client_e_pk": "037f104792df13a5e246c880f00aebec597fa1abac9b8e3e64899ec7fe629e76df2304661a159d3caf57fda54983e0be7b",
    "client_e_sk": "88b77b06bc2110a95518333ec327570dee30f3cbfa64346b131c7e3d58d9abf8a62b588e177bbb5bec46a9377e2f500e",
    "server_s_pk": "0257d7c41727d03493a26bfae57854dd1666cc30f08f0ff7099f2b58e1c49fcdaa8166a8ad8504c9e5e006b0cfa5ae8281",
    "server_s_sk": "777879b3ff36f640579c49b3f680c674146469636031c36eced7899363c3d66cdf454a279a44c29451ba135feaacbe38",
    "server_e_pk": "03807129632d9e2fe5c773f3d0fc113d866bd92564f9141eafa48b0fd721b5bd1345e3fffa6425b5192944ab2b75635260",
    "server_e_sk": "5fca049bdb6af2cb03ea00b8ff0e0b1f839e18ea72f694a044d37f646abee6281f5db9593daf6c6857b28ccf04bca3e9",
    "fake_sk": "8ad1f7d0a103dd13be480c8ede075b673059bc90d7632e121ae9158123557e35f741749265a97a4e2f0503ff1195156c",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "0031e8f83991d28a26ce8cdbf484c0363ee16921eea7502d299bc633718ee36b0ae813f4d55f4da1972343e37706c188d591dae064bc028ee3cfe25e780de4dc405c",
    "oprf_seed": "7277950cf320396a0e67fb283e5efe414e15ccfab8ccbdfd9442c162d4a2aeb21b867999769406e4c256fcadf04cfcb17253b1507dd7617366837140361489e2",
    "masking_nonce": "0170bdf7e98f19ca70155ec1c00711f60a47e561d8080d969c34ac05a5883d213a9d07fc3d89a74ce2ee827e27f69fc923d1a007d8ca671de746e0e39423e186",
    "envelope_nonce": "eb7c2a2b232f20f4315964b8fc9ef8f20b4966ceee71a2d24c8e3e8fe05d5c23",
    "client_nonce": "3aee871b7936d5a50b740969203a9522dcb9c24135258bbf314b2bcd928f4fbd",
    "server_nonce": "a24380e218dc0484ba08fb6a64232803eff6bf2e528de1865e2586686db55ba5",
    "context": "636f6e74657874",
    "registration_request": "0301332d4cfba4e2bfb676a6a22460f2bb754c03c96f28d446843da2b63fbecbe1fb5301a4aee34e47b1dd32db77baf80dba5959b5028ce91d09637d066b2fb440ba74",
    "registration_response": "0201972451a45e34081e445b943ea7e6f2abb4b3241e0a3d3216c4e4805ddc95d8d3ac36ccac7c8afee4c75ccac8b311c1aa4287666548ce18834567eb30a9553672330257d7c41727d03493a26bfae57854dd1666cc30f08f0ff7099f2b58e1c49fcdaa8166a8ad8504c9e5e006b0cfa5ae8281",
    "registration_upload": "03ea4d985d76b5068dcad073721659d276caf691ed1c6eb6cb74c55dfca1a682f9708d1cdb8fc1ec7ddf79f2e36a44f0ac209cf5e7526905af6a8d997f52d63f870a15753c147d897bd900d1903be25fa3bed7f876c5e853ea3cd16ac056bfdfc09a9cad88d0e0a68006e2a65b1dfe9af02a0f646176250a4d6887498f415a7ec9c6b092c335d32103403e898b473dd0179a2dba54122b5b5d2b0f834e679ffa3483779e5270466d8048a1e85ba42481e282889273ad5d16ee6fe3a6c1fa83d40231e9e5006790b9762d16b07a6eaaf60c",
    "credential_request": "0301332d4cfba4e2bfb676a6a22460f2bb754c03c96f28d446843da2b63fbecbe1fb5301a4aee34e47b1dd32db77baf80dba5959b5028ce91d09637d066b2fb440ba743aee871b7936d5a50b740969203a9522dcb9c24135258bbf314b2bcd928f4fbd03f9068cc82fa7fc88da37d321306babf56a4272b4ee70e13d3bba2be104781e5fbaf79b90cd2eab4b59908e927da8a14b",
    "credential_response": "0201972451a45e34081e445b943ea7e6f2abb4b3241e0a3d3216c4e4805ddc95d8d3ac36ccac7c8afee4c75ccac8b311c1aa4287666548ce18834567eb30a9553672330170bdf7e98f19ca70155ec1c00711f60a47e561d8080d969c34ac05a5883d215918dace90ddbef65d99a53aedb1ce2df2aed9694b64aaca2f4959e27c87c082062b8d106480363eb02a15cfbfd6c6a6847eb750c1f685b31f287ea2934fc7567b600856663482601c61129cb863577b0c21d2ad1853682d18d45f4700875d0b4ef48f695d7a4ed82d0a8458366d71021649c145bc8f3f8be12c744a8e9d97854b87c5f2e3a6b069b212e36a9490da9416839e18ea72f694a044d37f646abee6281f5db9593daf6c6857b28ccf04bca3e9031b5a7861fdbfd1c79a368c9ae7fc98cc524aafb7ea48bf413978496f106f6f2db0283ad17119492089c704091142aad4ce7f03eeeaae683708a4395cdcefbe53730c5f18b32ae731f5b17c2078ef56eb0690959ec470cdc43d424ed1724c0aca0251e98ca983ae9c4e9d8b193bec77a7",
    "credential_finalization": "9232d499808e284090ebca851eec4e952840116d503d5b576c1903449dd5086db14f5e5d88e351b46bed850d11bf6ac619e008f1fd1e5bbed6b63cbae4d8f0e9",
    "client_registration_state": "0031e8f83991d28a26ce8cdbf484c0363ee16921eea7502d299bc633718ee36b0ae813f4d55f4da1972343e37706c188d591dae064bc028ee3cfe25e780de4dc405c0301332d4cfba4e2bfb676a6a22460f2bb754c03c96f28d446843da2b63fbecbe1fb5301a4aee34e47b1dd32db77baf80dba5959b5028ce91d09637d066b2fb440ba74",
    "client_login_state": "0031e8f83991d28a26ce8cdbf484c0363ee16921eea7502d299bc633718ee36b0ae813f4d55f4da1972343e37706c188d591dae064bc028ee3cfe25e780de4dc405c0301332d4cfba4e2bfb676a6a22460f2bb754c03c96f28d446843da2b63fbecbe1fb5301a4aee34e47b1dd32db77baf80dba5959b5028ce91d09637d066b2fb440ba743aee871b7936d5a50b740969203a9522dcb9c24135258bbf314b2bcd928f4fbd03f9068cc82fa7fc88da37d321306babf56a4272b4ee70e13d3bba2be104781e5fbaf79b90cd2eab4b59908e927da8a14b7b77699cc0b1845726ab79f2a2f72c7d222393bda6d035a561d70bf8789a49069dede29b2224ff7854f4bb0eabd39a493aee871b7936d5a50b740969203a9522dcb9c24135258bbf314b2bcd928f4fbd",
    "server_login_state": "488b986871f89eda2f699cc3f5f56f053ffe04c5b8a96ace28cc5a97fde83caa63a31cfa816ca91d0999b5b11695cece9525dab7675a150c40ce8b99b82342f787cc3d40a791106e10c76bbd0a518d3f549f710ee58bf1a3854b924c89c43f32e961c922817a7982b3df5924159979ee830800d6546cb8869af9cbb691da7608c8504dd1f24b68d613966464335279551a81789e83859ee1d4ac3d72c22fd75673493507ea9ccc457f36e33ba7f9e0bb0b63dbafb163606f1cf5ae2d65892c91",
    "password_file": "03ea4d985d76b5068dcad073721659d276caf691ed1c6eb6cb74c55dfca1a682f9708d1cdb8fc1ec7ddf79f2e36a44f0ac209cf5e7526905af6a8d997f52d63f870a15753c147d897bd900d1903be25fa3bed7f876c5e853ea3cd16ac056bfdfc09a9cad88d0e0a68006e2a65b1dfe9af02a0f646176250a4d6887498f415a7ec9c6b092c335d32103403e898b473dd0179a2dba54122b5b5d2b0f834e679ffa3483779e5270466d8048a1e85ba42481e282889273ad5d16ee6fe3a6c1fa83d40231e9e5006790b9762d16b07a6eaaf60c",
    "export_key": "de6a72ca1a5767cf9c52b39aa00183cd1f930e1f9d826ccc5c20bf595e2823b6d6f27598dae2fc0173f64b8daf9cf6d24ac17a4e592edc7a045570a7b937b50c",
    "session_key": "c8504dd1f24b68d613966464335279551a81789e83859ee1d4ac3d72c22fd75673493507ea9ccc457f36e33ba7f9e0bb0b63dbafb163606f1cf5ae2d65892c91"
}
"#;

#[cfg(feature = "ristretto255")]
static TEST_VECTOR_P384_RISTRETTO255: &str = r#"
{
    "client_s_pk": "02c1d4d7d66aeb737564a1b854dd415b93cdc77c09652783d62947bac97d501bbb6a9fae15244f06b38f0f1c82a5585e5a",
    "client_s_sk": "a0563c18fa5e065414411f2b7a05a42ccafffe6c3f820a453fdc5ec4bcbf75164646c3dda5ad48424c33342cd7e7e4df",
    "client_e_pk": "02cfab78104a87ec00bbb5a59b9da3a2e8007ccf2b280129594f61f38702bdb9431f770201bda3cab38a583e907b686c16",
    "client_e_sk": "5254f4ded1c5274d284bd01dd1eed07ec23ae9748857606282c6170d5a722058763367284abe9caf9389d942a523db5b",
    "server_s_pk": "038b01c3863136ab24e59be966b61516c622bb2cbe4d615d598b692aec4584ccf03617949fa2eb768890b50f91316997f0",
    "server_s_sk": "6dd0f63b233b2bd25288bce7b7c4128e595d7e7ae14a502151f17496d821b976f2ffc636ad02dab23786054c943a5248",
    "server_e_pk": "0243dc3cd7669109cbe9dcd71c10c0df3c571603c90cb8f836471851c8c4e59b2b33df99a83e5f82b9997509b0937c5af7",
    "server_e_sk": "0c6514cb587895583f71bea545cd793eb5c6c3a7b47af02bf7eec36995013ff5e62d020aebaa8584cd0c09db2a57c394",
    "fake_sk": "bd88b0857965e266c8b9c070af374335ceed0a2588081b338128985d8e6d9ac5cf7dd28a4eab2ed92a8d1c5e40586667",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "945e750cc030ea56fb69fd959b1c869bbbd11598a55cca1c344680bb3af39e0c",
    "oprf_seed": "6ede60508d189654155ebdf35e3e1f9ffac1b0a3a7c3af5623a16f0db771341826aed1298ce0a2c9458d810d0db29fb91d2220c58e5a4866ce8d26449d2ca5dd",
    "masking_nonce": "581e546cc899d1aefb99c2b7444b66702b7e810f863303b3ae542cacee4e5fabf1b048c70e198d7f4ff92d9ef651e462ae64813d2a61dfb76834ab41ada048d4",
    "envelope_nonce": "c1711624ac043ceaefff11d3e7cd8d0968ce5cd737edccffdf981b6e550eda63",
    "client_nonce": "c45770702f6a169965cdc6bde6bd684ae0cca88beff84a10a10531c44881a251",
    "server_nonce": "e22873960b1dce985b72c7aceca1211b0d62901a12ec24d5836bee01d0fa3069",
    "context": "636f6e74657874",
    "registration_request": "38f651deae743ceb93947f3b29c0b6a8bdca06cd2ddbf8bf4034f188eb21a341",
    "registration_response": "9a35389a31de25ffdb70f4c76630c55089acf2b4f4de9543f59ece5ebe3a4626038b01c3863136ab24e59be966b61516c622bb2cbe4d615d598b692aec4584ccf03617949fa2eb768890b50f91316997f0",
    "registration_upload": "037243f014bbdfa0dbbc3caa7333fcad50be492f2c08233f81a798fed8fabef6b4b400920800531dc9eb25d3af5d9f20a1ac1cb96ceb4f40c0dc2a86f9b3fd0cb869b697b95cef3ceb267219df86f74d143102a91ea5499b1beb4d184964722caef65d052c9527104424e0320809928391a0563c18fa5e065414411f2b7a05a42ccafffe6c3f820a453fdc5ec4bcbf75161189765050d2b8e8e288f7e7d4dae5a4d864e39de8dfe6b56d4ecd2f7aa1d73b970ef1d89e00dd468e92465676f11fcbb3ce89dfa165700034942a4120ac8c14",
    "credential_request": "38f651deae743ceb93947f3b29c0b6a8bdca06cd2ddbf8bf4034f188eb21a341c45770702f6a169965cdc6bde6bd684ae0cca88beff84a10a10531c44881a25102ff65f91c0f286b9469d0f33463b70868e2693f8c511c92dba2e55689bbd298a440c2c6b0c831fe87dfb8ad6286460d1b",
    "credential_response": "9a35389a31de25ffdb70f4c76630c55089acf2b4f4de9543f59ece5ebe3a4626581e546cc899d1aefb99c2b7444b66702b7e810f863303b3ae542cacee4e5fab6a5aae2fee1f37a48874d26eda94d6285d5002bcc0c070fccf0c7731f55ceca1b678e1c355d4d933992866bee7f9f28b43359b348e63292bc9ffbd5d41ff8f14d5398384c86920b882e92476b954d4481234fbc01021b0c5e78327bc170aa0278eec426b7cedddd0d6b3d807bc3d9f52f3fc3a40a425f5514200f16eb92e0d7c67530fb4f215bc3e6b14e95cd4f03cbd7eb5c6c3a7b47af02bf7eec36995013ff5e62d020aebaa8584cd0c09db2a57c3940241e8e3ea63ecb7374164f8713b915f2d563a18f99c13e855a82d8f2af5af048835e4146f56612b9fd4e67f823a70e48a19df97488e6d1b7ff3a0a1e949ed25aa4835d88ea7a44f5028e8ad58ca0203c0087439e22dd7aea4ce64d8fae6432bfcb601acd244fe9e44b392c69cfc116ad4",
    "credential_finalization": "50f417b52847e0af257a96f03ec433bc1b202528727cd0d768247c7584d0e14879d9eff7a4a61c1b954f923c64b0c2fffb328cdba031b7be95b3dc49e23042d6",
    "client_registration_state": "945e750cc030ea56fb69fd959b1c869bbbd11598a55cca1c344680bb3af39e0c38f651deae743ceb93947f3b29c0b6a8bdca06cd2ddbf8bf4034f188eb21a341",
    "client_login_state": "945e750cc030ea56fb69fd959b1c869bbbd11598a55cca1c344680bb3af39e0c38f651deae743ceb93947f3b29c0b6a8bdca06cd2ddbf8bf4034f188eb21a341c45770702f6a169965cdc6bde6bd684ae0cca88beff84a10a10531c44881a25102ff65f91c0f286b9469d0f33463b70868e2693f8c511c92dba2e55689bbd298a440c2c6b0c831fe87dfb8ad6286460d1bd089e7b04a5bddab582c56c919ed4972e43ec70695d516b48b3d54f3a98a5c4b47e663fbc0691f3eaf2d33d7c6e951acc45770702f6a169965cdc6bde6bd684ae0cca88beff84a10a10531c44881a251",
    "server_login_state": "ab1b5088cc404142917da8cb9f0460800e222acd0abb20a0411824bbb3a33530caa46508d6a4d6778394fa3a1c7dc7c922241761e84567b0900365479ca10cdcae0c9adf368396b41a0c857c52274c3705ea4cc35b3dce1c83cd6b17b75723a0a93996c25c33f2fd1d2367416c40743ca0019db466d62c64cf832670a5e4e2e0526b13f76de824546a13c404d9545a6d401c13d0034c9e4b748854eaf316b74c5df9c3dc2caa274f196b9bd5c0e2ebf9036ec462f72da000d8e9631490aa19e0",
    "password_file": "037243f014bbdfa0dbbc3caa7333fcad50be492f2c08233f81a798fed8fabef6b4b400920800531dc9eb25d3af5d9f20a1ac1cb96ceb4f40c0dc2a86f9b3fd0cb869b697b95cef3ceb267219df86f74d143102a91ea5499b1beb4d184964722caef65d052c9527104424e0320809928391a0563c18fa5e065414411f2b7a05a42ccafffe6c3f820a453fdc5ec4bcbf75161189765050d2b8e8e288f7e7d4dae5a4d864e39de8dfe6b56d4ecd2f7aa1d73b970ef1d89e00dd468e92465676f11fcbb3ce89dfa165700034942a4120ac8c14",
    "export_key": "9763c031678a1b0398640298c9b2ab1651c580ca573e77279fb8e5869fd2d728faf4eff799ff9f6da74452935afe513da1dbaee132514c79529cd48680fa9df7",
    "session_key": "526b13f76de824546a13c404d9545a6d401c13d0034c9e4b748854eaf316b74c5df9c3dc2caa274f196b9bd5c0e2ebf9036ec462f72da000d8e9631490aa19e0"
}
"#;

static TEST_VECTOR_P521: &str = r#"
{
    "client_s_pk": "020155aa12371618bbfd1842a86121ce860958ffea0436a2ce6c0f97554ee17ff6e1ae5a8d4bdb060a224099a611889d4bb660747008b607efc695faf0e47d5d7fa262",
    "client_s_sk": "000b052eb9e91af4a983c94a21839f1f565d7529c5958fcebd88e69e1c8871a61ed62fe03a33f93fe330bbccc84a913a71e8c513589f3a0603504e0b8936b182758c",
    "client_e_pk": "0200b131bbb6cf4ee2919a26657f81a3eb082f87e8bbae7f0c7db69e85998ada86566276c6b5fde667d5eeb24e603686037ef7a46be366c94c24418d4a81980bc89376",
    "client_e_sk": "01a664e28301d34952eb4db292212baccaa619f40972d8c2e401f7c7098a846fc15734825316e262169f5aa4a09bc43177c3a40c9a5f7672e4a0b7ed555458e210ab",
    "server_s_pk": "0300ee7ef7cf52e265ce20d90c67975f1efb0a77387df056c5b1b480ae18d91b9a55e9a74ab7627b604d31b4fa42883f9363235925ac2a62c54d362f17a728ad2ac61f",
    "server_s_sk": "014198ae8ece980053ab7887cc30936bc4fa1d290578fa398e9cfe1e4cb755331eaa917684d1002501252eda0d887aa94b2af7c99bc36d68c33fa0862d9010d33fbf",
    "server_e_pk": "02006e8c57a318b9c92ea17e87b97cce835ed35c728f6e087728c4b3a0dddd347b0d3ee527ecea378b6e759c2caff07467dbdd2441d2e68b7f51009c2ce86e020e9bfd",
    "server_e_sk": "01fc737c87a13e2cbbaa050cf5bb8ef624d10967ed25fb40e880c269167e3d3befe2ff72a805d328c6b0065dd0c944c4258fe14d21db1d2a9d47b42f4e8335367fee",
    "fake_sk": "01ee8fa2543f4f7ce8e211d82fe9f66bcca74c6dd53ce54676527961451187fa414338025dd16c68ca11a14908af7d85cb6e7f9fd7ea98346fd3beed337855c8ec99",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "01b7a8ba3629e56dce389fe4a722877cab9dcb743b67cd442f74943d1c6cc1e33ed1194b61ae564e9dc9ba3bba7f30e197ab13d71861562ffcf6033d8cb4c50ac6ec",
    "oprf_seed": "48fdee5c8b37a08cdc6abcc261dba8d9f3966fc101bcc0bd7565c1c1b25afa4488a67e66e916b2780a0bc7272e626a2d08503ca15719fda9b2bdb3c4f3055cf7",
    "masking_nonce": "ec4643526cd59dfa2c4cbadaaae4f34dc4b78dc743b1cba386511aabcf59e59c407e7c73aef7c6e3f3d775d6538b54755724a609a158dc684740f1cfb7bcc148",
    "envelope_nonce": "e6969ee0b7772e728cdce7aca1f52195c225956011828f88210fbd3fe8492612",
    "client_nonce": "5caae8941b62e5203209ce9a64e1941f0e6d1d337be32906a13219994f389f28",
    "server_nonce": "86ff2e4db17a6762f2a3d48591976660d0c5909c6cb3ec7bd46815fa8c9a6473",
    "context": "636f6e74657874",
    "registration_request": "0300121f9200db627fd9ca835b4a6fda5cd00e7eb55bd832000f7a329449d36dcf8cf8ece478afea30686714f6bce5185731a85ae1fbc210905d371e839b0bd26e4737",
    "registration_response": "0200f0b1f2d5422869e96e89ce40f8e55a7157f4eabaf23858e3363a9723eb08fdb9ca976bde1b9f464e7a0eb64f90ead29014202280982cab148888c3505b51fb25a40300ee7ef7cf52e265ce20d90c67975f1efb0a77387df056c5b1b480ae18d91b9a55e9a74ab7627b604d31b4fa42883f9363235925ac2a62c54d362f17a728ad2ac61f",
    "registration_upload": "02008f24e782e033c63571a78a467a6cbbca70ce4983d8a4d8116fb7792d738de4748322a5afd2887f962b9ccac4cf830bbd150bea498ffebb258eeeb9455d0390bf03f2f3f8cdb75a04f061704def778d60d564a6a39cf1a729e7d3dd8056aced4509e1f2cbe01133af65786ac6818932f7f3de6428c434e724bf64100f787b794dac000b052eb9e91af4a983c94a21839f1f565d7529c5958fcebd88e69e1c8871a600e1801833baee4e01b62abf936de4d4c2818e6a986fe6a0f633d7b89ad66c113ef951a962eef5a43978822af88e72e0f47e2b670cf52fee5d0a1e68ee183bce",
    "credential_request": "0300121f9200db627fd9ca835b4a6fda5cd00e7eb55bd832000f7a329449d36dcf8cf8ece478afea30686714f6bce5185731a85ae1fbc210905d371e839b0bd26e47375caae8941b62e5203209ce9a64e1941f0e6d1d337be32906a13219994f389f2802007c1d795656616c230601344adf544af781ef6929252c2af9863203ec353a090693d1a277f7ddce3d5bf41f9c5ed9ff5e8bed7d5022d165bdeb81942ccb5dff95a1",
    "credential_response": "0200f0b1f2d5422869e96e89ce40f8e55a7157f4eabaf23858e3363a9723eb08fdb9ca976bde1b9f464e7a0eb64f90ead29014202280982cab148888c3505b51fb25a4ec4643526cd59dfa2c4cbadaaae4f34dc4b78dc743b1cba386511aabcf59e59cea5ad7bcae7fc6dc95c97a39bc5af2176e4682fda35a7aa20384f826d402a0d846d14b9af0fa1320d664f4b8cd9122f534db40a7a4be184261849d0f4e64e840d946b6b4663fea4423a65f50c7d5e85723a884beb44065e20c2d728d1829b6a30aa5cda90d25f9154dc9c3329da8e159b78fe4f7876ca9168aee94f9591e955b26926018f036d57f6368a0542e79e79812bfbcee40e58ca4ce0e261a62f4cd01cf8229ff72a805d328c6b0065dd0c944c4258fe14d21db1d2a9d47b42f4e8335367fee030089866b68c1fc74a3c2daabc34fd517dca403031f4ff8a73f7b558b12cb0763a0f9fc10a93ea888ce760187b06d39443bcece84ecea5760124254bcb5b2eb9e967d08874db8b8d9a85c803b4d39d2e286dfa260f549fddd67b409ff092a4196df9576c8b0311407d689cc4910fa8420a4f2e27a14f1c7472b54abd038cefaa919a5",
    "credential_finalization": "d7000519bc6978e357af50f45f1d37fb69f692b9dcb203ed7a7f09baa29118209cd4a451e05f9026ece8b5587224f24844b3d750af1e7db3b6de3a16ab7b245b",
    "client_registration_state": "01b7a8ba3629e56dce389fe4a722877cab9dcb743b67cd442f74943d1c6cc1e33ed1194b61ae564e9dc9ba3bba7f30e197ab13d71861562ffcf6033d8cb4c50ac6ec0300121f9200db627fd9ca835b4a6fda5cd00e7eb55bd832000f7a329449d36dcf8cf8ece478afea30686714f6bce5185731a85ae1fbc210905d371e839b0bd26e4737",
    "client_login_state": "01b7a8ba3629e56dce389fe4a722877cab9dcb743b67cd442f74943d1c6cc1e33ed1194b61ae564e9dc9ba3bba7f30e197ab13d71861562ffcf6033d8cb4c50ac6ec0300121f9200db627fd9ca835b4a6fda5cd00e7eb55bd832000f7a329449d36dcf8cf8ece478afea30686714f6bce5185731a85ae1fbc210905d371e839b0bd26e47375caae8941b62e5203209ce9a64e1941f0e6d1d337be32906a13219994f389f2802007c1d795656616c230601344adf544af781ef6929252c2af9863203ec353a090693d1a277f7ddce3d5bf41f9c5ed9ff5e8bed7d5022d165bdeb81942ccb5dff95a1016a03332a991d286aba95f844108e3b4a04ebce4930ab1e3a6c9e4ba04fa45269d9331e6df8e0386c3ad1bfd94d40e0114db4400431f02ee79f6fd383ba439d8c005caae8941b62e5203209ce9a64e1941f0e6d1d337be32906a13219994f389f28",
    "server_login_state": "3fd126cc014cb61682c923ec3faeb29c7a8fb786e8aa43908d08c80b2bc28f87bdc6f8f244c5abbc33ba0e7512e2e7b31bcda1bbd6666d963e26cf8451e4ae038395e053c36b2e1df8ec9f43c069a538c143ee5355ab9be3198edb3fe4281e95c0bf32965c7fb060f17f699c690380af797738c723905c17bac2b520779e915512843d221f80572d21f9d47c749ca4ff3936755986bb1c077654b70af2749377ad4f4206775badd6eca3afdf3ad86af7361dbf0ed705c58243d6830738b636d8",
    "password_file": "02008f24e782e033c63571a78a467a6cbbca70ce4983d8a4d8116fb7792d738de4748322a5afd2887f962b9ccac4cf830bbd150bea498ffebb258eeeb9455d0390bf03f2f3f8cdb75a04f061704def778d60d564a6a39cf1a729e7d3dd8056aced4509e1f2cbe01133af65786ac6818932f7f3de6428c434e724bf64100f787b794dac000b052eb9e91af4a983c94a21839f1f565d7529c5958fcebd88e69e1c8871a600e1801833baee4e01b62abf936de4d4c2818e6a986fe6a0f633d7b89ad66c113ef951a962eef5a43978822af88e72e0f47e2b670cf52fee5d0a1e68ee183bce",
    "export_key": "8e0148a4679af5c31898037cfe6e532afcad4594e7ea704612eb426f762d1c7a2a4f7eddf5fd7ed68f9c9ee9a4ebb35400d2436cbe7315f61476f0640dee8040",
    "session_key": "12843d221f80572d21f9d47c749ca4ff3936755986bb1c077654b70af2749377ad4f4206775badd6eca3afdf3ad86af7361dbf0ed705c58243d6830738b636d8"
}
"#;

static TEST_VECTOR_P521_P256: &str = r#"
{
    "client_s_pk": "020182baa8d1f1d343f3feaf4493612b6edb9f2e18ef1d1b65699b51fe803066b3f839187597f79ca9139c2a879bb1af46ab78fe93ef94973209e222e53d3816225bb6",
    "client_s_sk": "013fbfb5d9393f0a48cf0f49c54c5fa7f2780c57f6db721f95b66221a316e562773da08bf65e59c9aaf36dcf189a3f417840c837735f22ffaa15384f1b19cfabaa5d",
    "client_e_pk": "020039a0ced83ea05aab7b470b45a671cf0e748f5440587cd8da4542cb38b280bae966b6003892ebabdc8d0ca655df81d9dca19b9169f5bb44d71bc5064b6c5911833b",
    "client_e_sk": "01d7ccfb79a2cb2e13f00382f4d955d33da9de96c159dc2af88ec93fc74a925636c4bd5fa5f1bef15b1aae09fe7c7f8d0e898229ba9c9a531cada38be48e32262532",
    "server_s_pk": "0301ac8bee5225fddd19cff3bd04436aa7df133f4545fbc5ed749a5505edc7cc732e0351dbdf11656c2cd7acde6426af7d68daeb8a31c7ff80b6b05a48e12ba9b19eb0",
    "server_s_sk": "00944509ef50cb9aea5215d8306249dced1d69dab13ed375cdf8ee2ef6be3e64267f237439d186e8b4444fa3d0c61e13752da61391888c6a70dc74e4034cb72a1494",
    "server_e_pk": "03016dd431a0736eea405ea125a3223f0a421636f3e3f156fe5a38e39d3922225d460679739cfedb12256b20227c6f341c0d9a3d16596fb6ff000b9be83b052663f1e2",
    "server_e_sk": "00dcbb9d0c3d25e71a1bee0a964e09b9bdc1dc8b9b8f3cb97cd3004386772db539445c597e0d808ddf180bd9bcbd2ef77d2277fe6b293692581a8c023d6aa3133349",
    "fake_sk": "0016f89e8d435f9c2c96d55955f0a4199de9549e14baf76e7a367dd4f6bde39a52e03b7caa30e41f150341b7161f33d89bb6dbf253243e398e3214128698ca238ffb",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "6edd9450b0681cbec07aeef9c79e3fd64f3e176be77b60940dd837df02dcb5ea",
    "oprf_seed": "d09d38303e409ac1a80ac7adce8d58b19d0f5f08ea3af40fa786b324612263af",
    "masking_nonce": "900055de5a6d527a6c3eddd9f2ba88e16b47d242697a5adbfe5224b7c87807d695831d96ba4216d825a40016bcb9e296ad11a90d269233434652b00989328593",
    "envelope_nonce": "8369de9ceba2e041220da2ea3426a7e212377ccfb9f1da3347534ae122285998",
    "client_nonce": "7d1ef366c5c95c6522d1e87ee056fa887df54a0ab668a9cb1fe8c8ce4bcfb553",
    "server_nonce": "7a24cbbe1f408c0690dc70d298a5495beb393bd07468813413eb7212f585d744",
    "context": "636f6e74657874",
    "registration_request": "023bcd9d71a366ceeb22d526e0dee0a13c2c888b3d677af6476c0570b8526ad05e",
    "registration_response": "0310e8097b1bf7da801410b2ca15ec6c83436388eaaf1b3eabb21d2fb9cecbdc240301ac8bee5225fddd19cff3bd04436aa7df133f4545fbc5ed749a5505edc7cc732e0351dbdf11656c2cd7acde6426af7d68daeb8a31c7ff80b6b05a48e12ba9b19eb0",
    "registration_upload": "0300d2be0c8b4dca1ee3605aba73fe5057fc76b915f02cd4940f5ee3961e619faec43ca148a4e0465c536c58091c1c7a40a957931d5642536a69c4a39b8d027fe74e3e49c969aa894bcce8a6d5ddefb24ce776426f19bf746185887d489f91e0c18ba0013fbfb5d9393f0a48cf0f49c54c5fa7f2780c57f6db721f95b66221a316e5623bd771e593cc00cb079b45a22281482a82fa1e509f8765c172655ac0e503567c",
    "credential_request": "023bcd9d71a366ceeb22d526e0dee0a13c2c888b3d677af6476c0570b8526ad05e7d1ef366c5c95c6522d1e87ee056fa887df54a0ab668a9cb1fe8c8ce4bcfb553030069c0bad99332cb33fcc154081c12eb5c7451337b48efba8d579c182a07ee656ea0cf64cfc61391fa14d989405d7e35528a9aa6ceb36967629bf88268c807b8c67f",
    "credential_response": "0310e8097b1bf7da801410b2ca15ec6c83436388eaaf1b3eabb21d2fb9cecbdc24900055de5a6d527a6c3eddd9f2ba88e16b47d242697a5adbfe5224b7c87807d6f1e4d1f50f7862c0a5510c5dfaf3d0f21e42e37bfbf04dbe2ac81fe534a772eae5c127a580db94f62eb07d676199488d6e2582e2e65e2dec62ff444dc2d3aa35822d75acbc2fcdd9d8dba1ac28eec39d97775e38599790f0ce52d65a396fc39b657b40f19860e558aeab25b3a7baa7e4e34323de625182c73d6dfbaffc0c098adf79e55c597e0d808ddf180bd9bcbd2ef77d2277fe6b293692581a8c023d6aa31333490301c4951544279766de203fc4c5308fbe41b392a69df5b4b962fb5601095055573cb74f4ca8fa7f1eaf5a5c6919adc01a6336488695df9474d182c92769e081ed412a0393d6f581fc178da588e441a69ad707708ebf29573164dbb490b4c1f8b77589",
    "credential_finalization": "6321a88fae9cc76b5c03956b892f33c01e69b0d5f6a01653528610461ff93b18",
    "client_registration_state": "6edd9450b0681cbec07aeef9c79e3fd64f3e176be77b60940dd837df02dcb5ea023bcd9d71a366ceeb22d526e0dee0a13c2c888b3d677af6476c0570b8526ad05e",
    "client_login_state": "6edd9450b0681cbec07aeef9c79e3fd64f3e176be77b60940dd837df02dcb5ea023bcd9d71a366ceeb22d526e0dee0a13c2c888b3d677af6476c0570b8526ad05e7d1ef366c5c95c6522d1e87ee056fa887df54a0ab668a9cb1fe8c8ce4bcfb553030069c0bad99332cb33fcc154081c12eb5c7451337b48efba8d579c182a07ee656ea0cf64cfc61391fa14d989405d7e35528a9aa6ceb36967629bf88268c807b8c67f0029a4060ad4149ec5ab4feeb642c4326cc39f54ac8e29a572b775b88df12027aaae9cb0ab5b88f3bd7d65bd0b80067f82d26fe9f00be5f9a2a55a82473632eecdd67d1ef366c5c95c6522d1e87ee056fa887df54a0ab668a9cb1fe8c8ce4bcfb553",
    "server_login_state": "5c264a1b5efafcd258e6793b0e4a790eb752ae433ba031e5a67b37a64d4c2677fed50421f78558ba63575242a72398dc58998c419f66397ebfe1c5e8fb0ac6d898bd7bf40ad735152b0212e7a2a6fc55a19daaf44f13010faa0b51bfe8bd4c57",
    "password_file": "0300d2be0c8b4dca1ee3605aba73fe5057fc76b915f02cd4940f5ee3961e619faec43ca148a4e0465c536c58091c1c7a40a957931d5642536a69c4a39b8d027fe74e3e49c969aa894bcce8a6d5ddefb24ce776426f19bf746185887d489f91e0c18ba0013fbfb5d9393f0a48cf0f49c54c5fa7f2780c57f6db721f95b66221a316e5623bd771e593cc00cb079b45a22281482a82fa1e509f8765c172655ac0e503567c",
    "export_key": "91005130b35221059cb711b2726792f10ba88b5965fffc7c6b57cb1d04fd0390",
    "session_key": "98bd7bf40ad735152b0212e7a2a6fc55a19daaf44f13010faa0b51bfe8bd4c57"
}
"#;

static TEST_VECTOR_P521_P384: &str = r#"
{
    "client_s_pk": "0301e2981ba6654ed87fe228ae49a686f7ad21799f6da8b202e1c95d981d845b4d43935049ebecb370aa00ad92cbb3160694d054bfe6d45ebfc68b645ef2022d032428",
    "client_s_sk": "000e1920d2013da7400a842647c76e672f58bf23146499bdc6e1c4fa70a5b9a25410b714b0ae1536fb9887b0ee15b6fce92b4201d46c44c4e3fa22f3f1710ed8073e",
    "client_e_pk": "0201cadf499cbb61681c17b050a5dd6b6f7f8559b4278d11f0f7f1fdd7cc5628599c98fd710491927af7557973a59ae60bc70a12e0dc7a0145904f9514f462941d063c",
    "client_e_sk": "00207b5476bed0d74af4f358a04fb9d5b74ee30a7330502546a761cd8630e14361e880dd04a0a1d65fb0adb7eaff9baa23cff4f7dda34b3ff5373aa43eb1304a8775",
    "server_s_pk": "0301d4634ee71dbfaafa69f71a1103ca520fd73b696292ece4b1078706b94b1d45348ca8ee8e5c60ee4d940696e4ed6e834c298ca1ec6b789a88ebfc619d63ec438ed8",
    "server_s_sk": "01707da316a1fa1413a30154b8efcfd8cb142eddef4e9c2d3a77043b49264928dec7796c89f868b04c81c0d2bec3d1603b1583ac6e5058387b3c2cbee99a568ed6af",
    "server_e_pk": "02012c3e707f880c4580d1fe1e8ad9f2c908697ddbf7913ee6332abfb28ec0a71ff1088d983797f5fad1a6b174701b956a30cc693e179424ee53b8d4f9fc91c9f1bd50",
    "server_e_sk": "004e47c1a28e4046ca8ac23cb0c70c572214068f0f3989d914d6fd349f00feca6712488232e047727a445ec2221a7056fc37f349b09a362927595c962e7c7a60ce76",
    "fake_sk": "016649635ebb4d55240a85c4c190ca6cec56c510e9c7d254fa1f869f5ac9e67c97af063159a5b582f501ee796d08691fc60ebd9bc0947e7e78f7b31a72b3c63097d8",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "681374559f5c5386b92d4aa207f12e336353e3e0600e85a16048de08cf22eaab844730d6c63bb43e86cbc77b7ca8a6a0",
    "oprf_seed": "c8439e7af9a42c8c756c9c03e9949cf37b88dcf3722fed868f7899dbd2656ac133fdb5237869318ac4ed8c91c712ba02",
    "masking_nonce": "bc823b98c29605995ceb0b66e274fe915521ca7fcf6afe3bd7dc158729d0f1a77b14d8af2bbb411e2d301f13dc9e0122841b701c0665dece6418581a2a3e8771",
    "envelope_nonce": "9683c1ae991f7e8b3c3117cd7429354b3fda02010a0c8f595e365acf3a3111a1",
    "client_nonce": "8ec5f2b36174b3008b229c8fb15c011c568491d865ea733ebade40f535d3d579",
    "server_nonce": "45c91f66ee2fe153ba2cd8d9a146cb8148b9450f23d7dbae32fd3eeee306b859",
    "context": "636f6e74657874",
    "registration_request": "02aae92f0063848f8a6c15a4765cf20cf07a7e05bcbdb002417f7c805cab03637fa0ca81ad6586fd88eb50d31cf6665d33",
    "registration_response": "02ced85d5e2d01d2952394ca46695245415fbdc44f1ea6b9414463dbacd515004112037351843705f2b5204043ae28a2a30301d4634ee71dbfaafa69f71a1103ca520fd73b696292ece4b1078706b94b1d45348ca8ee8e5c60ee4d940696e4ed6e834c298ca1ec6b789a88ebfc619d63ec438ed8",
    "registration_upload": "0301f7c2ab43c80fd43d6b9e07c06ea3ecea60e7b9a06d2325e8448009cabc939960419e41250c299f812d18c40013cc8671b507fbe83cef2872618808b3b2ed52305691015c1b10e28e0009ccf42ed0c81f9e31e928352ef42a3c744702e57eea9ce669ae36924c62ed5eba6bc72e32adf46b000e1920d2013da7400a842647c76e672f58bf23146499bdc6e1c4fa70a5b9a2926feb2d5ee85af6dfd6362758ff965527da3eae39f26929ef1a0de46cc8f863a0a2de330bb13a12e0cec0053ba1d3d3",
    "credential_request": "02aae92f0063848f8a6c15a4765cf20cf07a7e05bcbdb002417f7c805cab03637fa0ca81ad6586fd88eb50d31cf6665d338ec5f2b36174b3008b229c8fb15c011c568491d865ea733ebade40f535d3d5790300af1020d54af94e626a4dc7d4c1a63afa62cef4ade8a8c500408356b4f2021a80ef23070631847b65da0983c1ee2054abdb0d43a2ed27a3933aaf20808664e3a07b",
    "credential_response": "02ced85d5e2d01d2952394ca46695245415fbdc44f1ea6b9414463dbacd515004112037351843705f2b5204043ae28a2a3bc823b98c29605995ceb0b66e274fe915521ca7fcf6afe3bd7dc158729d0f1a73b10a26544eb97528ce2ad0554c6e73f11c1bca2773a33b7ae48ef53b2395b9890797d8effe029e0f6f9daf55c061c585d99affae035af7c7e12ec64b83e31686e816582d8243e3c5c5d3159a045cf5ac949259dd6685f3441dc81b475c35ec91fb196a04299626f9e0c2422befab24d79f0c88996846c688497dd79a4d6a4a3f910dc8f47a3bb5f0f80b9b9dd076f7bf7c222488232e047727a445ec2221a7056fc37f349b09a362927595c962e7c7a60ce76030097ae93d1884e7be639d0acf69cd1d591896e84ce611bb965add4561074410d0569ae4bdcf2511df4fd64b539eca9fc6f258d3f9eeb192abae4dd8e7c1000ffda375b1c44fba2f97705dbc30c030fc40317c512f5c89b028832cc2d38b3bdf822fba386450bf354f7c10352dae67d07eb26",
    "credential_finalization": "88f38af5fff39049d0601965907240210e4162216cff798a143dc30314f4f35baf58d2aa48477c32ef8702474c4e4c2f",
    "client_registration_state": "681374559f5c5386b92d4aa207f12e336353e3e0600e85a16048de08cf22eaab844730d6c63bb43e86cbc77b7ca8a6a002aae92f0063848f8a6c15a4765cf20cf07a7e05bcbdb002417f7c805cab03637fa0ca81ad6586fd88eb50d31cf6665d33",
    "client_login_state": "681374559f5c5386b92d4aa207f12e336353e3e0600e85a16048de08cf22eaab844730d6c63bb43e86cbc77b7ca8a6a002aae92f0063848f8a6c15a4765cf20cf07a7e05bcbdb002417f7c805cab03637fa0ca81ad6586fd88eb50d31cf6665d338ec5f2b36174b3008b229c8fb15c011c568491d865ea733ebade40f535d3d5790300af1020d54af94e626a4dc7d4c1a63afa62cef4ade8a8c500408356b4f2021a80ef23070631847b65da0983c1ee2054abdb0d43a2ed27a3933aaf20808664e3a07b00f6a95f4aacae683e385b0672cb75b6d55ef442150616cb369a43eeee346bb736bb98cf7b0ebaf0237adac36b6d02831beceeca1331cdabf05cbd332390cfdbd6138ec5f2b36174b3008b229c8fb15c011c568491d865ea733ebade40f535d3d579",
    "server_login_state": "7568e421d1d6399c5ff0eece96c47e227f2f25c3127a75fb92571935e1ca6c7bd71bc300110b0943f9366144eecab1e59612fdfaf4f4965226aa01d18823514982bfc02dee80ea8c86b26d9965a9349cabd8e37b527b91c07c8dbb94216f73223c6ddd88017be41002076cc59df9e02212c598bf58092df79394bac4cc6b43c2a64f7946022d7267095ac23cbf9d720b",
    "password_file": "0301f7c2ab43c80fd43d6b9e07c06ea3ecea60e7b9a06d2325e8448009cabc939960419e41250c299f812d18c40013cc8671b507fbe83cef2872618808b3b2ed52305691015c1b10e28e0009ccf42ed0c81f9e31e928352ef42a3c744702e57eea9ce669ae36924c62ed5eba6bc72e32adf46b000e1920d2013da7400a842647c76e672f58bf23146499bdc6e1c4fa70a5b9a2926feb2d5ee85af6dfd6362758ff965527da3eae39f26929ef1a0de46cc8f863a0a2de330bb13a12e0cec0053ba1d3d3",
    "export_key": "abe2c7350c9375c089735fc9ed993ac86ab7717c3ff7537f84927c7e657814eb6cad33fdac22579b1da8a154473ac630",
    "session_key": "3c6ddd88017be41002076cc59df9e02212c598bf58092df79394bac4cc6b43c2a64f7946022d7267095ac23cbf9d720b"
}
"#;

#[cfg(feature = "ristretto255")]
static TEST_VECTOR_P521_RISTRETTO255: &str = r#"
{
    "client_s_pk": "0200c7b6ed4a01bc742f08c4ad459a1c322464b649f259deb4d8311891ce5c54cfa1743c3fd16510e1919b95d285e21edbb528d4a26ebea822bcb36fd0cb0d911a0838",
    "client_s_sk": "01790ba2fd567457fc789f7d0f3d5c21628d1f26b1858c294784fe2856213584fcb61ce64f172131a400a5de979f757caa03d9bc46585a8d9c2ddc9aa1ba097008b3",
    "client_e_pk": "02000922189ff2001f966be172afe232364a44c642088a413fa4d0c722036ecde062b27db553430170739b2c7344e4dc391353e963306c6762671dc5c81d41d487e979",
    "client_e_sk": "00ad4ee167cb575d3acb092b242e33ba1251fab824577b15103e46889da450bdc61d30063f31204e55176e1fa7cb9e6da98580264dfae9af0a8b292622abcd9176d9",
    "server_s_pk": "0200f7056f49bf9041e6ccfb53d8e004fa9877024d81ef4c8348cf203f1f428e72b40a981fbb14bfef555b18f5ba7449137c4779f927d326fa91c5b0f3618e51154db2",
    "server_s_sk": "00f4aa9e4df91f18f49f1291ae705695c41c0ef78ef3304e1a06295611d992d744a152f58b6b21701f58a5bd58308fca939d558032ceddc666050314f49987f52f34",
    "server_e_pk": "030095b5494431847efccf881a44a39b447497a5c42f780d31a842657046891e46c7be0a65b723fe58821a151252612c28fb6c6294a214a435b3fa63456d9933488fe8",
    "server_e_sk": "0129217ee6b2fddbb1e1383b3e51e366756ea467d308228a4e42fb7d5c61b961ca9064335cb75b9199db2facdcd470421c2ab0861820c965c78cc9283ce81d54f713",
    "fake_sk": "015a4348332316896d93e77dfe30c52d89dbb60feef92d058c0ac2caed874732378d0b12743ff3e7e124ccf8a8e8f8549dfd12ccc3b83337aa08d571e3d74bff25a6",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "78b1b0e414ff0620e08ce29ce7b3d0708ab8b714ce51b1462df445b330f0370e",
    "oprf_seed": "a10339762c30be4b7c3505717c82e30124d20c30a0d301c256ab857e554d19bb3a2fba7cb7f63712c87d1b565087df3295f5c3c6999893ebd2d3cfbc5e4b7ac0",
    "masking_nonce": "92e9d1e0cc4f4ba72324b4ea2f06f6566fb891966914bf1fb99deaaaf6ef3cd515e845dbd27aecd08804bef261f7ba1539891e392fdc531f5e8c5c339ebdc680",
    "envelope_nonce": "3c4ce4e1ea8d26fea55c8f3831239e9a3f3049c6ef592af64fbe8588a3a334de",
    "client_nonce": "4d3350751a212033cb9317d79f54ae7e212b1553cd995e70c80d6233a8135314",
    "server_nonce": "2ea9b358507e234c094e51ba9b29b2d1c66475874f67e1b10d321a127f81972c",
    "context": "636f6e74657874",
    "registration_request": "20a8cb5f3c006a290efa87cffd278fb7a03d774a912c00314bffb45bdc349d57",
    "registration_response": "de6934e30242b26558cca8bbb8305cadf2d520a0fc1ef31c35f7d0bc745bab170200f7056f49bf9041e6ccfb53d8e004fa9877024d81ef4c8348cf203f1f428e72b40a981fbb14bfef555b18f5ba7449137c4779f927d326fa91c5b0f3618e51154db2",
    "registration_upload": "02019f2dad65bb7c8c3235e37fe8eeb6020e5cad87e2f457f6e6d5580f470c170a570cf9c483cb0409908ca9601cccbcc0268b26b1f0b2b60a1da13a84b8838b7276c9137de96ca93e3371f5c8123cd2e11f8722235cffb9474c5f30e77fd935d7a2798381ce6edc637bcc6dec6457674082a9b0c44c1319512f1a9f3bedf6c41303a601790ba2fd567457fc789f7d0f3d5c21628d1f26b1858c294784fe28562135847eb091d8d5dfe2ea6bb8d4cc6da8762a2af950cee871e1f013ab8901c7abf3b7add55f6362b3c4788a352a17f8ac0ffb34920f05c2acdfc2ab08ad1aa08db037",
    "credential_request": "20a8cb5f3c006a290efa87cffd278fb7a03d774a912c00314bffb45bdc349d574d3350751a212033cb9317d79f54ae7e212b1553cd995e70c80d6233a8135314030140d3be5c6c945cd4d35fa7bc205b199b9e94842e3ba84027a8d3266956e7687802c967215813a79aee28d57c4027ec6839c16456eb09a99d34dda31e59ff803efe",
    "credential_response": "de6934e30242b26558cca8bbb8305cadf2d520a0fc1ef31c35f7d0bc745bab1792e9d1e0cc4f4ba72324b4ea2f06f6566fb891966914bf1fb99deaaaf6ef3cd5a589e01bf0e72646180a9be9b8caf6bf1c40b1f0b8746bd6fb05e345ed03fa49763205ac7b08e844387ee87942d9479360a05cb6cf38d94773cef1ed341695f53933581b917c4691bc9c0c6d234f598c41d3c403706d8c745eafaef8e9e956781b73d50ccb6dcfcdb613cf9c12188f65ef28a76b4d4e5621176734efad29d16ea91dae77e2a368a9335f80a9fcbfefc7484302e6309639f17632d1ff61a441656a7e7864335cb75b9199db2facdcd470421c2ab0861820c965c78cc9283ce81d54f713030101d16abe47f16b8aa41aa523dbac0d829739631b2c86630d6be8af90e9d76d1a0244ad8e80ba6b51b5e4f2d83b3cf52574ae71ade7e2cc5ad2ac63b9841824b7c6bdd510d5b3430c79e790bf823376f58cf764edb1b756bb8a6b717c951b773d36bd2a7fa7cc5c041dc291c58243bfc49fe10724a39b4846fe8f9462ffb5cfc336",
    "credential_finalization": "75bc6b1d874a12a54506e11ba8c39d7d276e3e35b78b9d672fe90dcb48954665c6b99c97f3cc58a2d0d564b021b103841189a216831be151626b9efe0aab7e7e",
    "client_registration_state": "78b1b0e414ff0620e08ce29ce7b3d0708ab8b714ce51b1462df445b330f0370e20a8cb5f3c006a290efa87cffd278fb7a03d774a912c00314bffb45bdc349d57",
    "client_login_state": "78b1b0e414ff0620e08ce29ce7b3d0708ab8b714ce51b1462df445b330f0370e20a8cb5f3c006a290efa87cffd278fb7a03d774a912c00314bffb45bdc349d574d3350751a212033cb9317d79f54ae7e212b1553cd995e70c80d6233a8135314030140d3be5c6c945cd4d35fa7bc205b199b9e94842e3ba84027a8d3266956e7687802c967215813a79aee28d57c4027ec6839c16456eb09a99d34dda31e59ff803efe01578726229c9f4c4a0b3d0514c2f9a297dcc14d0ee7e93f7ab5815256e8efdf2a62f9edd6019090e788a736dc6a6a2fee4a26cfd8151799d8872de94f973eac69ad4d3350751a212033cb9317d79f54ae7e212b1553cd995e70c80d6233a8135314",
    "server_login_state": "b24a046effadb7b53b9082c4e21a02abbbc85ef966ad912655b089ed87b5f3ba582c3b085041edaef140c2a4d3cee3586dfbf782628ab368755c1d9f766b63f7db9619b9f3e0c367ed3bc38611efbdadaf17c25515b338a799eb0698e9eaef8d1bfd72bca9f8067f2c87686e4466e5be960b65262226794ab73c28d9bc806b294ab998031003c6c2bbffb8932f06b3f100e84de57c2e9411aab982f23c269cae5b26b0c2485f6ca0fb29005c1e274871c94c43b0cb68bd77dcd0423ef4f600f9",
    "password_file": "02019f2dad65bb7c8c3235e37fe8eeb6020e5cad87e2f457f6e6d5580f470c170a570cf9c483cb0409908ca9601cccbcc0268b26b1f0b2b60a1da13a84b8838b7276c9137de96ca93e3371f5c8123cd2e11f8722235cffb9474c5f30e77fd935d7a2798381ce6edc637bcc6dec6457674082a9b0c44c1319512f1a9f3bedf6c41303a601790ba2fd567457fc789f7d0f3d5c21628d1f26b1858c294784fe28562135847eb091d8d5dfe2ea6bb8d4cc6da8762a2af950cee871e1f013ab8901c7abf3b7add55f6362b3c4788a352a17f8ac0ffb34920f05c2acdfc2ab08ad1aa08db037",
    "export_key": "2f9cdc35a5ac32c81e8f204fb95669c1c03a5a67d7146c59d5bd9ddf0ac181c7f24d5b2fe964944279d4f098288de70ef8a45cef30f5a137ed9f4b2c57921178",
    "session_key": "4ab998031003c6c2bbffb8932f06b3f100e84de57c2e9411aab982f23c269cae5b26b0c2485f6ca0fb29005c1e274871c94c43b0cb68bd77dcd0423ef4f600f9"
}
"#;

#[cfg(feature = "curve25519")]
static TEST_VECTOR_CURVE25519_P256: &str = r#"
{
    "client_s_pk": "356d33885c60c90a4bca2ca9e758c72842016738cb29114efe5b363a77e60e18",
    "client_s_sk": "98e74559a5af2af21de2f4caf01dd88232ee6a542e6bd2ed68b9dfa9ddf65e6f",
    "client_e_pk": "d9a367a4aa1f2822a5e50d3616f8763bda41a0882f2d29d78e25db36594dd44a",
    "client_e_sk": "f8ca80bc3fc0301986545adc309928a756d2aa1e79c6c617386a2ce9bc31da5c",
    "server_s_pk": "fd69aa024b1896f5911c50d2990ec5075738a5a86a9722b9779eb3032eb74838",
    "server_s_sk": "b06d35d129927c7427b2532656d7b33db7e6ff0070c630ab37a5022af8899b6d",
    "server_e_pk": "05369b574ab94ef297688d377c4fb4693b80898733128ebce44ad6614290aa64",
    "server_e_sk": "a02c5c8d35a1924823bd9ece4a67906211a29674355896061f2c72b63a806959",
    "fake_sk": "48faf5b2e5852fa92c7e431eee79383886885e9b2fa0e5957728614af670c964",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "afde4969d9abad215bc2d476b968a4113ce39c8736da16e107e067abbb9343c9",
    "oprf_seed": "1b55db8ba8bed7c6dffee2682971f938ae43f91898698c5f34a6c6dd64e69a19",
    "masking_nonce": "da87388c66103598f4b49a44abc7ac2ebf6caad4db2e32e19fb59d845e9d9b820f7afe413703648d03501421f9d2e25bd38bf35bd0a5b7167927cebe237c3dad",
    "envelope_nonce": "3c9f900ce6674b8ea3ee734678bd1e9397a1842392f2c79b3400434bee6934f4",
    "client_nonce": "e1b52de2ccb8b8b9175bca18cac32ac5138717d2bdea57dd1e8182f71e98af8e",
    "server_nonce": "d26610cea1112c2c57955b5e24242be031632dfd8ce1a018cc62ee653e5a8e33",
    "context": "636f6e74657874",
    "registration_request": "035741c014e89d5a10fd6f2b81e2cfc9f35e53222c619fb6fd20608843530b74ae",
    "registration_response": "0264db058e5010d658021d7c1b972d626fa353712c83bf7a7500d4a9bc22e85358fd69aa024b1896f5911c50d2990ec5075738a5a86a9722b9779eb3032eb74838",
    "registration_upload": "9dc1380a44873401d0dc181baecf898e9bc1f4bbcd75e7de3e28ef9f6b570479e059b27ad6ed0f9b240d9dde050aedbf30a5684e23dfe1af47f6bb75b240c74a98e74559a5af2af21de2f4caf01dd88232ee6a542e6bd2ed68b9dfa9ddf65e6f85396cff1f5d230d09bd9e662bd5a4d9594a32d2ab2b2f8a581542db82467f5e",
    "credential_request": "035741c014e89d5a10fd6f2b81e2cfc9f35e53222c619fb6fd20608843530b74aee1b52de2ccb8b8b9175bca18cac32ac5138717d2bdea57dd1e8182f71e98af8ed9a367a4aa1f2822a5e50d3616f8763bda41a0882f2d29d78e25db36594dd44a",
    "credential_response": "0264db058e5010d658021d7c1b972d626fa353712c83bf7a7500d4a9bc22e85358da87388c66103598f4b49a44abc7ac2ebf6caad4db2e32e19fb59d845e9d9b82aac713b4beab61312d2d57d98249f1a6e5e7c8bd435d704149679a381fe3c8da8b9b682af290e93422d1c52fa5cb94135823f8587b3c2a9056ab36845659ff2cad86ca029fd836b316471f1a42ee1a928331a4f7c1ec7aefc6429a13008c88bea02c5c8d35a1924823bd9ece4a67906211a29674355896061f2c72b63a806959606d4e3a19bfa8f940c87e5dc9e63ddf6c083d7406942c8c32e6bf7b35c504231d00490013365017c87b0c786f7d58e0bbe69c3c7f22f75e67c4a2ebf716c595",
    "credential_finalization": "e9e0ec963e9096dcfcbed47fdf6ac5c0fa43103a11753d7f82652ea3d64a2657",
    "client_registration_state": "afde4969d9abad215bc2d476b968a4113ce39c8736da16e107e067abbb9343c9035741c014e89d5a10fd6f2b81e2cfc9f35e53222c619fb6fd20608843530b74ae",
    "client_login_state": "afde4969d9abad215bc2d476b968a4113ce39c8736da16e107e067abbb9343c9035741c014e89d5a10fd6f2b81e2cfc9f35e53222c619fb6fd20608843530b74aee1b52de2ccb8b8b9175bca18cac32ac5138717d2bdea57dd1e8182f71e98af8ed9a367a4aa1f2822a5e50d3616f8763bda41a0882f2d29d78e25db36594dd44af8ca80bc3fc0301986545adc309928a756d2aa1e79c6c617386a2ce9bc31da5ce1b52de2ccb8b8b9175bca18cac32ac5138717d2bdea57dd1e8182f71e98af8e",
    "server_login_state": "f34318b0b8512ad4aed925465f80e25f3ca18b6ac57f0341beeaeda4ce944580d541e1e80e929cd4f2ce6e91c71a816e09833176a3a3e48801e9583b7da585535266262802364c33b9f4ebbf1e5fafe05b4beb6871bd197c5c3110d22404dd5b",
    "password_file": "9dc1380a44873401d0dc181baecf898e9bc1f4bbcd75e7de3e28ef9f6b570479e059b27ad6ed0f9b240d9dde050aedbf30a5684e23dfe1af47f6bb75b240c74a98e74559a5af2af21de2f4caf01dd88232ee6a542e6bd2ed68b9dfa9ddf65e6f85396cff1f5d230d09bd9e662bd5a4d9594a32d2ab2b2f8a581542db82467f5e",
    "export_key": "644446d460267013ccc320a626484f6d8b4fa773f1558c43eb0ddce656a53570",
    "session_key": "5266262802364c33b9f4ebbf1e5fafe05b4beb6871bd197c5c3110d22404dd5b"
}
"#;

#[cfg(feature = "curve25519")]
static TEST_VECTOR_CURVE25519_P384: &str = r#"
{
    "client_s_pk": "f94d2f4ed06a99e5dc09edb4ed4566a29cb6706243ad0665019b559932a93375",
    "client_s_sk": "8034c5724cb6345b3534de5b1e44f6e4e97f5a98c3f5c7203f84aa370f00dd54",
    "client_e_pk": "3a8ec2f554673ecf8c706759d6f24a3a068594f49e22769c763a3f712e289a22",
    "client_e_sk": "60dac79209e340f068112840c69c681f458d55916af81521e3aac61058aed542",
    "server_s_pk": "70dafba720cf8ed7c5001107f1679974c8dd53f51bb12c6362024bd46d294e6a",
    "server_s_sk": "b0beb05237a893edeefad4bfb87d8a56d79120e2ef71ccf335fb36719822bf54",
    "server_e_pk": "7e5ac26d2eece1e95a7db76a2c9b0f63119c59755bde71baa153b700d10afa09",
    "server_e_sk": "004fb840dc8e2b4bf44cbce8bc9fb2439439ea8c81bf9299fe62a6a7eb133572",
    "fake_sk": "a8b7f29cc8faa909eccd741c8a9c043adf30b76ceb29979015e4905aa8c98975",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "b448ff1079b9bb899acb01f271303e43a1db682c515780cff8ede88795ab7aae65af947df67425dacce97080a82d63ee",
    "oprf_seed": "453a628c1033f01a8a7e289afd6a0701249eb387115e68dda5e9762815acc3c6890201190623466deb6ebcfa8d348c97",
    "masking_nonce": "043b357b425f2fa9a3bcd694f4599838ade3d2a565f3debb64549400922f698bee9d14b0246b92eecf22aee99d9267643e33bf2e6d1985da0b12fb06a1acf102",
    "envelope_nonce": "872593dc9342df3095eabdd5f238c27874e6bfdac3f7f2b413f396aa878dcc30",
    "client_nonce": "5b11f9c0204aa46756eb81a3929a54e3723294459cb82b37694cf7c1b8c130c0",
    "server_nonce": "2ed607c5c0d2cf6babe59b07b175eb2daca2c7b7f4f18ab8109edde08a2467db",
    "context": "636f6e74657874",
    "registration_request": "03840be924a75bf138c7d6ae38a34cee612df596e2e375482cdec3416bcee6e18ced4de0fb21325b54695724bcb2f6fb4b",
    "registration_response": "037179bd08a76c2e668c9665df3a6b47d2753a6cd0d3cc84ceaccc8719f538a603a4704e4cc1e8c04dcb3e1f30fb69badd70dafba720cf8ed7c5001107f1679974c8dd53f51bb12c6362024bd46d294e6a",
    "registration_upload": "036855719f79f2e7431c00616260933a2ead332dddc0d6a431945095f3abc62da8d6f332c5d8508850d33745ef81d4a87c7c684c6546aa31ce1084a279bbdc6d76b7c58c398d438e046e1e2b60ae9c9a8034c5724cb6345b3534de5b1e44f6e4e97f5a98c3f5c7203f84aa370f00dd5432cae335c0d7f1dd6abcce898bc8a7c7fe2ccc1e8b37accacd9f28f8a236f71979e28d47fe3ccaadb292fff9d4cc4c67",
    "credential_request": "03840be924a75bf138c7d6ae38a34cee612df596e2e375482cdec3416bcee6e18ced4de0fb21325b54695724bcb2f6fb4b5b11f9c0204aa46756eb81a3929a54e3723294459cb82b37694cf7c1b8c130c03a8ec2f554673ecf8c706759d6f24a3a068594f49e22769c763a3f712e289a22",
    "credential_response": "037179bd08a76c2e668c9665df3a6b47d2753a6cd0d3cc84ceaccc8719f538a603a4704e4cc1e8c04dcb3e1f30fb69badd043b357b425f2fa9a3bcd694f4599838ade3d2a565f3debb64549400922f698b817494112f8b8547a859357085e26d06cdb5cf3fc1d815fc35c158d0fd079bcee961df7356749be2fd54f310f89260a7cf67de23b12ef4b3a1f4f39f9454279602f6c32842f7618aa41cb16cd94c58490e2174641dcc05134e3d7806c5a0af9eacc7c53bf8aea591bb25a7ac9ae6307d004fb840dc8e2b4bf44cbce8bc9fb2439439ea8c81bf9299fe62a6a7eb133572891c828f84395e2fa18bddf2779342d51d87a6cc0382ff7b4f792ec1d25dc9110c60c54343806bb3fabf01c74cd948cb089a4f5841b43f85335ccfea5c6bac71b282f1fda62f6c49d11fc7da20ff4f08",
    "credential_finalization": "e85722888bbf3939cee3510febedb204e6768dcdfb99d258754e5a9bbd7f8ea1a0d65a6dd28af223e94f334c5801a06c",
    "client_registration_state": "b448ff1079b9bb899acb01f271303e43a1db682c515780cff8ede88795ab7aae65af947df67425dacce97080a82d63ee03840be924a75bf138c7d6ae38a34cee612df596e2e375482cdec3416bcee6e18ced4de0fb21325b54695724bcb2f6fb4b",
    "client_login_state": "b448ff1079b9bb899acb01f271303e43a1db682c515780cff8ede88795ab7aae65af947df67425dacce97080a82d63ee03840be924a75bf138c7d6ae38a34cee612df596e2e375482cdec3416bcee6e18ced4de0fb21325b54695724bcb2f6fb4b5b11f9c0204aa46756eb81a3929a54e3723294459cb82b37694cf7c1b8c130c03a8ec2f554673ecf8c706759d6f24a3a068594f49e22769c763a3f712e289a2260dac79209e340f068112840c69c681f458d55916af81521e3aac61058aed5425b11f9c0204aa46756eb81a3929a54e3723294459cb82b37694cf7c1b8c130c0",
    "server_login_state": "92be6961dc5d248b0724bd3f428e036d968756f0b7e0e551c5f4100294b1c8dffa147894e74b1e0229d8fdca0971a529d85fe7c10eba397a9499c59e8513c72df6687652590a36cf7bf3cc4a06d9ab452431ee154bf2a41542c6ec5c4f5de94db19f799a9ab8cf49cc4ecd52b35f6b7a01d454a8f5bc0f3853e43278463da212a614bb4a32b3c3bbb8ee2e9e284a5749",
    "password_file": "036855719f79f2e7431c00616260933a2ead332dddc0d6a431945095f3abc62da8d6f332c5d8508850d33745ef81d4a87c7c684c6546aa31ce1084a279bbdc6d76b7c58c398d438e046e1e2b60ae9c9a8034c5724cb6345b3534de5b1e44f6e4e97f5a98c3f5c7203f84aa370f00dd5432cae335c0d7f1dd6abcce898bc8a7c7fe2ccc1e8b37accacd9f28f8a236f71979e28d47fe3ccaadb292fff9d4cc4c67",
    "export_key": "7175fbd9eed61a7cb5b723faafec8c945733622a90c75a72ec262599cff1afeb0ddc1f30eadb69c71def535001ef5e99",
    "session_key": "b19f799a9ab8cf49cc4ecd52b35f6b7a01d454a8f5bc0f3853e43278463da212a614bb4a32b3c3bbb8ee2e9e284a5749"
}
"#;

#[cfg(feature = "curve25519")]
static TEST_VECTOR_CURVE25519_P521: &str = r#"
{
    "client_s_pk": "e51157b128e045e034080d6f9c94c9f072a811868291a2a8b0507acae07d3058",
    "client_s_sk": "10a98984c3e92237cac31fbc8cfac6a5f66166856d5157f8cfb725bfb01bee6e",
    "client_e_pk": "ca077bcb85913a6bed08f36b9359696117cb62d2777f75a616aba34175f7162f",
    "client_e_sk": "68d7cd9f3f318e18c74318b413bd3af92515791777963d43bf01eb1d18e92b76",
    "server_s_pk": "01dfaa80028e044c9a6dc05f413fa81a97930a2d61a3e3ac4c613c1ea5aa9f64",
    "server_s_sk": "a81ff46e69e1ceb22e5ce01c2e210200517171f4bce98f17c8ee43d7e84eb170",
    "server_e_pk": "9c08035f138efb307bc4c4a331fbee84fef3ba69a62180bc2e68a107502db601",
    "server_e_sk": "b02d1a7b746c70154de464a6bbf7f569a3266069e5aecea208ebbb92f5259178",
    "fake_sk": "6828deab22a289a2ea67fccf685a93a279e5657dde2a0eae1da09d0b76829c5b",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "00965609755b1559b7b8b9158b722ac11ac549325bbc7c3656acd6e685e26483cba4feecb8e36074a5923ad5710780ecb176983b10516eeef5baeb38f9077ea490c9",
    "oprf_seed": "08d6d06353311921e6066c8c84609b2f7172db7502e14d85242d92cd3c2344fb279aacb4cb970d84b606bb949bc9d3e67288563160af407c9178a8107820ab2a",
    "masking_nonce": "8424ee5aad2da9e0584d9f19a0ba632e6dc3a927cf1bff0a37751f7168f612fa693ddca55027759f806318d21f491a3b73607d613651658a8f6a16ab4a1705f5",
    "envelope_nonce": "f0bf30325ce1abb9bb9c607101f4546039512a4314e339bcc899eca9c6eb7cde",
    "client_nonce": "f25c48001a3ef1e57ff5f3d2ec5168afe86661d85273516854ce8587e505e7f4",
    "server_nonce": "ad68f43c28f19ab84eef4978a127c049e75901a6168cf82a87e60fea541fc8eb",
    "context": "636f6e74657874",
    "registration_request": "020070e6e66baeedd725ce8a37d25220408ed517d6018d5700b06880024a10625d01545103b5152d8ffd36972ffaba91327a24b0e18177386244c3debec34c99100c63",
    "registration_response": "020001cd25216f810dc534b095321323a2b9cfc7e098d482addfa9ce843042b45912a03837ee1469044f3b78aad65bb35704b66917b09a537eb531ad5b205cc05daa5101dfaa80028e044c9a6dc05f413fa81a97930a2d61a3e3ac4c613c1ea5aa9f64",
    "registration_upload": "e6f7414e8521bef8d0e6d5f10a7b25d7e04ce56e3c11c16c515beb3b4e776f135ea1ccaef9ceaa480d3b3b04cf32570a502e7ce1efd33156a991c7135b980bd823b022a32cb83e6d02352cb72a3111a82a60148a1ba9444a4e9f317c5daa59e710a98984c3e92237cac31fbc8cfac6a5f66166856d5157f8cfb725bfb01bee6ed7a57577f895bd892134815176e2a42c90d3ad60d3a828bfe5b6cf839811872b5caba5f560b1d291078397dd26235512e2b1d37510973b9a0600839f15659ab0",
    "credential_request": "020070e6e66baeedd725ce8a37d25220408ed517d6018d5700b06880024a10625d01545103b5152d8ffd36972ffaba91327a24b0e18177386244c3debec34c99100c63f25c48001a3ef1e57ff5f3d2ec5168afe86661d85273516854ce8587e505e7f4ca077bcb85913a6bed08f36b9359696117cb62d2777f75a616aba34175f7162f",
    "credential_response": "020001cd25216f810dc534b095321323a2b9cfc7e098d482addfa9ce843042b45912a03837ee1469044f3b78aad65bb35704b66917b09a537eb531ad5b205cc05daa518424ee5aad2da9e0584d9f19a0ba632e6dc3a927cf1bff0a37751f7168f612fad03a8ec22437ff5a43c5a1a4f224a8b6dc4aaf2e1cdc61fd500b314277d6ceb693817163ec39b6d37d405775a4f1b1d3bcd52ff8a06b558444c70a881ec2670c1fed46bc0b381aa72b9426146136a1ebaae5b492ef43274e1576da6708e34620b0da07c776ec09ef3221e1b8b0d63c5167b34aa2249f3d03c1471f463f881574b02d1a7b746c70154de464a6bbf7f569a3266069e5aecea208ebbb92f5259178742563b32fb958454ff199f27c6a5f02d2e8fcb81f98de101f31ba1d6d5aec482c2b3d9f485b5cdbe0a5f3e44ba14b5ba2ba0e1346bf2de221c622e015288ab7f22d88edf1f925d459243ec6259cb91c018dc16855ebf9f19df48f905c5655cf",
    "credential_finalization": "1080b9083ae9ff94e7f384172f05bced0220a598953be5079a6ebc6399fc2f4d54da019acd5bcd6939fb7053acc653be7834698e9d4bd613f0b0f2ca4f96af0d",
    "client_registration_state": "00965609755b1559b7b8b9158b722ac11ac549325bbc7c3656acd6e685e26483cba4feecb8e36074a5923ad5710780ecb176983b10516eeef5baeb38f9077ea490c9020070e6e66baeedd725ce8a37d25220408ed517d6018d5700b06880024a10625d01545103b5152d8ffd36972ffaba91327a24b0e18177386244c3debec34c99100c63",
    "client_login_state": "00965609755b1559b7b8b9158b722ac11ac549325bbc7c3656acd6e685e26483cba4feecb8e36074a5923ad5710780ecb176983b10516eeef5baeb38f9077ea490c9020070e6e66baeedd725ce8a37d25220408ed517d6018d5700b06880024a10625d01545103b5152d8ffd36972ffaba91327a24b0e18177386244c3debec34c99100c63f25c48001a3ef1e57ff5f3d2ec5168afe86661d85273516854ce8587e505e7f4ca077bcb85913a6bed08f36b9359696117cb62d2777f75a616aba34175f7162f68d7cd9f3f318e18c74318b413bd3af92515791777963d43bf01eb1d18e92b76f25c48001a3ef1e57ff5f3d2ec5168afe86661d85273516854ce8587e505e7f4",
    "server_login_state": "a4326619610b42bb341c950aba574f951aa788323ef88c8116cf42237ba45a5ecbfd6c002910fb1dfb77d9e6d273ea5d8ba51c95bfd603f17871fdda3729433e95c8cf96afc48ca6be3005003066d6b0956ad9660eab5e3f41d26da4bc430a056ac685fab041bebe3aeac5f88806880038633c4bbf1038003776f522ec1225133304072e4a1005052f9c4f38d871c143d95b2ce387a12849601dcd547d87babf450019d9062da5a42afac06a34d3bd2635c640b5a75296253a4948b43ae86a31",
    "password_file": "e6f7414e8521bef8d0e6d5f10a7b25d7e04ce56e3c11c16c515beb3b4e776f135ea1ccaef9ceaa480d3b3b04cf32570a502e7ce1efd33156a991c7135b980bd823b022a32cb83e6d02352cb72a3111a82a60148a1ba9444a4e9f317c5daa59e710a98984c3e92237cac31fbc8cfac6a5f66166856d5157f8cfb725bfb01bee6ed7a57577f895bd892134815176e2a42c90d3ad60d3a828bfe5b6cf839811872b5caba5f560b1d291078397dd26235512e2b1d37510973b9a0600839f15659ab0",
    "export_key": "9cb234294ffb495fe5f70a9145c8701b3628d82164f2c9c353bd85d9b948912a6906498a66ddd75a7cc7273048bcc3fb2fbb4e67f3eeae43325653e6fb9afaf5",
    "session_key": "3304072e4a1005052f9c4f38d871c143d95b2ce387a12849601dcd547d87babf450019d9062da5a42afac06a34d3bd2635c640b5a75296253a4948b43ae86a31"
}
"#;

#[cfg(all(feature = "curve25519", feature = "ristretto255"))]
static TEST_VECTOR_CURVE25519_RISTRETTO255: &str = r#"
{
    "client_s_pk": "6f00b5a7c3400e5b3480e4ff963affa27a2e894bfc246da63404ab5dfcb12861",
    "client_s_sk": "402429cb18f30b6e5e6c3c4a9fb95480d31e9490c96ec09038bad2a2bba70378",
    "client_e_pk": "e5571e70f949d095f6f8385e0056abdf4182175d61f466a80d9ed8cbeb6da42d",
    "client_e_sk": "68d89ca14f80c9cf0cbe905ccc3573999c5eefacde6a2373591f6316828e9c65",
    "server_s_pk": "deafeb091131b492b8ad5af1aa10a3e95f503cc27f156daa5d612cf917b7512e",
    "server_s_sk": "40e5d55900e9402b0bf311e604fc6574cfc1786a9024132fd617b5e1015b9d7e",
    "server_e_pk": "40c97d16c9e95f8f7c7db8c9057afea8b3fccc06890e002ba36834e5271c3352",
    "server_e_sk": "480173d0dc1d7cc60382fb0c3fca5814acac964ae0e4984f31d9f3aac2a62850",
    "fake_sk": "50e9872b44d1595ab4478ce74d0e3b00666fd713ed5e1e5f172ef0bbf3014a6b",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "8a6a055fcb9a6b7d2ba698bbec4099dbbc6a35766b63b16c04731399657faa05",
    "oprf_seed": "acd7d6bb5cbc48e3a5002158e14292e10fd0bbe27084b2ff2b917e8ae4cfe6901cbcc8eaffd83229cea4895e3aefb0456f14b887bd2077a5743cce5e86304c5c",
    "masking_nonce": "8e287233c7add7f2d3b3faa6aece0bd88274c45431d1f20302bba6f281a75c5db416d615c291a870f6b2350d872543df723d719144fd5282f853711d1430f348",
    "envelope_nonce": "32a0ece9a749a9982968975690b8cff5853da742018ddca972f5b2a64b368558",
    "client_nonce": "e6763553592f4f197b5411ccc02eae73f45480f2695169b07477d7fa953d384a",
    "server_nonce": "dc3e7e45e29129c8ce05ae2bbfde44c41ab01b976724f5e1fddc432d812390d4",
    "context": "636f6e74657874",
    "registration_request": "184bb0c06beba0eb813d28339db050e46b1d78ef51e0f715e246435b1f387030",
    "registration_response": "c23d5b2943f63db89b026e555cd40be4e42679d748d6b773154b9734eb17f65ddeafeb091131b492b8ad5af1aa10a3e95f503cc27f156daa5d612cf917b7512e",
    "registration_upload": "e44f23560d80e1ad23fcd321329069f44c7ecadbf5cd382642b9ab8d4660213ba69f7c5367f5e2662a2576b2c1c0284ba19da7de6db380081d6fb00126d69d143054ac49ac14a8a4422f72c205abee5f58917dcfb92932adbb7e1da5fa729278402429cb18f30b6e5e6c3c4a9fb95480d31e9490c96ec09038bad2a2bba7037886ea885ea9a847da454f4c1778e2d3cf693bed5995fcb60ea884675dd9acd5bbc5042fa6df3b87e7ea739fa8a9028097c5801348dba62a33b88b337030303639",
    "credential_request": "184bb0c06beba0eb813d28339db050e46b1d78ef51e0f715e246435b1f387030e6763553592f4f197b5411ccc02eae73f45480f2695169b07477d7fa953d384ae5571e70f949d095f6f8385e0056abdf4182175d61f466a80d9ed8cbeb6da42d",
    "credential_response": "c23d5b2943f63db89b026e555cd40be4e42679d748d6b773154b9734eb17f65d8e287233c7add7f2d3b3faa6aece0bd88274c45431d1f20302bba6f281a75c5decb46e775794d8612374cc354c24bb650bec4bae29d5ee748314a317a650176f02a606fbbd9565d62d0d82c8b989ed3c6cdca843b2c900591e661b76de3df23652ecea5aed831de1f3e68ee6a71953ada0ee5a0349f7a8469f0ea58113cc82e9a5f293cb03a74d05eb14d57ffe14b5a8dccc5b1fe8b5e31e8eec756ce7418d18480173d0dc1d7cc60382fb0c3fca5814acac964ae0e4984f31d9f3aac2a62850976c2d5a50e59e96708446af04c477438782bd8ab1be69ed331deb0f17a24c1ee2bdc5fedb0ecd1c2a842ace5d81b4ed0e93c89d883e7b8c59a3a3ca5f9c868eadb3d9835e09fd6bbbb45d91543c061cde3e3d94df2cc61f80993946065bc032",
    "credential_finalization": "45929de91f8996598dbe7c65db1f445a62510e8a27ddcef0ae1bcb033f4b74d03f4beb4f83f46602a20152adf0aad3afa465d5b2346f31be62bcc9adac4b5aab",
    "client_registration_state": "8a6a055fcb9a6b7d2ba698bbec4099dbbc6a35766b63b16c04731399657faa05184bb0c06beba0eb813d28339db050e46b1d78ef51e0f715e246435b1f387030",
    "client_login_state": "8a6a055fcb9a6b7d2ba698bbec4099dbbc6a35766b63b16c04731399657faa05184bb0c06beba0eb813d28339db050e46b1d78ef51e0f715e246435b1f387030e6763553592f4f197b5411ccc02eae73f45480f2695169b07477d7fa953d384ae5571e70f949d095f6f8385e0056abdf4182175d61f466a80d9ed8cbeb6da42d68d89ca14f80c9cf0cbe905ccc3573999c5eefacde6a2373591f6316828e9c65e6763553592f4f197b5411ccc02eae73f45480f2695169b07477d7fa953d384a",
    "server_login_state": "56f1f25910e0eca4e3d2d604b9cf8d3878138b4d89ef4966ae001cb5847f658f81850a6ee1aad03cf3864fa652ca9a7b04f02669d5a3e46f49641b8f188af27c06540e830a2f68264f3c7cb533f623b3fbef2ba87777f6909c20c42e911f26c92abdf474b4b1c9d591864a59b508a820b53ba819a0b14189e28b94302707cfe4164a6e3ec2dcba09aa66b70ee18c83ebbc9338aa0092d130051ad98a4bb931dd7bbc6ec93018ee8087435ac9f7171bb1b1b9fe022170963e39681129e2fe104b",
    "password_file": "e44f23560d80e1ad23fcd321329069f44c7ecadbf5cd382642b9ab8d4660213ba69f7c5367f5e2662a2576b2c1c0284ba19da7de6db380081d6fb00126d69d143054ac49ac14a8a4422f72c205abee5f58917dcfb92932adbb7e1da5fa729278402429cb18f30b6e5e6c3c4a9fb95480d31e9490c96ec09038bad2a2bba7037886ea885ea9a847da454f4c1778e2d3cf693bed5995fcb60ea884675dd9acd5bbc5042fa6df3b87e7ea739fa8a9028097c5801348dba62a33b88b337030303639",
    "export_key": "931b2394c380c1ae3a7e9cedaa9fc438fbc19e920fe74965813a7d4ee2c5cec8c13b144c826b259dd67a2507b3cf2e84f95d8e52dc2111050e7a91ee9d72be99",
    "session_key": "164a6e3ec2dcba09aa66b70ee18c83ebbc9338aa0092d130051ad98a4bb931dd7bbc6ec93018ee8087435ac9f7171bb1b1b9fe022170963e39681129e2fe104b"
}
"#;

macro_rules! run_all {
    ($name:ident $(, $par:expr)*) => {
        #[cfg(feature = "ristretto255")]
        $name::<Ristretto255>(TEST_VECTOR_RISTRETTO255 $(, $par)*)?;
        #[cfg(feature = "ristretto255")]
        $name::<Ristretto255P256>(TEST_VECTOR_RISTRETTO255_P256 $(, $par)*)?;
        #[cfg(feature = "ristretto255")]
        $name::<Ristretto255P384>(TEST_VECTOR_RISTRETTO255_P384 $(, $par)*)?;
        #[cfg(feature = "ristretto255")]
        $name::<Ristretto255P521>(TEST_VECTOR_RISTRETTO255_P521 $(, $par)*)?;
        $name::<P256>(TEST_VECTOR_P256 $(, $par)*)?;
        $name::<P256P384>(TEST_VECTOR_P256_P384 $(, $par)*)?;
        $name::<P256P521>(TEST_VECTOR_P256_P521 $(, $par)*)?;
        #[cfg(feature = "ristretto255")]
        $name::<P256Ristretto255>(TEST_VECTOR_P256_RISTRETTO255 $(, $par)*)?;
        $name::<P384>(TEST_VECTOR_P384 $(, $par)*)?;
        $name::<P384P256>(TEST_VECTOR_P384_P256 $(, $par)*)?;
        $name::<P384P521>(TEST_VECTOR_P384_P521 $(, $par)*)?;
        #[cfg(feature = "ristretto255")]
        $name::<P384Ristretto255>(TEST_VECTOR_P384_RISTRETTO255 $(, $par)*)?;
        $name::<P521>(TEST_VECTOR_P521 $(, $par)*)?;
        $name::<P521P256>(TEST_VECTOR_P521_P256 $(, $par)*)?;
        $name::<P521P384>(TEST_VECTOR_P521_P384 $(, $par)*)?;
        #[cfg(feature = "ristretto255")]
        $name::<P521Ristretto255>(TEST_VECTOR_P521_RISTRETTO255 $(, $par)*)?;
        #[cfg(feature = "curve25519")]
        $name::<Curve25519P256>(TEST_VECTOR_CURVE25519_P256 $(, $par)*)?;
        #[cfg(feature = "curve25519")]
        $name::<Curve25519P384>(TEST_VECTOR_CURVE25519_P384 $(, $par)*)?;
        #[cfg(feature = "curve25519")]
        $name::<Curve25519P521>(TEST_VECTOR_CURVE25519_P521 $(, $par)*)?;
        #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
        $name::<Curve25519Ristretto255>(TEST_VECTOR_CURVE25519_RISTRETTO255 $(, $par)*)?;
    };
}

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
    let server_s_kp = KeyPair::<CS::KeGroup>::generate_random::<CS::OprfCs, _>(&mut rng);
    let server_e_kp = KeyPair::<CS::KeGroup>::generate_random::<CS::OprfCs, _>(&mut rng);
    let client_s_kp = KeyPair::<CS::KeGroup>::generate_random::<CS::OprfCs, _>(&mut rng);
    let client_e_kp = KeyPair::<CS::KeGroup>::generate_random::<CS::OprfCs, _>(&mut rng);
    let fake_kp = KeyPair::<CS::KeGroup>::generate_random::<CS::OprfCs, _>(&mut rng);
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

        let parameters = generate_parameters::<Ristretto255P256>()?;
        println!(
            "Ristretto255 P-256: {}",
            stringify_test_vectors(&parameters)
        );

        let parameters = generate_parameters::<Ristretto255P384>()?;
        println!(
            "Ristretto255 P-384: {}",
            stringify_test_vectors(&parameters)
        );

        let parameters = generate_parameters::<Ristretto255P521>()?;
        println!(
            "Ristretto255 P-521: {}",
            stringify_test_vectors(&parameters)
        );
    }

    let parameters = generate_parameters::<P256>()?;
    println!("P-256: {}", stringify_test_vectors(&parameters));

    let parameters = generate_parameters::<P256P384>()?;
    println!("P-256 P-384: {}", stringify_test_vectors(&parameters));

    let parameters = generate_parameters::<P256P521>()?;
    println!("P-256 P-521: {}", stringify_test_vectors(&parameters));

    #[cfg(feature = "ristretto255")]
    {
        let parameters = generate_parameters::<P256Ristretto255>()?;
        println!(
            "P-256 Ristretto255: {}",
            stringify_test_vectors(&parameters)
        );
    }

    let parameters = generate_parameters::<P384>()?;
    println!("P-384: {}", stringify_test_vectors(&parameters));

    let parameters = generate_parameters::<P384P256>()?;
    println!("P-384 P-256: {}", stringify_test_vectors(&parameters));

    let parameters = generate_parameters::<P384P521>()?;
    println!("P-384 P-521: {}", stringify_test_vectors(&parameters));

    #[cfg(feature = "ristretto255")]
    {
        let parameters = generate_parameters::<P384Ristretto255>()?;
        println!(
            "P-384 Ristretto255: {}",
            stringify_test_vectors(&parameters)
        );
    }

    let parameters = generate_parameters::<P521>()?;
    println!("P-521: {}", stringify_test_vectors(&parameters));

    let parameters = generate_parameters::<P521P256>()?;
    println!("P-521 P-256: {}", stringify_test_vectors(&parameters));

    let parameters = generate_parameters::<P521P384>()?;
    println!("P-521 P-384: {}", stringify_test_vectors(&parameters));

    #[cfg(feature = "ristretto255")]
    {
        let parameters = generate_parameters::<P521Ristretto255>()?;
        println!(
            "P-521 Ristretto255: {}",
            stringify_test_vectors(&parameters)
        );
    }

    #[cfg(feature = "curve25519")]
    {
        let parameters = generate_parameters::<Curve25519P256>()?;
        println!("Curve25519 P-256: {}", stringify_test_vectors(&parameters));

        let parameters = generate_parameters::<Curve25519P384>()?;
        println!("Curve25519 P-384: {}", stringify_test_vectors(&parameters));

        let parameters = generate_parameters::<Curve25519P521>()?;
        println!("Curve25519 P-521: {}", stringify_test_vectors(&parameters));
    }

    #[cfg(all(feature = "curve25519", feature = "ristretto255"))]
    {
        let parameters = generate_parameters::<Curve25519Ristretto255>()?;
        println!(
            "Curve25519 Ristretto255: {}",
            stringify_test_vectors(&parameters)
        );
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

    run_all!(inner);

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

    run_all!(inner);

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

    run_all!(inner);

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

    run_all!(inner);

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

    run_all!(inner);

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

    run_all!(inner);

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

    run_all!(inner);

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

    run_all!(inner);

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

    run_all!(inner);

    Ok(())
}

fn test_complete_flow<CS: CipherSuite>(
    _test_vector: &str,
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
    run_all!(test_complete_flow, b"good password", b"good password");
    Ok(())
}

#[test]
fn test_complete_flow_fail() -> Result<(), ProtocolError> {
    run_all!(test_complete_flow, b"good password", b"bad password");
    Ok(())
}

// Zeroize tests

#[test]
fn test_zeroize_client_registration_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
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

    run_all!(inner);

    Ok(())
}

#[test]
fn test_zeroize_client_registration_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
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

    run_all!(inner);

    Ok(())
}

#[test]
fn test_zeroize_server_registration_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
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

    run_all!(inner);

    Ok(())
}

#[test]
fn test_zeroize_client_login_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite<KeyExchange = TripleDh>>(
        _test_vector: &str,
    ) -> Result<(), ProtocolError>
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

    run_all!(inner);

    Ok(())
}

#[test]
fn test_zeroize_server_login_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
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

    run_all!(inner);

    Ok(())
}

#[test]
fn test_zeroize_client_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite<KeyExchange = TripleDh>>(
        _test_vector: &str,
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

    run_all!(inner);

    Ok(())
}

#[test]
fn test_zeroize_server_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
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

    run_all!(inner);

    Ok(())
}

#[test]
fn test_scalar_always_nonzero() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
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

    run_all!(inner);

    Ok(())
}

#[test]
fn test_reflected_value_error_registration() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
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

    run_all!(inner);

    Ok(())
}

#[test]
fn test_reflected_value_error_login() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
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

    run_all!(inner);

    Ok(())
}

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
// cargo test --features curve25519 -- --nocapture generate_test_vectors
#[cfg(feature = "ristretto255")]
static TEST_VECTOR_RISTRETTO255: &str = r#"
{
    "client_s_pk": "74809ab73f3fce1f0f96994b134a3419ceb3f4ddf70576cf954a2983dcb40b00",
    "client_s_sk": "fc5227f5c05133d431605a7a81c4603dd608314ba144e869930c99f0a154a205",
    "client_e_pk": "d8a5c8709fd94b9a5accba09a7655549a0618688503d03292c5fdff2a4f7ca56",
    "client_e_sk": "94d7fb3feac2038d4874b20289d8b9ab7e5bf9bd32caf55cbfcc0a0feac9da02",
    "server_s_pk": "f85a606216a069db8eb4fbc610d01c9f1309729c54587a5c2a8d938b4a0f5c3b",
    "server_s_sk": "9df3e9139b27b1b86cb7dc660c9006d00148170efbd4ca5cf1048d10c102c708",
    "server_e_pk": "ae6e6397fcbf62a1a28febc9c249f2cde43a6a6cb794e48de4e3e70067073a0c",
    "server_e_sk": "f5e60f90edd94d9371b65bd83ca03e66bb81f19199f5518c7829dd6f2412db06",
    "fake_sk": "967f3070bc4a34d75708d677442595daadfc8edfff517b133dab2d8e9356e705",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "28205f2551a55a8e6703ac6ce61ba5c8cae6c4111372964a926685fa57dcc300",
    "oprf_seed": "641ca025289d724e292d5187fbf6c702e6fa0a233b015bb97afc0dc44e1a17d71e67c21eb117a3947a734a798b413d9257930082548c6da147a87d78b99009e4",
    "masking_nonce": "f5ba0c75c9ebbe84b0c2c3bf2eda017e5920a2dbc7d6887e3cd336b0f8ff6fc3e6d6e8f6f6b0b6e58c49ed150a19f388b3840a922e5ce7276d2c7c10748f0e04",
    "envelope_nonce": "7b918e30a79047ec3449153ac013afc42ef7dc1d8fece7fda9d99c3111398d90",
    "client_nonce": "c217cae6fa4e305d0dabe55c75598bf05f209eba5641dc296b1e377d34e64a69",
    "server_nonce": "2b57918ed314d46741d879044983b6dd20647556f6fecba8af18a09e2667ca12",
    "context": "636f6e74657874",
    "registration_request": "549790b0d74736be19aab565cbe0163eef5f5f8488a57f063acc0e4e35301159",
    "registration_response": "ec358a9f69f92c1d88215ef9f4a1c3c45cd3470db243dbe4298d455b7447db43f85a606216a069db8eb4fbc610d01c9f1309729c54587a5c2a8d938b4a0f5c3b",
    "registration_upload": "7eb2a312703c26e518cc4102da14f3151e76d86219fda92b021c8b6c8848f5614cd9ca81aaae9aa37733ef75867e570f4762513d1417fc77660eb5d8688d72fa24edea76c09d28b1877f151b84bf7f25e2a81fb589d51bc4725a7ab03a9694e0fc5227f5c05133d431605a7a81c4603dd608314ba144e869930c99f0a154a2056a35c3c5d994bb196547e57c4a12af3c33e5d3582d58f236b023f8a587e655bcbad3ec7974ae71caa39cb604a1a9445b9d2d8b8063f03d93a2ca9e8817a2af76",
    "credential_request": "549790b0d74736be19aab565cbe0163eef5f5f8488a57f063acc0e4e35301159c217cae6fa4e305d0dabe55c75598bf05f209eba5641dc296b1e377d34e64a69d8a5c8709fd94b9a5accba09a7655549a0618688503d03292c5fdff2a4f7ca56",
    "credential_response": "ec358a9f69f92c1d88215ef9f4a1c3c45cd3470db243dbe4298d455b7447db43f5ba0c75c9ebbe84b0c2c3bf2eda017e5920a2dbc7d6887e3cd336b0f8ff6fc331e708bf8c612085e1ea9e1545b6e5957d8d785741715e152965adb413cc86c4e075657bd56f81b41200d604133d9df1d0381ae71a79a0540b1f6128a265b7701947b3f2e3f0f3b9be424a49a09e0184a1062ff2b15ddd72f9ad68bc606eeef26597ce0db39ff2365856f27b06e823e63ecb6ae0ca2f334b61894049fa466408f5e60f90edd94d9371b65bd83ca03e66bb81f19199f5518c7829dd6f2412db0674d915e104875d7ba4eeb915f4822b3aad70fc66747187669047d7f53e0c6523540695161155a6e59f14e6cfef920e49899da214f171ee75a16fb0257c76cee2a01401ead72a1d4fe2edd175a9235b52603f91f97e167b6001f04a7d66e1aba6",
    "credential_finalization": "d2c7bde39504f20420c0fddc12c731af8590a63c1020aea3adeba13290f55901cc19c27875c2a0b0f0b95d3e8d6183dfbcde45888f3895a74e954db099b7e3ef",
    "client_registration_state": "28205f2551a55a8e6703ac6ce61ba5c8cae6c4111372964a926685fa57dcc300549790b0d74736be19aab565cbe0163eef5f5f8488a57f063acc0e4e35301159",
    "client_login_state": "28205f2551a55a8e6703ac6ce61ba5c8cae6c4111372964a926685fa57dcc300549790b0d74736be19aab565cbe0163eef5f5f8488a57f063acc0e4e35301159c217cae6fa4e305d0dabe55c75598bf05f209eba5641dc296b1e377d34e64a69d8a5c8709fd94b9a5accba09a7655549a0618688503d03292c5fdff2a4f7ca5694d7fb3feac2038d4874b20289d8b9ab7e5bf9bd32caf55cbfcc0a0feac9da02c217cae6fa4e305d0dabe55c75598bf05f209eba5641dc296b1e377d34e64a69",
    "server_login_state": "621d4360cf6fdfb7c791207ff86ea4164283ed8b689dccb9392c4deb7699d52f470cc327c98c87bf4ceb13376f6534440c3d92436bf6f4b0375ccc5917021cde227f00ac99e7ae2dd04629950f585b1d4e8a79ce36dc5c119c53f5a758338b2756c21997c3052d9a05b1a909e416dfefdf3bdf711763a65d1a9fa81defb2c79164f8cbc52564e0471fc1f6f9370c96e5676c11df6adc537bc35f92909b36332a77551d366292b3fe6a7db972ea50b8fb52cf423d141c849ec65323c65b5de440",
    "password_file": "7eb2a312703c26e518cc4102da14f3151e76d86219fda92b021c8b6c8848f5614cd9ca81aaae9aa37733ef75867e570f4762513d1417fc77660eb5d8688d72fa24edea76c09d28b1877f151b84bf7f25e2a81fb589d51bc4725a7ab03a9694e0fc5227f5c05133d431605a7a81c4603dd608314ba144e869930c99f0a154a2056a35c3c5d994bb196547e57c4a12af3c33e5d3582d58f236b023f8a587e655bcbad3ec7974ae71caa39cb604a1a9445b9d2d8b8063f03d93a2ca9e8817a2af76",
    "export_key": "a9da8db284bcb3756adb7f3dbc12337a0e1d23f34f4236e9ec91a3fa117e1c10f7e9f7af63e4a206e1acae1de3dc88a2bde37adab5ea69c729290ddd5042e18f",
    "session_key": "64f8cbc52564e0471fc1f6f9370c96e5676c11df6adc537bc35f92909b36332a77551d366292b3fe6a7db972ea50b8fb52cf423d141c849ec65323c65b5de440"
}
"#;

static TEST_VECTOR_P256: &str = r#"
{
    "client_s_pk": "03ba09cc920ee3df2e43ffb721110ddf265a982e6a89558ea1dc10addaa3455392",
    "client_s_sk": "cf71ab13c11eafdbbb2ee3d1ab93e5ea4147066aebc4cb2b797532f5820ecbfe",
    "client_e_pk": "03f67e124f8a46717bcd4a3c80f779d56d84b6c22d533b4348aa761aba2c5e1295",
    "client_e_sk": "d01f9be5f5539c15cdc63d48c2ab9d6e3329096bc22d36d78450b7ff59f474ec",
    "server_s_pk": "02225c43793bcb8dc6ec78412cae060c986bca1c180fe8b9bc56906c7a524d8300",
    "server_s_sk": "2664e45be7fdc8c5cb74a2cebb5995996b0f88df038c9e3d9ea8e4b918623a3c",
    "server_e_pk": "03ebd9e89b8999d83150784b3e3afd3bc7c1880d9269f4c7dc674b40736e65e613",
    "server_e_sk": "ae42a6c3e349903d571aa8e66a15d6893255d42ddbc52e8549fa802d62d2f56e",
    "fake_sk": "73fd9f31fe851b14415b70e6cf5a22959625068d3d57c50920e293917735aee1",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "2344f4c8de9c8c6d4044d0a6919152da6dfe485b2c1549e6b2cd1b35329a5b87",
    "oprf_seed": "d52435ca68bb26647630447a6fe825a73aa2ead0ea85d3b3ded18dcdc10b621c",
    "masking_nonce": "5b69b8162dfdef41d857061345ca8428f157ab217834de1e1219ff04bd434f92f85c4114ebfd79a2fb7cd3d92607e74968a32cd8e192c8ad1cfb98361cd26993",
    "envelope_nonce": "51ae418ba3286101d479830117db34fd2dbdbf6279703987a324e52a1231df8d",
    "client_nonce": "6d8a5cf32ffbb3e0bdbe098587fee2c85bcfd01c51b0970b6f129f9a6d5b2cd7",
    "server_nonce": "c28f73203eee45450eb971fce7f6ccd1bc60810657c6bbf497cbdc6729882814",
    "context": "636f6e74657874",
    "registration_request": "0377bd074feb36a98dfbf37d584c453df4446ddd13fa947b8aab97a063f5576a92",
    "registration_response": "02a6d7506a8ab1ef8c68d4e4dcd24e0c533ec946e3c4a5e5134553f4f8441b4ba402225c43793bcb8dc6ec78412cae060c986bca1c180fe8b9bc56906c7a524d8300",
    "registration_upload": "033401de03ada6737181eeb0b23c474ac0c5188b3f3eaeebea3e5a2f7377acb18025241605e14316f3c616871895deff33a28627ffc839a81fbb1636f06f57d5e2cf71ab13c11eafdbbb2ee3d1ab93e5ea4147066aebc4cb2b797532f5820ecbfe0a60761e979c1229dc761f8b2ec1c4aefac063cc0b1311d538e855db87095540",
    "credential_request": "0377bd074feb36a98dfbf37d584c453df4446ddd13fa947b8aab97a063f5576a926d8a5cf32ffbb3e0bdbe098587fee2c85bcfd01c51b0970b6f129f9a6d5b2cd703f67e124f8a46717bcd4a3c80f779d56d84b6c22d533b4348aa761aba2c5e1295",
    "credential_response": "02a6d7506a8ab1ef8c68d4e4dcd24e0c533ec946e3c4a5e5134553f4f8441b4ba45b69b8162dfdef41d857061345ca8428f157ab217834de1e1219ff04bd434f92a7ea405a1a0f70f60491195ee22080080f953e784fd04278b63104417028dc2fd65cd99339e53b707fbe5711d1930ec28457c8ebf11738939ac8e2748a56606d726363fe2fe3a373b28256d0260b1d88f4f9fd44a2265f25a4130d04909b15e82aae42a6c3e349903d571aa8e66a15d6893255d42ddbc52e8549fa802d62d2f56e02dd382526b48be890830fd89fc56656552895ff19abc62b5df06d863581f62c0d53d05f8751af316de619ee42e43c476154ad5e28c0633445c8c613b22870d8fa",
    "credential_finalization": "5f86d6931015c179e4d7b2c715553dd35419a40a8dfd5c65217f12c0e7de69d6",
    "client_registration_state": "2344f4c8de9c8c6d4044d0a6919152da6dfe485b2c1549e6b2cd1b35329a5b870377bd074feb36a98dfbf37d584c453df4446ddd13fa947b8aab97a063f5576a92",
    "client_login_state": "2344f4c8de9c8c6d4044d0a6919152da6dfe485b2c1549e6b2cd1b35329a5b870377bd074feb36a98dfbf37d584c453df4446ddd13fa947b8aab97a063f5576a926d8a5cf32ffbb3e0bdbe098587fee2c85bcfd01c51b0970b6f129f9a6d5b2cd703f67e124f8a46717bcd4a3c80f779d56d84b6c22d533b4348aa761aba2c5e1295d01f9be5f5539c15cdc63d48c2ab9d6e3329096bc22d36d78450b7ff59f474ec6d8a5cf32ffbb3e0bdbe098587fee2c85bcfd01c51b0970b6f129f9a6d5b2cd7",
    "server_login_state": "9ebf2f5264481a9fdb9148065ae3d56f2ce113806f1a6be6717777e2b6f2f675890459ad11e18f50321fdbe7501fa6e864efcde5615595565521402ef6243e94bd09c3d173f084b3dcf0eb86260871c7d4c1825a04c9e84ecac2c0e87505b124",
    "password_file": "033401de03ada6737181eeb0b23c474ac0c5188b3f3eaeebea3e5a2f7377acb18025241605e14316f3c616871895deff33a28627ffc839a81fbb1636f06f57d5e2cf71ab13c11eafdbbb2ee3d1ab93e5ea4147066aebc4cb2b797532f5820ecbfe0a60761e979c1229dc761f8b2ec1c4aefac063cc0b1311d538e855db87095540",
    "export_key": "b1df1b63547d8d063bd6aa9c8685472620fbf090be1f99971d70a39c4aecc2cc",
    "session_key": "bd09c3d173f084b3dcf0eb86260871c7d4c1825a04c9e84ecac2c0e87505b124"
}
"#;

#[cfg(all(feature = "curve25519", feature = "ristretto255"))]
static TEST_VECTOR_CURVE25519_RISTRETTO255: &str = r#"
{
    "client_s_pk": "7bfb892bba1ae4ac84ae87ab25446cd91203335394e16eea0ad05052d646a942",
    "client_s_sk": "cb8f82b8bcf5920266d6059ce780fa704c5aa57a1ca5f3aff79bf014db173605",
    "client_e_pk": "26eedfaeaa51aed902511a3e3179d949adc2ccfe79e620f1e21a03b203a11f67",
    "client_e_sk": "14604ae5e68315e7294a18942ae014db157e9a6b923e7e6f12b841ff94dc7d03",
    "server_s_pk": "203eb4f95ec6afb37c0db900fb658b2e8e96050f69a6f5bee0ee6649f0b1253d",
    "server_s_sk": "63852f4e742c1c8743b036e73ea1201dae1ff8c5c6bb438e3f53cccf7a997d0a",
    "server_e_pk": "7ee92cbdf7eaf414e4cf276f5e1773dd952b733ee45a0ecf3a56bf79b7592137",
    "server_e_sk": "a0236b1c0975561723cb831c2662454a2b17262f156cdd18b9c4fc46f7802c09",
    "fake_sk": "83a2ecb15d13a2b40752876036d2cea52cec3f16f515b607e81b36b5c99fd204",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "9bbb78819f58bbb900830d507ee4e24097c8f1c0bfe468f09465c0db37dbb604",
    "oprf_seed": "5003e5bc19d2cc1f3103e7dc9533d98883f862f3fee460ee2f2a37bf08da90ce60c7533cdf82aa83791471a6517b11900a5c67c34f516586ba90a3b4f5a88b7b",
    "masking_nonce": "4fb0ae0456980c706da747b13ef7d54567701080229fbbef63aaaadc67fd169cc376479022fa7ccbae949cdd9b95370f84eb809cb8d19f361b846c75d6960442",
    "envelope_nonce": "51f68bd9aebff5df62f4db2296f0b34decb08137d6b9365a49dc24bae2180a56",
    "client_nonce": "5250aae5fa4181cca434921ea5a5c1fd8de2a4fb9f867f97340f322e077f9a16",
    "server_nonce": "e6176d41c9244820193eb2e70d4ef11827fa552956b95d2fe8546a3a74aca09b",
    "context": "636f6e74657874",
    "registration_request": "a040df6470f0315f7c4213e93669a14888b15abebba558e071604ad235269c48",
    "registration_response": "707da7eaed7b139127828cb70e5e3f035c93e190b11a554e87e4ab327807fb69203eb4f95ec6afb37c0db900fb658b2e8e96050f69a6f5bee0ee6649f0b1253d",
    "registration_upload": "8e9d0972e928419f618f9ef73960cb49fb24545b354023e06f4b3c7d9fe35c15bc84106946c59822a2647d2d1f5a05fb04f85d2bc29eea90565c05e7c12d3141d1fa235c0c80cd7ac30f017c89cac4d3020d899f9d7fd9bdd1229cf83cf6c662cb8f82b8bcf5920266d6059ce780fa704c5aa57a1ca5f3aff79bf014db1736058921c28513973fb771ae13b2bdfaf1a4deb01adcc4ddee31238d58c066164ced970c88a2e50139b0e18a0932c148b501305ee4e6f88a1986ae14a3962c6653dc",
    "credential_request": "a040df6470f0315f7c4213e93669a14888b15abebba558e071604ad235269c489bbb78819f58bbb900830d507ee4e24097c8f1c0bfe468f09465c0db37dbb60461d2995f4d4bf5e280f63f8ca2a58c81ba4c26242c53dab224ec0f6aa763c749",
    "credential_response": "707da7eaed7b139127828cb70e5e3f035c93e190b11a554e87e4ab327807fb694fb0ae0456980c706da747b13ef7d54567701080229fbbef63aaaadc67fd169ce963d84e5acbbfb3534ddcff39d4472372ff03982c2041b8d100546109385c9e28b40aa49bf89fbda38b5bb4355e27248d12974e39034e18c3cda86b3957dc1b0ed7f6fb179684a55987a27c0206ffb54b4cda6b7fed260b41916e716a5a50fba556bcaaf666144cdd5002bdd2c5071b1e59998cd315d5bd7b0ba48cb7c13632e6176d41c9244820193eb2e70d4ef11827fa552956b95d2fe8546a3a74aca09bdb4a83eb029389ffcd4ae79484f167cd561f2189491e48baa94f515376257742f3c8db728907df5ad519f2a9eb2ef1eafa74abe335b4bbc7348cbef4ac4ebb6e7f6001e3ffea237ed8904d3163ba1546829d7c21862297364a2b09be991ab3bb",
    "credential_finalization": "36b69c0ded4929dc77b9a380de915943273d660a7c7cc650067513e6df1e01198d3e3665fc0cb58a1d0d4899eca3129f940699e672a7846d71311b061a09fb6c",
    "client_registration_state": "9bbb78819f58bbb900830d507ee4e24097c8f1c0bfe468f09465c0db37dbb604a040df6470f0315f7c4213e93669a14888b15abebba558e071604ad235269c48",
    "client_login_state": "9bbb78819f58bbb900830d507ee4e24097c8f1c0bfe468f09465c0db37dbb604a040df6470f0315f7c4213e93669a14888b15abebba558e071604ad235269c489bbb78819f58bbb900830d507ee4e24097c8f1c0bfe468f09465c0db37dbb60461d2995f4d4bf5e280f63f8ca2a58c81ba4c26242c53dab224ec0f6aa763c749c76f18dd7cd7bbd1ab68fddafe32fa48fb1e900068b3d01117af64cd85b023029bbb78819f58bbb900830d507ee4e24097c8f1c0bfe468f09465c0db37dbb604",
    "server_login_state": "32913d91522e45e609166e0386ad8e3eb0dcbc851f2b05b686ba21089d9908f37e7d2dce1fe75916466c9e318938e8b6d5045fe7c8959f54730668b22867eeac3aa3e3bf41ae32c1ef83cc66aa1b7fbca7e091673280812b99b899464ea43b7779fc4f3afaa2295867dbfd2bd3d734a40d7f82bc82fefdf1cebe5f438b016373363db7a74e1296085816f466a5142be250020747a5d9c305b028265e5b2ad12871217ae79f7e4bcc01156044f51104a2ca7eb21727c440a5252f4fa0b3609128",
    "password_file": "8e9d0972e928419f618f9ef73960cb49fb24545b354023e06f4b3c7d9fe35c15bc84106946c59822a2647d2d1f5a05fb04f85d2bc29eea90565c05e7c12d3141d1fa235c0c80cd7ac30f017c89cac4d3020d899f9d7fd9bdd1229cf83cf6c662cb8f82b8bcf5920266d6059ce780fa704c5aa57a1ca5f3aff79bf014db1736058921c28513973fb771ae13b2bdfaf1a4deb01adcc4ddee31238d58c066164ced970c88a2e50139b0e18a0932c148b501305ee4e6f88a1986ae14a3962c6653dc",
    "export_key": "5f35a4a1e7dbc865462a3ba67e4a6a5db9b1d3e83b3cd9f538fe17d6a7b62a816473bb7b0310a149b89f04255336f44727e817d0ee6ca76cd01b4429d22666d2",
    "session_key": "363db7a74e1296085816f466a5142be250020747a5d9c305b028265e5b2ad12871217ae79f7e4bcc01156044f51104a2ca7eb21727c440a5252f4fa0b3609128"
}
"#;

#[cfg(feature = "curve25519")]
static TEST_VECTOR_CURVE25519_P256: &str = r#"
{
    "client_s_pk": "1ba0bdfca82aa3d6c0eb4a349c7d36042881e4960d7b99a063c601906e70eb15",
    "client_s_sk": "167b99abd660ef266685854d4dcb8e26aea23f0d8cf00dfb10905a3eb89dbd03",
    "client_e_pk": "6af220284b7ebffde097896915bf03c3c87dcbe7f6375e7222be62c64dcceb0a",
    "client_e_sk": "361b739f6c6630fc685e6123442009ca89857f98381f25497598043060885802",
    "server_s_pk": "5f226e9521e00b2d7ec7e3c41d47dd187a8c77499efa42a87163ab70e93e541d",
    "server_s_sk": "3696a1d2493096c28dc7d29fe809696e344af03e853839f09bc86255c773be00",
    "server_e_pk": "a69e109b1a8b586294bae24afec953d81c8a6516e1479fd783b3a0b7a338c03a",
    "server_e_sk": "a87b0143fcdb990394a6f80f56560a65f4c1052f098558a6751a3f677308840f",
    "fake_sk": "0d3daded07009f8fc0e2934905619afa1241063ab785684c1f7d03b7904b8a0c",
    "credential_identifier": "637265644964656e746966696572",
    "id_u": "696455",
    "id_s": "696453",
    "password": "70617373776f7264",
    "blinding_factor": "f0e66144c0390aef68713b73ccbea10a5a2abd9f733d75771e0c0f899f73f6dc",
    "oprf_seed": "2fbf64932a13c55ed622b498dd07674d82c25d7b7952fe6b7b5a022dde50c164",
    "masking_nonce": "8a6bae5f566ee9011549c82a090a8e47eec2269ff482a1c28f2678f7805b9db36c68cf2befa99fbc52bbcd69f2bc0416e921c8e1d231d3100c6a95233faf47e1",
    "envelope_nonce": "72ffe3f86b162df0ecf3f3e6240e0c35014633087dea1e5223916c80a8b26438",
    "client_nonce": "ad3b5bb65067f4e28090073f6a874b3ff8cce39d9a3ee5397f991ddcfd22375d",
    "server_nonce": "0d10adb1b52bc0c05640f429f6e08387a9148e0e97d8be24afb0bcf457e72af9",
    "context": "636f6e74657874",
    "registration_request": "0235cebe22f9659bc3758a89e65104443bf9a609a1aee9a3d7716a77829656854c",
    "registration_response": "0264fda857b0776b071ae478d16eedc235e00cf48251a02f526af44def8a7296275f226e9521e00b2d7ec7e3c41d47dd187a8c77499efa42a87163ab70e93e541d",
    "registration_upload": "eb1d8e736dfe169b9c0caf3565b406dfb4c8dd548aeefb45dff3624b13b31c6b2ee923ff4fa8200fe5588666e71310c7bd517378669c184f3a53cdfa10e5deb1167b99abd660ef266685854d4dcb8e26aea23f0d8cf00dfb10905a3eb89dbd03b386ec283d54779d2a4aa4d918efd0c7d41851e846067a7944a1e34d6475c3d2",
    "credential_request": "0235cebe22f9659bc3758a89e65104443bf9a609a1aee9a3d7716a77829656854cf0e66144c0390aef68713b73ccbea10a5a2abd9f733d75771e0c0f899f73f6dcc9e23fda78eb4fd4b0867524983264f448e207696c68425b3f4f08a83af27516",
    "credential_response": "0264fda857b0776b071ae478d16eedc235e00cf48251a02f526af44def8a7296278a6bae5f566ee9011549c82a090a8e47eec2269ff482a1c28f2678f7805b9db378322e861cc6b139c58bfe5ccc5b6f7db784d0c8f0e4ba5b9e9cdb171e2e66f57d45fa6dd000ee8cb99474a1cb5f893b9724709530acc0d7b5fe0eb959525a12e33f6a80cc640c0e41439e94d767b4e4847e23cae9cff89b2e5431888b8905f50d10adb1b52bc0c05640f429f6e08387a9148e0e97d8be24afb0bcf457e72af99f84b11795b6bad0f556d33a5487d5cb45d26ab165c3fae05f07fc81e2b45b22f438cf617efd92c71aae8f3845123b50d67ab4006630944cee0e014cbb0cbab9",
    "credential_finalization": "90051b471dca75e3a79e782d1664353e81a81b2898212a5a4092227e4ee0395c",
    "client_registration_state": "f0e66144c0390aef68713b73ccbea10a5a2abd9f733d75771e0c0f899f73f6dc0235cebe22f9659bc3758a89e65104443bf9a609a1aee9a3d7716a77829656854c",
    "client_login_state": "f0e66144c0390aef68713b73ccbea10a5a2abd9f733d75771e0c0f899f73f6dc0235cebe22f9659bc3758a89e65104443bf9a609a1aee9a3d7716a77829656854cf0e66144c0390aef68713b73ccbea10a5a2abd9f733d75771e0c0f899f73f6dcc9e23fda78eb4fd4b0867524983264f448e207696c68425b3f4f08a83af27516d87a36c75ff8dea4632fa5f407b1ec710d058d4eb5503c26d4d5f17344ea4a0ef0e66144c0390aef68713b73ccbea10a5a2abd9f733d75771e0c0f899f73f6dc",
    "server_login_state": "bfca2b0a372e348b68f4526018d14fb42c8a7d48bd0eeb55d94f847100fa2048ab556d443b62917da2eec3bbf0ccb21df79b9b20f05c4542587a53f245dfa1f3e79ab64a068fc5768cb7eebd6cfde730b6f5667c762f115a5b7380437011a3b2",
    "password_file": "eb1d8e736dfe169b9c0caf3565b406dfb4c8dd548aeefb45dff3624b13b31c6b2ee923ff4fa8200fe5588666e71310c7bd517378669c184f3a53cdfa10e5deb1167b99abd660ef266685854d4dcb8e26aea23f0d8cf00dfb10905a3eb89dbd03b386ec283d54779d2a4aa4d918efd0c7d41851e846067a7944a1e34d6475c3d2",
    "export_key": "ac662d2f1189b64582e38985458200a1e8a8182b802728499a39da70177427da",
    "session_key": "e79ab64a068fc5768cb7eebd6cfde730b6f5667c762f115a5b7380437011a3b2"
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

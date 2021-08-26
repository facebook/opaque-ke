// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite, errors::*, group::Group, key_exchange::tripledh::TripleDH, opaque::*,
    slow_hash::NoOpHash, tests::mock_rng::CycleRng, *,
};
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use curve25519_dalek::ristretto::RistrettoPoint;
use generic_array::typenum::Unsigned;
use serde_json::Value;

// Tests
// =====

struct Ristretto255Sha512NoSlowHash;
impl CipherSuite for Ristretto255Sha512NoSlowHash {
    type OprfGroup = RistrettoPoint;
    type KeGroup = RistrettoPoint;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = NoOpHash;
}

#[cfg(feature = "p256")]
struct P256Sha256NoSlowHash;
#[cfg(feature = "p256")]
impl CipherSuite for P256Sha256NoSlowHash {
    type OprfGroup = p256_::ProjectivePoint;
    type KeGroup = p256_::ProjectivePoint;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha256;
    type SlowHash = NoOpHash;
}

#[allow(non_snake_case)]
pub struct TestVectorParameters {
    pub dummy_private_key: Vec<u8>,
    pub dummy_masking_key: Vec<u8>,
    pub context: Vec<u8>,
    pub client_private_key: Option<Vec<u8>>,
    pub client_keyshare: Vec<u8>,
    pub client_private_keyshare: Vec<u8>,
    pub server_public_key: Vec<u8>,
    pub server_private_key: Vec<u8>,
    pub server_keyshare: Vec<u8>,
    pub server_private_keyshare: Vec<u8>,
    pub client_identity: Option<Vec<u8>>,
    pub server_identity: Option<Vec<u8>>,
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
    pub auth_key: Vec<u8>,
    pub randomized_pwd: Vec<u8>,
    pub handshake_secret: Vec<u8>,
    pub server_mac_key: Vec<u8>,
    pub client_mac_key: Vec<u8>,
    pub oprf_key: Vec<u8>,
}

// Pulled from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-06#appendix-C
static RISTRETTO_TEST_VECTORS: &[&str] = &[
    r#"
### OPAQUE-3DH Real Test Vector 1

#### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Group: ristretto255
Context: 4f50415155452d504f43
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

#### Input Values

~~~
oprf_seed: 5c4f99877d253be5817b4b03f37b6da680b0d5671d1ec5351fa61c5d82
eab28b9de4c4e170f27e433ba377c71c49aa62ad26391ee1cac17011d8a7e9406657c
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd
539c4676775
masking_nonce: 54f9341ca183700f6b6acf28dbfe4a86afad788805de49f2d680ab
86ff39ed7f
server_private_key: 16eb9dc74a3df2033cd738bf2cfb7a3670c569d7749f284b2
b241cb237e7d10f
server_public_key: 18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d
402f672bcc0933
server_nonce: f9c5ec75a8cd571370add249e99cb8a8c43f6ef05610ac6e354642b
f4fedbf69
client_nonce: 804133133e7ee6836c8515752e24bb44d323fef4ead34cde967798f
2e9784f69
server_keyshare: 6e77d4749eb304c4d74be9457c597546bc22aed699225499910f
c913b3e90712
client_keyshare: f67926bd036c5dc4971816b9376e9f64737f361ef8269c18f69f
1ab555e96d4a
server_private_keyshare: f8e3e31543dd6fc86833296726773d51158291ab9afd
666bb55dce83474c1101
client_private_keyshare: 4230d62ea740b13e178185fc517cf2c313e6908c4cd9
fb42154870ff3490c608
blind_registration: c62937d17dc9aa213c9038f84fe8c5bf3d953356db01c4d48
acb7cae48e6a504
blind_login: b5f458822ea11c900ad776e38e29d7be361f75b4d79b55ad74923299
bf8d6503
~~~

#### Intermediate Values

~~~
client_public_key: 2046d15924599adbcb7c03abe00350e9dde62267037eb0d2a9
59a17b2210eb0f
auth_key: 0ee186ac3a0fe0ec45d36c7cc9786934918a58d6a1abce6842a2b7bd0ec
1c0626e64d887622e8937e987bfbe042f904728966e121b01c739c8dbe66beb6241eb
randomized_pwd: 22f5e31fbbbf4649f77ebfc92a2ef555fc30a09edc903123d978d
e3ca356b85ce2120b0d2735bd772011ecb573e614cd7b1aeeb86ca0ac6b8732c33cdf
7a6816
envelope: 71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c46
767759f0fe7ab535b75ff4a01887e30a733091b05cc6ace0fd49309fe3758f57f4d01
71b270e309d14e59413849c3ed672e076d97d71ceace93dcade9f26712461611
handshake_secret: 036b0351f1b041d4e2eb6f4104833e3d13db721b9e9ec85d797
daf354e8e13ce55ceb3756b9a781439e15015712ce9bc0d66caddb5d5d19c4aa6d03b
fd075301
server_mac_key: 95592913b88470536b3dc7ecb514a17fbb1916e3efa8e64d55639
7acbc5ed37f654bf860bfa8ae106f73ef9df92f303715bf29c7dc67d49598d8d6640c
4c7ce3
client_mac_key: bbb5ee19ec9d491094878dd4a458a776557be3d79d078f40bb294
01f74b80eb8102c65e2cc203c79740bc0e5bb71a138a9efda58f35a486da1835abe63
38838b
oprf_key: 3f76113135e6ca7e51ac5bb3e8774eb84709ad36b8907ec8f7bc3537828
71906
~~~

#### Output Values

~~~
registration_request: 76cc85628d5ac0e01de4ede72479d607490e7f58b94578d
b7a0606d74bc58b03
registration_response: 865f3305ff73be7388313e7a74b5fc277a165ff2895f92
60391057b84c7bc72718d5035fd0a9c1d6412226df037125901a43f4dff660c0549d4
02f672bcc0933
registration_upload: 2046d15924599adbcb7c03abe00350e9dde62267037eb0d2
a959a17b2210eb0fdc3b0057603d1c23df7e6f239984604c4b0dfa111528ab0ba3c7f
6ab1ceb11d10aa85433f63bbf30b9b0ae8951653bcd3beb12aa61cf942e6e5b442282
0d810871b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c467677
59f0fe7ab535b75ff4a01887e30a733091b05cc6ace0fd49309fe3758f57f4d0171b2
70e309d14e59413849c3ed672e076d97d71ceace93dcade9f26712461611
KE1: e47c1c5e5eed1910a1cbb6420c5edf26ea3c099aaaedcb03599fc311a724d84f
804133133e7ee6836c8515752e24bb44d323fef4ead34cde967798f2e9784f69f6792
6bd036c5dc4971816b9376e9f64737f361ef8269c18f69f1ab555e96d4a
KE2: 9692d473e0bde7a1fbb6d2c0e4001ccc58902102857d0e67e5fa44f4b902b17f
54f9341ca183700f6b6acf28dbfe4a86afad788805de49f2d680ab86ff39ed7f7b11e
e2cb784efa8e6cbbb9cc6b52b16290e3906235d71b773534c3da1575a00708219fa81
05b3d2a1292d58d6ea6b0e464c752df6f957a9e34a66de7e5d44dbdf958070f8a97fa
374af5dd0febfaf9003095e610278b5ba10de7a16816365d2df80cfd566e6f9ea4a93
968992e9b153fe4196e4c1f5144643eb240575aba49bf9c5ec75a8cd571370add249e
99cb8a8c43f6ef05610ac6e354642bf4fedbf696e77d4749eb304c4d74be9457c5975
46bc22aed699225499910fc913b3e90712b085f3437e22abbf37e997f507589944fbc
ccb0128441680382a3eec27d1a80bb154296a1f00e10e984dfa7434a7c7db09284261
12bd54a0063fff8584da1261
KE3: faac852789872a58c40e406c301655a55806b117c61c5070364561ecdc5f0951
8c745ca87a13ca20b41116957066aa040a69786b247e811fb92cbc85d8b3d9bb
export_key: 47d742be256471ec7a7b0ebc022d6ca016b022a7dcbdd41fa1b6dbfcd
6f88285aee60db87e7c5e5aff87b55904b07137b3d85648bb62d70a18954dd1c66cdd
c2
session_key: 01905d1312467beaca17c20e64c50c91ca6e756067adebbc38a89efd
9c1305f8eff3c641062755ba156749ea4ac7d9e9a6187791c40adc13473538b470b20
a67
~~~
"#,
    r#"
### OPAQUE-3DH Real Test Vector 2

#### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Group: ristretto255
Context: 4f50415155452d504f43
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

#### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: db5c1c16e264b8933d5da56439e7cfed23ab7287b474fe3cdcd58df089
a365a426ea849258d9f4bc13573601f2e727c90ecc19d448cf3145a662e0065f157ba
5
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: d0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf
2747829b2d2
masking_nonce: 30635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853b
5def228c85
server_private_key: eeb2fcc794f98501b16139771720a0713a2750b9e528adfd3
662ad56a7e19b04
server_public_key: 8aa90cb321a38759fc253c444f317782962ca18d33101eab2c
8cda04405a181f
server_nonce: 3fa57f7ef652185f89114109f5a61cc8c9216fdd7398246bb7a0c20
e2fbca2d8
client_nonce: a6bcd29b5aecc3507fc1f8f7631af3d2f5105155222e48099e5e608
5d8c1187a
server_keyshare: ae070cdffe5bb4b1c373e71be8e7d8f356ee5de37881533f1039
7bcd84d35445
client_keyshare: 642e7eecf19b804a62817486663d6c6c239396f709b663a4350c
da67d025687a
server_private_keyshare: 0974010a8528b813f5b33ae0d791df88516c8839c152
b030697637878b2d8b0a
client_private_keyshare: 03b52f066898929f4aca48014b2b97365205ce691ee3
444b0a7cecec3c7efb01
blind_registration: a66ffb41ccf1194a8d7dda900f8b6b0652e4c7fac4610066f
e0489a804d3bb05
blind_login: e6f161ac189e6873a19a54efca4baa0719e801e336d929d35ca28b5b
4f60560e
~~~

#### Intermediate Values

~~~
client_public_key: 64b38be7d1b6cb0e7c50644acb8b326f67167eb164899b1867
970ab770628643
auth_key: 494f1326c65c057e301f15e619b9e3de553c77132987828ba20026062da
a1f18d516ac2e37b1dfc296e21137623856fb3ccba48cc511f143110944848764dfb7
randomized_pwd: a4853e726d14efb03c35686ee2bc67665d02bdccb0c4c02523bf4
e1398e78b1094195a082b5ebb1b62ac75d06711643e9990c2be0071a42bc21a2b766b
787eac
envelope: d0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf274782
9b2d21a6d25b3a1b8a541f47fc4bbe5783c2cc61c77ed389280a05ed2ef8c2c2d03fe
2066bd22ea959c7bb14b5259ee136e86f4d956fbaa2af2f6a326785f21262909
handshake_secret: 39ec65469f2bbabfa47bdf29f5d3c2f655009cc9ffffa423688
6b6b0c25cf0e7f677bc2a4f2454ffaa916b1abf3d53c8a76df2b8ec32cd6a579daf09
e9606088
server_mac_key: d47c287732202807e20f9309201019fd167aeadb41d6cc28dc7a3
eb05dd385a9fa2d1737e8719e89ecd3cc1db0bf53dc084bd8a5ab4586d1927679d11e
c42d69
client_mac_key: e2ff0e615fb1283856e8d68d284245c5e3790272fc83db97f784e
6f90d2c54a0123459c1d5f75c904ee191c5d535dcbbb1df6c1a900f32d3458dfc30dc
518f93
oprf_key: 531b0c7b0a3f90060c28d3d96ef5fecf56e25b8e4bf71c14bc770804c3f
b4507
~~~

#### Output Values

~~~
registration_request: ec2927a03ced1220168b6d5a54f0372f813ced8ad3673d5
1dee92d2cbfee500c
registration_response: f6e244e131f8cd14bc37a856a933c91128b2498c06540d
2dba3a197ed7d8bd778aa90cb321a38759fc253c444f317782962ca18d33101eab2c8
cda04405a181f
registration_upload: 64b38be7d1b6cb0e7c50644acb8b326f67167eb164899b18
67970ab7706286439fabb8544108ec64de2b992935dd5fd9a98441412ccf724bf4853
c28749d9fd33fb1824b964f616a7fce654e05bb15133bd4a69441dcbfe6a02b8a546e
1b32dbd0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf2747829b2d
21a6d25b3a1b8a541f47fc4bbe5783c2cc61c77ed389280a05ed2ef8c2c2d03fe2066
bd22ea959c7bb14b5259ee136e86f4d956fbaa2af2f6a326785f21262909
KE1: d0a498e621d3ff7a011b37166a63ef40fe268f93c7d75a467eea42a98c0a490d
a6bcd29b5aecc3507fc1f8f7631af3d2f5105155222e48099e5e6085d8c1187a642e7
eecf19b804a62817486663d6c6c239396f709b663a4350cda67d025687a
KE2: e6d0c01cdc14f7bfdb38effbd63394f6304b47c2dc26fd510ecdbf471486b972
30635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853b5def228c8563625
e7cfa2857bdc95991bfccc09b69ed53fd5f173389f4d8786b261b6dfd2fc7c18968dd
1be8cdb52b1ca691d8d27ad655e6c78a6ef67c2ad43899259b060706f7d4f4946f97b
d283c009a736227e9c1913b394d0d88419c6463970c0c2887bd5890eac805e8657903
f7f8887f5eab9e700414af99bbabe3b6594418e2a3723fa57f7ef652185f89114109f
5a61cc8c9216fdd7398246bb7a0c20e2fbca2d8ae070cdffe5bb4b1c373e71be8e7d8
f356ee5de37881533f10397bcd84d354456350043199df4e4d9b338cbc2314a9f67e5
9f4334595f5ae18954bfcc2815ba19a0682403d2f1a62bd050851a038a3c0fb5a8179
6f627dbae98c7e1e4a9a46ff
KE3: 328b7fdd7d94b63093184409b850c7af99a24dd2a4e14dc9c758ed4c7ada94a6
5a81d394b881e00d99dc6e71cf7acba03d8235f6e681b802b9a48be03f23991f
export_key: 7f2e5b749ec5f6ab34663655184f3653275aafd5db070b6aac6afd80a
78309a8ec0f97a2f2cfcc7a971983a914ead081a8a642b65d298c579d3526d2219381
8d
session_key: 70d8c538c371757e5e63d522a5f5e1329d7024f73fa854f5899733e3
d2b5afa800e6db4727aec02ca58cee310c7e8f8193f7cdb5a667fe32247711a3c72ca
06a
~~~
"#,
];

static RISTRETTO_FAKE_TEST_VECTORS: &[&str] = &[r#"
### OPAQUE-3DH Fake Test Vector 1

#### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Group: ristretto255
Context: 4f50415155452d504f43
Nh: 64
Npk: 32
Nsk: 32
Nm: 64
Nx: 64
Nok: 32
~~~

#### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 98ee70b2c51d3e89d9c08b00889a1fa8f3947a48dac9ad994e946f408a
2c31250ee34f9d04a7d85661bab11c67048ecfb7a68c657a3df87cff3d09c6af9912a
1
credential_identifier: 31323334
masking_nonce: 7cb33db5ba8082e4f4bfb830e8e3f525b0ddcb70469b34224758d7
25ce53ac76
client_private_key: 21c97ffc56be5d93f86441023b7c8a4b629399933b3f845f5
852e8c716a60408
client_public_key: 5cc46fdc0337a684e126f8663deacc67872a7daffc75312a1d
6377783935f932
server_private_key: 030c7634ae24b9c6d4e2c07176719e7a246850b8e019f1c71
a23af6bdb847b0b
server_public_key: 1ac449e9cdd633788069cca1aaea36ea359d7c2d493b254e5f
fe8d64212dcc59
server_nonce: cae1f4fee4ee4ba509fda550ea0421a85762305b1db20e37f4539b2
327d37b80
server_keyshare: 5e5c0ac2904c7d9bf38f99e0050594e484b4d8ded8038ef6e0c1
41a985fa6b35
server_private_keyshare: a4abffe3bef8082b78323ea4507fbb0ce8105ca62b38
1919a35767deaa699709
masking_key: 077adba76f768fd0979f8dc006ca297e7954ebf0e81a893021ee24ac
c35e1a3f4b5e0366c15771133082ec21035ae0ef0d8bcd0e59d26775ae953b9552fdf
bf2
KE1: 1ef5fc13fa7695e81b5fcadf57eb49a579b10e4f51bbee11afb278608592456b
8837b6c0709160251cbebe0d55e4423554c45da7a8952367cf336eb623379e80dae2f
1e0cd79b733131d499fb9e77efe0f235d73c1f920bdc5816259ad3a7429
~~~

#### Output Values

~~~
KE2: 2e1bb024ff255d0f35eb7b1f11174b3e60d8aaabb11ea347a6da0c1964594f4f
7cb33db5ba8082e4f4bfb830e8e3f525b0ddcb70469b34224758d725ce53ac76094c0
aa800d9a0884392e4efbc0479e3cb84a38c9ead879f1ff755ad762c06812b9858f82c
9722acc61b8eb1d156bc994839bf9ed8a760615258d23e0f94fa2cffadc655ed0d6ff
6914066427366019d4e6989b65d13e38e8edc5ae6f82aa1b6a46bfe6ca0256c64d0cf
db50a3eb7676e1d212e155e152e3bbc9d1fae3c679aacae1f4fee4ee4ba509fda550e
a0421a85762305b1db20e37f4539b2327d37b805e5c0ac2904c7d9bf38f99e0050594
e484b4d8ded8038ef6e0c141a985fa6b3528ef79e28dbd3783322ab69900a43be8919
a840cfcc5aa31a8f42b6f2a0c1ce1f9fa50c58dc5787a957af588580117b70d304639
dc68851224301bbbae9cd654
~~~
"#];

#[cfg(feature = "p256")]
static P256_TEST_VECTORS: &[&str] = &[
    r#"
### OPAQUE-3DH Real Test Vector 3

#### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Group: P256_XMD:SHA-256_SSWU_RO_
Context: 4f50415155452d504f43
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

#### Input Values

~~~
oprf_seed: 77bfc065218c9a5593c952161b93193f025b3474102519e6984fa64831
0dd1bf
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1
acacc4a8319
masking_nonce: cb792f3657240ce5296dd5633e7333531009c11ee6ab46b6111f15
6d96a160b2
server_private_key: 87ef09986545b295e8f5bbbaa7ad3dce15eb299eb2a5b3487
5ff421b1d63d7a3
server_public_key: 025b95a6add1f2f3d038811b5ad3494bed73b1e2500d8dadec
592d88406e25c2f2
server_nonce: 8018e88ecfc53891529278c47239f8fe6f1be88972721898ef81cc0
a76a0b550
client_nonce: 967fcded96ed46986e60fcbdf985232639f537377ca3fcf07ad4899
56b2e9019
server_keyshare: 0242bc29993976185dacf6be815cbfa923aac80fad8b7f020c9d
4f18e0b6867a17
client_keyshare: 03358b4eae039953116889466bfddeb40168e39ed83809fd5f0d
5f2de9c5234398
server_private_keyshare: b1c0063e442238bdd89cd62b4c3ad31f016b68085d25
f85613f5838cd7c6b16a
client_private_keyshare: 10256ab078bc1edbaf79bee4cd28dd9db89179dcc921
9bc8f388b533f5439099
blind_registration: d50e29b581d716c3c05c4a0d6110b510cb5c9959bee817fde
b1eabd7ccd74fee
blind_login: 503d8495c6d04efaee8370c45fa1dfad70201edd140cec8ed6c73b5f
cd15c478
~~~

#### Intermediate Values

~~~
client_public_key: 0234cb18fb529a1cd33b4cf6b9330e4a429d8b8fbe8b2c43a0
d130713a190b3eb7
auth_key: 570a8105a7d86679b4c9d009edc9627af6b17e8b2d2f0d50cbd13ea8a00
82cd7
randomized_pwd: 04f1615bc400765f22f7af1277a0814b5665ad1d4ef9bf1829880
2a0f6b4636b
envelope: 2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1acacc4
a831916a15211679ac4d0731e49058f79917d87536c617ab8d7192ac87826a8f76b5f
handshake_secret: 72f5c4fa597d8b722fa6aa5ae837df06fd7a568a1584489c51d
11b1d43b68e46
server_mac_key: ec74ece1dce2352dd92693f0bcdb543e97d85d9a778078bad935b
ffb6b2b9a65
client_mac_key: f680934996037732c95caacc9f15910b60e5ebdba63b915ba9eaa
64c944ed47e
oprf_key: d153d662a1e7dd4383837aa7125685d2be6f8041472ecbfd610e46952a6
a24f1
~~~

#### Output Values

~~~
registration_request: 0325768a660df0c15f6f2a1dcbb7efd4f1c92702401edf3
e2f0742c8dce85d5fa8
registration_response: 0244211a4d2a067f7a61ed88dff6764856d347465f330d
0e15502700afd1865911025b95a6add1f2f3d038811b5ad3494bed73b1e2500d8dade
c592d88406e25c2f2
registration_upload: 0234cb18fb529a1cd33b4cf6b9330e4a429d8b8fbe8b2c43
a0d130713a190b3eb78efb26f2bb390fd23b90c49ae680c4560fbd2b3c4f32891505c
ad7d95b7bc58e2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1aca
cc4a831916a15211679ac4d0731e49058f79917d87536c617ab8d7192ac87826a8f76
b5f
KE1: 03884e56429f1ee53559f2e244392eb8f994fd46c8fd9ffdd24ac5a7af963a66
3b967fcded96ed46986e60fcbdf985232639f537377ca3fcf07ad489956b2e9019033
58b4eae039953116889466bfddeb40168e39ed83809fd5f0d5f2de9c5234398
KE2: 0383fff1b3e8003723dff1b1f90a7934a036bd6691aca0366b07a100bf2bb3dc
2acb792f3657240ce5296dd5633e7333531009c11ee6ab46b6111f156d96a160b23b6
a5ff1ce8035a1dca4776f32f43c7ce626d796da0f27fc9897522fc1fab70d2fb443d8
2a4333770057e929c2f9977d40a64e8b4a5a553d25a8b8392b4adbf0a03947082b3aa
9836bc20c7dd255e57b7d3a29c9cbee85481ed776cada975dae758018e88ecfc53891
529278c47239f8fe6f1be88972721898ef81cc0a76a0b5500242bc29993976185dacf
6be815cbfa923aac80fad8b7f020c9d4f18e0b6867a177d92ce531ed6f48a6592d14a
a9e7fee37fa1e8ef1ffb85181e66661196447dc0
KE3: 00afa7c015df8f9e9dcd491c88a41663320549b163761e11ea5aefb398e470be
export_key: a83a3fe26af0dadb63d15ed808a4dc2edb57f45212554ecc1af5e0273
50651de
session_key: 9cbab7cb765fe14d3a6bbcba0945ff6aaee8db71877842502fd61c24
2a12384e
~~~
"#,
    r#"
### OPAQUE-3DH Real Test Vector 4

#### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Group: P256_XMD:SHA-256_SSWU_RO_
Context: 4f50415155452d504f43
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

#### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: 482123652ea37c7e4a0f9f1984ff1f2a310fe428d9de5819bf63b3942d
be09f9
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 75c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b
842e4426e42
masking_nonce: 5947586f69259e0708bdfab794f689eec14c7deb7edde68c816451
56cf278f21
server_private_key: c728ebf47b1c65594d77dab871872dba848bdf20ed725f0fa
3b58e7d8f3eab2b
server_public_key: 029a2c6097fbbcf3457fe3ff7d4ef8e89dab585a67dfed0905
c9f104d909138bae
server_nonce: 581ac468101aee528cc6b69daac7a90de8837d49708e76310767cbe
4af18594d
client_nonce: 46498f95ec7986f0602019b3fbb646db87a2fdbc12176d4f7ab74fa
5fadace60
server_keyshare: 022aa8746ab4329d591296652d44f6dfb04470103311bacd7ad5
1060ef5abac41b
client_keyshare: 02a9f857ad3eabe09047049e8b8cee72feea2acb7fc487777c0b
22d3add6a0e0c0
server_private_keyshare: 48a5baa24274d5acc5e007a44f2147549ac8dd675564
2638f1029631944beed4
client_private_keyshare: 161e3aaa50f50e33344022969d17d9cf4c88b7a9eec4
c36bf64de079abb6dc7b
blind_registration: 9280e203ef27d9ef0d1d189bb3c02a66ef9a72d48cca6c1f9
afc1fedea22567c
blind_login: 4308682dc1bdab92ff91bb1a5fc5bc084223fe4369beddca3f1640a6
645455ad
~~~

#### Intermediate Values

~~~
client_public_key: 028e38bb4030255ad81d48afba0ae8f8f65169a6ff17f536c8
91816cd2f47c9e89
auth_key: 76cba5b349c60c5a19ab06b70a3191d3418318b5a203fd298b18a0eda53
efd1a
randomized_pwd: 74649c9c7b0d7436c4873984732fe45e19dabd1a96d7e9175468a
85ed16bea65
envelope: 75c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b842e44
26e423938d818ea53f58fdaab8541765d5171e99b1bdc2c63e8e1eaf62d3a60aacabe
handshake_secret: 77ef201cd5f558cd2b184d5bc63e28ad2fe6171c4967e8962b7
83f0c9e9c5aea
server_mac_key: accc90a00130230aaee45ed5ff69dcb257d3dda31519ef7ed3fa7
575b6c8072d
client_mac_key: 8471a38dd92988b8d5139ffac80873921c01f34b9be332d819624
73218e10578
oprf_key: f14e1fc34ba1218bfd3f7373f036889bf4f35a8fbc9e8c9c07ccf2d2388
79d9c
~~~

#### Output Values

~~~
registration_request: 02792b0f4670aced5970a68b01bb951004ccad962159be4
b6783170c9ad68f6052
registration_response: 03cc3491b4bcb3e4804f3eadbc6a04c8fff18cc9ca5a4f
eeb577fdfebd71f5060f029a2c6097fbbcf3457fe3ff7d4ef8e89dab585a67dfed090
5c9f104d909138bae
registration_upload: 028e38bb4030255ad81d48afba0ae8f8f65169a6ff17f536
c891816cd2f47c9e89260603b2690f3d466fb0b747e256283bed94836ac98c10d4588
1372046d3b1e875c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b842
e4426e423938d818ea53f58fdaab8541765d5171e99b1bdc2c63e8e1eaf62d3a60aac
abe
KE1: 02fe96fc48d9fc921edd8e92ada581cbcc2a65e30962d0002ea5242f5baf627f
f646498f95ec7986f0602019b3fbb646db87a2fdbc12176d4f7ab74fa5fadace6002a
9f857ad3eabe09047049e8b8cee72feea2acb7fc487777c0b22d3add6a0e0c0
KE2: 035115b21dde0992cb812926d65c7dccd5e0f8ffff573da4a7c1e603e0e40827
895947586f69259e0708bdfab794f689eec14c7deb7edde68c81645156cf278f21cef
3adc4e524db33258c5774efaec59750eaf3755a2dfa194ec593ce41a7a17f889978a2
f97ced10bd1592793497e58b5d05a02ebf003f8a8949a2f8a22a09e4d1b8ba19c9e77
4b6f31545ac4c02aba4ad8e26b4f43d65319f8d1c5a5a04668d4b581ac468101aee52
8cc6b69daac7a90de8837d49708e76310767cbe4af18594d022aa8746ab4329d59129
6652d44f6dfb04470103311bacd7ad51060ef5abac41b2a2eb8e68a375b1d2f55c77c
db2d1cb355df3ca50a966c3582f16a76e518e2ad
KE3: 9656352a2ae1c1569ff6bb69c5d533fff9aa174faad1f3980eaa3e6d0df2102e
export_key: 5b92e3454d59062460a87ad2ff6546d862f722c6fbd7678a0997b3c9d
c61e9a0
session_key: 7d9430d675055a95b323a012be00690382618f4f687cbe0c5f7c4d20
b1fb71c1
~~~
"#,
];

#[cfg(feature = "p256")]
static P256_FAKE_TEST_VECTORS: &[&str] = &[r#"
### OPAQUE-3DH Fake Test Vector 2

#### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
Group: P256_XMD:SHA-256_SSWU_RO_
Context: 4f50415155452d504f43
Nh: 32
Npk: 33
Nsk: 32
Nm: 32
Nx: 32
Nok: 32
~~~

#### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: f7664fae89be455ee3350b04a85eab390b2dc63256fbd311d8de944b45
b859e6
credential_identifier: 31323334
masking_nonce: 21cd364318a92b2afbfccea5d80d337f07defe40d92673a52f3844
058f5d949a
client_private_key: 41ffab7c86e2b0916361fb6a69f9a097e3ef2f83f8fd5f95c
c79432eabf3e020
client_public_key: 0251bc2a7e0cb7c043eec5ee7d1b769b69f85b0fa19d1ae907
5416e93fa01689de
server_private_key: 61764783412278e6ce3c6c66f1995a2a30b5824be6a6d31ca
d35a578ec3d9353
server_public_key: 03727dd31712275905b1a3cca3bbb33bc71034a1d0c3801be0
20541933dd497f18
server_nonce: 2b772c1eb569cc2b57741bf3be630e377c8245b11d0b6ad1fe1d606
490c27208
server_keyshare: 02a59205c836a2ab86e19dbd9a417818052179e9a5c99221e2d1
d8a780dfe4734d
server_private_keyshare: e8c25741b201c2ba00abe390e5a3933a75efdb71b50e
1e0087cc7235f6f9448a
masking_key: 5bb4d884375d7dcbd562a62190cc569ccc809cff9d5aa5e176d48e96
46b558eb
KE1: 031ac7e5c8099fcb7de5ad5b6cf33ff53078dbee1da64f15f6cd53b2afe6e332
06a91c9485d74c9010185f462ce1eec52f588a8e392f36915849b6bfcb6bd5b904037
6a35db8f7e582569dba2e573c4af1462f91c59a9bdee253ed13f60108746252
~~~

#### Output Values

~~~
KE2: 02200f91b03819f6a4b0957216fc94a2230d75d0e1be1fe0ced9434b0ec9d23a
5621cd364318a92b2afbfccea5d80d337f07defe40d92673a52f3844058f5d949a604
39294e7567fc29643e0d5c8799d0dffbbfc8609558b982012fa90aef2ce52b1ffdd8f
96bda49f5306ae346cd745812d3a953ff94712e4ed0acc67c99b432860e337fe3234b
ba88415ac55368b938106cca4049b5c13496fe167d3a092bd990e2b772c1eb569cc2b
57741bf3be630e377c8245b11d0b6ad1fe1d606490c2720802a59205c836a2ab86e19
dbd9a417818052179e9a5c99221e2d1d8a780dfe4734d7325a81225091665460460ec
37fcf0431f738ba6cb80b63756ee70c6e43aeae5
~~~
"#];

macro_rules! parse {
    ( $v:ident, $s:expr ) => {
        parse_default!($v, $s, vec![])
    };
}

macro_rules! parse_default {
    ( $v:ident, $s:expr, $d:expr ) => {
        match decode(&$v, $s) {
            Some(x) => x,
            None => $d,
        }
    };
}

macro_rules! rfc_to_params {
    ( $v:ident ) => {
        $v.iter()
            .map(|x| {
                populate_test_vectors::<CS>(&serde_json::from_str(rfc_to_json(x).as_str()).unwrap())
            })
            .collect::<Vec<TestVectorParameters>>()
    };
}

fn rfc_to_json(input: &str) -> alloc::string::String {
    let mut json = vec![];
    for line in input.lines() {
        // If line contains colon, then
        if line.contains(':') {
            if !json.is_empty() {
                // Adding closing quote for previous line, comma, and newline
                json.push("\",\n".to_string());
            }

            let mut iter = line.split(':');
            let key = iter.next().unwrap().split_whitespace().next().unwrap();
            let val = iter.next().unwrap().split_whitespace().next().unwrap();

            json.push(format!("    \"{}\": \"{}", key, val));
        } else {
            let s = line.trim().to_string();
            if s.contains("~") || s.contains("#") {
                // Ignore comment lines
                continue;
            }
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

fn populate_test_vectors<CS: CipherSuite>(values: &Value) -> TestVectorParameters {
    TestVectorParameters {
        dummy_private_key: parse_default!(
            values,
            "client_private_key",
            vec![0u8; <CS::OprfGroup as Group>::ScalarLen::USIZE]
        ),
        dummy_masking_key: parse_default!(values, "masking_key", vec![0u8; 64]),
        context: parse!(values, "Context"),
        client_private_key: decode(values, "client_private_key"),
        client_keyshare: parse!(values, "client_keyshare"),
        client_private_keyshare: parse!(values, "client_private_keyshare"),
        server_public_key: parse!(values, "server_public_key"),
        server_private_key: parse!(values, "server_private_key"),
        server_keyshare: parse!(values, "server_keyshare"),
        server_private_keyshare: parse!(values, "server_private_keyshare"),
        client_identity: decode(values, "client_identity"),
        server_identity: decode(values, "server_identity"),
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
        auth_key: parse!(values, "auth_key"),
        randomized_pwd: parse!(values, "randomized_pwd"),
        handshake_secret: parse!(values, "handshake_secret"),
        server_mac_key: parse!(values, "server_mac_key"),
        client_mac_key: parse!(values, "client_mac_key"),
        oprf_key: parse!(values, "oprf_key"),
    }
}

fn get_password_file_bytes<CS: CipherSuite>(
    parameters: &TestVectorParameters,
) -> Result<Vec<u8>, ProtocolError> {
    let password_file = ServerRegistration::<CS>::finish(
        RegistrationUpload::deserialize(&parameters.registration_upload[..]).unwrap(),
    );

    Ok(password_file.serialize())
}

fn parse_identifiers(
    client_identity: Option<Vec<u8>>,
    server_identity: Option<Vec<u8>>,
) -> Option<Identifiers> {
    match (client_identity, server_identity) {
        (None, None) => None,
        (Some(x), None) => Some(Identifiers::ClientIdentifier(x)),
        (None, Some(y)) => Some(Identifiers::ServerIdentifier(y)),
        (Some(x), Some(y)) => Some(Identifiers::ClientAndServerIdentifiers(x, y)),
    }
}

#[test]
fn tests() -> Result<(), ProtocolError> {
    test_registration_request::<Ristretto255Sha512NoSlowHash>(RISTRETTO_TEST_VECTORS)?;
    test_registration_response::<Ristretto255Sha512NoSlowHash>(RISTRETTO_TEST_VECTORS)?;
    test_registration_upload::<Ristretto255Sha512NoSlowHash>(RISTRETTO_TEST_VECTORS)?;
    test_ke1::<Ristretto255Sha512NoSlowHash>(RISTRETTO_TEST_VECTORS)?;
    test_ke2::<Ristretto255Sha512NoSlowHash>(RISTRETTO_TEST_VECTORS)?;
    test_ke3::<Ristretto255Sha512NoSlowHash>(RISTRETTO_TEST_VECTORS)?;
    test_server_login_finish::<Ristretto255Sha512NoSlowHash>(RISTRETTO_TEST_VECTORS)?;
    test_fake_vectors::<Ristretto255Sha512NoSlowHash>(RISTRETTO_FAKE_TEST_VECTORS)?;

    #[cfg(feature = "p256")]
    {
        test_registration_request::<P256Sha256NoSlowHash>(P256_TEST_VECTORS)?;
        test_registration_response::<P256Sha256NoSlowHash>(P256_TEST_VECTORS)?;
        test_registration_upload::<P256Sha256NoSlowHash>(P256_TEST_VECTORS)?;
        test_ke1::<P256Sha256NoSlowHash>(P256_TEST_VECTORS)?;
        test_ke2::<P256Sha256NoSlowHash>(P256_TEST_VECTORS)?;
        test_ke3::<P256Sha256NoSlowHash>(P256_TEST_VECTORS)?;
        test_server_login_finish::<P256Sha256NoSlowHash>(P256_TEST_VECTORS)?;
        test_fake_vectors::<P256Sha256NoSlowHash>(P256_FAKE_TEST_VECTORS)?;
    }

    Ok(())
}

fn test_registration_request<CS: CipherSuite>(tvs: &[&str]) -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(tvs) {
        let mut rng = CycleRng::new(parameters.blind_registration.to_vec());
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut rng, &parameters.password)?;
        assert_eq!(
            hex::encode(&parameters.registration_request),
            hex::encode(client_registration_start_result.message.serialize())
        );
    }
    Ok(())
}

fn test_registration_response<CS: CipherSuite>(tvs: &[&str]) -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(tvs) {
        let server_setup = ServerSetup::<CS>::deserialize(
            &[
                &parameters.oprf_seed[..],
                &parameters.server_private_key[..],
                &parameters.dummy_private_key[..],
            ]
            .concat(),
        )?;
        let server_registration_start_result = ServerRegistration::<CS>::start(
            &server_setup,
            RegistrationRequest::deserialize(&parameters.registration_request[..]).unwrap(),
            &parameters.credential_identifier,
        )?;
        assert_eq!(
            hex::encode(parameters.oprf_key),
            hex::encode(server_registration_start_result.oprf_key)
        );
        assert_eq!(
            hex::encode(parameters.registration_response),
            hex::encode(server_registration_start_result.message.serialize())
        );
    }
    Ok(())
}

fn test_registration_upload<CS: CipherSuite>(tvs: &[&str]) -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(tvs) {
        let mut rng = CycleRng::new(parameters.blind_registration.to_vec());
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut rng, &parameters.password)?;

        let mut finish_registration_rng = CycleRng::new(parameters.envelope_nonce);
        let result = client_registration_start_result.state.finish(
            &mut finish_registration_rng,
            RegistrationResponse::deserialize(&parameters.registration_response[..]).unwrap(),
            match parse_identifiers(parameters.client_identity, parameters.server_identity) {
                None => ClientRegistrationFinishParameters::Default,
                Some(ids) => ClientRegistrationFinishParameters::WithIdentifiers(ids),
            },
        )?;

        assert_eq!(
            hex::encode(parameters.auth_key),
            hex::encode(result.auth_key)
        );
        assert_eq!(
            hex::encode(parameters.randomized_pwd),
            hex::encode(result.randomized_pwd)
        );
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

fn test_ke1<CS: CipherSuite>(tvs: &[&str]) -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(tvs) {
        let client_login_start = [
            parameters.blind_login,
            parameters.client_private_keyshare,
            parameters.client_nonce,
        ]
        .concat();
        let mut client_login_start_rng = CycleRng::new(client_login_start);
        let client_login_start_result =
            ClientLogin::<CS>::start(&mut client_login_start_rng, &parameters.password)?;
        assert_eq!(
            hex::encode(&parameters.KE1),
            hex::encode(client_login_start_result.message.serialize())
        );
    }
    Ok(())
}

fn test_ke2<CS: CipherSuite>(tvs: &[&str]) -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(tvs) {
        let server_setup = ServerSetup::<CS>::deserialize(
            &[
                &parameters.oprf_seed[..],
                &parameters.server_private_key[..],
                &parameters.dummy_private_key[..],
            ]
            .concat(),
        )?;

        let record = ServerRegistration::<CS>::deserialize(
            &get_password_file_bytes::<CS>(&parameters)?[..],
        )?;

        let mut server_private_keyshare_and_nonce_rng = CycleRng::new(
            [
                parameters.masking_nonce,
                parameters.server_private_keyshare,
                parameters.server_nonce,
            ]
            .concat(),
        );
        let server_login_start_result = ServerLogin::<CS>::start(
            &mut server_private_keyshare_and_nonce_rng,
            &server_setup,
            Some(record),
            CredentialRequest::<CS>::deserialize(&parameters.KE1[..]).unwrap(),
            &parameters.credential_identifier,
            match parse_identifiers(parameters.client_identity, parameters.server_identity) {
                None => ServerLoginStartParameters::WithContext(parameters.context.to_vec()),
                Some(ids) => ServerLoginStartParameters::WithContextAndIdentifiers(
                    parameters.context.to_vec(),
                    ids,
                ),
            },
        )?;
        assert_eq!(
            hex::encode(&parameters.handshake_secret),
            hex::encode(server_login_start_result.handshake_secret)
        );
        assert_eq!(
            hex::encode(&parameters.server_mac_key),
            hex::encode(server_login_start_result.server_mac_key)
        );
        assert_eq!(
            hex::encode(&parameters.oprf_key),
            hex::encode(server_login_start_result.oprf_key)
        );
        assert_eq!(
            hex::encode(&parameters.KE2),
            hex::encode(server_login_start_result.message.serialize())
        );
    }
    Ok(())
}

fn test_ke3<CS: CipherSuite>(tvs: &[&str]) -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(tvs) {
        let client_login_start = [
            parameters.blind_login,
            parameters.client_private_keyshare,
            parameters.client_nonce,
        ]
        .concat();
        let mut client_login_start_rng = CycleRng::new(client_login_start);
        let client_login_start_result =
            ClientLogin::<CS>::start(&mut client_login_start_rng, &parameters.password)?;

        let client_login_finish_result = client_login_start_result.state.finish(
            CredentialResponse::<CS>::deserialize(&parameters.KE2[..])?,
            match parse_identifiers(parameters.client_identity, parameters.server_identity) {
                None => ClientLoginFinishParameters::WithContext(parameters.context),
                Some(ids) => {
                    ClientLoginFinishParameters::WithContextAndIdentifiers(parameters.context, ids)
                }
            },
        )?;

        assert_eq!(
            hex::encode(&parameters.session_key),
            hex::encode(&client_login_finish_result.session_key)
        );
        assert_eq!(
            hex::encode(&parameters.handshake_secret),
            hex::encode(&client_login_finish_result.handshake_secret)
        );
        assert_eq!(
            hex::encode(&parameters.client_mac_key),
            hex::encode(&client_login_finish_result.client_mac_key)
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

fn test_server_login_finish<CS: CipherSuite>(tvs: &[&str]) -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(tvs) {
        let server_setup = ServerSetup::<CS>::deserialize(
            &[
                &parameters.oprf_seed[..],
                &parameters.server_private_key[..],
                &parameters.dummy_private_key[..],
            ]
            .concat(),
        )?;

        let record = ServerRegistration::<CS>::deserialize(
            &get_password_file_bytes::<CS>(&parameters)?[..],
        )?;

        let mut server_private_keyshare_and_nonce_rng = CycleRng::new(
            [
                parameters.masking_nonce,
                parameters.server_private_keyshare,
                parameters.server_nonce,
            ]
            .concat(),
        );
        let server_login_start_result = ServerLogin::<CS>::start(
            &mut server_private_keyshare_and_nonce_rng,
            &server_setup,
            Some(record),
            CredentialRequest::<CS>::deserialize(&parameters.KE1[..]).unwrap(),
            &parameters.credential_identifier,
            match parse_identifiers(parameters.client_identity, parameters.server_identity) {
                None => ServerLoginStartParameters::WithContext(parameters.context.to_vec()),
                Some(ids) => ServerLoginStartParameters::WithContextAndIdentifiers(
                    parameters.context.to_vec(),
                    ids,
                ),
            },
        )?;

        let server_login_result = server_login_start_result
            .state
            .finish(CredentialFinalization::deserialize(&parameters.KE3[..])?)?;

        assert_eq!(
            hex::encode(parameters.session_key),
            hex::encode(&server_login_result.session_key)
        );
    }
    Ok(())
}

fn test_fake_vectors<CS: CipherSuite>(tvs: &[&str]) -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(tvs) {
        let server_setup = ServerSetup::<CS>::deserialize(
            &[
                &parameters.oprf_seed[..],
                &parameters.server_private_key[..],
                &parameters.dummy_private_key[..],
            ]
            .concat(),
        )?;

        let mut server_private_keyshare_and_nonce_rng = CycleRng::new(
            [
                parameters.dummy_masking_key,
                parameters.masking_nonce,
                parameters.server_private_keyshare,
                parameters.server_nonce,
            ]
            .concat(),
        );
        let server_login_start_result = ServerLogin::<CS>::start(
            &mut server_private_keyshare_and_nonce_rng,
            &server_setup,
            None,
            CredentialRequest::<CS>::deserialize(&parameters.KE1[..]).unwrap(),
            &parameters.credential_identifier,
            match parse_identifiers(parameters.client_identity, parameters.server_identity) {
                None => ServerLoginStartParameters::WithContext(parameters.context.to_vec()),
                Some(ids) => ServerLoginStartParameters::WithContextAndIdentifiers(
                    parameters.context.to_vec(),
                    ids,
                ),
            },
        )?;
        assert_eq!(
            hex::encode(&parameters.KE2),
            hex::encode(server_login_start_result.message.serialize())
        );
    }
    Ok(())
}

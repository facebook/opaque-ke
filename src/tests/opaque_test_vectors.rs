// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite, errors::*, key_exchange::tripledh::TripleDH, keypair::PrivateKey,
    opaque::*, slow_hash::NoOpHash, tests::mock_rng::CycleRng, *,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use generic_array::typenum::Unsigned;
use generic_bytes::SizedBytes;
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

#[cfg(feature = "p256")]
struct P256Sha256NoSlowHash;
#[cfg(feature = "p256")]
impl CipherSuite for P256Sha256NoSlowHash {
    type Group = p256_::ProjectivePoint;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha256;
    type SlowHash = NoOpHash;
}

#[derive(PartialEq)]
pub enum EnvelopeMode {
    Base,
    CustomIdentifier,
}

#[allow(non_snake_case)]
pub struct TestVectorParameters {
    pub dummy_private_key: Vec<u8>,
    pub dummy_masking_key: Vec<u8>,
    pub context: Vec<u8>,
    pub envelope_mode: EnvelopeMode,
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
EnvelopeMode: 01
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
client_public_key: 100f6f945b57e4a316e46ed7169b6e9e533c35b29128368a9a
40534b09227428
auth_key: 0ee186ac3a0fe0ec45d36c7cc9786934918a58d6a1abce6842a2b7bd0ec
1c0626e64d887622e8937e987bfbe042f904728966e121b01c739c8dbe66beb6241eb
randomized_pwd: 22f5e31fbbbf4649f77ebfc92a2ef555fc30a09edc903123d978d
e3ca356b85ce2120b0d2735bd772011ecb573e614cd7b1aeeb86ca0ac6b8732c33cdf
7a6816
envelope: 71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c46
767754ed20356eabd714970fc0058aad92414cc26131c7c3f9a0f5baa76c8fc410984
0921d83e26786e9c5b6a1cbc4458925fd65415547ffd61d2afbcb593a3a82fb1
handshake_secret: 9dc2e984200002626dac10f89b9d2efe967f68c8eb19612dd6c
2592d531ca5bd443c0548b8cef946f6e99998d810838c0ee99219fe13052beae3dc2c
b157c991
server_mac_key: 66739820f04e1cddc7090b05d510baf0de4273ebd9e26f6da961b
687dfdc05c6a68a93f81fd6ed7ff19c1c7f95cc76ceb2c680ed4ab2d6a5eb53088abd
3f7a36
client_mac_key: e0d836ea8e158a50a7cc610ca27eee2fb92187aa7273cb46ee21d
230be82e7efddf742fe127bc95eb6e034a01efe38ae3c4240b0d0f7fa395dfa52032a
0c1cb5
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
registration_upload: 100f6f945b57e4a316e46ed7169b6e9e533c35b29128368a
9a40534b09227428dc3b0057603d1c23df7e6f239984604c4b0dfa111528ab0ba3c7f
6ab1ceb11d10aa85433f63bbf30b9b0ae8951653bcd3beb12aa61cf942e6e5b442282
0d810871b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c467677
54ed20356eabd714970fc0058aad92414cc26131c7c3f9a0f5baa76c8fc4109840921
d83e26786e9c5b6a1cbc4458925fd65415547ffd61d2afbcb593a3a82fb1
KE1: e47c1c5e5eed1910a1cbb6420c5edf26ea3c099aaaedcb03599fc311a724d84f
804133133e7ee6836c8515752e24bb44d323fef4ead34cde967798f2e9784f69f6792
6bd036c5dc4971816b9376e9f64737f361ef8269c18f69f1ab555e96d4a
KE2: 9692d473e0bde7a1fbb6d2c0e4001ccc58902102857d0e67e5fa44f4b902b17f
54f9341ca183700f6b6acf28dbfe4a86afad788805de49f2d680ab86ff39ed7f7b11e
e2cb784efa8e6cbbb9cc6b52b16290e3906235d71b773534c3da1575a00708219fa81
05b3d2a1292d58d6ea6b0e464c752df6f957a9e34a66de7e5d44db0e48648d414f7b1
54e52d5f664c1b88dd42a8117b048fb26428a3b86885d2157a7136708494fd92f50c1
c3f63bd60d0b458254ac54c6e64841be63f1c4459d3bf9c5ec75a8cd571370add249e
99cb8a8c43f6ef05610ac6e354642bf4fedbf696e77d4749eb304c4d74be9457c5975
46bc22aed699225499910fc913b3e907129491571e3137ff950f905e6c83db79e5103
bd8b7c27799d1eac8d8c57fd2f0b913e81411c02bc722b30b4eb4ee3a53fc1b21232b
4218eb0ed00996dc8c841a96
KE3: 5a4e48d857196ce709b054f7be4e3973f0892abfafc030762bd4be5dbeb342af
b5bf1fd24a7b355f556f9d53f146ebb3729ae693f69fc1f7862a0c11c8ee7c9d
export_key: 47d742be256471ec7a7b0ebc022d6ca016b022a7dcbdd41fa1b6dbfcd
6f88285aee60db87e7c5e5aff87b55904b07137b3d85648bb62d70a18954dd1c66cdd
c2
session_key: e132b5c83951919bc0f22aa4e3b12b4af81831ccf770f318d11c8c0a
854fddf6bbeee72e24114402ff9012cf117bac95dda241b24d055f7ce2750e6975fa2
22d
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
EnvelopeMode: 01
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
client_public_key: c8c9f3a9adab66971bbdb230bd44512741a489e333624186ac
a1b0e967011e06
auth_key: 494f1326c65c057e301f15e619b9e3de553c77132987828ba20026062da
a1f18d516ac2e37b1dfc296e21137623856fb3ccba48cc511f143110944848764dfb7
randomized_pwd: a4853e726d14efb03c35686ee2bc67665d02bdccb0c4c02523bf4
e1398e78b1094195a082b5ebb1b62ac75d06711643e9990c2be0071a42bc21a2b766b
787eac
envelope: d0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf274782
9b2d21a6d25b3a1b8a541f47fc4bbe5783c2cc61c77ed389280a05ed2ef8c2c2d03fe
2066bd22ea959c7bb14b5259ee136e86f4d956fbaa2af2f6a326785f21262909
handshake_secret: aacad16f4fb6ff90e3a6afb4e430a550000f0351cd30aab930c
3118c8aebbf8bcaa5252809b065d19a26ab475214a1c4dd60c28e91ce310b5a79968d
bb87938c
server_mac_key: 58edbb9aa5489765c102470a5287b5036893b8cea58ecc836bd0c
df4a818f41d6cd58c46d64db3548774f2cc651d10f8e152a7fdd47493c90a28b1106c
8d329b
client_mac_key: 57be496bd6fa74ecfed7a8c30a9ee085f3e56dbf0d5c18c9ad8c3
8799f0ededd9a8af85e59276935da7bc3ddd2a8cf4fa9ea723ea70b6dba1db2872815
27944a
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
registration_upload: c8c9f3a9adab66971bbdb230bd44512741a489e333624186
aca1b0e967011e069fabb8544108ec64de2b992935dd5fd9a98441412ccf724bf4853
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
f356ee5de37881533f10397bcd84d354450f1409ae0d487a21921d7edbfe34f9e16a8
ac94f6f83b0d4a78c1fe567ea4bda594d375917e22fe0fc203773bf728eff0309f259
4ac3f4dc2cf066f4febcca0e
KE3: c3dc494d69ef860b348714fd67a3e6490e5afd493d7212729a96d61e9502f7a8
202a18be10b513f236b3e7e2e2f62ff25a61525991c81c030836cb1933b7a13d
export_key: 7f2e5b749ec5f6ab34663655184f3653275aafd5db070b6aac6afd80a
78309a8ec0f97a2f2cfcc7a971983a914ead081a8a642b65d298c579d3526d2219381
8d
session_key: a07bb20c5ad960af8caf83b112a008a61e10e2475456fd0620a11ea5
a75706750b72c4943c3985cae5f31969dea9c74192c8bf601e2d062fcb141c89234ff
7be
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
EnvelopeMode: 01
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
oprf_seed: d3cb00535339fe4063c7ba5506a990c243a2b5c77b06848a0be9a0568c
252fb0d7425382babd267deeed669e56d1d5654c036211f49b42f4489f96f37100779
f
credential_identifier: 31323334
masking_nonce: 3058799f42516228746821dc8c8530d0e8273ebde81941591d69ca
5aea773090
client_private_key: 83c9bcc31a9da0ffa4489900d3d1f85bb65c27f26e9ae4e3b
66f6e02e098c503
client_public_key: 56717b74a5e1770edb14c65f22cee0487046bd96e122ba97da
ffed06c4bf4052
server_private_key: 8d3a9355f9757e7071b3f836e3fb1461a6436e92971625b17
cd7e580dd27c009
server_public_key: 7a464761cb19c8b6e832fdfcfd18779b0edc246fe808f5de6c
e7bdb54df41b67
server_nonce: 4e2a8098173efa2968036f1762f2e5df41ab976fb1bfb91dae29950
f8526de4c
server_keyshare: 0e247410004d83d7cbe3af89c62ff03f942127aec4b0084c9eb5
88e74ce6dd06
server_private_keyshare: 326345820acc8aacf4948fce775a1fd265e4e93fd579
cec8177d6389ee379b0a
masking_key: e968bfe56ad934c3e1088115bcbf1af8b405fd0de94cdf301f9192cc
2781de00617e568b14b7235cc1189265811ea354031ea39b62e31a104f181c01d3dae
4b8
KE1: b61bfe5997b644e9654b7796203831ea9b9e86499c17db3331a40673832c9729
05603c1acb64ea417c0dabaab858a5f9da046d4a0cdbf092034c00451ccdc6e1ee835
5c91d5ed7aa5ea75b8a730ba8dc45f6b41ae9713e6aa7126211346e8754
~~~

#### Output Values

~~~
KE2: 0826f0581be79672ccf51276e4b4079bf05aa94530591b24acbf4106cf2fa34e
3058799f42516228746821dc8c8530d0e8273ebde81941591d69ca5aea77309078577
13efdc95f69166737cd7a80ead60e1a1f805c1da9cccbc0d29120f34be291518798c7
00793f232374e66182495b76b388d9e11f479580cc2297da02fecee88a99cea6bc411
b9467e8bfa9a4006aba7f21b74b4ce3bccd686785878b0ec9b3fc4200228014d5d073
69d42d1d1b1669ecd2ad8905734ca0a641d8f16667ca4e2a8098173efa2968036f176
2f2e5df41ab976fb1bfb91dae29950f8526de4c0e247410004d83d7cbe3af89c62ff0
3f942127aec4b0084c9eb588e74ce6dd0689ffd826511fa128dc90837369bb9ed14d0
794aa3a6e45d2ef533cf6b7e3b47d963eed736c71c8ca933af078af45f573bd3fb790
336c9b47cc40f3d7c091a552
~~~
"#];

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
EnvelopeMode: 01
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
client_public_key: 02680493263d3bc4c7af455ba1219fd9bbe329fd0c2a0248e8
7321ded8ff17b386
auth_key: 570a8105a7d86679b4c9d009edc9627af6b17e8b2d2f0d50cbd13ea8a00
82cd7
randomized_pwd: 04f1615bc400765f22f7af1277a0814b5665ad1d4ef9bf1829880
2a0f6b4636b
envelope: 2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1acacc4
a8319890e251c4b6397fb35900ff46ae1df1e86eed2d23005c6b9c61caa4e12af8bf5
handshake_secret: 56212ac60eca9f917f6a4ce6aefe762743da701b008ec986cd1
87ff75df5df84
server_mac_key: 8c7f132b6cd9a7e4ce9171cd469d02dc1ab0e8d96f4e1ddca1718
55fc723203f
client_mac_key: 348cb4526417423090d386ce43459d652a6489122e27d3953ed47
5b3ab9cd336
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
registration_upload: 02680493263d3bc4c7af455ba1219fd9bbe329fd0c2a0248
e87321ded8ff17b3868efb26f2bb390fd23b90c49ae680c4560fbd2b3c4f32891505c
ad7d95b7bc58e2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1aca
cc4a8319890e251c4b6397fb35900ff46ae1df1e86eed2d23005c6b9c61caa4e12af8
bf5
KE1: 03884e56429f1ee53559f2e244392eb8f994fd46c8fd9ffdd24ac5a7af963a66
3b967fcded96ed46986e60fcbdf985232639f537377ca3fcf07ad489956b2e9019033
58b4eae039953116889466bfddeb40168e39ed83809fd5f0d5f2de9c5234398
KE2: 0383fff1b3e8003723dff1b1f90a7934a036bd6691aca0366b07a100bf2bb3dc
2acb792f3657240ce5296dd5633e7333531009c11ee6ab46b6111f156d96a160b23b6
a5ff1ce8035a1dca4776f32f43c7ce626d796da0f27fc9897522fc1fab70d2fb443d8
2a4333770057e929c2f9977d40a64e8b4a5a553d25a8b8392b4adbf0a0a6e87f26165
0d04084823b23b07d351e3b947778a43859be3ba218b22d054edf8018e88ecfc53891
529278c47239f8fe6f1be88972721898ef81cc0a76a0b5500242bc29993976185dacf
6be815cbfa923aac80fad8b7f020c9d4f18e0b6867a171e7fda886b9fd9f3bc9e37c4
04ca07f7a5c9a6f98df20a5cac42371162731faa
KE3: 86a57a3e1a2e537ea667031091c025cb539826dbbb1756683220dd239d4a7bff
export_key: a83a3fe26af0dadb63d15ed808a4dc2edb57f45212554ecc1af5e0273
50651de
session_key: e26d54798ce8a66fb415cb67f4d87647dcd3d8aa79a7ab6a5f701b82
f037b1e3
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
EnvelopeMode: 01
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
client_public_key: 02e89507b3a1a946e8096cd7e1e8fbc31e2dd39fecc49580ed
2659262c08ea33eb
auth_key: 76cba5b349c60c5a19ab06b70a3191d3418318b5a203fd298b18a0eda53
efd1a
randomized_pwd: 74649c9c7b0d7436c4873984732fe45e19dabd1a96d7e9175468a
85ed16bea65
envelope: 75c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b842e44
26e423938d818ea53f58fdaab8541765d5171e99b1bdc2c63e8e1eaf62d3a60aacabe
handshake_secret: 22f608959308cb4dff55cf77c006ea8e9bc66df75d7076a927a
3d21d3fce5562
server_mac_key: 76e1415cfcf0ff271533fdd4ce4fffb4110ba1ff4aa9a02a1734d
9ae0e0ce47a
client_mac_key: 9341b0b36ac36875910cd1260cd8dc6d6cd58e0fb6503fece6524
11b6f627bf7
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
registration_upload: 02e89507b3a1a946e8096cd7e1e8fbc31e2dd39fecc49580
ed2659262c08ea33eb260603b2690f3d466fb0b747e256283bed94836ac98c10d4588
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
6652d44f6dfb04470103311bacd7ad51060ef5abac41bbe51a3c1deeeab8ded9273ad
681001416cbb6d1f0976548f36d1ddb1d3b1f948
KE3: 5770a1ce912fecf1fa339fe1646b2abfe8dd683767c885a0f1dedba8dfab653e
export_key: 5b92e3454d59062460a87ad2ff6546d862f722c6fbd7678a0997b3c9d
c61e9a0
session_key: 3a04636e2c14b4ef3a01070a2ff129cd2248318d8b85d6c4368f5115
0f0348ff
~~~
"#,
];

static P256_FAKE_TEST_VECTORS: &[&str] = &[r#"
### OPAQUE-3DH Fake Test Vector 2

#### Configuration

~~~
OPRF: 0003
Hash: SHA256
MHF: Identity
KDF: HKDF-SHA256
MAC: HMAC-SHA256
EnvelopeMode: 01
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
oprf_seed: 42cd4f606841ca8f403920a8ecf2d60399962f49d83f857ca86676b272
1c4366
credential_identifier: 31323334
masking_nonce: d3974af728aeafc9e5af4b4cab57d7e7dfbe0ef6b08df28fae5269
229cac2332
client_private_key: 0e6b97ef90ea8cedbada0e1295233ba417790ed8e99676903
71d527ddad59a64
client_public_key: 033043e30c3dd5fb22d0b3d167acc28878ea7c3ac49cf82b2e
b4b60a8299a67f7a
server_private_key: b08b686382820021a7d32ad3cb8ff60f15437b5cb00c53f21
f3fa17ac31d2bc0
server_public_key: 03983ac5783e6a460a526066f1398cdc648518a985cc26a66f
c7573a71ce36dbe5
server_nonce: 1a60a3e31bb007db74b7114aab2f196ef6bec942a9b4fe6c61143fa
c34d42143
server_keyshare: 03eefd21dd74c665064ebcbf63ac5ebce9a45097d47dfc08d845
52a105419b44aa
server_private_keyshare: 751e5012ba0c535e008b2389bea166a5d59a49353f12
20f5e345f0546463ccdf
masking_key: 5b8caab90accd4f239e85ec978f6a6346edc0019c5671e81034ead61
5ce096fc
KE1: 028bc054fff79a9e0f0315e31cc035384aedd9d50ea8ee36630d39876ca4e592
93d797d24fe5ad528130825016bfdc2eeaeef19914c366a615bcdbefd1f04b7208023
843b78440c0e79d828ac4c2658d1cedf7e9795f2242527a4c1a254501d2ca1a
~~~

#### Output Values

~~~
KE2: 0353685a152940706b1ed877b2da12f3c9f417d38fab56f3228c60f72429f602
d9d3974af728aeafc9e5af4b4cab57d7e7dfbe0ef6b08df28fae5269229cac23329a9
93151e43ac41ce18939444cea5d012b8a8316ed439d6fccf06b064f7564722f555750
61897fbb6051f37e3247d08804437259fb9b022cc12715caca4ac12ef7a8b2f101269
37619ce4725e6b821de5f44ddb71a8582883aa9b5aaefa9e3d0231a60a3e31bb007db
74b7114aab2f196ef6bec942a9b4fe6c61143fac34d4214303eefd21dd74c665064eb
cbf63ac5ebce9a45097d47dfc08d84552a105419b44aadb37380855acdd939b7eb300
708d78b17ff0f99cee4ca4777c7628fb8ff591d1
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

fn rfc_to_json(input: &str) -> String {
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
            vec![0u8; <PrivateKey<CS::Group> as SizedBytes>::Len::to_usize()]
        ),
        dummy_masking_key: parse_default!(values, "masking_key", vec![0u8; 64]),
        context: parse!(values, "Context"),
        envelope_mode: match values["EnvelopeMode"].as_str() {
            Some("01") => EnvelopeMode::Base,
            Some("02") => EnvelopeMode::CustomIdentifier,
            _ => panic!("Could not match envelope mode"),
        },
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
        //test_registration_upload::<P256Sha256NoSlowHash>(P256_TEST_VECTORS)?;
        //test_ke1::<P256Sha256NoSlowHash>(P256_TEST_VECTORS)?;
        //test_ke2::<P256Sha256NoSlowHash>(P256_TEST_VECTORS)?;
        //test_ke3::<P256Sha256NoSlowHash>(P256_TEST_VECTORS)?;
        //test_server_login_finish::<P256Sha256NoSlowHash>(P256_TEST_VECTORS)?;
        //test_fake_vectors::<P256Sha256NoSlowHash>(P256_FAKE_TEST_VECTORS)?;
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

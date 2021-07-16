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
    type PrivateKey = PrivateKey<RistrettoPoint>;
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

// Pulled from "OPAQUE-3DH Test Vector 1" and "OPAQUE-3DH Test Vector 6"
// of https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/
static TEST_VECTORS: &[&str] = &[
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

static FAKE_TEST_VECTORS: &[&str] = &[r#"
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
            .map(|x| populate_test_vectors(&serde_json::from_str(rfc_to_json(x).as_str()).unwrap()))
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

fn populate_test_vectors(values: &Value) -> TestVectorParameters {
    TestVectorParameters {
        dummy_private_key: parse_default!(
            values,
            "client_private_key",
            vec![0u8; <PrivateKey<RistrettoPoint> as SizedBytes>::Len::to_usize()]
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

fn get_password_file_bytes(parameters: &TestVectorParameters) -> Result<Vec<u8>, ProtocolError> {
    let password_file = ServerRegistration::<Ristretto255Sha512NoSlowHash>::finish(
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
fn test_registration_request() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let mut rng = CycleRng::new(parameters.blind_registration.to_vec());
        let client_registration_start_result =
            ClientRegistration::<Ristretto255Sha512NoSlowHash>::start(
                &mut rng,
                &parameters.password,
            )?;
        assert_eq!(
            hex::encode(&parameters.registration_request),
            hex::encode(client_registration_start_result.message.serialize())
        );
    }
    Ok(())
}

#[test]
fn test_registration_response() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let server_setup = ServerSetup::<Ristretto255Sha512NoSlowHash>::deserialize(
            &[
                &parameters.oprf_seed[..],
                &parameters.server_private_key[..],
                &parameters.dummy_private_key[..],
            ]
            .concat(),
        )?;
        let server_registration_start_result =
            ServerRegistration::<Ristretto255Sha512NoSlowHash>::start(
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

#[test]
fn test_registration_upload() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let mut rng = CycleRng::new(parameters.blind_registration.to_vec());
        let client_registration_start_result =
            ClientRegistration::<Ristretto255Sha512NoSlowHash>::start(
                &mut rng,
                &parameters.password,
            )?;

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

#[test]
fn test_ke1() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let client_login_start = [
            parameters.blind_login,
            parameters.client_private_keyshare,
            parameters.client_nonce,
        ]
        .concat();
        let mut client_login_start_rng = CycleRng::new(client_login_start);
        let client_login_start_result = ClientLogin::<Ristretto255Sha512NoSlowHash>::start(
            &mut client_login_start_rng,
            &parameters.password,
        )?;
        assert_eq!(
            hex::encode(&parameters.KE1),
            hex::encode(client_login_start_result.message.serialize())
        );
    }
    Ok(())
}

#[test]
fn test_ke2() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let server_setup = ServerSetup::<Ristretto255Sha512NoSlowHash>::deserialize(
            &[
                &parameters.oprf_seed[..],
                &parameters.server_private_key[..],
                &parameters.dummy_private_key[..],
            ]
            .concat(),
        )?;

        let record = ServerRegistration::<Ristretto255Sha512NoSlowHash>::deserialize(
            &get_password_file_bytes(&parameters)?[..],
        )?;

        let mut server_private_keyshare_and_nonce_rng = CycleRng::new(
            [
                parameters.masking_nonce,
                parameters.server_private_keyshare,
                parameters.server_nonce,
            ]
            .concat(),
        );
        let server_login_start_result = ServerLogin::<Ristretto255Sha512NoSlowHash>::start(
            &mut server_private_keyshare_and_nonce_rng,
            &server_setup,
            Some(record),
            CredentialRequest::<Ristretto255Sha512NoSlowHash>::deserialize(&parameters.KE1[..])
                .unwrap(),
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

#[test]
fn test_ke3() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let client_login_start = [
            parameters.blind_login,
            parameters.client_private_keyshare,
            parameters.client_nonce,
        ]
        .concat();
        let mut client_login_start_rng = CycleRng::new(client_login_start);
        let client_login_start_result = ClientLogin::<Ristretto255Sha512NoSlowHash>::start(
            &mut client_login_start_rng,
            &parameters.password,
        )?;

        let client_login_finish_result = client_login_start_result.state.finish(
            CredentialResponse::<Ristretto255Sha512NoSlowHash>::deserialize(&parameters.KE2[..])?,
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

#[test]
fn test_server_login_finish() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(TEST_VECTORS) {
        let server_setup = ServerSetup::<Ristretto255Sha512NoSlowHash>::deserialize(
            &[
                &parameters.oprf_seed[..],
                &parameters.server_private_key[..],
                &parameters.dummy_private_key[..],
            ]
            .concat(),
        )?;

        let record = ServerRegistration::<Ristretto255Sha512NoSlowHash>::deserialize(
            &get_password_file_bytes(&parameters)?[..],
        )?;

        let mut server_private_keyshare_and_nonce_rng = CycleRng::new(
            [
                parameters.masking_nonce,
                parameters.server_private_keyshare,
                parameters.server_nonce,
            ]
            .concat(),
        );
        let server_login_start_result = ServerLogin::<Ristretto255Sha512NoSlowHash>::start(
            &mut server_private_keyshare_and_nonce_rng,
            &server_setup,
            Some(record),
            CredentialRequest::<Ristretto255Sha512NoSlowHash>::deserialize(&parameters.KE1[..])
                .unwrap(),
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

#[test]
fn test_fake_vectors() -> Result<(), ProtocolError> {
    for parameters in rfc_to_params!(FAKE_TEST_VECTORS) {
        let server_setup = ServerSetup::<Ristretto255Sha512NoSlowHash>::deserialize(
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
        let server_login_start_result = ServerLogin::<Ristretto255Sha512NoSlowHash>::start(
            &mut server_private_keyshare_and_nonce_rng,
            &server_setup,
            None,
            CredentialRequest::<Ristretto255Sha512NoSlowHash>::deserialize(&parameters.KE1[..])
                .unwrap(),
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

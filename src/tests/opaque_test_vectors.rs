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
## OPAQUE-3DH Test Vector 1

### Configuration

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

### Input Values

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
oprf_key: 23d431bab39aea4d2737ac391a50076300210730971788e3a6a8c29ad3c
5930e
~~~

### Intermediate Values

~~~
client_public_key: f692d6b738b4e240d5f59d534371363b47817c00c7058d4a33
439911e66c3c27
auth_key: 27972f9b1cf2ce524d50a7afa40a2ee6957904e2bef29976bdbda452a84
fcf01023f3ddd8182e64ea5287f99765dd39b83fa89fe189db227212a144134684783
randomized_pwd: 750ef06299c2fb102242fd84e59613616338f83e69c09c1dc3f91
c57ac0642876ccbe785e94aa094262efdc6aed08b3faff7c1bddfa14c434c5a908ad6
c5f9d5
envelope: 71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c46
76775455739db882585a7c8b3e9ae7955da7135900d85ab832aa83a34b3ce481efc9e
43d4c2276220c8bcb9d27b5a827a5a2d655700321f3b32d21f578c21316195d8
handshake_secret: 02fb23a668b7138b029c95d21f1e0eec9e10377be933bdbf3e5
33ea39073d3ce9d1ef16b55a8a8464f3bf6a991cc645d14c1fa3d9d6cfe36c6c0dcc2
691d7109
server_mac_key: e75ce46beeebd26f22540d7988de9809a69cf34fec6c050750708
e91232297fdbb51e875cd37167d5ce661ebccf0004dbbf96311daf64ddec7faae04c4
8bbd89
client_mac_key: 4bce132daa031fff2a6e5ac29287c4641e3b9dc2560394b8c73f3
b748f1e51e577b932a960b236981217b33bee220b0bce2696638cfb7791f427ade292
d60f55
~~~

### Output Values

~~~
registration_request: 80576bce33c6ce89f9e1a06d8595cd9d09d9aef46b20dad
d57a845dc50e7c074
registration_response: 1a80fdb4f4eb1985587b5b95661d2cff1ef2493cdcdd88
b5699f39048f0d6c2618d5035fd0a9c1d6412226df037125901a43f4dff660c0549d4
02f672bcc0933
registration_upload: f692d6b738b4e240d5f59d534371363b47817c00c7058d4a
33439911e66c3c2795014d8fc0c710bd763c981c5b9329c95e149c6717af91bad2cec
daf87f2c3c9c11914cb6d44aaee5679e3e61e1b65241fda74902cca908a065495c0b2
8b799e71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c467677
5455739db882585a7c8b3e9ae7955da7135900d85ab832aa83a34b3ce481efc9e43d4
c2276220c8bcb9d27b5a827a5a2d655700321f3b32d21f578c21316195d8
KE1: 60d71c9f5d2a14568807b869e2c251a8e5f7ad8951cd8386c7e32c0634b26b16
804133133e7ee6836c8515752e24bb44d323fef4ead34cde967798f2e9784f69f6792
6bd036c5dc4971816b9376e9f64737f361ef8269c18f69f1ab555e96d4a
KE2: 78a428204f552d3532bad040c961324edb22c738d98f1dd770d65caba0bd8966
54f9341ca183700f6b6acf28dbfe4a86afad788805de49f2d680ab86ff39ed7fbcbbb
84a18810b8eb1dc898d9af686f5901a21d0768720b325279fde4931ee52f0d4a0d0d9
cd1cd7c424d4622b1588ba554cd9241352a59ef52bbe85e0f865021404b115ba954f5
540cf2d811a6566a93876cac1239b1f75f39b070250af5a84a819e08b13e9e437a80f
c25cc130f8475dde43efe6d900c664e9bac300298bb0f9c5ec75a8cd571370add249e
99cb8a8c43f6ef05610ac6e354642bf4fedbf696e77d4749eb304c4d74be9457c5975
46bc22aed699225499910fc913b3e907120485942e3e077f71c1dd2d87053b39f0d31
bfe5d5f90df0e85ad9ce771e4f4d1ab697a10a02002cd73916051b887da9554465d58
68811fd8b22b8f457ed5a4b0
KE3: b4f8aece9fb4f6b7b5ffe1c98747a91f4ec7bf5481fe5719ba4baad668e3fd4e
8aba4fa227bd4c688ed9e17f6c6d28ab5e5617a883207d80979dc4797ca89304
export_key: 045f61f4baa0a945c2e85dfb7a85fe4df8a49e6c31344920e863c286b
c8a17fe25fc16c84836335b4b5ecc9743c5d3a221101ab004aa99ce65026b6953ad6c
c0
session_key: 91187690e5ea0da3110a1dd7d5ffd7c4c3111950c587d9fcf3b9f34b
f73b86dbeafed42a05024fa875a32415c6143d20c39cd732eb0e31db5e60ea3fb2551
cf7
~~~
"#,
    r#"
## OPAQUE-3DH Test Vector 2

### Configuration

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

### Input Values

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
oprf_key: 1e0550d2dbb9ce5dd9bdbb5f808afbb724c573dc03306dcfc7217796465
ce607
~~~

### Intermediate Values

~~~
client_public_key: ba6cb41f1870e9db7e858440a664e6559d01fdbfb638bbf7e1
c9004f20d5db71
auth_key: 5142ae6f6bd80686039656fd7a03cdd7e39cc6e869aa637220d4b5fb64f
afee2f284a1581fff95ad3a5261b413c5e5b91115f78a3c35486fa56023c300d1726b
randomized_pwd: cea240b632b9c1d704034920cc3dc3c664ed8cd82cf5c0339af76
4d6350d2ee9ba1f675ce8df7b6cf8692d1efb158bafa3c2695ac03a2d92346c19810c
1a698b
envelope: d0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf274782
9b2d26e18240c0cbad3b4cdbd7d9d86512f87e43fac39e3785a17504aaa8508f81e3c
1517b150259be478720935e175b1e34bbe625d0828a62ca9983f9a27aed27f5e
handshake_secret: 7925c12d7bf3050e62fe5c8caaece3c85737754c5df79bc59a6
0fa87929ab1f4a4730f903b87be8b7d89ded8ec97aaec97bc8e7d53a555fd4ad74c4f
33b9bc83
server_mac_key: 27d6036335c5654132fb08cc81d95b3067ef7fe795f017531231a
e3fa03cd3ab72f1f5e81473318f9c01f990263d885dfce4b6ac8630fdc8ee8abc6a36
7c2339
client_mac_key: ebb3693bac6310075a89922c7a40599d14d03d9104b7a331106e8
a578a32a4944751f9d3c230a6690a5747137388a86159cf587969d13dadc0a3830218
dfbca5
~~~

### Output Values

~~~
registration_request: f841cbb85844967568c7405f3831a58c4f5f37ccddb0baa
4972ea912c960ae66
registration_response: 0256257cc6e2b04444edc076b9ad44d8b31593e050bea8
06485707a818f8a93f8aa90cb321a38759fc253c444f317782962ca18d33101eab2c8
cda04405a181f
registration_upload: ba6cb41f1870e9db7e858440a664e6559d01fdbfb638bbf7
e1c9004f20d5db71146e42585d25fa19913876edce4b5ee99b638eb37b1d8a8a76607
efaa12299e828641ba4fbf1c46fc2c3776e0a0c9791f88a15b9ddfb5495d63ce92d8f
58823bd0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf2747829b2d
26e18240c0cbad3b4cdbd7d9d86512f87e43fac39e3785a17504aaa8508f81e3c1517
b150259be478720935e175b1e34bbe625d0828a62ca9983f9a27aed27f5e
KE1: 14cc586d982b6db9846c78e0b3c543591e95fbf2fc877fa0e5eff89897dd3050
a6bcd29b5aecc3507fc1f8f7631af3d2f5105155222e48099e5e6085d8c1187a642e7
eecf19b804a62817486663d6c6c239396f709b663a4350cda67d025687a
KE2: 8ab71c17547f376ae787741c367142790087090cdde6327dabb2581197bffa59
30635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853b5def228c85dd973
a1ac59244f674da4a1c057961886661bd29e0c1346f0fcf75bf1c78d4781815c2f9f6
f2f9fe0e370b256f6e82fb2e14c7ffc374d42caf26abf13dca169a6faafd5cff8baa9
717090bc1fc5e1ba56acb93492d1a8b789f33ff29b6004c4be9a755ff590d7d00d6e8
893e7e54e639aebf69d18f2182a9bb0f2e1c27c81ba73fa57f7ef652185f89114109f
5a61cc8c9216fdd7398246bb7a0c20e2fbca2d8ae070cdffe5bb4b1c373e71be8e7d8
f356ee5de37881533f10397bcd84d35445401c619d464ab3a134c71da4d9874f2f736
189b8bbb659c28f8db25a58b9f089272132e3091efa87d6b07d10321ba464047be011
3e91514aba299fd1553bcebb
KE3: c4a0d5b8148f3ac0f8611b38de38bda085d4eb00d561397ae59676f36dc705be
1c939e7bfdd7301103af5eb164bdfb70298aab889bd2ac797e419a82bfb442e6
export_key: 6b50ae4dba956930c0465b4a26c3cee58e05afcab623c1c254ae34acc
38babf954530a53475672ff46a1cf7fd53ef9e808f85b08793d021bb5c6d2a1bb9204
f6
session_key: c9bc2b7e2237f6fbeccd92dc6ec6d51faeb886492f8d23f21743a967
597025215df02a4afb75349acbafeef9dfd4f19e6d38da8bea4912f7b691b70849b0d
78e
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
KE1: 480b6c0066c9320c50dce20f8b6b63e4ded7681defd9da3f70ecdc15770f9e68
05603c1acb64ea417c0dabaab858a5f9da046d4a0cdbf092034c00451ccdc6e1ee835
5c91d5ed7aa5ea75b8a730ba8dc45f6b41ae9713e6aa7126211346e8754
~~~

#### Output Values

~~~
KE2: 04013bca360b4b9ba95b2f494927375e0f234dac23053822e466a9738f781522
3058799f42516228746821dc8c8530d0e8273ebde81941591d69ca5aea77309078577
13efdc95f69166737cd7a80ead60e1a1f805c1da9cccbc0d29120f34be291518798c7
00793f232374e66182495b76b388d9e11f479580cc2297da02fecee88a99cea6bc411
b9467e8bfa9a4006aba7f21b74b4ce3bccd686785878b0ec9b3fc4200228014d5d073
69d42d1d1b1669ecd2ad8905734ca0a641d8f16667ca4e2a8098173efa2968036f176
2f2e5df41ab976fb1bfb91dae29950f8526de4c0e247410004d83d7cbe3af89c62ff0
3f942127aec4b0084c9eb588e74ce6dd06fb1a0fd81da51bc1d87c740c186d881ed79
71fdba5ad1d5cfc94ffe6a731241c78ea7ea5dae503e987edc37355b7348883dc65cd
b57aec04e64593007f98a405
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
            vec![0u8; <PrivateKey as SizedBytes>::Len::to_usize()]
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

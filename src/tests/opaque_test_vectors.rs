// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite, errors::*, key_exchange::tripledh::TripleDH, opaque::*,
    slow_hash::NoOpHash, tests::mock_rng::CycleRng, *,
};
use curve25519_dalek::ristretto::RistrettoPoint;
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
Name: 3DH
EnvelopeMode: 01
Group: ristretto255
~~~

### Input Values

~~~
oprf_seed: 0156ea279de42bab6d7ac2f4a3c0009a3b63908abbb2d0d3ce9122432e
9c598c3bd7c4513f02c1e0b2db0bd5912a599f519d9792634badff1969a31740c271a
b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 738d571dd3a2731b5f3c19037a8332f5a3dfb2e2c9a56ea53d717
75e4c651942
masking_nonce: c9badc4ef14d6892895f4423d65dd2ed1c957ec949c92eba41d939
25142fdaa0
client_public_key: 4a12fd9e1d035c060e44167f1155569497bfd04ad9e32d2313
63c86fc4c41e21
server_private_key: 3af5aec325791592eee4a8860522f8444c8e71ac33af5186a
9706137886dce08
server_public_key: 4c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b
78624cbd10b371
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: ce474ab156143f6c2d684009329a2d93220ce7bc0f1ae5f36e3dc82
a98a3f63e
client_nonce: b42c6eae134360274851dd546b1de25994585d4fad7bd20fa8778ca
248943ad6
server_keyshare: ca372e52516d51c19763ad5eb1a5b60dafb68c264dcf6bcc692f
667a71c5a617
client_keyshare: 4c415eebd7a9bb5f921cbcfc5863e48c9e79fd2ecc1788e2b616
bea0853f627a
server_private_keyshare: 080d0a4d352de92672ab709b1ae1888cb48dfabc2d6c
a5b914b335512fe70508
client_private_keyshare: 7e5bcbf82a46109ee0d24e9bcab41fc830a6ce8b82fc
1e9213a043b743b95800
blind_registration: 8bcb0b70dac18de24eef12e737d6b28724d3e37774e0b092f
9f70b255defaf04
blind_login: f3a0829898a89239dce29ccc98ec8b449a34b255ba1e6f944829d18e
0d589b0f
oprf_key: 65b06f219a738315f08153b83a6b2945b97c256008f10b17232d3e36f68
0c40d
~~~

### Intermediate Values

~~~
auth_key: abbbe03787526080977f1d63efd4b23c3bae3720677dd594a4510632390
1a18b563fd59426ff54a8956d6480e54aefe8999f82a5a763d828faa62b04818ae151
prk: 993051805e5fc4c41d466939847b3c88e204e834701e26ec45e4afbec0451758
e0af1cb0f737544ad03bac67fd319455fed81e301c0314613093661b3442f5d8
envelope: 01738d571dd3a2731b5f3c19037a8332f5a3dfb2e2c9a56ea53d71775e4
c651942fa74e1a24324ad3a1ac3aec2f53d022bf01346fa764c29b42bb34f1cdd941f
85a2504e32f3cec693420c318b7008da4ed3d40232ba388096d687905324dee281
handshake_secret: 28e37e0c27fa3c4569670d0eb6eed4b5a43cae6b604ed5742b4
051ae5539a76a731b8a5fe32fd5cb36c05fb754544f416bc3304c4e5bb0e8216df1bd
11991db5
handshake_encrypt_key: 54f9cdb87112a324d7cdcdcce49983274609767ff0e6e9
3a08fc76cecadc146c0b1f33d9e3ea3fb61b53f16aa2e9fcb3bffcace001e1d4a41b6
1be06cc71e34d
server_mac_key: 64808d0a408ebeeba663583cd1946233029c33d7ada7e4feba03d
1ee34958655b53ebb812fe87239fdfdd18ce3b496b7199cb55c400690ff66ef2a3b11
db03fb
client_mac_key: 8e3eccf394faf02f62c5a7ffb37fc1e75d08dcaddfeb799832595
9857fc3fc101708179e9d03747f17a479155f9f5cd9cbbdd3c2bf89004f8bef8b7a50
cd4447
~~~

### Output Values

~~~
registration_request: 24bbcabb15452642f709cb8567eff38f4cda6044aca3356
87a62b8453d849c18
registration_response: 00d358c8204c36f5a44f695acad3fca27a5cba9d655639
8d62220baaf1bcb3554c6dff3083c068b8ca6fec4dbaabc16b5fdac5d98832f25a5b7
8624cbd10b371
registration_upload: 4a12fd9e1d035c060e44167f1155569497bfd04ad9e32d23
1363c86fc4c41e21133330ab219fcd107dee7a2a201d8d3c6cef15dc7d4f4bf102dd7
3b62c8a43923f1edab0022d02684c6ad8e5fd4844a198a56ae4a058a3973fac2f6cb8
f6d26401738d571dd3a2731b5f3c19037a8332f5a3dfb2e2c9a56ea53d71775e4c651
942fa74e1a24324ad3a1ac3aec2f53d022bf01346fa764c29b42bb34f1cdd941f85a2
504e32f3cec693420c318b7008da4ed3d40232ba388096d687905324dee281
KE1: 0e8eeeb2ca0dbf5f690cfe0b76783d7667245f399b874a989f168fdd3e572663
b42c6eae134360274851dd546b1de25994585d4fad7bd20fa8778ca248943ad600096
8656c6c6f20626f624c415eebd7a9bb5f921cbcfc5863e48c9e79fd2ecc1788e2b616
bea0853f627a
KE2: 78b9a7d676c3b58738cc70327e5bc66b86bbdcdf2362524f3411c5290dad6c1e
c9badc4ef14d6892895f4423d65dd2ed1c957ec949c92eba41d93925142fdaa02983b
bea970e845e437b05f7b9d0376dcc8df22bce182b8182f725ae6670e506fe20e56ff6
204c306de7277cb3b932bdf7862ad32dfe9f42ddeb18d748d345be5b050bcba100449
885c4cee99123726e84e4a6b74fe15e6ede09448812ff5c2f625c5d7e71f479f31ce1
7353c11a52b77070e017f5c421cd1f72e70e90375b0f3ace474ab156143f6c2d68400
9329a2d93220ce7bc0f1ae5f36e3dc82a98a3f63eca372e52516d51c19763ad5eb1a5
b60dafb68c264dcf6bcc692f667a71c5a617000f2b5d4135ea72408901917ee44e9a8
c7e3ac2fac3e82081504387a5a4b2d25e8ae521c845e37f4cbc05f358de6c7fc34355
a926ff7cc009b6d36797aef6bc5d566593fbef456bbb6f75b453340a8cf6
KE3: 2820bd4a7b97600c0be23ccf558458c9e6b9f4ada91cbc3116e1267d8f3066b8
ce516c621ab0cef3cdb39661e6f3690352b80e9b6a12b2e0693861b99d3c9b44
export_key: 65caf6dad061b5c4afd26819769d8a404cc8e778ff7821b21e4876a92
2f5695cb4208c5a2fdba4ae2ef960aa25d45f6c572b4e065e3b39af91a05e0fc56067
51
session_key: 2131d2f316aed5cc7c4ead5d88d9189400d1ec59a6454bab1a9d79f6
5d4339f50ff7da0aef4c7d2e872a20c93dfb876724f7c927bf19cf106cd8e1ce698b7
817
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
Name: 3DH
EnvelopeMode: 01
Group: ristretto255
~~~

### Input Values

~~~
client_identity: 616c696365
oprf_seed: 4c44d659603cd0699995cd4ae50989f9f13b17a0a493856646e7936dfc
401d76182b8fbd66f3f9f50b356f62052903381fc49614d4b4eb2100f11e0e6149abe
b
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: b7950d891838b48c27734e951c4b5e7cf2374cb99c29529ef6bed
d2f99bc8364
masking_nonce: 75d4c6e41e7fe8e93976f84003647c3151f2ed8710218f3bfe2662
7109781ac6
client_public_key: ceb2afff14b6300344ba1d0fd9905e6af3e15616ee71a24e42
4e02e9b2d58463
server_private_key: de2e98f422bf7b99be19f7da7cac62f1599d35a225ec63401
49a0aaff3102003
server_public_key: a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e7874
92b98265a5e651
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 08388a20e9cbb91b0a70145308cdc9fa4d00a7e045629897202b255
040d13e31
client_nonce: 7f8518a1f4f8b9ef3177ad4d6cf129c612f3f1052fd25817b0a8cc9
cae93f037
server_keyshare: 80d9b21c255bf04113a6d339fff579c68475e516c0c98f625a90
f6532a310f13
client_keyshare: 746987c9ba92c3636d92fa7afc0379009ed54a7fb2db3cf7e4c4
07d4ed2c6e35
server_private_keyshare: 0bb106c0e1aac79e92dd2d051e90efe4e2e093bc1e82
b80e8cce6afa4f519802
client_private_keyshare: e79a642b20f4c9118febffaf6b6a31471fe7794aa77c
ed123f07e56cb8cf7c01
blind_registration: c4d002aa4cfcf281657cf36fe562bc60d9133e0e72a74432f
685b2b6a4b42a0c
blind_login: 614bb578f29cc677ea9e7aea3e4839413997e020f9377b63c1358415
2d81b40d
oprf_key: fa92ae90dba8cd939c39701cbbb47fbfd17eb405b41f0a675fa3c217931
9290b
~~~

### Intermediate Values

~~~
auth_key: 634ac8589271904b0bc6ef16bcdc51298df7ce8d767c8a9cfde9c5618cc
3b190d41aa754420a3fee69b6c6300a64694090a557c35aedfb2078c6c049ad31dc2f
prk: a52f2a371743c35adf2d826fe94fc3e2ab5c61321da32615d1448d0585396eb8
15b3cb26a731c5152fd17724444321dc35c650cc499ed43f5ae8fb45be93988c
envelope: 01b7950d891838b48c27734e951c4b5e7cf2374cb99c29529ef6bedd2f9
9bc83641d55937829fbcfb65ed2ef7fe65f03ac0df61a705f19459f6622bfeb0143ef
a8f4d873cf7a417c42a80ee0fe5b0fdfe2fe108f862cbc7ffcf898657002f16226
handshake_secret: ceb9000e9f176974cac62044999f1461893942aef7c987a5387
6c9f571d2ffe86d71a4a66452fcaec8ae663b2279f47b35de43cf16411591c574e7fc
bdb0edef
handshake_encrypt_key: 08fa679aa7241fd2a82ce47b5bf99e29ab906ca3408468
19e12d7bda845ddb7f331afcc10f2c6af6ad2a9b5287ab4f68692a02f86e43f3610ba
989771f4ceca6
server_mac_key: eda09d38484bdafbb27660357533cab26ae16b9559fff85aeaf52
5b5ccd034c994dfebddf9376fee6e86e831e1c2a1fc95d992987661ea0f41e439ae9d
95418e
client_mac_key: ca0d389ea39d790e5986b090afda58813401f92e974263229164d
80f85b9fb70980a3fc8d700541523a5e3c30ca6c2e18f174e4ed464b232f02aaa7442
0a3797
~~~

### Output Values

~~~
registration_request: fa8c0e0144f7b9cd1de1bfcf78104f94d63c0f90398c9df
ceee06ab5593ec500
registration_response: cad088b4d4eab5242f962a1d2ad09b330f2b514f481ba1
d7c37e254bbf364858a4084c7296b1a3d5a5e4a24358750489575acfd8fcfa6e78749
2b98265a5e651
registration_upload: ceb2afff14b6300344ba1d0fd9905e6af3e15616ee71a24e
424e02e9b2d584635cd99efd88c492841c03cda62b8e50c8cbc83f37e97931083e1d0
0302f84ec43b60ea4b0b180d46b4f5891fc1bf54a6bd50c43a0f774032735d560025a
70c86b01b7950d891838b48c27734e951c4b5e7cf2374cb99c29529ef6bedd2f99bc8
3641d55937829fbcfb65ed2ef7fe65f03ac0df61a705f19459f6622bfeb0143efa8f4
d873cf7a417c42a80ee0fe5b0fdfe2fe108f862cbc7ffcf898657002f16226
KE1: dedef709c5faf24970b4fa77480a2c640dc8c6b7a53ae78a2dbf3fc75134a250
7f8518a1f4f8b9ef3177ad4d6cf129c612f3f1052fd25817b0a8cc9cae93f03700096
8656c6c6f20626f62746987c9ba92c3636d92fa7afc0379009ed54a7fb2db3cf7e4c4
07d4ed2c6e35
KE2: da3bfc53bf7e2d3b2f2c29c1da4dcbfef13441e13332d4eb16bdd2702e0a804a
75d4c6e41e7fe8e93976f84003647c3151f2ed8710218f3bfe26627109781ac68e2a7
0e8e8692cc348effbaf7f5fc77d1aa3f47d7f742a4690a2ef7cd05c22738a5c358bb5
1cb5dc1035ac812ee918ea6c5a37031699fa342333541c16c8a810842c505f45ad661
b15fb11a5bc1cdb95b27c2b4a717a2397a55cc4f642b28881d0fffb264402a290c05c
a53134c72d65bec480f53f7cdf715c50403a26e45ed2ad08388a20e9cbb91b0a70145
308cdc9fa4d00a7e045629897202b255040d13e3180d9b21c255bf04113a6d339fff5
79c68475e516c0c98f625a90f6532a310f13000f420c899fb8de007e8f8ffdb1aa767
4b35ef5f0bd0abcc5ad3653d14f8366bdc30dd2e5c734649511bc119024f6e30446d2
989d04d31f0dad6c9a4b45a6faf22ea24925a5253dfa44df6ab455d95bc2
KE3: 6dc988418a34c9390e353a36d1d8c057df611bf3916f3518073f8b359e70b5e4
c49b9f19a81bd05d7e20b18a9ae00c81ccca7d3b74786d8bc1d01bad740e3cb3
export_key: 16bc303d14e05bf24604563c9a2f01488d05e18c769259b1abfaa8062
bbb13a6407434102c957eac5210ecf1ba52da96001fced8fb3652639db496356fb8d0
4b
session_key: 855f082da610f2720b4b450c47fcae8f7cc0abc7ecbdadb1bbc068f9
91cacd5f18b71a69326d63d039f557ae07861e2470fdad67320b708daa31ea56b1ca0
c7f
~~~
"#,
    r#"
## OPAQUE-3DH Test Vector 3

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
EnvelopeMode: 01
Group: ristretto255
~~~

### Input Values

~~~
server_identity: 626f62
oprf_seed: 8b3809b2c36ebbf960c8bee4a60314b444148390a1001fdd262e17c60c
274f2ae663aaf6afc4beaf32b553209ee87d06a0875f108823ae6b0bf9afebd662ab2
8
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: e3eef0aebbbb975904051f5c0a0dcffe43319935d9f9edadfdb19
a5d62c79a18
masking_nonce: db11182a3bce5d6a32186f6891ce7343263e77860cc152e4191ddd
a2b363ad6c
client_public_key: 2e42be10565b34a1bd16b2b998e55423be4f593567f5191f91
45e612480c8141
server_private_key: be81db28eb1e147561c478a3f84cbf77037f010272fd51abc
ff08ac9537e750b
server_public_key: 5ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3
f459678b0e0d25
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 531d9b97938bdc35315c2b601021403ca593fc2b3e43cb4f29ce3ec
ab2814ba6
client_nonce: f9cf7ab26b874836309cf580c4995bcf03c19bfe9c120939592079e
7d159e4d7
server_keyshare: a6d76012999541f1ec0c014ec1606f2bd2a517e51f731d595469
51d9699e1739
client_keyshare: 2e8a05799d3c524ede0482f39e047df99d9a53dc2dc30e8947eb
5da98b8c4354
server_private_keyshare: 14a08c384d74f6dcaed32bb9448c02865efb17a32b82
c7f06a9586c6e72e4b06
client_private_keyshare: 01229ee057507c3e53534ad9db9f6df6ce515d1b8017
923b65cada1973524d0c
blind_registration: 27fa7b2a6d920c76cf03fb57bdeacc2ec39330fd6e7f9e5db
dfcb571e271a60f
blind_login: a4e7b12d5b712efcac9ba734d54c2b24bff0ef6310404b5c05d60d7c
8451bd0c
oprf_key: c3e68a942b07bda15ecc609f78768751626c5c28bbb17f43c646d0abc0c
4960a
~~~

### Intermediate Values

~~~
auth_key: d7aebfcca8feaca2e65a3d99820910c677642a3e81f011c67a6f8d172cc
683d96aa3714b35f64874cb3ab1b567a7a1ce1ceaa7e08fed72db694ea8d2cbab9216
prk: 60f39e51f146b6562b577558cfdf5a95f7e79494c537aab09ffc9d5b2176d736
53d04c2b3c9b818cd14ab6c57b4a1609b95d230a392a6d69f6aae3c06a8a277f
envelope: 01e3eef0aebbbb975904051f5c0a0dcffe43319935d9f9edadfdb19a5d6
2c79a18fd86023c78e71b2ea7a188e8f6952014af4af37620b733c3369fc344d16052
c27335db2109750121f38393b7a4c0276a2bcccead98db320b238d1f348c92a325
handshake_secret: f4a694a597ed17949721658bc37fa2f5e0e5cefc048ebbcccf6
3f17992e623824de73aa601232e91faca1130bafdf36ea6a1f93f6fa5cb3cc15b7fcd
a7f70d54
handshake_encrypt_key: a95159e4521495baec838a0c9b88b1fce3fa5478dac9d8
7ec62e772d496da4679489488f9130be02e169831604260a87d83ee137b254e9136a8
ce7beea420ea9
server_mac_key: a84089ede1a212885da10380eef33f27ed1c733a1c718f3b9ca43
8a1f7bfbacbc5f4c9ae5dec68719b91696a77b96281d101224a8a969edf5a9d7c6213
0c9bfc
client_mac_key: ccd417bbee27300bc6a27033d9ae479e84452813fb6126997ea47
7a9058ed058ed537470d8bb943934fd3559b5f4387c876c75d6353a6bdf353b76d75c
9d1df5
~~~

### Output Values

~~~
registration_request: fa39a478c220a89929613f9e65c9a4617da96b62509c42b
39d7e3606ed2e8031
registration_response: 7628061169119aa339586502b570ea1675d15f7c01afc0
964fc6e21a8693fb055ab8bfa5e626d2249e0aa9e9546cd2f9e30bb1e6f568334ef3f
459678b0e0d25
registration_upload: 2e42be10565b34a1bd16b2b998e55423be4f593567f5191f
9145e612480c814141a0af9d37a17e65177a04ce2979c3fb85dd3bdee45152011a28c
ac2adc944a9a9941201e8d552f5b6fbe0546cfd250f0def00d3ddb3dc9ec7e4105521
234bd601e3eef0aebbbb975904051f5c0a0dcffe43319935d9f9edadfdb19a5d62c79
a18fd86023c78e71b2ea7a188e8f6952014af4af37620b733c3369fc344d16052c273
35db2109750121f38393b7a4c0276a2bcccead98db320b238d1f348c92a325
KE1: 96f9f35ebc0ca71607fd2cfcd465e285eeeabdec61151b39b2b4fb735538aa0c
f9cf7ab26b874836309cf580c4995bcf03c19bfe9c120939592079e7d159e4d700096
8656c6c6f20626f622e8a05799d3c524ede0482f39e047df99d9a53dc2dc30e8947eb
5da98b8c4354
KE2: 5a71da44c8197b969343524ece08f7a7f566812d558590f6de8245aabc5e1e53
db11182a3bce5d6a32186f6891ce7343263e77860cc152e4191ddda2b363ad6cb659a
69e90279b9893592bcfd8fb686956ef2f8e2150275ea261065e5b4f2aa23921188449
b870498c2ebeffb3e71fde7b0fc02c20a5edc8ca4d3b8d4ea5ceb743f45a983a84895
d0bb42ac82a226cdb5d3c26a7211eeddff3f2f5344c3086564894b0a37d094d563abe
a5e0f9c8d065555ecb5dae9f5ba39cd3c914de2d104a1c531d9b97938bdc35315c2b6
01021403ca593fc2b3e43cb4f29ce3ecab2814ba6a6d76012999541f1ec0c014ec160
6f2bd2a517e51f731d59546951d9699e1739000f81f6eb8b07aa839535cfb6c7e6812
9decabcd853d57cd443450e114d5e16691f7ce0f8377f45d127e8b204754bee651137
a612999ab11903daadfb0adef737f7e0916970c77b8be93e6f575ae7a23b
KE3: eb5df83db1ade393a4d2a318afb0fb5b295cd52a2ad81b36adc0bab03ede6fe1
0c1d62fff89ffec1f89990eb62ddb73882e25044270347f8ac5bf527bc28edb9
export_key: 6b5092258a76247443c455832c44ade23f07029ef0f3f02210a62598c
11fd6eba724db8a81203fdc63bc58e40fa345ad8bbb34093360186a6d494b4c3ee5e5
d0
session_key: 9ff41971a2a72553d51a78f4b06e7808e39b55d94f3526a5a8d806bd
e27d523f4b94f17f159f8e9304ddd5de605f3ad1c822efadcde0d1e5263e03c4956bd
885
~~~
"#,
    r#"
## OPAQUE-3DH Test Vector 4

### Configuration

~~~
OPRF: 0001
Hash: SHA512
MHF: Identity
KDF: HKDF-SHA512
MAC: HMAC-SHA512
Name: 3DH
EnvelopeMode: 01
Group: ristretto255
~~~

### Input Values

~~~
client_identity: 616c696365
server_identity: 626f62
oprf_seed: ccf7f07800ac1fe92f121975df8f853c0d0ee02e7b1ed36f5e8c6d8043
4723ab67e5dcf5e5e0a7f49e6940bf2cea547ae533705264829c82d1ce80da9dafca1
4
credential_identifier: 31323334
password: 436f7272656374486f72736542617474657279537461706c65
envelope_nonce: 7c0c9f9c569e13609c98c368d22f1a67840b810628fb113912cfb
51c4394b65f
masking_nonce: ac587de9dd4b3398a629e0146c973e1a148db7a1b6f795fc2ea4f4
98e6d95f9a
client_public_key: a2cf81ef8192a4b1ea280d2eaadcb2a0104f5379418eac174b
83aa2cb755946b
server_private_key: d49399dc3bc1022938dfb0e79db523d4e4e41f494c3898eac
652bf95f6efa108
server_public_key: fc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce50
017dc037001c63
client_info: 68656c6c6f20626f62
server_info: 6772656574696e677320616c696365
server_nonce: 330f21253d8cfee01f97226c00a7253b48ffca520a76b7049fc5f38
2d72c039b
client_nonce: 8b2c03b323e158936f67ba2fd6806a1b9c84527ee41cd9fc6ee7381
636005c53
server_keyshare: 6a398e50c4e395ee52ef332d6c2c0a77187e2e0b3564617eb66d
2878c41e6c47
client_keyshare: 14b434e33a39d7d9fd6dbe3638925edd7a0344a312a22971754b
d075d8347342
server_private_keyshare: 5f4a55d2e8474fe0ec811b4cca7c0e51a886c4343d83
c4e5228b8739b3e37700
client_private_keyshare: 2928684a1796b559988623c12413cf511d13cb07ecb6
d54be4962fe2b1bd6f08
blind_registration: 89ae863bc6f3e8b59bbd1354548220e81cd0ffb6f9e4ec217
3870ae6107f8d03
blind_login: 07e41ecdb9ef83429e58098b8f30a6b49d414ad5e6073d177a1f0b69
cf537f05
oprf_key: d67188082a017e8c8ec23832f5d28cd3ad53ff8a228c4018bb1aa2e0b80
9ff0a
~~~

### Intermediate Values

~~~
auth_key: 5ec6cdd359979eca8d12f4d0ea01c66c36959709dfaedb455134ca0ef22
221d046d51bab43b9e52395d8965a0a79f130238980ca3fc05bf203a88c5bfa363d51
prk: 580d7681c8252a35a02e90db94775ddf6729b698c58c6002b5df11536dcbbfb6
60d88faf5ce490a611d12be031e36c5bc424f3fc4c14cda2f35b7bc1d5606fd3
envelope: 017c0c9f9c569e13609c98c368d22f1a67840b810628fb113912cfb51c4
394b65f48addcccfbf5d3726e3aaef3dd781020efe1f1f8ac7f8c010d5b5c3d2ba229
ab34034c28d24856627ae05e27a89fed9f84b17466e958cf5e556b7cd558993d82
handshake_secret: aa118857a0b89554bec1ed4478d7bb0983fcdecba2f766f1531
aa4d75f040e44cf99a99fd6f4622def27e6b73b6966187246fac51102a209f7643a34
9c7a2ee6
handshake_encrypt_key: ae7b3d70918a37f2b7471e07c398b78fc18b10a08deb91
bd566ed7bc8bd581725b95dc102ed33c371108285a858ec493e4bb96a323dbc7e0de1
310fc99fd7a77
server_mac_key: d80b33d3d7b975550a276c40438cb59e761c9f963e3cb8539c675
53530a0c1fa716aa9bda5a31b825e8bd5a8eb051ffc0786466e10982cda53c7ba657a
849f47
client_mac_key: af48cc7296caec42dd24cbc8f8673543a2017a873bb6cf7a982a8
77b4c2d1652d86231905f0c1e05b01abdcceaa01aaf0c89d31cd1a7a21bb4329c9021
7cd0d6
~~~

### Output Values

~~~
registration_request: 307ff12c023cb5ce33a04efd497252442fa899505732b4c
322b02d1e7a655f21
registration_response: 141f23c19ab2df260cb4cb44cfcd3c28ed131e573c39db
cb1df6efc0df340c48fc5638262d8f6ba5848b70dbe22394d6c346edcd2f889cce500
17dc037001c63
registration_upload: a2cf81ef8192a4b1ea280d2eaadcb2a0104f5379418eac17
4b83aa2cb755946bf143c9385cdabef03507e630fd886a96ed479110b89504eb88c45
d6a52491e4d51856bcc6a9bdf7bacab59f0acb78759ead9c480bf81221c152f5e7fa4
ea6682017c0c9f9c569e13609c98c368d22f1a67840b810628fb113912cfb51c4394b
65f48addcccfbf5d3726e3aaef3dd781020efe1f1f8ac7f8c010d5b5c3d2ba229ab34
034c28d24856627ae05e27a89fed9f84b17466e958cf5e556b7cd558993d82
KE1: e6fb9b013986abe5f6e9586a0110395a97ad695dde622d58470adb0a0cdcb37e
8b2c03b323e158936f67ba2fd6806a1b9c84527ee41cd9fc6ee7381636005c5300096
8656c6c6f20626f6214b434e33a39d7d9fd6dbe3638925edd7a0344a312a22971754b
d075d8347342
KE2: 3a0b7e0cc575659d23fd7f5300e350c73bafd377b3668f44dc3c4601424ba92a
ac587de9dd4b3398a629e0146c973e1a148db7a1b6f795fc2ea4f498e6d95f9a41de1
d966cb8326a9281ae011811f797d41476896306c1ec1896d2c4e44cc71eb48f0b396b
26e8fa862044c72598b02c41ce8a54b9581ba3a13d09b72e253d8176fb71b73d723b7
12bceb6eff2609de0ed4b916a6e6e0120db251efb3b9b17946fae70e7b1148940d701
db35dba25f42efe1c3d6ee4df23877019f29bec78723aa330f21253d8cfee01f97226
c00a7253b48ffca520a76b7049fc5f382d72c039b6a398e50c4e395ee52ef332d6c2c
0a77187e2e0b3564617eb66d2878c41e6c47000f8a9cd415e4b55e4fd1a7dc6a57ace
cd8f3ea1ea68ecc355edb1a94d21347ddf95641a2140598bb7d4be9361cc10049356f
14fa45cf8b95b5fc7fcc75ed97e7093c05a0e2dfe3ebb400eb4520a80cb5
KE3: 9bec04bf5d56d031ef57a3b5df42ffdc337ddbb036035a765f4b1368efd213c9
824916239de04bd2575e4c77391791ba3b4f391fce60e895c377ce495d1d8c50
export_key: 34aa2ee55f88757f0dabc3a6c37b75c153203afe5e9c35bff89ec565a
9e7c5caf7cb8996aa648f931bf7b3ced8c2ebacacbc4f4b278403e794ba880f833abd
fb
session_key: d9fbcc6aca11cf7990dccdc178d05c0d1fb19eadadc353ee3bb80906
c6bda530a6b25e4a97b57e0cf897f337e5db17ccf42cdf94f2b958ad2c5d39a49428f
be9
~~~
"#,
];

macro_rules! parse {
    ( $v:ident, $s:expr ) => {
        match decode(&$v, $s) {
            Some(x) => x,
            None => vec![],
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
        if line.contains(":") {
            if json.len() > 0 {
                // Adding closing quote for previous line, comma, and newline
                json.push("\",\n".to_string());
            }

            let mut iter = line.split(":");
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
            match (
                parameters.client_private_key,
                parse_identifiers(parameters.client_identity, parameters.server_identity),
            ) {
                (None, None) => ClientRegistrationFinishParameters::Default,
                (None, Some(ids)) => ClientRegistrationFinishParameters::WithIdentifiers(ids),
                (Some(client_s_sk), Some(ids)) => {
                    ClientRegistrationFinishParameters::WithPrivateKeyAndIdentifiers(
                        client_s_sk,
                        ids,
                    )
                }
                (Some(client_s_sk), None) => {
                    ClientRegistrationFinishParameters::WithPrivateKey(client_s_sk)
                }
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
            ClientLoginStartParameters::WithInfo(parameters.client_info),
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
            ]
            .concat(),
        )?;
        let password_file_bytes = get_password_file_bytes(&parameters)?;

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
            Some(ServerRegistration::deserialize(&password_file_bytes[..]).unwrap()),
            CredentialRequest::<Ristretto255Sha512NoSlowHash>::deserialize(&parameters.KE1[..])
                .unwrap(),
            &parameters.credential_identifier,
            match parse_identifiers(parameters.client_identity, parameters.server_identity) {
                None => ServerLoginStartParameters::WithInfo(parameters.server_info.to_vec()),
                Some(ids) => ServerLoginStartParameters::WithInfoAndIdentifiers(
                    parameters.server_info.to_vec(),
                    ids,
                ),
            },
        )?;
        assert_eq!(
            hex::encode(&parameters.client_info),
            hex::encode(server_login_start_result.plain_info),
        );
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
            ClientLoginStartParameters::WithInfo(parameters.client_info),
        )?;

        let client_login_finish_result = client_login_start_result.state.finish(
            CredentialResponse::<Ristretto255Sha512NoSlowHash>::deserialize(&parameters.KE2[..])?,
            match parse_identifiers(parameters.client_identity, parameters.server_identity) {
                None => ClientLoginFinishParameters::Default,
                Some(ids) => ClientLoginFinishParameters::WithIdentifiers(ids),
            },
        )?;

        assert_eq!(
            hex::encode(&parameters.server_info),
            hex::encode(&client_login_finish_result.confidential_info)
        );
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
            ]
            .concat(),
        )?;
        let password_file_bytes = get_password_file_bytes(&parameters)?;

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
            Some(ServerRegistration::deserialize(&password_file_bytes[..]).unwrap()),
            CredentialRequest::<Ristretto255Sha512NoSlowHash>::deserialize(&parameters.KE1[..])
                .unwrap(),
            &parameters.credential_identifier,
            match parse_identifiers(parameters.client_identity, parameters.server_identity) {
                None => ServerLoginStartParameters::WithInfo(parameters.server_info.to_vec()),
                Some(ids) => ServerLoginStartParameters::WithInfoAndIdentifiers(
                    parameters.server_info.to_vec(),
                    ids,
                ),
            },
        )?;

        let server_login_result = server_login_start_result
            .state
            .finish(CredentialFinalization::deserialize(&parameters.KE3[..])?)?;

        assert_eq!(
            hex::encode(parameters.session_key),
            hex::encode(server_login_result.session_key)
        );
    }
    Ok(())
}

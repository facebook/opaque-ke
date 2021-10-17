// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! The OPAQUE test vectors taken from:
//! https://github.com/cfrg/draft-irtf-cfrg-opaque/blob/master/draft-irtf-cfrg-opaque.md

pub(crate) static VECTORS: &str = r#"
## Real Test Vectors {#real-vectors}

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
client_public_key: 3ea81ee30a44d65ca6db8f42a9c125277898ead7fe1604da98
70ad4542044a56
auth_key: 7816871e2ab2d039dc0d8a07ce94081dfd975de003ea1b7ff2b120cc74c
f18c32e11d2ed730fae9040f87be5c11cfc90cdf3393557c47065d7127ece8ca2b09c
randomized_pwd: c9c8c47dece13aed16b80ca049cedc86e984177d98b549ba40390
eb77981f954537e743ca3ec854fce472981714aadb3a280f4b2c15040d97653c64b7e
5c265e
envelope: 71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c46
76775eca8b48680e4973b26f754fbe0865af5135b284b00afce879c285db39b2ef0a9
c1bd2f847c3f2139556b34885691be2d1917be4de9d2f50ef198950964142256
handshake_secret: 706bae252489cd38228083790e3ead93f6b5b41682468741508
124a58185fbb5fc2ee23850dd5285095d6e18dd133f16ecda7e35837429efdf71455e
a6642cf6
server_mac_key: b63f98de411d2b008abaee6699ed14fa2834986f9fc2f9ae59af2
292fe8aa5e125d0ab0d5e5954cb8de5966da7994d798c800062c17fc167c598aa0d86
071685
client_mac_key: 187335e3edd777cb419d055e54001325cb19ebac8d43cf736f101
127bb19c932717960b2401699b0d5029cd3637a3175248048f1eba202eada9428b475
f2867a
oprf_key: 3f76113135e6ca7e51ac5bb3e8774eb84709ad36b8907ec8f7bc3537828
71906
~~~

#### Output Values

~~~
registration_request: 76cc85628d5ac0e01de4ede72479d607490e7f58b94578d
b7a0606d74bc58b03
registration_response: 583fd26fd3130386b1a1a970e4617d45dc21c7a6f07052
8f0175985570b4ea2018d5035fd0a9c1d6412226df037125901a43f4dff660c0549d4
02f672bcc0933
registration_upload: 3ea81ee30a44d65ca6db8f42a9c125277898ead7fe1604da
9870ad4542044a56dde0af371300d8b13f4dc7039ae643560c279c0e67be6086bfbe2
188a65480689c9044a36b844b3f137a1fb594caff5e79002232a877aba39da085ce62
e1a59f71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c467677
5eca8b48680e4973b26f754fbe0865af5135b284b00afce879c285db39b2ef0a9c1bd
2f847c3f2139556b34885691be2d1917be4de9d2f50ef198950964142256
KE1: e47c1c5e5eed1910a1cbb6420c5edf26ea3c099aaaedcb03599fc311a724d84f
804133133e7ee6836c8515752e24bb44d323fef4ead34cde967798f2e9784f69f6792
6bd036c5dc4971816b9376e9f64737f361ef8269c18f69f1ab555e96d4a
KE2: b01355438b21dc20aaa46a5dea61d5b60f81b81f347f80e8ee3addc12f62be05
54f9341ca183700f6b6acf28dbfe4a86afad788805de49f2d680ab86ff39ed7f98431
127a277d18a821887ef0e23d92d73000161f14a3437d5fa6e028e4b33edad12212183
73ef515b13f023d4a17ed5f62201416b4ae07f56605093eda407390f83457ce80c4ad
48e25a7875deacb41fa9ee9c3fb9895407733ef147a97fb0eee9b47abd930777b6599
1c53b126f9f5aae3307a111a85107fe2229f93db8fe0f9c5ec75a8cd571370add249e
99cb8a8c43f6ef05610ac6e354642bf4fedbf696e77d4749eb304c4d74be9457c5975
46bc22aed699225499910fc913b3e907125ff3ab1b935c6740b10dd4441074507761b
1d955aba1296ba52061dfec49c5e003bf84a354d30f2a1f00fb320256002b781da075
e838cc535ece42b26d6043af
KE3: 19624915863ad577d4c6c15d56207fe0dfd96a8ec489b4bc25a7b79cc33c1d75
717c0ba4db2cc5bb95d275ba5a5bcd39ad17459fb162d83455658acd20a4b4e4
export_key: 252cfa49d8fd722663fe16ef7451d8cc25345f05f4967859e7500763f
42b18b036fb1c4e7f0ad0110c71fb87f80da9ab53724976c4f8fa368d1c4cb6b9c6cd
e4
session_key: f31b89ce77171a51e6da037ad77f634184406844057f7875f04c7c4d
e08aa26d2f3bf9ab78e1e8a5faa6f625b12008d98da5e00d8aa36f9e097890337ac9c
005
~~~

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
client_public_key: 003e4b5cd9124a026302a223cd2187fb62285d33d987155c4a
3307aa55f60c5e
auth_key: c34629e50ddce1db7aa01edb9cf6979890c40f0e55d8abfc388dae762a6
5300955344d1e273be49a1a513dbadeb045163b8882809f885dd46e978797484da85b
randomized_pwd: 2d0285e5872af71e6b6f3e76e1605de56ee229d1436563988aab1
13b2f8104a7a14377b71158451988bb4ec11a235fbac2063dad136cffd0b1f76019d4
123199
envelope: d0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf274782
9b2d2d20f701d2571da6f0fe29687724db96371b552df07e06c6cf3a2534147161ba4
5e543a6d4a15eda6af8ec5aab229abbaac2af81b48c1737a419a524bb618a48d
handshake_secret: b7cab8367758393c3a7c72b38accaa91e164d77be82d4c01364
0b8d2d6e1750f5ce1b77dcaf4173d07deeefc67895ad2d9ae6c6be8bdb384a9f54c7d
946ad85e
server_mac_key: aa959f4338f440f08dbaee86a576aae1ba65ee348f51e339feeda
8ce93ab0673904c1bb3de591689613f489705de68ae9e96146b0f54c7e0333fa50855
587fd5
client_mac_key: 3a3ca98df30379ac1cf59f3508b3daa60ea644c28f1e9de5a4911
f641514db7df1f46ec850ed2f9a2053f5a7cccd77f0a9b14e0e7c570319b8080c4484
cecf74
oprf_key: 531b0c7b0a3f90060c28d3d96ef5fecf56e25b8e4bf71c14bc770804c3f
b4507
~~~

#### Output Values

~~~
registration_request: ec2927a03ced1220168b6d5a54f0372f813ced8ad3673d5
1dee92d2cbfee500c
registration_response: 588b259785af29c162958ebfdc4ca3b1fcf46bd1894c81
854db7d2d41bf1933c8aa90cb321a38759fc253c444f317782962ca18d33101eab2c8
cda04405a181f
registration_upload: 003e4b5cd9124a026302a223cd2187fb62285d33d987155c
4a3307aa55f60c5e3114123a82551b4851bbc26b4a6a25444a60c501bb3e8eae95f2a
eae7971f1358c5fe0cfa3cbf7f493be05418740bc884c1a20ad220c43ea30a7af1e92
3e81b7d0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf2747829b2d
2d20f701d2571da6f0fe29687724db96371b552df07e06c6cf3a2534147161ba45e54
3a6d4a15eda6af8ec5aab229abbaac2af81b48c1737a419a524bb618a48d
KE1: d0a498e621d3ff7a011b37166a63ef40fe268f93c7d75a467eea42a98c0a490d
a6bcd29b5aecc3507fc1f8f7631af3d2f5105155222e48099e5e6085d8c1187a642e7
eecf19b804a62817486663d6c6c239396f709b663a4350cda67d025687a
KE2: 6810ba4cf3049dab416529542385d194eddf0105ad6480ea0c92f872cab6af46
30635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853b5def228c854aa9f
c9066d61f2a64d5890ed79ff8e4a200444dc2e180ae57d6e78bdb594722d57283a3ff
9a6600f61341f9ad49c32be9054ad8a26837d8ccea6de753520b1eb836c85faa907a4
428828fb5ad362ff1b5327afdd1d1c300e03db05f9d55c1535bac50d76b4e5f19dcd7
0ee043d2254ffcae31bffaf426f0b862f5fd311649723fa57f7ef652185f89114109f
5a61cc8c9216fdd7398246bb7a0c20e2fbca2d8ae070cdffe5bb4b1c373e71be8e7d8
f356ee5de37881533f10397bcd84d35445a04e7e9047091f5b371582b6f7eb8f8f665
6f800f2ad2491122a28fb5623987c28cd9d8fae45e0ab205cff7635c83fe993a83b0f
b2c1c85e599f0a33bd65a7ef
KE3: 37de6eb166462dd8d36a6f0c75bbe826856cf6f7f067935aaf5fddaeb6e56935
e8f1b53af96d5194dd49cb2438801745597affd3af7508f260746573d42144bd
export_key: cb43c5c131fc4ee3c72a9c5a664a0137d46088c58cf24de4408e838d8
1b743f6e1b9516cdc307775c45d3c70d3a446180782cb4a7dea4be5777b1934a78c11
e1
session_key: a40fa034f8220e18c1991f981655e8255009d62a596a579f08fd476a
08cca7d66189a19e68f180e520de10ee841ab4e4f1a61291468429f093776f0bc8663
528
~~~

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
client_public_key: 03c84a1dc96d2b896f20b390e75ae7e5ebedbb4db6c6cc9a78
96e3c5d5f280e7ab
auth_key: 9a6ce467dca8841cb0f706bfd83f39cc8e855d000d982554af799acc33d
8354e
randomized_pwd: d8a0060fa0d6118cf89fe9df92a9b65dd1b0dd86cccbdee067926
7dce6f50e3a
envelope: 2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1acacc4
a8319bb19ce6d364d86bd95a1516a49e288e0e013a197609e1de0b4e9e5950ade9c13
handshake_secret: 3f11e9bb0233a88d5c00f236485058ebcbfd24180d0b8f7f078
e8b88fa8a1c04
server_mac_key: 7d82030842afc175e1a0fbddceba0e0e53102bf170ee394419d2b
fdefefda358
client_mac_key: a605eb6d2e72308f29fc1d1709a683aaa5d09e775134bded0deae
e17dccaa9a1
oprf_key: d153d662a1e7dd4383837aa7125685d2be6f8041472ecbfd610e46952a6
a24f1
~~~

#### Output Values

~~~
registration_request: 0325768a660df0c15f6f2a1dcbb7efd4f1c92702401edf3
e2f0742c8dce85d5fa8
registration_response: 03de5c8f7d8ea7fd9590b0c8321b5f508bb8f49bbff83c
5449ef50d66bf3e93892025b95a6add1f2f3d038811b5ad3494bed73b1e2500d8dade
c592d88406e25c2f2
registration_upload: 03c84a1dc96d2b896f20b390e75ae7e5ebedbb4db6c6cc9a
7896e3c5d5f280e7aba453596f5b719f2cf3c0982ebd2466a8442f3a98d9dcfe420b3
5acb7cd8d0e592527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1aca
cc4a8319bb19ce6d364d86bd95a1516a49e288e0e013a197609e1de0b4e9e5950ade9
c13
KE1: 03884e56429f1ee53559f2e244392eb8f994fd46c8fd9ffdd24ac5a7af963a66
3b967fcded96ed46986e60fcbdf985232639f537377ca3fcf07ad489956b2e9019033
58b4eae039953116889466bfddeb40168e39ed83809fd5f0d5f2de9c5234398
KE2: 0225dbce19cf48eb908d66d0e955d0fe7d0f67d09bb0362154c7316d69700e23
29cb792f3657240ce5296dd5633e7333531009c11ee6ab46b6111f156d96a160b268f
4a82c2b61a752672a3e322b6b8580c1a2c76fad4563d06c12a27146f73dbb5267ca8b
b86a83d0b902b97ac14d12501697300815c5d5fdc262830a351bb4416baceb16938e6
cfd021f43dee80b9bc400304a4398480e195bc51b3bcc186ff0bf8018e88ecfc53891
529278c47239f8fe6f1be88972721898ef81cc0a76a0b5500242bc29993976185dacf
6be815cbfa923aac80fad8b7f020c9d4f18e0b6867a17c4af032f0221800fec352a2b
ec9ddb2dd8b91a087aa51c7fbbaf5efcbbea52fe
KE3: eb86a68c5e8812293d1da4a60e499236ffdffb34b29f6f8f0ac46979f07b1ef4
export_key: b755602f5d0a8c2118f38608a98cf08f20adadf5ef759cea8e246e5ed
5bf95c3
session_key: 08b539a036c888da87a25205c9c386f382bc53b098dae42f88f2320c
48f1a3dd
~~~

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
client_public_key: 03a12f7047c8a1774a745520b2eaac995687fbb6212a418f9c
1696d4186278eaa3
auth_key: 2461460e02dde8a10c98e2911d4d5a3be0bd85f095064ade2f3a0ae79a4
89b07
randomized_pwd: 3d990218aab34ca0137bbbb298adcf585d4495ae843eddcbe3ca8
f969b690676
envelope: 75c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b842e44
26e423d452786ba80be94bd8ebe643394d1a07e745a07e97b37a88b585b8afd6ce3cb
handshake_secret: 586e927091452c797e0eb69fc90840f4c1923a6852834644c5f
47cc8b5810d55
server_mac_key: 09f90fb15227c185ba6102b797251d32f6bfaec56b218743ba4bb
c64696f9734
client_mac_key: 7612361b97d074852344ee92ecfe154b93241e696808438745d4c
b4f5b8513fb
oprf_key: f14e1fc34ba1218bfd3f7373f036889bf4f35a8fbc9e8c9c07ccf2d2388
79d9c
~~~

#### Output Values

~~~
registration_request: 02792b0f4670aced5970a68b01bb951004ccad962159be4
b6783170c9ad68f6052
registration_response: 02101f7b9999e363b44dfa946eaad9930fda88d53632aa
701778747b6a411a071c029a2c6097fbbcf3457fe3ff7d4ef8e89dab585a67dfed090
5c9f104d909138bae
registration_upload: 03a12f7047c8a1774a745520b2eaac995687fbb6212a418f
9c1696d4186278eaa37b6e2a7531d9ca9a324ac5c1a02303f00175c41646a873441a5
eb69dcbec4ea975c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b842
e4426e423d452786ba80be94bd8ebe643394d1a07e745a07e97b37a88b585b8afd6ce
3cb
KE1: 02fe96fc48d9fc921edd8e92ada581cbcc2a65e30962d0002ea5242f5baf627f
f646498f95ec7986f0602019b3fbb646db87a2fdbc12176d4f7ab74fa5fadace6002a
9f857ad3eabe09047049e8b8cee72feea2acb7fc487777c0b22d3add6a0e0c0
KE2: 03463f69fc22bfa666c55bd38319addcf5816f063ec5ae9fdeb7e572603c6698
025947586f69259e0708bdfab794f689eec14c7deb7edde68c81645156cf278f219cb
3882d08a0617909c1a9f545dace3d56b5034d8025220e0280d5d541eb22ade140fa11
663bd0a4c787203b93e423f431b3702ffcc635919dcf0d22520d90596fccdef52f3ca
c75d2804a96d1521b78205c47c998cdb4aafcb7cce4c174671423581ac468101aee52
8cc6b69daac7a90de8837d49708e76310767cbe4af18594d022aa8746ab4329d59129
6652d44f6dfb04470103311bacd7ad51060ef5abac41ba38a2e46ce2cfd59c6dfdd1e
77758505d944b28e753a7254bac79302947dc7d0
KE3: 2ae94c682a2bc4c89eb16c395dc09d2b14d216dee0e59f34c317f5a6d8bbc717
export_key: 04f3100265180b083abbd84109f5ed963481eb78a5d377e888810217f
fb8af04
session_key: 7a0a42051497621e659270552be01baadddd1ee829f802891535a3fb
ac2a33ec
~~~

## Fake Test Vectors {#fake-vectors}

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
KE2: 02648d7558231b92265efe08ec0b3dec70e596e36ea6c70ceae961411bf8f328
7cb33db5ba8082e4f4bfb830e8e3f525b0ddcb70469b34224758d725ce53ac76094c0
aa800d9a0884392e4efbc0479e3cb84a38c9ead879f1ff755ad762c06812b9858f82c
9722acc61b8eb1d156bc994839bf9ed8a760615258d23e0f94fa2cffadc655ed0d6ff
6914066427366019d4e6989b65d13e38e8edc5ae6f82aa1b6a46bfe6ca0256c64d0cf
db50a3eb7676e1d212e155e152e3bbc9d1fae3c679aacae1f4fee4ee4ba509fda550e
a0421a85762305b1db20e37f4539b2327d37b805e5c0ac2904c7d9bf38f99e0050594
e484b4d8ded8038ef6e0c141a985fa6b35afc0c330be0512ba1eace7c1cae0b807f01
6f2a67b604008b270f3e41a8fb3d54084b62510495baa0309a993a48cf2110cfe2555
33047291134a010c13509ba1
~~~

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
KE2: 02ed3cb4182cb2c2659d6c1d88014e821ea4fc00de1aca987fae5483f5f8aa59
d021cd364318a92b2afbfccea5d80d337f07defe40d92673a52f3844058f5d949a604
39294e7567fc29643e0d5c8799d0dffbbfc8609558b982012fa90aef2ce52b1ffdd8f
96bda49f5306ae346cd745812d3a953ff94712e4ed0acc67c99b432860e337fe3234b
ba88415ac55368b938106cca4049b5c13496fe167d3a092bd990e2b772c1eb569cc2b
57741bf3be630e377c8245b11d0b6ad1fe1d606490c2720802a59205c836a2ab86e19
dbd9a417818052179e9a5c99221e2d1d8a780dfe4734dc9b9b3f64e5b3572a8f05f68
93b0fa4dd12fba85ea99c8760b8011321bc37263
~~~
"#;

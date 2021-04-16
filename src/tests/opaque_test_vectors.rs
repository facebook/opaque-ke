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
    pub client_public_key: Vec<u8>,
    pub client_private_key: Vec<u8>,
    pub client_keyshare: Vec<u8>,
    pub client_private_keyshare: Vec<u8>,
    pub server_public_key: Vec<u8>,
    pub server_private_key: Vec<u8>,
    pub server_keyshare: Vec<u8>,
    pub server_private_keyshare: Vec<u8>,
    pub client_identity: Vec<u8>,
    pub server_identity: Vec<u8>,
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
static TEST_VECTORS: &[&str] = &[r#"
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
"#];

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
        client_public_key: parse!(values, "client_public_key"),
        client_private_key: parse!(values, "client_private_key"),
        client_keyshare: parse!(values, "client_keyshare"),
        client_private_keyshare: parse!(values, "client_private_keyshare"),
        server_public_key: parse!(values, "server_public_key"),
        server_private_key: parse!(values, "server_private_key"),
        server_keyshare: parse!(values, "server_keyshare"),
        server_private_keyshare: parse!(values, "server_private_keyshare"),
        client_identity: parse!(values, "client_identity"),
        server_identity: parse!(values, "server_identity"),
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
        ClientRegistrationFinishParameters::WithIdentifiers( // FIXME for when client_identity and server_identity are unfilled
                    parameters.client_identity,
                    parameters.server_identity,
                )
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
    ServerLoginStartParameters::WithInfoAndIdentifiers(
            parameters.server_info.to_vec(),
            parameters.client_identity,
            parameters.server_identity,
                )
            ,
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
                ClientLoginFinishParameters::WithIdentifiers(
                    parameters.client_identity,
                    parameters.server_identity,
                ),
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
                ServerLoginStartParameters::WithInfoAndIdentifiers(
                    parameters.server_info.to_vec(),
                    parameters.client_identity,
                    parameters.server_identity,
                ),
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

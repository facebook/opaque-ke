// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite, errors::*, key_exchange::tripledh::TripleDH, keypair::Key, opaque::*,
    slow_hash::NoOpHash, tests::mock_rng::CycleRng, *,
};
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use rand_core::OsRng;
use serde_json::Value;
use std::convert::TryFrom;

// Tests
// =====

struct Ristretto255Sha512NoSlowHash;
impl CipherSuite for Ristretto255Sha512NoSlowHash {
    type Group = RistrettoPoint;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha512;
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
    pub client_identifier: Vec<u8>,
    pub server_identifier: Vec<u8>,
    pub password: Vec<u8>,
    pub blinding_factor_registration: Vec<u8>,
    pub oprf_key: Vec<u8>,
    pub envelope_nonce: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub server_nonce: Vec<u8>,
    pub info1: Vec<u8>,
    pub info2: Vec<u8>,
    pub registration_request: Vec<u8>,
    pub registration_response: Vec<u8>,
    pub registration_upload: Vec<u8>,
    pub credential_request: Vec<u8>,
    pub blinding_factor_login: Vec<u8>,
    pub credential_response: Vec<u8>,
    pub credential_finalization: Vec<u8>,
    pub password_file: Vec<u8>,
    pub export_key: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

static TEST_VECTOR: &str = r#"
{
    "auth_key": "5da3dcc6721e638fa4eef769f7af5bd30f7132308d41fff00f0cf9745e9090235f75697a0dc58fe8692204c4702a20db4a6ee59119fe6ab4173322f06b896309",
    "blinding_factor_login": "ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e3263503",
    "blinding_factor_registration": "c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03",
    "client_e_pk": "645a5d8c715454a2ba77918d44234d9cbbd723d03113b68c9ea076ab4e776067",
    "client_e_sk": "9be30157b01e572d9ee296defd7bd2f98fed15fbbf3cbed847547d6759c73c08",
    "client_identifier": "0aa0f9643e2ecaf3075201e9e762371d1b5cdfac674494b2d5ed0b0908c46e5b",
    "client_nonce": "a9f275415d9bee6b86c2c390b7577c7684d70479c7e23bfbc01652a7464fb1cc",
    "client_s_pk": "0aa0f9643e2ecaf3075201e9e762371d1b5cdfac674494b2d5ed0b0908c46e5b",
    "client_s_sk": "8772da7da9af3fcdae2a23cf8a34a49954a56b48ae2f866b71113132664f0e09",
    "credential_finalization": "b8de4c989e5caefb57f5a506fd469c4e329aa3076d17a8c8648266c2c2db6f4c33be2161c11c63b7039459de0f9f7f9c5b6a429e6002ac03516ba3979fc970f7",
    "credential_request": "b68e0e356f8490fa9c3bed952e16cc02db21eda686b3c484f3d9d912caa41f76a9f275415d9bee6b86c2c390b7577c7684d70479c7e23bfbc01652a7464fb1cc000968656c6c6f20626f62645a5d8c715454a2ba77918d44234d9cbbd723d03113b68c9ea076ab4e776067",
    "credential_response": "e83812f06568d57b8cdfdcc90fe91454e21bd25dd2a1c32dd1599a2e4a4b6c35002008a499182bb67b86190e2d8315ca1ae4a6cdd503db50bed3d90cc7670dcb9f2b0090f17bbbfeaf88def8713679002f4825d936a5347afdf4d020a99167843056d60022147e90c0c40a3652bdef905ab2f61386a4119a121f3411c1da6463ac5d0c633c6e6eaf0eb0d45ab8afb746ccd00a1e96cbb2eca09cdc61520772b32978470dcdb0f8aaec7016681d431f194a447bea2c0be84c7191837e362f0f69b7f29676e15d0351c529e997a215d410ef6f387a2f1e708729d2316bf27b75138fb440020c1fcdbcae720a4acd4a44602024a9d6f2d536baf230f8301c9f9ff5113e229549fd05000f3b629da91fc6405e82b16c18ae4be1ff00020b37dfa8dbd7eeea4bef1c678693b2f1e2da0370e6792f5ab860fad7a098f0d5d00d4d4205aae4d70887fb28edc16f5f1268aa021dba8810909cb2f9e6",
    "envU": "0090f17bbbfeaf88def8713679002f4825d936a5347afdf4d020a99167843056d60022147e90c0c40a3652bdef905ab2f61386a4119a121f3411c1da6463ac5d0c633c6e6eaf0eb0d45ab8afb746ccd00a1e96cbb2eca09cdc61520772b32978470dcdb0f8aaec7016681d431f194a447bea2c0be84c7191837e362f0f69b7f29676e15d03",
    "envelope_nonce": "90f17bbbfeaf88def8713679002f4825d936a5347afdf4d020a99167843056d6",
    "export_key": "453f61eae9b840519eb025d2297eb31ad13c960deba40c2799d2cd4b5034161e1c13695877b460643386ed5e41d5ec9bf2bc845592469fab50abf77d4812fcf0",
    "handshake_secret": "67b75ff7291d68e20bdbc6a15209aba0c61b7b690d69f293db3761ad62f6014476daeb8ce1235e2d29404bdba3b843dbd544250751e51af747010bb25c310fd5",
    "info1": "68656c6c6f20626f62",
    "info2": "6772656574696e677320616c696365",
    "ke2": "44feeac8078ca91e22ac0133fe33890207c3d927ace293fffa66296c74e82e09ffb1ac00f76198e0ebe74eab722ac49173bdee616f32b3a7416ddee1d8075d54",
    "km2": "0d5b3bd8e1f6b937570b501d5647cb061276bba36cfc3213205c36d2240e8fe55f2338108f52947fd589ce344ce0a677ddb178c881deb4d075874ade133b99c7",
    "km3": "8ed3a633ad925fedcf19f9f4acca15f8bfbd147ba11e0950a2ae6c3efb6e41aef75faa20ae0f9104801bdb8a4edbd23a5cc19fe626a00c50e4718d8dedb180fd",
    "oprf_key": "5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b",
    "password": "436f7272656374486f72736542617474657279537461706c65",
    "pseudorandom_pad": "145e17b21e779ffd82223e70913999b20088ceb7747cbfee5c0f12bd6c3e05736067",
    "registration_request": "241b621c417c0705b5ea7a8b7cdd5039fd61e6b63effe2a44418164c4d49003e",
    "registration_response": "1867301bcc67bdf8e640b7d6edcbe2a65488446417b50d30cdba66ccb379e572002008a499182bb67b86190e2d8315ca1ae4a6cdd503db50bed3d90cc7670dcb9f2b",
    "registration_upload": "00200aa0f9643e2ecaf3075201e9e762371d1b5cdfac674494b2d5ed0b0908c46e5b0090f17bbbfeaf88def8713679002f4825d936a5347afdf4d020a99167843056d60022147e90c0c40a3652bdef905ab2f61386a4119a121f3411c1da6463ac5d0c633c6e6eaf0eb0d45ab8afb746ccd00a1e96cbb2eca09cdc61520772b32978470dcdb0f8aaec7016681d431f194a447bea2c0be84c7191837e362f0f69b7f29676e15d03",
    "rwdU": "17eacc90e168aafd6cf5cbf4aba71e6c08d16800e4880a3fcc5252a1b5072ab7253942f3b4da8a2132863730970ca7a737b5bec96e038a8fa2915b4eeb678180",
    "server_e_pk": "bcae720a4acd4a44602024a9d6f2d536baf230f8301c9f9ff5113e229549fd05",
    "server_e_sk": "c02a638f90e8a9fd25b69252ec7465b7dd33aa905ba947c013b6e6be6edf3909",
    "server_identifier": "08a499182bb67b86190e2d8315ca1ae4a6cdd503db50bed3d90cc7670dcb9f2b",
    "server_nonce": "51c529e997a215d410ef6f387a2f1e708729d2316bf27b75138fb440020c1fcd",
    "server_s_pk": "08a499182bb67b86190e2d8315ca1ae4a6cdd503db50bed3d90cc7670dcb9f2b",
    "server_s_sk": "852b5300434b5f39f7885ee812255747793e04846b910cf9ae80a5a904bd3a03",
    "shared_secret": "d0336451e8de1df9a648772c86f97a1b9ed860297f0fafa13faa4e23bb44b9355ec196a25ba39e7db5b9102a06fa09ca778b10aee5acb11f4eb5826b1370e98c",
    "password_file": "5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b0aa0f9643e2ecaf3075201e9e762371d1b5cdfac674494b2d5ed0b0908c46e5b0090f17bbbfeaf88def8713679002f4825d936a5347afdf4d020a99167843056d60022147e90c0c40a3652bdef905ab2f61386a4119a121f3411c1da6463ac5d0c633c6e6eaf0eb0d45ab8afb746ccd00a1e96cbb2eca09cdc61520772b32978470dcdb0f8aaec7016681d431f194a447bea2c0be84c7191837e362f0f69b7f29676e15d03"
}
"#;

fn decode(values: &Value, key: &str) -> Option<Vec<u8>> {
    values[key]
        .as_str()
        .and_then(|s| hex::decode(&s.to_string()).ok())
}

macro_rules! parse {
    ( $v:ident, $s:expr ) => {
        match decode(&$v, $s) {
            Some(x) => x,
            None => vec![],
        }
    };
}

fn populate_test_vectors(values: &Value) -> TestVectorParameters {
    TestVectorParameters {
        client_s_pk: parse!(values, "client_s_pk"),
        client_s_sk: parse!(values, "client_s_sk"),
        client_e_pk: parse!(values, "client_e_pk"),
        client_e_sk: parse!(values, "client_e_sk"),
        server_s_pk: parse!(values, "server_s_pk"),
        server_s_sk: parse!(values, "server_s_sk"),
        server_e_pk: parse!(values, "server_e_pk"),
        server_e_sk: parse!(values, "server_e_sk"),
        client_identifier: parse!(values, "client_identifier"),
        server_identifier: parse!(values, "server_identifier"),
        password: parse!(values, "password"),
        blinding_factor_registration: parse!(values, "blinding_factor_registration"),
        oprf_key: parse!(values, "oprf_key"),
        envelope_nonce: parse!(values, "envelope_nonce"),
        client_nonce: parse!(values, "client_nonce"),
        server_nonce: parse!(values, "server_nonce"),
        info1: parse!(values, "info1"),
        info2: parse!(values, "info2"),
        registration_request: parse!(values, "registration_request"),
        registration_response: parse!(values, "registration_response"),
        registration_upload: parse!(values, "registration_upload"),
        credential_request: parse!(values, "credential_request"),
        credential_response: parse!(values, "credential_response"),
        credential_finalization: parse!(values, "credential_finalization"),
        blinding_factor_login: parse!(values, "blinding_factor_login"),
        password_file: parse!(values, "password_file"),
        export_key: parse!(values, "export_key"),
        shared_secret: parse!(values, "shared_secret"),
    }
}

#[test]
fn test_registration_request() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut rng = CycleRng::new(parameters.blinding_factor_registration.to_vec());
    let client_registration_start_result =
        ClientRegistration::<Ristretto255Sha512NoSlowHash>::start(&mut rng, &parameters.password)?;
    assert_eq!(
        hex::encode(&parameters.registration_request),
        hex::encode(client_registration_start_result.message.serialize())
    );
    Ok(())
}

#[test]
fn test_registration_response() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());
    let mut oprf_key_rng = CycleRng::new(parameters.oprf_key);
    let server_registration_start_result =
        ServerRegistration::<Ristretto255Sha512NoSlowHash>::start(
            &mut oprf_key_rng,
            RegistrationRequest::deserialize(&parameters.registration_request[..]).unwrap(),
            &Key::try_from(&parameters.server_s_pk[..]).unwrap(),
        )?;
    assert_eq!(
        hex::encode(parameters.registration_response),
        hex::encode(server_registration_start_result.message.serialize())
    );
    Ok(())
}

#[test]
fn test_registration_upload() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let mut rng = CycleRng::new(parameters.blinding_factor_registration.to_vec());
    let client_registration_start_result =
        ClientRegistration::<Ristretto255Sha512NoSlowHash>::start(&mut rng, &parameters.password)?;

    let sk_u_and_nonce: Vec<u8> = [parameters.client_s_sk, parameters.envelope_nonce].concat();
    let mut finish_registration_rng = CycleRng::new(sk_u_and_nonce);
    let result = client_registration_start_result.state.finish(
        &mut finish_registration_rng,
        RegistrationResponse::deserialize(&parameters.registration_response[..]).unwrap(),
        ClientRegistrationFinishParameters::default(),
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

#[test]
fn test_password_file() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let mut oprf_key_rng = CycleRng::new(parameters.oprf_key);
    let server_registration_start_result =
        ServerRegistration::<Ristretto255Sha512NoSlowHash>::start(
            &mut oprf_key_rng,
            RegistrationRequest::deserialize(&parameters.registration_request[..]).unwrap(),
            &Key::try_from(&parameters.server_s_pk[..]).unwrap(),
        )?;

    let password_file = server_registration_start_result
        .state
        .finish(RegistrationUpload::deserialize(&parameters.registration_upload[..]).unwrap())?;
    assert_eq!(
        hex::encode(parameters.password_file),
        hex::encode(password_file.to_bytes())
    );
    Ok(())
}

#[test]
fn test_credential_request() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_login_start = [
        parameters.blinding_factor_login,
        parameters.client_e_sk,
        parameters.client_nonce,
    ]
    .concat();
    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let client_login_start_result = ClientLogin::<Ristretto255Sha512NoSlowHash>::start(
        &mut client_login_start_rng,
        &parameters.password,
        ClientLoginStartParameters::WithInfo(parameters.info1),
    )?;
    assert_eq!(
        hex::encode(&parameters.credential_request),
        hex::encode(client_login_start_result.message.serialize())
    );
    Ok(())
}

#[test]
fn test_credential_response() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let mut server_e_sk_and_nonce_rng =
        CycleRng::new([parameters.server_e_sk, parameters.server_nonce].concat());
    let server_login_start_result = ServerLogin::<Ristretto255Sha512NoSlowHash>::start(
        &mut server_e_sk_and_nonce_rng,
        ServerRegistration::try_from(&parameters.password_file[..]).unwrap(),
        &Key::try_from(&parameters.server_s_sk[..]).unwrap(),
        CredentialRequest::<Ristretto255Sha512NoSlowHash>::deserialize(
            &parameters.credential_request[..],
        )
        .unwrap(),
        ServerLoginStartParameters::WithInfo(parameters.info2.to_vec()),
    )?;
    assert_eq!(
        hex::encode(&parameters.info1),
        hex::encode(server_login_start_result.plain_info),
    );
    assert_eq!(
        hex::encode(&parameters.credential_response),
        hex::encode(server_login_start_result.message.serialize())
    );
    Ok(())
}

#[test]
fn test_credential_finalization() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let client_login_start = [
        parameters.blinding_factor_login,
        parameters.client_e_sk,
        parameters.client_nonce,
    ]
    .concat();
    let mut client_login_start_rng = CycleRng::new(client_login_start);
    let client_login_start_result = ClientLogin::<Ristretto255Sha512NoSlowHash>::start(
        &mut client_login_start_rng,
        &parameters.password,
        ClientLoginStartParameters::WithInfo(parameters.info1),
    )?;

    let client_login_finish_result = client_login_start_result.state.finish(
        CredentialResponse::<Ristretto255Sha512NoSlowHash>::deserialize(
            &parameters.credential_response[..],
        )?,
        ClientLoginFinishParameters::default(),
    )?;

    assert_eq!(
        hex::encode(&parameters.info2),
        hex::encode(&client_login_finish_result.confidential_info)
    );
    assert_eq!(
        hex::encode(&parameters.shared_secret),
        hex::encode(&client_login_finish_result.shared_secret)
    );
    assert_eq!(
        hex::encode(&parameters.credential_finalization),
        hex::encode(client_login_finish_result.message.to_bytes())
    );
    assert_eq!(
        hex::encode(&parameters.export_key),
        hex::encode(client_login_finish_result.export_key)
    );
    Ok(())
}

#[test]
fn test_server_login_finish() -> Result<(), ProtocolError> {
    let parameters = populate_test_vectors(&serde_json::from_str(TEST_VECTOR).unwrap());

    let mut server_e_sk_and_nonce_rng =
        CycleRng::new([parameters.server_e_sk, parameters.server_nonce].concat());
    let server_login_start_result = ServerLogin::<Ristretto255Sha512NoSlowHash>::start(
        &mut server_e_sk_and_nonce_rng,
        ServerRegistration::try_from(&parameters.password_file[..]).unwrap(),
        &Key::try_from(&parameters.server_s_sk[..]).unwrap(),
        CredentialRequest::<Ristretto255Sha512NoSlowHash>::deserialize(
            &parameters.credential_request[..],
        )
        .unwrap(),
        ServerLoginStartParameters::WithInfo(parameters.info2.to_vec()),
    )?;

    let server_login_result =
        server_login_start_result
            .state
            .finish(CredentialFinalization::try_from(
                &parameters.credential_finalization[..],
            )?)?;

    assert_eq!(
        hex::encode(parameters.shared_secret),
        hex::encode(server_login_result.shared_secret)
    );

    Ok(())
}

fn test_complete_flow(
    registration_password: &[u8],
    login_password: &[u8],
) -> Result<(), ProtocolError> {
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_kp = Ristretto255Sha512NoSlowHash::generate_random_keypair(&mut server_rng);
    let client_registration_start_result =
        ClientRegistration::<Ristretto255Sha512NoSlowHash>::start(
            &mut client_rng,
            registration_password,
        )?;
    let server_registration_start_result =
        ServerRegistration::<Ristretto255Sha512NoSlowHash>::start(
            &mut server_rng,
            client_registration_start_result.message,
            server_kp.public(),
        )?;
    let client_registration_finish_result = client_registration_start_result.state.finish(
        &mut client_rng,
        server_registration_start_result.message,
        ClientRegistrationFinishParameters::default(),
    )?;
    let p_file = server_registration_start_result
        .state
        .finish(client_registration_finish_result.message)?;
    let client_login_start_result = ClientLogin::<Ristretto255Sha512NoSlowHash>::start(
        &mut client_rng,
        login_password,
        ClientLoginStartParameters::default(),
    )?;
    let server_login_start_result = ServerLogin::<Ristretto255Sha512NoSlowHash>::start(
        &mut server_rng,
        p_file,
        &server_kp.private(),
        client_login_start_result.message,
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
            hex::encode(server_login_finish_result.shared_secret),
            hex::encode(client_login_finish_result.shared_secret)
        );
        assert_eq!(
            hex::encode(client_registration_finish_result.export_key),
            hex::encode(client_login_finish_result.export_key)
        );
    } else {
        let res = matches!(
            client_login_result,
            Err(ProtocolError::VerificationError(
                PakeError::InvalidLoginError
            ))
        );
        assert!(res);
    }

    Ok(())
}

#[test]
fn test_complete_flow_success() -> Result<(), ProtocolError> {
    test_complete_flow(b"good password", b"good password")
}

#[test]
fn test_complete_flow_fail() -> Result<(), ProtocolError> {
    test_complete_flow(b"good password", b"bad password")
}

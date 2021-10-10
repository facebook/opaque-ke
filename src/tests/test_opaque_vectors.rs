// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite, errors::*, key_exchange::tripledh::TripleDH, opaque::*,
    slow_hash::NoOpHash, tests::mock_rng::CycleRng, *,
};
use alloc::{string::ToString, vec, vec::Vec};
use json::JsonValue;

#[allow(non_snake_case)]
pub struct OpaqueTestVectorParameters {
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

fn decode(values: &JsonValue, key: &str) -> Option<Vec<u8>> {
    values[key]
        .as_str()
        .and_then(|s| hex::decode(&s.to_string()).ok())
}

fn populate_test_vectors(values: &JsonValue) -> OpaqueTestVectorParameters {
    OpaqueTestVectorParameters {
        dummy_private_key: parse_default!(values, "client_private_key", vec![0u8; 32]),
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
    parameters: &OpaqueTestVectorParameters,
) -> Result<Vec<u8>, ProtocolError> {
    let password_file = ServerRegistration::<CS>::finish(
        RegistrationUpload::deserialize(&parameters.registration_upload[..]).unwrap(),
    );

    Ok(password_file.serialize())
}

fn parse_identifiers(
    client_identity: &Option<Vec<u8>>,
    server_identity: &Option<Vec<u8>>,
) -> Option<Identifiers> {
    match (client_identity, server_identity) {
        (None, None) => None,
        (Some(x), None) => Some(Identifiers::ClientIdentifier(x.clone())),
        (None, Some(y)) => Some(Identifiers::ServerIdentifier(y.clone())),
        (Some(x), Some(y)) => Some(Identifiers::ClientAndServerIdentifiers(
            x.clone(),
            y.clone(),
        )),
    }
}

macro_rules! json_to_test_vectors {
    ( $v:ident, $vector_type:expr, $cs:expr, ) => {
        $v[$vector_type][$cs]
            .members()
            .map(|x| populate_test_vectors(&x))
            .collect::<Vec<OpaqueTestVectorParameters>>()
    };
}

#[test]
fn tests() -> Result<(), ProtocolError> {
    let rfc = json::parse(super::parser::rfc_to_json(super::opaque_vectors::VECTORS).as_str())
        .expect("Could not parse json");

    let ristretto_real_tvs = json_to_test_vectors!(
        rfc,
        String::from("Real"),
        String::from("ristretto255, SHA512"),
    );
    let ristretto_fake_tvs = json_to_test_vectors!(
        rfc,
        String::from("Fake"),
        String::from("ristretto255, SHA512"),
    );

    struct Ristretto255Sha512NoSlowHash;
    impl CipherSuite for Ristretto255Sha512NoSlowHash {
        type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
        type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
        type KeyExchange = TripleDH;
        type Hash = sha2::Sha512;
        type SlowHash = NoOpHash;
    }

    test_registration_request::<Ristretto255Sha512NoSlowHash>(&ristretto_real_tvs)?;
    test_registration_response::<Ristretto255Sha512NoSlowHash>(&ristretto_real_tvs)?;
    test_registration_upload::<Ristretto255Sha512NoSlowHash>(&ristretto_real_tvs)?;
    test_ke1::<Ristretto255Sha512NoSlowHash>(&ristretto_real_tvs)?;
    test_ke2::<Ristretto255Sha512NoSlowHash>(&ristretto_real_tvs)?;
    test_ke3::<Ristretto255Sha512NoSlowHash>(&ristretto_real_tvs)?;
    test_server_login_finish::<Ristretto255Sha512NoSlowHash>(&ristretto_real_tvs)?;
    test_fake_vectors::<Ristretto255Sha512NoSlowHash>(&ristretto_fake_tvs)?;

    #[cfg(feature = "p256")]
    {
        let p256_real_tvs = json_to_test_vectors!(
            rfc,
            String::from("Real"),
            String::from("P256_XMD:SHA-256_SSWU_RO_, SHA256"),
        );
        let p256_fake_tvs = json_to_test_vectors!(
            rfc,
            String::from("Fake"),
            String::from("P256_XMD:SHA-256_SSWU_RO_, SHA256"),
        );

        struct P256Sha256NoSlowHash;
        impl CipherSuite for P256Sha256NoSlowHash {
            type OprfGroup = p256_::ProjectivePoint;
            type KeGroup = p256_::ProjectivePoint;
            type KeyExchange = TripleDH;
            type Hash = sha2::Sha256;
            type SlowHash = NoOpHash;
        }

        test_registration_request::<P256Sha256NoSlowHash>(&p256_real_tvs)?;
        test_registration_response::<P256Sha256NoSlowHash>(&p256_real_tvs)?;
        test_registration_upload::<P256Sha256NoSlowHash>(&p256_real_tvs)?;
        test_ke1::<P256Sha256NoSlowHash>(&p256_real_tvs)?;
        test_ke2::<P256Sha256NoSlowHash>(&p256_real_tvs)?;
        test_ke3::<P256Sha256NoSlowHash>(&p256_real_tvs)?;
        test_server_login_finish::<P256Sha256NoSlowHash>(&p256_real_tvs)?;
        test_fake_vectors::<P256Sha256NoSlowHash>(&p256_fake_tvs)?;
    }

    Ok(())
}

fn test_registration_request<CS: CipherSuite>(
    tvs: &[OpaqueTestVectorParameters],
) -> Result<(), ProtocolError> {
    for parameters in tvs {
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

fn test_registration_response<CS: CipherSuite>(
    tvs: &[OpaqueTestVectorParameters],
) -> Result<(), ProtocolError> {
    for parameters in tvs {
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
            hex::encode(&parameters.oprf_key),
            hex::encode(server_registration_start_result.oprf_key)
        );
        assert_eq!(
            hex::encode(&parameters.registration_response),
            hex::encode(server_registration_start_result.message.serialize())
        );
    }
    Ok(())
}

fn test_registration_upload<CS: CipherSuite>(
    tvs: &[OpaqueTestVectorParameters],
) -> Result<(), ProtocolError> {
    for parameters in tvs {
        let mut rng = CycleRng::new(parameters.blind_registration.to_vec());
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut rng, &parameters.password)?;

        let mut finish_registration_rng = CycleRng::new(parameters.envelope_nonce.to_vec());
        let result = client_registration_start_result.state.finish(
            &mut finish_registration_rng,
            RegistrationResponse::deserialize(&parameters.registration_response[..]).unwrap(),
            match parse_identifiers(&parameters.client_identity, &parameters.server_identity) {
                None => ClientRegistrationFinishParameters::default(),
                Some(ids) => ClientRegistrationFinishParameters::new(Some(ids), None),
            },
        )?;

        assert_eq!(
            hex::encode(&parameters.auth_key),
            hex::encode(result.auth_key)
        );
        assert_eq!(
            hex::encode(&parameters.randomized_pwd),
            hex::encode(result.randomized_pwd)
        );
        assert_eq!(
            hex::encode(&parameters.registration_upload),
            hex::encode(result.message.serialize())
        );
        assert_eq!(
            hex::encode(&parameters.export_key),
            hex::encode(result.export_key.to_vec())
        );
    }

    Ok(())
}

fn test_ke1<CS: CipherSuite>(tvs: &[OpaqueTestVectorParameters]) -> Result<(), ProtocolError> {
    for parameters in tvs {
        let client_login_start = [
            &parameters.blind_login[..],
            &parameters.client_private_keyshare[..],
            &parameters.client_nonce[..],
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

fn test_ke2<CS: CipherSuite>(tvs: &[OpaqueTestVectorParameters]) -> Result<(), ProtocolError> {
    for parameters in tvs {
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
                &parameters.masking_nonce[..],
                &parameters.server_private_keyshare[..],
                &parameters.server_nonce[..],
            ]
            .concat(),
        );
        let server_login_start_result = ServerLogin::<CS>::start(
            &mut server_private_keyshare_and_nonce_rng,
            &server_setup,
            Some(record),
            CredentialRequest::<CS>::deserialize(&parameters.KE1[..]).unwrap(),
            &parameters.credential_identifier,
            match parse_identifiers(&parameters.client_identity, &parameters.server_identity) {
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

fn test_ke3<CS: CipherSuite>(tvs: &[OpaqueTestVectorParameters]) -> Result<(), ProtocolError> {
    for parameters in tvs {
        let client_login_start = [
            &parameters.blind_login[..],
            &parameters.client_private_keyshare[..],
            &parameters.client_nonce[..],
        ]
        .concat();
        let mut client_login_start_rng = CycleRng::new(client_login_start);
        let client_login_start_result =
            ClientLogin::<CS>::start(&mut client_login_start_rng, &parameters.password)?;

        let client_login_finish_result = client_login_start_result.state.finish(
            CredentialResponse::<CS>::deserialize(&parameters.KE2[..])?,
            match parse_identifiers(&parameters.client_identity, &parameters.server_identity) {
                None => {
                    ClientLoginFinishParameters::new(Some(parameters.context.clone()), None, None)
                }
                Some(ids) => ClientLoginFinishParameters::new(
                    Some(parameters.context.clone()),
                    Some(ids),
                    None,
                ),
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

fn test_server_login_finish<CS: CipherSuite>(
    tvs: &[OpaqueTestVectorParameters],
) -> Result<(), ProtocolError> {
    for parameters in tvs {
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
                &parameters.masking_nonce[..],
                &parameters.server_private_keyshare[..],
                &parameters.server_nonce[..],
            ]
            .concat(),
        );
        let server_login_start_result = ServerLogin::<CS>::start(
            &mut server_private_keyshare_and_nonce_rng,
            &server_setup,
            Some(record),
            CredentialRequest::<CS>::deserialize(&parameters.KE1[..]).unwrap(),
            &parameters.credential_identifier,
            match parse_identifiers(&parameters.client_identity, &parameters.server_identity) {
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
            hex::encode(&parameters.session_key),
            hex::encode(&server_login_result.session_key)
        );
    }
    Ok(())
}

fn test_fake_vectors<CS: CipherSuite>(
    tvs: &[OpaqueTestVectorParameters],
) -> Result<(), ProtocolError> {
    for parameters in tvs {
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
                &parameters.dummy_masking_key[..],
                &parameters.masking_nonce[..],
                &parameters.server_private_keyshare[..],
                &parameters.server_nonce[..],
            ]
            .concat(),
        );
        let server_login_start_result = ServerLogin::<CS>::start(
            &mut server_private_keyshare_and_nonce_rng,
            &server_setup,
            None,
            CredentialRequest::<CS>::deserialize(&parameters.KE1[..]).unwrap(),
            &parameters.credential_identifier,
            match parse_identifiers(&parameters.client_identity, &parameters.server_identity) {
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

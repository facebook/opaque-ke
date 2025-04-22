// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

#![allow(unsafe_code)]

use core::ops::Add;
use std::string::String;
use std::vec::Vec;
use std::{format, println, ptr, vec};

use digest::Output;
use generic_array::typenum::{Sum, Unsigned};
use generic_array::{ArrayLength, GenericArray};
use rand::rngs::OsRng;
use serde_json::Value;
use subtle::ConstantTimeEq;
use voprf::Group as _;

use crate::ciphersuite::{CipherSuite, KeGroup, OprfGroup, OprfHash};
use crate::envelope::EnvelopeLen;
use crate::errors::*;
use crate::hash::OutputSize;
use crate::key_exchange::group::Group;
use crate::key_exchange::shared::NonceLen;
use crate::key_exchange::sigma_i::SigmaI;
use crate::key_exchange::traits::{
    Deserialize, Ke1MessageLen, Ke1StateLen, Ke2MessageLen, KeyExchange, Serialize,
};
use crate::key_exchange::tripledh::TripleDh;
use crate::ksf::Identity;
use crate::messages::{
    CredentialRequestLen, CredentialResponseLen, CredentialResponseWithoutKeLen,
    RegistrationResponseLen, RegistrationUploadLen,
};
use crate::opaque::*;
use crate::tests::mock_rng::CycleRng;
use crate::util::AssertZeroized;
use crate::*;

// Tests
// =====

macro_rules! ciphersuite_types {
    ($(#[$attr:meta])* $name:ident, $oprf:ty, $ke:ty, $par:tt) => {
        $(#[$attr])*
        struct $name;

        $(#[$attr])*
        impl CipherSuite for $name {
            type OprfCs = $oprf;
            type KeyExchange = $ke;
            type Ksf = Identity;
        }
    };
}

macro_rules! generate {
    ($(#[$attr:meta])* $name:ident, $oprf:ty, $ke:ty, ($output:ident)) => {
        paste::paste! {
            $(#[$attr])*
            {
                let parameters = generate_parameters::<$name>()?;
                $(
                    $output.push_str(&format!("#[{}]\n", stringify!($attr)));
                )*
                $output.push_str(&format!(
                    "pub static {}: &str = r#\"\n{}\"#;\n",
                    stringify!([<TEST_VECTOR_ $name:snake:upper>]),
                    stringify_test_vectors(&parameters)
                ));
            }
        }
    };
}

macro_rules! run_all {
    ($(#[$attr:meta])* $name:ident, $oprf:ty, $ke:ty, ($fn:ident $(, $par:expr)*)) => {
        paste::paste! {
            $(#[$attr])*
            $fn::<$name>(super::full_test_vectors::[<TEST_VECTOR_ $name:snake:upper>] $(, $par)*)?;
        }
    };
}

macro_rules! oprf_ciphersuites {
    ($macro:ident!$par:tt => [$($(#[$ke_attr:meta])* [$ke_name:ident, $ke:ty$(,)?]),+$(,)?]) => {
        $(
            oprf_ciphersuites!(
                $macro!$par =>
                $(#[$ke_attr])* [$ke_name, $ke],
                [
                    #[cfg(feature = "ristretto255")] [
                        Ristretto255, crate::Ristretto255,
                    ],
                    [P256, p256::NistP256],
                    [P384, p384::NistP384],
                    [P521, p521::NistP521],
                ],
            );
        )+
    };
    (
        $macro:ident!$par:tt =>
        #[$ke_attr_1:meta] #[$ke_attr_2:meta] [$ke_name:ident, $ke:ty],
        [$($(#[$oprf_attr:meta])? [$oprf_name:ident, $oprf:ty$(,)?]),+$(,)?],
    ) => {
        paste::paste! {
            $($macro!(#[$ke_attr_1] #[$ke_attr_2] $(#[$oprf_attr])? [<$oprf_name $ke_name>], $oprf, $ke, $par);)+
        }
    };
    (
        $macro:ident!$par:tt =>
        #[$ke_attr:meta] [$ke_name:ident, $ke:ty],
        [$($(#[$oprf_attr:meta])? [$oprf_name:ident, $oprf:ty$(,)?]),+$(,)?],
    ) => {
        paste::paste! {
            $($macro!(#[$ke_attr] $(#[$oprf_attr])? [<$oprf_name $ke_name>], $oprf, $ke, $par);)+
        }
    };
    (
        $macro:ident!$par:tt =>
        [$ke_name:ident, $ke:ty],
        [$($(#[$oprf_attr:meta])? [$oprf_name:ident, $oprf:ty$(,)?]),+$(,)?],
    ) => {
        paste::paste! {
            $($macro!($(#[$oprf_attr])? [<$oprf_name $ke_name>], $oprf, $ke, $par);)+
        }
    }
}

macro_rules! triple_dh_ciphersuites {
    ($macro:ident!$par:tt) => {
        oprf_ciphersuites!(
            $macro!$par => [
                #[cfg(feature = "ristretto255")] [
                    TripleDhRistretto255, TripleDh<crate::Ristretto255, sha2::Sha512>,
                ],
                [TripleDhP256, TripleDh<p256::NistP256, sha2::Sha256>],
                [TripleDhP384, TripleDh<p384::NistP384, sha2::Sha384>],
                [TripleDhP521, TripleDh<p521::NistP521, sha2::Sha512>],
                #[cfg(feature = "curve25519")] [
                    TripleDhCurve25519, TripleDh<crate::Curve25519, sha2::Sha512>,
                ],
            ]
        );
    };
}

macro_rules! sigma_i_ciphersuites {
    ($macro:ident!$par:tt) => {
        sigma_i_ciphersuites!(
            $macro!$par => [
                #[cfg(feature = "ecdsa")] [P256, p256::NistP256],
                #[cfg(feature = "ecdsa")] [P384, p384::NistP384],
            ],
        );
    };
    (
        $macro:ident!$par:tt =>
        [$($(#[$sig_attr:meta])? [$sig_name:ident, $sig:ty]),+$(,)?],
    ) => {
        paste::paste! {
            $(
                oprf_ciphersuites!(
                    $macro!$par => [
                        $(#[$sig_attr])? #[cfg(feature = "ristretto255")] [
                            [<SigmaI $sig_name Ristretto255>], SigmaI<$sig, crate::Ristretto255, sha2::Sha512>,
                        ],
                        $(#[$sig_attr])? [[<SigmaI $sig_name P256>], SigmaI<$sig, p256::NistP256, sha2::Sha256>],
                        $(#[$sig_attr])? [[<SigmaI $sig_name P384>], SigmaI<$sig, p384::NistP384, sha2::Sha384>],
                        $(#[$sig_attr])? [[<SigmaI $sig_name P521>], SigmaI<$sig, p521::NistP521, sha2::Sha512>],
                        $(#[$sig_attr])? #[cfg(feature = "curve25519")] [
                            [<SigmaI $sig_name Curve25519>], SigmaI<$sig, crate::Curve25519, sha2::Sha512>,
                        ],
                    ]
                );
            )+
        }
    };
}

triple_dh_ciphersuites!(ciphersuite_types!());
sigma_i_ciphersuites!(ciphersuite_types!());

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
    pub dummy_masking_key: Vec<u8>,
    pub masking_nonce: Vec<u8>,
    pub envelope_nonce: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub server_nonce: Vec<u8>,
    pub server_sig_rng: Vec<u8>,
    pub client_sig_rng: Vec<u8>,
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
        dummy_masking_key: decode(values, "dummy_masking_key").unwrap(),
        masking_nonce: decode(values, "masking_nonce").unwrap(),
        envelope_nonce: decode(values, "envelope_nonce").unwrap(),
        client_nonce: decode(values, "client_nonce").unwrap(),
        server_nonce: decode(values, "server_nonce").unwrap(),
        server_sig_rng: decode(values, "server_sig_rng").unwrap(),
        client_sig_rng: decode(values, "client_sig_rng").unwrap(),
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
    s.push_str(
        format!(
            "    \"client_s_pk\": \"{}\",\n",
            hex::encode(&p.client_s_pk)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"client_s_sk\": \"{}\",\n",
            hex::encode(&p.client_s_sk)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"client_e_pk\": \"{}\",\n",
            hex::encode(&p.client_e_pk)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"client_e_sk\": \"{}\",\n",
            hex::encode(&p.client_e_sk)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"server_s_pk\": \"{}\",\n",
            hex::encode(&p.server_s_pk)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"server_s_sk\": \"{}\",\n",
            hex::encode(&p.server_s_sk)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"server_e_pk\": \"{}\",\n",
            hex::encode(&p.server_e_pk)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"server_e_sk\": \"{}\",\n",
            hex::encode(&p.server_e_sk)
        )
        .as_str(),
    );
    s.push_str(format!("    \"fake_sk\": \"{}\",\n", hex::encode(&p.fake_sk)).as_str());
    s.push_str(
        format!(
            "    \"credential_identifier\": \"{}\",\n",
            hex::encode(&p.credential_identifier)
        )
        .as_str(),
    );
    s.push_str(format!("    \"id_u\": \"{}\",\n", hex::encode(&p.id_u)).as_str());
    s.push_str(format!("    \"id_s\": \"{}\",\n", hex::encode(&p.id_s)).as_str());
    s.push_str(format!("    \"password\": \"{}\",\n", hex::encode(&p.password)).as_str());
    s.push_str(
        format!(
            "    \"blinding_factor\": \"{}\",\n",
            hex::encode(&p.blinding_factor)
        )
        .as_str(),
    );
    s.push_str(format!("    \"oprf_seed\": \"{}\",\n", hex::encode(&p.oprf_seed)).as_str());
    s.push_str(
        format!(
            "    \"dummy_masking_key\": \"{}\",\n",
            hex::encode(&p.dummy_masking_key)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"masking_nonce\": \"{}\",\n",
            hex::encode(&p.masking_nonce)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"envelope_nonce\": \"{}\",\n",
            hex::encode(&p.envelope_nonce)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"client_nonce\": \"{}\",\n",
            hex::encode(&p.client_nonce)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"server_nonce\": \"{}\",\n",
            hex::encode(&p.server_nonce)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"server_sig_rng\": \"{}\",\n",
            hex::encode(&p.server_sig_rng)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"client_sig_rng\": \"{}\",\n",
            hex::encode(&p.client_sig_rng)
        )
        .as_str(),
    );
    s.push_str(format!("    \"context\": \"{}\",\n", hex::encode(&p.context)).as_str());
    s.push_str(
        format!(
            "    \"registration_request\": \"{}\",\n",
            hex::encode(&p.registration_request)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"registration_response\": \"{}\",\n",
            hex::encode(&p.registration_response)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"registration_upload\": \"{}\",\n",
            hex::encode(&p.registration_upload)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"credential_request\": \"{}\",\n",
            hex::encode(&p.credential_request)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"credential_response\": \"{}\",\n",
            hex::encode(&p.credential_response)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"credential_finalization\": \"{}\",\n",
            hex::encode(&p.credential_finalization)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"client_registration_state\": \"{}\",\n",
            hex::encode(&p.client_registration_state)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"client_login_state\": \"{}\",\n",
            hex::encode(&p.client_login_state)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"server_login_state\": \"{}\",\n",
            hex::encode(&p.server_login_state)
        )
        .as_str(),
    );
    s.push_str(
        format!(
            "    \"password_file\": \"{}\",\n",
            hex::encode(&p.password_file)
        )
        .as_str(),
    );
    s.push_str(format!("    \"export_key\": \"{}\",\n", hex::encode(&p.export_key)).as_str());
    s.push_str(format!("    \"session_key\": \"{}\"\n", hex::encode(&p.session_key)).as_str());
    s.push_str("}\n");
    s
}

fn generate_parameters<CS: CipherSuite>() -> Result<TestVectorParameters, ProtocolError>
where
    <CS::KeyExchange as KeyExchange>::KE2State: Serialize,
    <CS::KeyExchange as KeyExchange>::KE3Message: Serialize,
    // ClientRegistration: KgSk + KgPk
    <OprfGroup<CS> as voprf::Group>::ScalarLen: Add<<OprfGroup<CS> as voprf::Group>::ElemLen>,
    ClientRegistrationLen<CS>: ArrayLength<u8>,
    // RegistrationResponse: KgPk + KePk
    <OprfGroup<CS> as voprf::Group>::ElemLen: Add<<KeGroup<CS> as Group>::PkLen>,
    RegistrationResponseLen<CS>: ArrayLength<u8>,
    // Envelope: Nonce + Hash
    NonceLen: Add<OutputSize<OprfHash<CS>>>,
    EnvelopeLen<CS>: ArrayLength<u8>,
    // RegistrationUpload: (KePk + Hash) + Envelope
    <KeGroup<CS> as Group>::PkLen: Add<OutputSize<OprfHash<CS>>>,
    Sum<<KeGroup<CS> as Group>::PkLen, OutputSize<OprfHash<CS>>>:
        ArrayLength<u8> + Add<EnvelopeLen<CS>>,
    RegistrationUploadLen<CS>: ArrayLength<u8>,
    // ServerRegistration = RegistrationUpload
    // CredentialRequest: KgPk + Ke1Message
    <CS::KeyExchange as KeyExchange>::KE1Message: Serialize,
    <OprfGroup<CS> as voprf::Group>::ElemLen: Add<Ke1MessageLen<CS>>,
    CredentialRequestLen<CS>: ArrayLength<u8>,
    // ClientLogin: KgSk + CredentialRequest + Ke1State
    <OprfGroup<CS> as voprf::Group>::ScalarLen: Add<CredentialRequestLen<CS>>,
    <CS::KeyExchange as KeyExchange>::KE1State: Serialize,
    Sum<<OprfGroup<CS> as voprf::Group>::ScalarLen, CredentialRequestLen<CS>>:
        ArrayLength<u8> + Add<Ke1StateLen<CS>>,
    ClientLoginLen<CS>: ArrayLength<u8>,
    // MaskedResponse: (Nonce + Hash) + KePk
    NonceLen: Add<OutputSize<OprfHash<CS>>>,
    Sum<NonceLen, OutputSize<OprfHash<CS>>>: ArrayLength<u8> + Add<<KeGroup<CS> as Group>::PkLen>,
    MaskedResponseLen<CS>: ArrayLength<u8>,
    // CredentialResponseWithoutKeLen: (KgPk + Nonce) + MaskedResponse
    <OprfGroup<CS> as voprf::Group>::ElemLen: Add<NonceLen>,
    Sum<<OprfGroup<CS> as voprf::Group>::ElemLen, NonceLen>:
        ArrayLength<u8> + Add<MaskedResponseLen<CS>>,
    CredentialResponseWithoutKeLen<CS>: ArrayLength<u8>,
    // CredentialResponse: CredentialResponseWithoutKeLen + Ke2Message
    <CS::KeyExchange as KeyExchange>::KE2Message: Serialize,
    CredentialResponseWithoutKeLen<CS>: Add<Ke2MessageLen<CS>>,
    CredentialResponseLen<CS>: ArrayLength<u8>,
{
    use rand::RngCore;

    use crate::keypair::KeyPair;

    let mut rng = OsRng;

    // Inputs
    let server_s_kp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
    let server_e_kp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
    let client_s_kp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
    let client_e_kp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
    let fake_kp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
    let credential_identifier = b"credIdentifier";
    let id_u = b"idU";
    let id_s = b"idS";
    let password = b"password";
    let context = b"context";
    let mut oprf_seed = Output::<OprfHash<CS>>::default();
    rng.fill_bytes(&mut oprf_seed);
    let mut dummy_masking_key = Output::<OprfHash<CS>>::default();
    rng.fill_bytes(&mut dummy_masking_key);
    let mut masking_nonce = [0u8; 64];
    rng.fill_bytes(&mut masking_nonce);
    let mut envelope_nonce = [0u8; 32];
    rng.fill_bytes(&mut envelope_nonce);
    let mut client_nonce = [0u8; NonceLen::USIZE];
    rng.fill_bytes(&mut client_nonce);
    let mut server_nonce = [0u8; NonceLen::USIZE];
    rng.fill_bytes(&mut server_nonce);
    let mut server_sig_rng = GenericArray::<u8, <KeGroup<CS> as Group>::SkLen>::default();
    rng.fill_bytes(&mut server_sig_rng);
    let mut client_sig_rng = GenericArray::<u8, <KeGroup<CS> as Group>::SkLen>::default();
    rng.fill_bytes(&mut client_sig_rng);

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

    let blinding_factor = <OprfGroup<CS> as voprf::Group>::random_scalar(&mut rng);
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
            dummy_masking_key.to_vec(),
            masking_nonce.to_vec(),
            server_e_kp.private().serialize().to_vec(),
            server_nonce.to_vec(),
            server_sig_rng.to_vec(),
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
            &mut CycleRng::new(client_sig_rng.to_vec()),
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
        dummy_masking_key: dummy_masking_key.to_vec(),
        masking_nonce: masking_nonce.to_vec(),
        envelope_nonce: envelope_nonce.to_vec(),
        client_nonce: client_nonce.to_vec(),
        server_nonce: server_nonce.to_vec(),
        server_sig_rng: server_sig_rng.to_vec(),
        client_sig_rng: client_sig_rng.to_vec(),
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
    let mut output = String::new();

    #[rustfmt::skip]
    output.push_str(
        "\
        // Copyright (c) Meta Platforms, Inc. and affiliates.\n\
        //\n\
        // This source code is dual-licensed under either the MIT license found in the\n\
        // LICENSE-MIT file in the root directory of this source tree or the Apache\n\
        // License, Version 2.0 found in the LICENSE-APACHE file in the root directory\n\
        // of this source tree. You may select, at your option, one of the above-listed\n\
        // licenses.\n\
        //\n\
        // To regenerate these test vectors, run:\n\
        // FULL_TEST_VECTORS_FILE=src/tests/full_test_vectors.rs cargo test --features ristretto255,curve25519,ecdsa -- generate_test_vectors\n\
        \n\
        #![allow(clippy::duplicated_attributes)]\n\
        \n",
    );

    triple_dh_ciphersuites!(generate!(output));
    sigma_i_ciphersuites!(generate!(output));

    if let Ok(path) = std::env::var("FULL_TEST_VECTORS_FILE") {
        std::fs::write(path, output).unwrap();
    } else {
        println!("{output}");
    }

    Ok(())
}

#[test]
fn test_registration_request() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        // ClientRegistration: KgSk + KgPk
        <OprfGroup<CS> as voprf::Group>::ScalarLen: Add<<OprfGroup<CS> as voprf::Group>::ElemLen>,
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

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn test_serialization() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError> {
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

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_registration_response() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        // RegistrationResponse: KgPk + KePk
        <OprfGroup<CS> as voprf::Group>::ElemLen: Add<<KeGroup<CS> as Group>::PkLen>,
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

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_registration_upload() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <KeGroup<CS> as Group>::PkLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<<KeGroup<CS> as Group>::PkLen, OutputSize<OprfHash<CS>>>:
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

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_password_file() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <KeGroup<CS> as Group>::PkLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<<KeGroup<CS> as Group>::PkLen, OutputSize<OprfHash<CS>>>:
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

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_credential_request() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        // CredentialRequest: KgPk + Ke1Message
        <CS::KeyExchange as KeyExchange>::KE1Message: Serialize,
        <OprfGroup<CS> as voprf::Group>::ElemLen: Add<Ke1MessageLen<CS>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
        // ClientLogin: KgSk + CredentialRequest + Ke1State
        <OprfGroup<CS> as voprf::Group>::ScalarLen: Add<CredentialRequestLen<CS>>,
        <CS::KeyExchange as KeyExchange>::KE1State: Serialize,
        Sum<<OprfGroup<CS> as voprf::Group>::ScalarLen, CredentialRequestLen<CS>>:
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

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_credential_response() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE1Message: Deserialize,
        <CS::KeyExchange as KeyExchange>::KE2State: Serialize,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<NonceLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<<KeGroup<CS> as Group>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
        // CredentialResponseWithoutKeLen: (KgPk + Nonce) + MaskedResponse
        <OprfGroup<CS> as voprf::Group>::ElemLen: Add<NonceLen>,
        Sum<<OprfGroup<CS> as voprf::Group>::ElemLen, NonceLen>:
            ArrayLength<u8> + Add<MaskedResponseLen<CS>>,
        CredentialResponseWithoutKeLen<CS>: ArrayLength<u8>,
        // CredentialResponse: CredentialResponseWithoutKeLen + Ke2Message
        <CS::KeyExchange as KeyExchange>::KE2Message: Serialize,
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
                parameters.dummy_masking_key,
                parameters.masking_nonce,
                parameters.server_e_sk,
                parameters.server_nonce,
                parameters.server_sig_rng,
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

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_credential_finalization() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE1Message: Deserialize + Serialize,
        <CS::KeyExchange as KeyExchange>::KE1State: Deserialize + Serialize,
        <CS::KeyExchange as KeyExchange>::KE2Message: Deserialize + Serialize,
        <CS::KeyExchange as KeyExchange>::KE3Message: Serialize,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<NonceLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<<KeGroup<CS> as Group>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
    {
        let parameters = populate_test_vectors(&serde_json::from_str(test_vector).unwrap());

        let client_login_finish_result =
            ClientLogin::<CS>::deserialize(&parameters.client_login_state)?.finish(
                &mut CycleRng::new(parameters.client_sig_rng),
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
            hex::encode(client_login_finish_result.server_s_pk.serialize())
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

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_server_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE2State: Deserialize,
        <CS::KeyExchange as KeyExchange>::KE3Message: Deserialize,
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

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

fn test_complete_flow<CS: CipherSuite>(
    _test_vector: &str,
    registration_password: &[u8],
    login_password: &[u8],
) -> Result<(), ProtocolError>
where
    // MaskedResponse: (Nonce + Hash) + KePk
    NonceLen: Add<OutputSize<OprfHash<CS>>>,
    Sum<NonceLen, OutputSize<OprfHash<CS>>>: ArrayLength<u8> + Add<<KeGroup<CS> as Group>::PkLen>,
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
        &mut client_rng,
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
    triple_dh_ciphersuites!(run_all!(
        test_complete_flow,
        b"good password",
        b"good password"
    ));
    sigma_i_ciphersuites!(run_all!(
        test_complete_flow,
        b"good password",
        b"good password"
    ));
    Ok(())
}

#[test]
fn test_complete_flow_fail() -> Result<(), ProtocolError> {
    triple_dh_ciphersuites!(run_all!(
        test_complete_flow,
        b"good password",
        b"bad password"
    ));
    sigma_i_ciphersuites!(run_all!(
        test_complete_flow,
        b"good password",
        b"bad password"
    ));
    Ok(())
}

// Zeroize tests

#[test]
fn test_zeroize_client_registration_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError> {
        let mut client_rng = OsRng;
        let client_registration_start_result =
            ClientRegistration::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;

        let mut state = client_registration_start_result.state;
        unsafe { ptr::drop_in_place(&mut state) };
        state.assert_zeroized();

        Ok(())
    }

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_zeroize_client_registration_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError> {
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
        state.assert_zeroized();

        Ok(())
    }

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_zeroize_server_registration_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
    where
        <KeGroup<CS> as Group>::Pk: AssertZeroized,
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <KeGroup<CS> as Group>::PkLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<<KeGroup<CS> as Group>::PkLen, OutputSize<OprfHash<CS>>>:
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
        unsafe { ptr::drop_in_place(&mut state) };
        state.assert_zeroized();

        Ok(())
    }

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_zeroize_client_login_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE1State: AssertZeroized,
        <CS::KeyExchange as KeyExchange>::KE1Message: AssertZeroized,
    {
        let mut client_rng = OsRng;
        let client_login_start_result =
            ClientLogin::<CS>::start(&mut client_rng, STR_PASSWORD.as_bytes())?;

        let mut state = client_login_start_result.state;
        unsafe { ptr::drop_in_place(&mut state) };
        state.assert_zeroized();

        Ok(())
    }

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_zeroize_server_login_start() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE2State: Serialize + AssertZeroized,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<NonceLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<<KeGroup<CS> as Group>::PkLen>,
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
        state.assert_zeroized();

        Ok(())
    }

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_zeroize_client_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE1State: AssertZeroized,
        <CS::KeyExchange as KeyExchange>::KE1Message: AssertZeroized,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<NonceLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<<KeGroup<CS> as Group>::PkLen>,
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
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
            server_login_start_result.message,
            ClientLoginFinishParameters::default(),
        )?;

        let mut state = client_login_finish_result.state;
        unsafe { ptr::drop_in_place(&mut state) };
        state.assert_zeroized();

        Ok(())
    }

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_zeroize_server_login_finish() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE2State: Serialize + AssertZeroized,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<NonceLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<<KeGroup<CS> as Group>::PkLen>,
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
            &mut client_rng,
            STR_PASSWORD.as_bytes(),
            server_login_start_result.message,
            ClientLoginFinishParameters::default(),
        )?;
        let server_login_finish_result = server_login_start_result
            .state
            .finish(client_login_finish_result.message)?;

        let mut state = server_login_finish_result.state;
        unsafe { ptr::drop_in_place(&mut state) };
        state.assert_zeroized();

        Ok(())
    }

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_scalar_always_nonzero() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError> {
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

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_reflected_value_error_registration() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError> {
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

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

#[test]
fn test_reflected_value_error_login() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>(_test_vector: &str) -> Result<(), ProtocolError>
    where
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<NonceLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<<KeGroup<CS> as Group>::PkLen>,
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
            &mut client_rng,
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

    triple_dh_ciphersuites!(run_all!(inner));
    sigma_i_ciphersuites!(run_all!(inner));

    Ok(())
}

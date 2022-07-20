// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Demonstrates a simple client-server password-based login protocol using
//! OPAQUE, over a command-line interface
//!
//! This specific example shows how to use a custom KSF (Key Stretching
//! Function). `scrypt` is used for this example, but any KSF can be used.

use std::collections::HashMap;
use std::process::exit;

use generic_array::GenericArray;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginStartParameters, ServerRegistration, ServerRegistrationLen, ServerSetup,
};
use rustyline::error::ReadlineError;
use rustyline::Editor;

// We can define a structure here to hold the parameters for the KSF.
#[derive(Default)]
struct CustomKsf(scrypt::Params);

// The Ksf trait must be implemented to be used in the ciphersuite.
impl opaque_ke::ksf::Ksf for CustomKsf {
    fn hash<L: generic_array::ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, opaque_ke::errors::InternalError> {
        let mut output = GenericArray::<u8, L>::default();
        scrypt::scrypt(&input, &[], &self.0, &mut output)
            .map_err(|_| opaque_ke::errors::InternalError::KsfError)?;

        Ok(output)
    }
}

// The ciphersuite trait allows to specify the underlying primitives that will
// be used in the OPAQUE protocol
#[allow(dead_code)]
struct Default;

#[cfg(feature = "ristretto255")]
impl CipherSuite for Default {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;

    type Ksf = CustomKsf;
}

#[cfg(not(feature = "ristretto255"))]
impl CipherSuite for Default {
    type OprfCs = p256::NistP256;
    type KeGroup = p256::NistP256;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;

    type Ksf = CustomKsf;
}

// Password-based registration between a client and server
fn account_registration(
    server_setup: &ServerSetup<Default>,
    username: String,
    password: String,
) -> GenericArray<u8, ServerRegistrationLen<Default>> {
    let mut client_rng = OsRng;
    let client_registration_start_result =
        ClientRegistration::<Default>::start(&mut client_rng, password.as_bytes()).unwrap();
    let registration_request_bytes = client_registration_start_result.message.serialize();

    // Client sends registration_request_bytes to server

    let server_registration_start_result = ServerRegistration::<Default>::start(
        server_setup,
        RegistrationRequest::deserialize(&registration_request_bytes).unwrap(),
        username.as_bytes(),
    )
    .unwrap();
    let registration_response_bytes = server_registration_start_result.message.serialize();

    // Server sends registration_response_bytes to client

    // Sets up custom parameters for the KSF
    let custom_ksf =
        CustomKsf(scrypt::Params::new(8, 8, 1).expect("scrypt parameter should be valid"));

    let client_finish_params = ClientRegistrationFinishParameters {
        ksf: Some(&custom_ksf),
        ..core::default::Default::default()
    };

    let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            RegistrationResponse::deserialize(&registration_response_bytes).unwrap(),
            client_finish_params,
        )
        .unwrap();
    let message_bytes = client_finish_registration_result.message.serialize();

    // Client sends message_bytes to server

    let password_file = ServerRegistration::finish(
        RegistrationUpload::<Default>::deserialize(&message_bytes).unwrap(),
    );
    password_file.serialize()
}

// Password-based login between a client and server
fn account_login(
    server_setup: &ServerSetup<Default>,
    username: String,
    password: String,
    password_file_bytes: &[u8],
) -> bool {
    let mut client_rng = OsRng;
    let client_login_start_result =
        ClientLogin::<Default>::start(&mut client_rng, password.as_bytes()).unwrap();
    let credential_request_bytes = client_login_start_result.message.serialize();

    // Client sends credential_request_bytes to server

    let password_file = ServerRegistration::<Default>::deserialize(password_file_bytes).unwrap();
    let mut server_rng = OsRng;
    let server_login_start_result = ServerLogin::start(
        &mut server_rng,
        server_setup,
        Some(password_file),
        CredentialRequest::deserialize(&credential_request_bytes).unwrap(),
        username.as_bytes(),
        ServerLoginStartParameters::default(),
    )
    .unwrap();
    let credential_response_bytes = server_login_start_result.message.serialize();

    // Server sends credential_response_bytes to client

    // Sets up custom parameters for the KSF
    let custom_ksf =
        CustomKsf(scrypt::Params::new(8, 8, 1).expect("scrypt parameter should be valid"));

    let client_finish_params = ClientLoginFinishParameters {
        ksf: Some(&custom_ksf),
        ..core::default::Default::default()
    };

    let result = client_login_start_result.state.finish(
        password.as_bytes(),
        CredentialResponse::deserialize(&credential_response_bytes).unwrap(),
        client_finish_params,
    );

    if result.is_err() {
        // Client-detected login failure
        return false;
    }
    let client_login_finish_result = result.unwrap();
    let credential_finalization_bytes = client_login_finish_result.message.serialize();

    // Client sends credential_finalization_bytes to server

    let server_login_finish_result = server_login_start_result
        .state
        .finish(CredentialFinalization::deserialize(&credential_finalization_bytes).unwrap())
        .unwrap();

    client_login_finish_result.session_key == server_login_finish_result.session_key
}

fn main() {
    let mut rng = OsRng;
    let server_setup = ServerSetup::<Default>::new(&mut rng);

    let mut rl = Editor::<()>::new();
    let mut registered_users =
        HashMap::<String, GenericArray<u8, ServerRegistrationLen<Default>>>::new();
    loop {
        println!(
            "\nCurrently registered usernames: {:?}\n",
            registered_users.keys()
        );

        println!("Enter an option (1 or 2):");
        println!("1) Register a user");
        println!("2) Login as a user\n");
        let readline = rl.readline("> ");
        match readline {
            Ok(line) => {
                if line != "1" && line != "2" {
                    println!("Error: Invalid option (either specify 1 or 2)");
                    continue;
                }
                let (username, password) = get_two_strings("Username", "Password", &mut rl, None);
                match line.as_ref() {
                    "1" => {
                        registered_users.insert(
                            username.clone(),
                            account_registration(&server_setup, username, password),
                        );
                        continue;
                    }
                    "2" => match registered_users.get(&username) {
                        Some(password_file_bytes) => {
                            if account_login(&server_setup, username, password, password_file_bytes)
                            {
                                println!("\nLogin success!");
                            } else {
                                // Note that at this point, the client knows whether or not the
                                // login succeeded. In this example, we simply rely on
                                // client-reported result of login, but in a real client-server
                                // implementation, the server may not know the outcome of login yet,
                                // and extra care must be taken to ensure that the server can learn
                                // the outcome as well.
                                println!("\nIncorrect password, please try again.");
                            }
                        }
                        None => println!("Error: Could not find username registered"),
                    },
                    _ => exit(0),
                }
            }
            Err(err) => {
                handle_error(err);
                exit(0)
            }
        }
    }
}

// Helper functions

// Handle readline errors
fn handle_error(err: ReadlineError) {
    match err {
        ReadlineError::Interrupted => {
            println!("CTRL-C");
        }
        ReadlineError::Eof => {
            println!("CTRL-D");
        }
        err => {
            println!("Error: {:?}", err);
        }
    }
}

// A function run on the client which extracts two strings from the CLI
fn get_two_strings(
    s1: &str,
    s2: &str,
    rl: &mut Editor<()>,
    string1: Option<String>,
) -> (String, String) {
    let query = if string1.is_none() { s1 } else { s2 };
    let readline = rl.readline(&format!("{}: ", query));
    match readline {
        Ok(line) => match string1 {
            Some(x) => (x, line),
            None => get_two_strings(s1, s2, rl, Some(line)),
        },
        Err(err) => {
            handle_error(err);
            exit(0)
        }
    }
}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Demonstrates a simple client-server password-based login protocol
//! using OPAQUE, over a command-line interface
//!
//! The client-server interactions are executed in a three-step protocol
//! within the account_registration (for password registration) and
//! account_login (for password login) functions. These steps
//! must be performed in the specific sequence outlined in each of these
//! functions.
//!
//! The CipherSuite trait allows the application to configure the
//! primitives used by OPAQUE, but must be kept consistent across the steps
//! of the protocol.
//!
//! In a more realistic client-server interaction, the client must send
//! messages over "the wire" to the server. These bytes are serialized
//! and explicitly annotated in the below functions.

use generic_array::GenericArray;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::collections::HashMap;
use std::process::exit;

use opaque_ke::{
    ciphersuite::CipherSuite, rand::rngs::OsRng, ClientLogin, ClientLoginFinishParameters,
    ClientRegistration, ClientRegistrationFinishParameters, CredentialFinalization,
    CredentialRequest, CredentialResponse, RegistrationRequest, RegistrationResponse,
    RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration,
    ServerRegistrationLen, ServerSetup,
};

// The ciphersuite trait allows to specify the underlying primitives
// that will be used in the OPAQUE protocol
#[allow(dead_code)]
struct Default;

#[cfg(feature = "ristretto255")]
impl CipherSuite for Default {
    type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
    type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = opaque_ke::slow_hash::NoOpHash;
}

#[cfg(not(feature = "ristretto255"))]
impl CipherSuite for Default {
    type OprfGroup = p256_::ProjectivePoint;
    type KeGroup = p256_::PublicKey;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha256;
    type SlowHash = opaque_ke::slow_hash::NoOpHash;
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

    let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            RegistrationResponse::deserialize(&registration_response_bytes).unwrap(),
            ClientRegistrationFinishParameters::default(),
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

    let result = client_login_start_result.state.finish(
        password.as_bytes(),
        CredentialResponse::deserialize(&credential_response_bytes).unwrap(),
        ClientLoginFinishParameters::default(),
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
                                // Note that at this point, the client knows whether or not the login
                                // succeeded. In this example, we simply rely on client-reported result
                                // of login, but in a real client-server implementation, the server may not
                                // know the outcome of login yet, and extra care must be taken to ensure
                                // that the server can learn the outcome as well.
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

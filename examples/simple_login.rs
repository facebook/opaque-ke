// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

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

use rand_core::OsRng;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::process::exit;

use opaque_ke::{
    ciphersuite::CipherSuite,
    keypair::KeyPair,
    opaque::{
        ClientLogin, ClientRegistration, LoginFirstMessage, LoginSecondMessage, LoginThirdMessage,
        RegisterFirstMessage, RegisterSecondMessage, RegisterThirdMessage, ServerLogin,
        ServerRegistration,
    },
};

// The ciphersuite trait allows to specify the underlying primitives
// that will be used in the OPAQUE protocol
#[allow(dead_code)]
struct Default;
impl CipherSuite for Default {
    type Group = curve25519_dalek::ristretto::RistrettoPoint;
    type KeyFormat = opaque_ke::keypair::X25519KeyPair;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha256;
    type SlowHash = opaque_ke::slow_hash::NoOpHash;
}

// Password-based registration between a client and server
fn account_registration(
    server_kp: &opaque_ke::keypair::X25519KeyPair,
    password: String,
) -> Vec<u8> {
    let mut client_rng = OsRng;
    let (r1, client_state) =
        ClientRegistration::<Default>::start(password.as_bytes(), &mut client_rng).unwrap();
    let r1_bytes = r1.serialize();

    // Client sends r1_bytes to server

    let mut server_rng = OsRng;
    let (r2, server_state) = ServerRegistration::<Default>::start(
        RegisterFirstMessage::deserialize(&r1_bytes[..]).unwrap(),
        &mut server_rng,
    )
    .unwrap();
    let r2_bytes = r2.serialize();

    // Server sends r2_bytes to client

    let (r3, _) = client_state
        .finish(
            RegisterSecondMessage::deserialize(&r2_bytes[..]).unwrap(),
            server_kp.public(),
            &mut client_rng,
        )
        .unwrap();
    let r3_bytes = r3.serialize();

    // Client sends r3_bytes to server

    let password_file = server_state
        .finish(RegisterThirdMessage::deserialize(&r3_bytes[..]).unwrap())
        .unwrap();
    password_file.to_bytes()
}

// Password-based login between a client and server
fn account_login(
    server_kp: &opaque_ke::keypair::X25519KeyPair,
    password: String,
    password_file_bytes: &[u8],
) -> bool {
    let mut client_rng = OsRng;
    let (l1, client_state) =
        ClientLogin::<Default>::start(password.as_bytes(), &mut client_rng).unwrap();
    let l1_bytes = l1.serialize();

    // Client sends l1_bytes to server

    let password_file = ServerRegistration::<Default>::try_from(password_file_bytes).unwrap();
    let mut server_rng = OsRng;
    let (l2, server_state) = ServerLogin::start(
        password_file,
        &server_kp.private(),
        LoginFirstMessage::deserialize(&l1_bytes[..]).unwrap(),
        &mut server_rng,
    )
    .unwrap();
    let l2_bytes = l2.serialize();

    // Server sends l2_bytes to client

    let result = client_state.finish(
        LoginSecondMessage::deserialize(&l2_bytes[..]).unwrap(),
        &server_kp.public(),
        &mut client_rng,
    );

    if result.is_err() {
        // Client-detected login failure
        return false;
    }
    let (l3, client_shared_secret, _) = result.unwrap();
    let l3_bytes = l3.serialize();

    // Client sends l3_bytes to server

    let server_shared_secret = server_state
        .finish(LoginThirdMessage::deserialize(&l3_bytes[..]).unwrap())
        .unwrap();

    client_shared_secret == server_shared_secret
}

// A function run on the client which extracts a username and password from the CLI
fn get_username_and_password(rl: &mut Editor<()>, username: Option<String>) -> (String, String) {
    let query = if username.is_none() {
        "Username: "
    } else {
        "Password: "
    };
    let readline = rl.readline(query);
    match readline {
        Ok(line) => match username {
            Some(x) => (x, line),
            None => get_username_and_password(rl, Some(line)),
        },
        Err(ReadlineError::Interrupted) => {
            println!("CTRL-C");
            exit(0)
        }
        Err(ReadlineError::Eof) => {
            println!("CTRL-D");
            exit(0)
        }
        Err(err) => {
            println!("Error: {:?}", err);
            exit(0)
        }
    }
}

fn main() {
    let mut rng = OsRng;
    let server_kp = Default::generate_random_keypair(&mut rng).unwrap();

    let mut rl = Editor::<()>::new();
    let mut registered_users = HashMap::<String, Vec<u8>>::new();
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
                let (username, password) = get_username_and_password(&mut rl, None);
                match line.as_ref() {
                    "1" => {
                        registered_users
                            .insert(username, account_registration(&server_kp, password));
                        continue;
                    }
                    "2" => match registered_users.get(&username) {
                        Some(password_file_bytes) => {
                            if account_login(&server_kp, password, password_file_bytes) {
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
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                exit(0)
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                exit(0)
            }
            Err(err) => {
                println!("Error: {:?}", err);
                exit(0)
            }
        }
    }
}

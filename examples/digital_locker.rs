// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Demonstrates an implementation of a server-side secured digital locker using
//! the client's OPAQUE export key, over a command-line interface
//!
//! A client can password-protect a secret message to be stored in a digital locker,
//! controlled by the server. The locker's contents are only revealed to the holder
//! of the password when attempting to open the locker.
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

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::process::exit;

use opaque_ke::{
    ciphersuite::CipherSuite,
    keypair::PrivateKey,
    rand::{rngs::OsRng, RngCore},
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginStartParameters, ServerRegistration, ServerSetup,
};

// The ciphersuite trait allows to specify the underlying primitives
// that will be used in the OPAQUE protocol
#[allow(dead_code)]
struct Default;
impl CipherSuite for Default {
    type Group = curve25519_dalek::ristretto::RistrettoPoint;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = opaque_ke::slow_hash::NoOpHash;
    type PrivateKey = PrivateKey<Self::Group>;
}

struct Locker {
    contents: Vec<u8>,
    password_file: Vec<u8>,
}

// Given a key and plaintext, produce an AEAD ciphertext along with a nonce
fn encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..32]));

    let mut rng = OsRng;
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
    [nonce_bytes.to_vec(), ciphertext].concat()
}

// Decrypt using a key and a ciphertext (nonce included) to recover the original plaintext
fn decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..32]));
    cipher
        .decrypt(
            Nonce::from_slice(&ciphertext[..12]),
            ciphertext[12..].as_ref(),
        )
        .unwrap()
}

// Password-based registration and encryption of client secret message between a client and server
fn register_locker(
    server_setup: &ServerSetup<Default>,
    locker_id: usize,
    password: String,
    secret_message: String,
) -> Locker {
    let mut client_rng = OsRng;
    let client_registration_start_result =
        ClientRegistration::<Default>::start(&mut client_rng, password.as_bytes()).unwrap();
    let registration_request_bytes = client_registration_start_result.message.serialize();

    // Client sends registration_request_bytes to server
    let server_registration_start_result = ServerRegistration::<Default>::start(
        &server_setup,
        RegistrationRequest::deserialize(&registration_request_bytes[..]).unwrap(),
        &locker_id.to_be_bytes(),
    )
    .unwrap();
    let registration_response_bytes = server_registration_start_result.message.serialize();

    // Server sends registration_response_bytes to client

    let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            RegistrationResponse::deserialize(&registration_response_bytes[..]).unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let message_bytes = client_finish_registration_result.message.serialize();

    // Client encrypts secret message using export key
    let ciphertext = encrypt(
        &client_finish_registration_result.export_key,
        secret_message.as_bytes(),
    );

    // Client sends message_bytes to server

    let password_file = ServerRegistration::finish(
        RegistrationUpload::<Default>::deserialize(&message_bytes[..]).unwrap(),
    );

    Locker {
        contents: ciphertext,
        password_file: password_file.serialize(),
    }
}

// Open the contents of a locker with a password between a client and server
fn open_locker(
    server_setup: &ServerSetup<Default>,
    locker_id: usize,
    password: String,
    locker: &Locker,
) -> Result<String, String> {
    let mut client_rng = OsRng;
    let client_login_start_result =
        ClientLogin::<Default>::start(&mut client_rng, password.as_bytes()).unwrap();
    let credential_request_bytes = client_login_start_result.message.serialize();

    // Client sends credential_request_bytes to server

    let password_file =
        ServerRegistration::<Default>::deserialize(&locker.password_file[..]).unwrap();
    let mut server_rng = OsRng;
    let server_login_start_result = ServerLogin::start(
        &mut server_rng,
        &server_setup,
        Some(password_file),
        CredentialRequest::deserialize(&credential_request_bytes[..]).unwrap(),
        &locker_id.to_be_bytes(),
        ServerLoginStartParameters::default(),
    )
    .unwrap();
    let credential_response_bytes = server_login_start_result.message.serialize();

    // Server sends credential_response_bytes to client

    let result = client_login_start_result.state.finish(
        CredentialResponse::deserialize(&credential_response_bytes[..]).unwrap(),
        ClientLoginFinishParameters::default(),
    );

    if result.is_err() {
        // Client-detected login failure
        return Err(String::from("Incorrect password, please try again."));
    }
    let client_login_finish_result = result.unwrap();
    let credential_finalization_bytes = client_login_finish_result.message.serialize();

    // Client sends credential_finalization_bytes to server

    let server_login_finish_result = server_login_start_result
        .state
        .finish(CredentialFinalization::deserialize(&credential_finalization_bytes[..]).unwrap())
        .unwrap();

    // Server sends locker contents, encrypted under the session key, to the client
    let encrypted_locker_contents =
        encrypt(&server_login_finish_result.session_key, &locker.contents);

    // Client decrypts contents of locker, first under the session key, and then under the export key
    let plaintext = decrypt(
        &client_login_finish_result.export_key,
        &decrypt(
            &client_login_finish_result.session_key,
            &encrypted_locker_contents,
        ),
    );
    String::from_utf8(plaintext).map_err(|_| String::from("UTF8 error"))
}

fn main() {
    let mut rng = OsRng;
    let server_setup = ServerSetup::<Default>::new(&mut rng);

    let mut rl = Editor::<()>::new();
    let mut registered_lockers: Vec<Locker> = vec![];
    loop {
        display_lockers(&registered_lockers);

        println!("Enter an option (1 or 2):");
        println!("1) Register a locker");
        println!("2) Open a locker\n");
        let readline = rl.readline("> ");
        match readline {
            Ok(line) => {
                if line != "1" && line != "2" {
                    println!("Error: Invalid option (either specify 1 or 2)");
                    continue;
                }
                match line.as_ref() {
                    "1" => {
                        let (password, secret_message) = get_two_strings(
                            "Choose a password",
                            "Set a secret message",
                            &mut rl,
                            None,
                        );
                        let locker_id = registered_lockers.len();
                        registered_lockers.push(register_locker(
                            &server_setup,
                            locker_id,
                            password,
                            secret_message,
                        ));
                        continue;
                    }
                    "2" => {
                        let (locker, password) = get_two_strings(
                            "Choose a locker number",
                            "Enter the password",
                            &mut rl,
                            None,
                        );
                        let locker_index: usize = match locker.parse() {
                            Ok(index) => index,
                            Err(_) => {
                                println!("Error: Could not find locker number");
                                continue;
                            }
                        };

                        if locker_index >= registered_lockers.len() {
                            println!("Error: Could not find locker number");
                            continue;
                        }

                        match open_locker(
                            &server_setup,
                            locker_index,
                            password,
                            &registered_lockers[locker_index],
                        ) {
                            Ok(contents) => {
                                println!("\n\nSuccess! Contents: {}\n\n", contents);
                            }
                            Err(err) => {
                                println!(
                                    "\n\nError encountered, could not open locker: {}\n\n",
                                    err
                                );
                            }
                        }
                    }
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

fn display_lockers(lockers: &Vec<Locker>) {
    let mut locker_numbers = vec![];
    for (i, _) in lockers.iter().enumerate() {
        locker_numbers.push(i);
    }

    println!(
        "\nCurrently registered locker numbers: {:?}\n",
        locker_numbers
    );
}

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

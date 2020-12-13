// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of the OPAQUE asymmetric password authentication key exchange protocol
//!
//! Note: This implementation is in sync with [draft-irtf-cfrg-opaque-01](https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-01.html),
//! but this specification is subject to change, until the final version published by the IETF.
//!
//! # Overview
//!
//! OPAQUE is a protocol between a client and a server. They must first agree on a collection of primitives
//! to be kept consistent throughout protocol execution. These include:
//! * a finite cyclic group along with a point representation,
//! * a keypair type,
//! * a key exchange protocol,
//! * a hashing function, and
//! * a slow hashing function.
//!
//! We will use the following choices in this example:
//! ```
//! use opaque_ke::ciphersuite::CipherSuite;
//! struct Default;
//! impl CipherSuite for Default {
//!     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//!     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//!     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//!     type Hash = sha2::Sha256;
//!     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! }
//! ```
//!
//! Note that our choice of slow hashing function in this example, `NoOpHash`, is selected only to ensure
//! that the tests execute quickly. A real application should use an actual slow hashing function, such as `scrypt`,
//! which can be enabled through the `slow-hash` feature.
//!
//! ## Setup
//! To set up the protocol, the server begins by generating a static keypair:
//! ```
//! # use opaque_ke::keypair::{KeyPair, X25519KeyPair};
//! # use opaque_ke::errors::ProtocolError;
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha256;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! use rand_core::{OsRng, RngCore};
//! let mut rng = OsRng;
//! let server_kp = Default::generate_random_keypair(&mut rng)?;
//! # Ok::<(), ProtocolError>(())
//! ```
//! The server must persist this keypair for the registration and login steps, where the public component will be
//! used by the client during both registration and login, and the private component will be used by the server during login.
//!
//! ## Registration
//! The registration protocol between the client and server consists of four steps along with three messages:
//! [RegistrationRequest], [RegistrationResponse], and [RegistrationUpload]. A successful execution of the registration protocol results in the
//! server producing a password file corresponding to the password provided by
//! the client. This password file is typically stored server-side, and retrieved upon future login attempts made by the client.
//!
//! ### Client Registration Start
//! In the first step of registration, the client chooses as input a registration password. The client runs [ClientRegistration::start]
//! to produce an output consisting of a [RegistrationRequest] to be sent to the server, and
//! a [ClientRegistration] which must be persisted on the client for the final step of client registration.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ServerRegistration,
//! #   keypair::{KeyPair, X25519KeyPair},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha256;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! use opaque_ke::{ClientRegistration, ClientRegistrationStartParameters};
//! use rand_core::{OsRng, RngCore};
//! let mut client_rng = OsRng;
//! let client_registration_start_result = ClientRegistration::<Default>::start(
//!     &mut client_rng,
//!     b"password",
//!     ClientRegistrationStartParameters::default(),
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! ### Server Registration Start
//! In the second step of registration, the server takes as input the instance of [RegistrationRequest] from the client, and
//! the server's public key `server_kp.public()`.
//! The server runs [ServerRegistration::start] to produce an output consisting of
//! a [RegistrationResponse] to be returned to the client, and
//! a [ServerRegistration] which must be persisted on the server for the final step of server registration.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationStartParameters,
//! #   keypair::{KeyPair, X25519KeyPair},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha256;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! #     ClientRegistrationStartParameters::default(),
//! # )?;
//! use opaque_ke::ServerRegistration;
//! let mut server_rng = OsRng;
//! let server_kp = Default::generate_random_keypair(&mut server_rng)?;
//! let server_registration_start_result = ServerRegistration::<Default>::start(
//!     &mut server_rng,
//!     client_registration_start_result.message,
//!     server_kp.public(),
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! ### Client Registration Finish
//! In the third step of registration, the client takes as input
//! a [RegistrationResponse] from the server, and
//! a [ClientRegistration] from the first step of registration.
//! The client runs [ClientRegistration::finish] to produce an output consisting of a [RegistrationUpload]
//! to be sent to the server.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationStartParameters, ServerRegistration,
//! #   keypair::{KeyPair, X25519KeyPair},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha256;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! #     ClientRegistrationStartParameters::default(),
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_kp = Default::generate_random_keypair(&mut server_rng)?;
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&mut server_rng, client_registration_start_result.message, server_kp.public())?;
//! let client_registration_finish_result = client_registration_start_result.state.finish(
//!     &mut client_rng,
//!     server_registration_start_result.message,
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! ### Server Registration Finish
//! In the fourth step of registration, the server takes as input
//! a [RegistrationUpload] from the client, and
//! a [ServerRegistration] from the second step.
//! The server runs [ServerRegistration::finish] to produce a finalized [ServerRegistration].
//! At this point, the client can be considered as successfully registered, and the server can invoke
//! [ServerRegistration::to_bytes] to store the password file for use during the login protocol.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationStartParameters, ServerRegistration,
//! #   keypair::{KeyPair, X25519KeyPair},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha256;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! #     ClientRegistrationStartParameters::default(),
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_kp = Default::generate_random_keypair(&mut server_rng)?;
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&mut server_rng, client_registration_start_result.message, server_kp.public())?;
//! # let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message)?;
//! let password_file = server_registration_start_result.state.finish(
//!     client_registration_finish_result.message,
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! ## Login
//! The login protocol between a client and server also consists of four steps along with three messages:
//! [CredentialRequest], [CredentialResponse], [CredentialFinalization]. The server is expected to have access to the password file
//! corresponding to an output of the registration phase. The login protocol will execute successfully only if the same password
//! was used in the registration phase that produced the password file that the server is testing against.
//!
//! ### Client Login Start
//! In the first step of login, the client chooses as input a login password.
//! The client runs [ClientLogin::start] to produce an output consisting of
//! a [CredentialRequest] to be sent to the server, and
//! a [ClientLogin] which must be persisted on the client for the final step of client login.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ServerRegistration, ServerLogin, CredentialFinalization,
//! #   keypair::{KeyPair, X25519KeyPair},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha256;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! use opaque_ke::{ClientLogin, ClientLoginStartParameters};
//! let mut client_rng = OsRng;
//! let client_login_start_result = ClientLogin::<Default>::start(
//!   &mut client_rng,
//!   b"password",
//!   ClientLoginStartParameters::default(),
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! ### Server Login Start
//! In the second step of login, the server takes as input
//! a [CredentialRequest] from the client,
//! the server's private key `server_kp.private()`, and
//! the password file output from registration.
//! The server runs [ServerLogin::start] to produce an output consisting of
//! a [CredentialResponse] which is returned to the client, and
//! a [ServerLogin] which must be persisted on the server for the final step of login.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationStartParameters, ServerRegistration, ClientLogin, ClientLoginStartParameters, CredentialFinalization,
//! #   keypair::{KeyPair, X25519KeyPair},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha256;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! #     ClientRegistrationStartParameters::default(),
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_kp = Default::generate_random_keypair(&mut server_rng)?;
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&mut server_rng, client_registration_start_result.message, server_kp.public())?;
//! # let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message)?;
//! # let password_file_bytes = server_registration_start_result.state.finish(client_registration_finish_result.message)?.to_bytes();
//! # let client_login_start_result = ClientLogin::<Default>::start(
//! #   &mut client_rng,
//! #   b"password",
//! #   ClientLoginStartParameters::default(),
//! # )?;
//! use opaque_ke::{ServerLogin, ServerLoginStartParameters};
//! use std::convert::TryFrom;
//! let password_file = ServerRegistration::<Default>::try_from(&password_file_bytes[..])?;
//! let mut server_rng = OsRng;
//! let server_login_start_result = ServerLogin::start(
//!     &mut server_rng,
//!     password_file,
//!     &server_kp.private(),
//!     client_login_start_result.message,
//!     ServerLoginStartParameters::default(),
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! ### Client Login Finish
//! In the third step of login, the client takes as input a [CredentialResponse] from the server.
//! The client runs [ClientLogin::finish] and produces an output consisting of
//! a [CredentialFinalization] to be sent to the server to complete the protocol,
//! the `shared_secret` sequence of bytes which will match the server's shared secret upon a successful login.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationStartParameters, ServerRegistration, ClientLogin, ClientLoginStartParameters, ClientLoginFinishParameters, ServerLogin, ServerLoginStartParameters, CredentialFinalization,
//! #   keypair::{KeyPair, X25519KeyPair},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha256;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! #     ClientRegistrationStartParameters::default(),
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_kp = Default::generate_random_keypair(&mut server_rng)?;
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&mut server_rng, client_registration_start_result.message, server_kp.public())?;
//! # let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message)?;
//! # let password_file_bytes = server_registration_start_result.state.finish(client_registration_finish_result.message)?.to_bytes();
//! # let client_login_start_result = ClientLogin::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! #     ClientLoginStartParameters::default(),
//! # )?;
//! # use std::convert::TryFrom;
//! # let password_file =
//! #   ServerRegistration::<Default>::try_from(
//! #     &password_file_bytes[..],
//! #   )?;
//! # let server_login_start_result =
//! #     ServerLogin::start(&mut server_rng, password_file, &server_kp.private(), client_login_start_result.message, ServerLoginStartParameters::default())?;
//! let client_login_finish_result = client_login_start_result.state.finish(
//!   server_login_start_result.message,
//!   ClientLoginFinishParameters::default(),
//! )?;
//! assert_eq!(
//!     client_registration_finish_result.export_key,
//!     client_login_finish_result.export_key,
//! );
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! ### Server Login Finish
//! In the fourth step of login, the server takes as input a [CredentialFinalization] from the client and runs [ServerLogin::finish] to
//! produce an output consisting of the `shared_secret` sequence of bytes which will match the client's shared secret upon a successful login.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationStartParameters, ServerRegistration, ClientLogin, ClientLoginStartParameters, ClientLoginFinishParameters, ServerLogin, ServerLoginStartParameters, CredentialFinalization,
//! #   keypair::{KeyPair, X25519KeyPair},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha256;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! #     ClientRegistrationStartParameters::default(),
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_kp = Default::generate_random_keypair(&mut server_rng)?;
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&mut server_rng, client_registration_start_result.message, server_kp.public())?;
//! # let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message)?;
//! # let password_file_bytes = server_registration_start_result.state.finish(client_registration_finish_result.message)?.to_bytes();
//! # let client_login_start_result = ClientLogin::<Default>::start(
//! #   &mut client_rng,
//! #   b"password",
//! #   ClientLoginStartParameters::default(),
//! # )?;
//! # use std::convert::TryFrom;
//! # let password_file =
//! #   ServerRegistration::<Default>::try_from(
//! #     &password_file_bytes[..],
//! #   )?;
//! # let server_login_start_result =
//! #     ServerLogin::start(&mut server_rng, password_file, &server_kp.private(), client_login_start_result.message, ServerLoginStartParameters::default())?;
//! # let client_login_finish_result = client_login_start_result.state.finish(
//! #   server_login_start_result.message,
//! #   ClientLoginFinishParameters::default(),
//! # )?;
//! let server_login_finish_result = server_login_start_result.state.finish(
//!    client_login_finish_result.message,
//! )?;
//! assert_eq!(
//!    client_login_finish_result.shared_secret,
//!    server_login_finish_result.shared_secret,
//! );
//! # Ok::<(), ProtocolError>(())
//! ```
//! If the protocol completes successfully, then the server obtains a `server_login_finish_result.shared_secret` which is guaranteed to
//! match `client_login_finish_result.shared_secret`. Otherwise, on failure, the [ServerLogin::finish] algorithm outputs the error [InvalidLoginError](errors::PakeError::InvalidLoginError).
//!

#![cfg_attr(not(feature = "bench"), deny(missing_docs))]
#![deny(unsafe_code)]

#[cfg(not(any(feature = "u64_backend", feature = "u32_backend",)))]
compile_error!(
    "no dalek arithmetic backend cargo feature enabled! \
     please enable one of: u64_backend, u32_backend"
);

// Error types
pub mod errors;

// High-level API
mod opaque;

mod messages;

pub mod ciphersuite;
mod envelope;
pub mod hash;

mod elligator;
pub mod group;

pub mod map_to_curve;

pub mod key_exchange;
pub mod keypair;

#[cfg(feature = "bench")]
pub mod oprf;
#[cfg(not(feature = "bench"))]
mod oprf;

pub mod slow_hash;

mod serialization;

#[cfg(test)]
mod tests;

// Exports

pub use crate::messages::{
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    RegistrationResponse, RegistrationUpload,
};
pub use crate::opaque::{ClientLogin, ClientRegistration, ServerLogin, ServerRegistration};
pub use crate::opaque::{
    ClientLoginFinishParameters, ClientLoginStartParameters, ClientRegistrationStartParameters,
    ServerLoginStartParameters,
};

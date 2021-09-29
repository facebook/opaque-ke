// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of the OPAQUE asymmetric password authentication key exchange protocol
//!
//! Note: This implementation is in sync with [draft-irtf-cfrg-opaque-05](https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-05.html),
//! but this specification is subject to change, until the final version published by the IETF.
//!
//! ### Minimum Supported Rust Version
//!
//! Rust **1.51** or higher.
//!
//! # Overview
//!
//! OPAQUE is a protocol between a client and a server. They must first agree on a collection of primitives
//! to be kept consistent throughout protocol execution. These include:
//! * a finite cyclic group along with a point representation
//!   * for the OPRF and
//!   * for the key exchange
//! * a key exchange protocol,
//! * a hashing function, and
//! * a slow hashing function.
//!
//! We will use the following choices in this example:
//! ```
//! use opaque_ke::CipherSuite;
//! struct Default;
//! impl CipherSuite for Default {
//!     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//!     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//!     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//!     type Hash = sha2::Sha512;
//!     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! }
//! ```
//! See [examples/simple_login.rs](https://github.com/novifinancial/opaque-ke/blob/main/examples/simple_login.rs)
//! for a working example of a simple password-based login using OPAQUE.
//!
//! Note that our choice of slow hashing function in this example, `NoOpHash`, is selected only to ensure
//! that the tests execute quickly. A real application should use an actual slow hashing function, such as `Argon2`,
//! which can be enabled through the `slow-hash` feature. See more details in the [features](#features) section.
//!
//! ## Setup
//! To set up the protocol, the server begins by creating a `ServerSetup` object:
//! ```
//! # use opaque_ke::errors::ProtocolError;
//! # use opaque_ke::CipherSuite;
//! # use opaque_ke::ServerSetup;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! use rand::{rngs::OsRng, RngCore};
//! let mut rng = OsRng;
//! let server_setup = ServerSetup::<Default>::new(&mut rng);
//! # Ok::<(), ProtocolError>(())
//! ```
//! The server must persist an instance of [ServerSetup] for the registration and login steps.
//!
//! ## Registration
//! The registration protocol between the client and server consists of four steps along with three messages:
//! [RegistrationRequest], [RegistrationResponse], and [RegistrationUpload]. A successful execution of the registration protocol results in the
//! server producing a password file corresponding to a server-side identifier for the client, along with the password provided by
//! the client. This password file is typically stored in a key-value database, where the keys consist of these server-side identifiers for each client,
//! and the values consist of their corresponding password files, to be retrieved upon future login attempts made by the client.
//!
//! ### Client Registration Start
//! In the first step of registration, the client chooses as input a registration password. The client runs [ClientRegistration::start]
//! to produce a [ClientRegistrationStartResult], which consists of a [RegistrationRequest] to be sent to the server and
//! a [ClientRegistration] which must be persisted on the client for the final step of client registration.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ServerRegistration,
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! use opaque_ke::ClientRegistration;
//! use rand::{rngs::OsRng, RngCore};
//! let mut client_rng = OsRng;
//! let client_registration_start_result = ClientRegistration::<Default>::start(
//!     &mut client_rng,
//!     b"password",
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! ### Server Registration Start
//! In the second step of registration, the server takes as input a persisted instance of [ServerSetup], a [RegistrationRequest] from the client, and
//! a server-side identifier for the client.
//! The server runs [ServerRegistration::start] to produce a [ServerRegistrationStartResult], which consists of
//! a [RegistrationResponse] to be returned to the client.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration,
//! #   ServerSetup,
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand::{rngs::OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! use opaque_ke::ServerRegistration;
//! # let mut server_rng = OsRng;
//! # let server_setup = ServerSetup::<Default>::new(&mut server_rng);
//! let server_registration_start_result = ServerRegistration::<Default>::start(
//!     &server_setup,
//!     client_registration_start_result.message,
//!     b"alice@example.com",
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! ### Client Registration Finish
//! In the third step of registration, the client takes as input
//! a [RegistrationResponse] from the server, and
//! a [ClientRegistration] from the first step of registration.
//! The client runs [ClientRegistration::finish] to produce a [ClientRegistrationFinishResult], which consists of a [RegistrationUpload]
//! to be sent to the server and an `export_key` field which can be used optionally as described in the [Export Key](#export-key) section.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ServerSetup,
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand::{rngs::OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_setup = ServerSetup::<Default>::new(&mut server_rng);
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&server_setup, client_registration_start_result.message, b"alice@example.com")?;
//! let client_registration_finish_result = client_registration_start_result.state.finish(
//!     &mut client_rng,
//!     server_registration_start_result.message,
//!     ClientRegistrationFinishParameters::default(),
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
//! [ServerRegistration::serialize] to store the password file for use during the login protocol.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ServerSetup,
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand::{rngs::OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_setup = ServerSetup::<Default>::new(&mut server_rng);
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&server_setup, client_registration_start_result.message, b"alice@example.com")?;
//! # let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message, ClientRegistrationFinishParameters::default())?;
//! let password_file = ServerRegistration::<Default>::finish(
//!     client_registration_finish_result.message,
//! );
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! ## Login
//! The login protocol between a client and server also consists of four steps along with three messages:
//! [CredentialRequest], [CredentialResponse], [CredentialFinalization]. The server is expected to have access to the password file
//! corresponding to an output of the registration phase (see [Dummy Server Login](#dummy-server-login) for handling the scenario where
//! no password file is available). The login protocol will execute successfully only if the same password
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
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand::{rngs::OsRng, RngCore};
//! use opaque_ke::ClientLogin;
//! let mut client_rng = OsRng;
//! let client_login_start_result = ClientLogin::<Default>::start(
//!   &mut client_rng,
//!   b"password",
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! ### Server Login Start
//! In the second step of login, the server takes as input
//! a persisted instance of [ServerSetup],
//! the password file output from registration,
//! a [CredentialRequest] from the client, and
//! a server-side identifier for the client.
//! The server runs [ServerLogin::start] to produce an output consisting of
//! a [CredentialResponse] which is returned to the client, and
//! a [ServerLogin] which must be persisted on the server for the final step of login.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ClientLogin, CredentialFinalization, ServerSetup,
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand::{rngs::OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_setup = ServerSetup::<Default>::new(&mut server_rng);
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&server_setup, client_registration_start_result.message, b"alice@example.com")?;
//! # let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message, ClientRegistrationFinishParameters::default())?;
//! # let password_file_bytes = ServerRegistration::<Default>::finish(client_registration_finish_result.message).serialize();
//! # let client_login_start_result = ClientLogin::<Default>::start(
//! #   &mut client_rng,
//! #   b"password",
//! # )?;
//! use opaque_ke::{ServerLogin, ServerLoginStartParameters};
//! let password_file = ServerRegistration::<Default>::deserialize(&password_file_bytes[..])?;
//! let mut server_rng = OsRng;
//! let server_login_start_result = ServerLogin::start(
//!     &mut server_rng,
//!     &server_setup,
//!     Some(password_file),
//!     client_login_start_result.message,
//!     b"alice@example.com",
//!     ServerLoginStartParameters::default(),
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//! Note that if there is no corresponding password file found for the user,
//! the server can use `None` in place of `Some(password_file)` in order to generate
//! a [CredentialResponse] that is indistinguishable from a valid [CredentialResponse]
//! returned for a registered client. This allows the server to prevent leaking information
//! about whether or not a client has previously registered with the server.
//!
//! ### Client Login Finish
//! In the third step of login, the client takes as input a [CredentialResponse] from the server.
//! The client runs [ClientLogin::finish] and produces an output consisting of
//! a [CredentialFinalization] to be sent to the server to complete the protocol,
//! the `session_key` sequence of bytes which will match the server's session key upon a successful login.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ClientLogin, ClientLoginFinishParameters, ServerLogin, ServerLoginStartParameters, CredentialFinalization, ServerSetup,
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand::{rngs::OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_setup = ServerSetup::<Default>::new(&mut server_rng);
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&server_setup, client_registration_start_result.message, b"alice@example.com")?;
//! # let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message, ClientRegistrationFinishParameters::default())?;
//! # let password_file_bytes = ServerRegistration::<Default>::finish(client_registration_finish_result.message).serialize();
//! # let client_login_start_result = ClientLogin::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let password_file =
//! #   ServerRegistration::<Default>::deserialize(
//! #     &password_file_bytes[..],
//! #   )?;
//! # let server_login_start_result =
//! #     ServerLogin::start(&mut server_rng, &server_setup, Some(password_file), client_login_start_result.message, b"alice@example.com", ServerLoginStartParameters::default())?;
//! let client_login_finish_result = client_login_start_result.state.finish(
//!     server_login_start_result.message,
//!     ClientLoginFinishParameters::default(),
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! ### Server Login Finish
//! In the fourth step of login, the server takes as input a [CredentialFinalization] from the client and runs [ServerLogin::finish] to
//! produce an output consisting of the `session_key` sequence of bytes which will match the client's session key upon a successful login.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ClientLogin, ClientLoginFinishParameters, ServerLogin, ServerLoginStartParameters, CredentialFinalization, ServerSetup,
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand::{rngs::OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_setup = ServerSetup::<Default>::new(&mut server_rng);
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&server_setup, client_registration_start_result.message, b"alice@example.com")?;
//! # let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message, ClientRegistrationFinishParameters::default())?;
//! # let password_file_bytes = ServerRegistration::<Default>::finish(client_registration_finish_result.message).serialize();
//! # let client_login_start_result = ClientLogin::<Default>::start(
//! #   &mut client_rng,
//! #   b"password",
//! # )?;
//! # let password_file =
//! #   ServerRegistration::<Default>::deserialize(
//! #     &password_file_bytes[..],
//! #   )?;
//! # let server_login_start_result =
//! #     ServerLogin::start(&mut server_rng, &server_setup, Some(password_file), client_login_start_result.message, b"alice@example.com", ServerLoginStartParameters::default())?;
//! # let client_login_finish_result = client_login_start_result.state.finish(
//! #   server_login_start_result.message,
//! #   ClientLoginFinishParameters::default(),
//! # )?;
//! let server_login_finish_result = server_login_start_result.state.finish(
//!     client_login_finish_result.message,
//! )?;
//!
//! assert_eq!(
//!    client_login_finish_result.session_key,
//!    server_login_finish_result.session_key,
//! );
//! # Ok::<(), ProtocolError>(())
//! ```
//! If the protocol completes successfully, then the server obtains a `server_login_finish_result.session_key` which is guaranteed to
//! match `client_login_finish_result.session_key` (see the [Session Key](#session-key) section).
//! Otherwise, on failure, the [ServerLogin::finish] algorithm outputs the error [InvalidLoginError](errors::ProtocolError::InvalidLoginError).
//!
//! # Advanced Usage
//!
//! This implementation offers support for several optional features of OPAQUE, described below. They are not critical to the
//! execution of the main protocol, but can provide additional security benefits which can be suitable for various applications that rely on
//! OPAQUE for authentication.
//!
//! ## Session Key
//!
//! Upon a successful completion of the OPAQUE protocol (the client runs login with the same password used during registration),
//! the client and server have access to a session key, which is a pseudorandomly distributed 32-byte string which only the client
//! and server know. Multiple login runs using the same password for the same client will produce different session keys, distributed
//! as uniformly random strings. Thus, the session key can be used to establish a secure channel between the client and server.
//!
//! The session key can be accessed from the `session_key` field of [ClientLoginFinishResult] and [ServerLoginFinishResult]. See
//! the combination of [Client Login Finish](#client-login-finish) and [Server Login Finish](#server-login-finish) for example usage.
//!
//! ## Checking Server Consistency
//!
//! A [ClientLoginFinishResult] contains the `server_s_pk` field, which is represents the static public key of the server that is established
//! during the setup phase. This can be used by the client to verify the authenticity of the server it engages with during the login phase. In particular,
//! the client can check that the static public key of the server supplied during registration (with the `server_s_pk` field of
//! [ClientRegistrationFinishResult]) matches this field during login.
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ClientLogin, ClientLoginFinishParameters, ServerLogin, ServerLoginStartParameters, CredentialFinalization, ServerSetup,
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand::{rngs::OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_setup = ServerSetup::<Default>::new(&mut server_rng);
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&server_setup, client_registration_start_result.message, b"alice@example.com")?;
//! // During registration, the client obtains a ClientRegistrationFinishResult with
//! // a server_s_pk field
//! let client_registration_finish_result = client_registration_start_result.state.finish(
//!     &mut client_rng,
//!     server_registration_start_result.message,
//!     ClientRegistrationFinishParameters::default(),
//! )?;
//! # let password_file_bytes = ServerRegistration::<Default>::finish(client_registration_finish_result.message).serialize();
//! # let client_login_start_result = ClientLogin::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let password_file =
//! #   ServerRegistration::<Default>::deserialize(
//! #     &password_file_bytes[..],
//! #   )?;
//! # let server_login_start_result =
//! #     ServerLogin::start(&mut server_rng, &server_setup, Some(password_file), client_login_start_result.message, b"alice@example.com", ServerLoginStartParameters::default())?;
//!
//! // And then later, during login...
//! let client_login_finish_result = client_login_start_result.state.finish(
//!     server_login_start_result.message,
//!     ClientLoginFinishParameters::default(),
//! )?;
//!
//! // Check that the server's static public key obtained from login matches what
//! // was obtained during registration
//! assert_eq!(
//!     &client_registration_finish_result.server_s_pk,
//!     &client_login_finish_result.server_s_pk,
//! );
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! Note that without this check over the consistency of the server's static public key, a malicious actor could impersonate the registration server if it were able to copy the password
//! file output during registration! Therefore, it is recommended to perform the following check in the application layer if the client can obtain a copy of the server's static
//! public key beforehand.
//!
//!
//! ## Export Key
//!
//! The export key is a pseudorandomly distributed 32-byte string output by both the
//! [Client Registration Finish](#client-registration-finish) and [Client Login Finish](#client-login-finish) steps.
//! The same export key string will be output by both functions only if the exact same password is passed to [ClientRegistration::start] and [ClientLogin::start].
//!
//! The export key retains as much secrecy as the password itself, and is similarly derived through an evaluation of the slow hashing function. Hence, only the parties which
//! know the password the client uses during registration and login can recover this secret, as it is never exposed to the server. As a result, the export key
//! can be used (separately from the OPAQUE protocol) to provide confidentiality and integrity to other data which only the client should be able to process.
//! For instance, if the server is expected to maintain any client-side secrets which require a password to access, then this export key can be used to encrypt
//! these secrets so that they remain hidden from the server (see [examples/digital_locker.rs](https://github.com/novifinancial/opaque-ke/blob/main/examples/digital_locker.rs)
//! for a working example).
//!
//! You can access the export key from the `export_key` field of [ClientRegistrationFinishResult] and [ClientLoginFinishResult].
//!
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ClientLogin, ClientLoginFinishParameters, ServerLogin, ServerLoginStartParameters, CredentialFinalization, ServerSetup,
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand::{rngs::OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_setup = ServerSetup::<Default>::new(&mut server_rng);
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&server_setup, client_registration_start_result.message, b"alice@example.com")?;
//! // During registration...
//! let client_registration_finish_result = client_registration_start_result.state.finish(
//!     &mut client_rng,
//!     server_registration_start_result.message,
//!     ClientRegistrationFinishParameters::default()
//! )?;
//! # let password_file_bytes = ServerRegistration::<Default>::finish(client_registration_finish_result.message).serialize();
//! # let client_login_start_result = ClientLogin::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let password_file =
//! #   ServerRegistration::<Default>::deserialize(
//! #     &password_file_bytes[..],
//! #   )?;
//! # let server_login_start_result =
//! #     ServerLogin::start(&mut server_rng, &server_setup, Some(password_file), client_login_start_result.message, b"alice@example.com", ServerLoginStartParameters::default())?;
//!
//! // And then later, during login...
//! let client_login_finish_result = client_login_start_result.state.finish(
//!     server_login_start_result.message,
//!     ClientLoginFinishParameters::default(),
//! )?;
//!
//! assert_eq!(
//!     client_registration_finish_result.export_key,
//!     client_login_finish_result.export_key,
//! );
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! ## Custom Identifiers
//!
//! Typically when applications use OPAQUE to authenticate a client to a server, the client has a registered username which is sent to the server to
//! identify the corresponding password file established during registration. This username may or may not coincide with the server-side identifier;
//! however, this username must be known to both the client and the server (whereas the server-side identifier does not need to be exposed to the client).
//! The server may also have an identifier corresponding to an entity (e.g. Facebook).
//! By default, neither of these public identifiers need to be supplied to the OPAQUE protocol.
//!
//! But, for applications that wish to cryptographically bind these identities to
//! the registered password file as well as the session key output by the login phase, these custom identifiers can be specified through
//! [ClientRegistrationFinishParameters] in [Client Registration Finish](#client-registration-finish):
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationFinishParameters, Identifiers, ServerRegistration, ServerSetup,
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand::{rngs::OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_setup = ServerSetup::<Default>::new(&mut server_rng);
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&server_setup, client_registration_start_result.message, b"alice@example.com")?;
//! let client_registration_finish_result = client_registration_start_result.state.finish(
//!     &mut client_rng,
//!     server_registration_start_result.message,
//!     ClientRegistrationFinishParameters::new(
//!         Some(Identifiers::ClientAndServerIdentifiers(
//!             b"Alice_the_Cryptographer".to_vec(),
//!             b"Facebook".to_vec(),
//!         )),
//!         None,
//!     ),
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! The same identifiers must also be supplied using [ServerLoginStartParameters::WithIdentifiers] in [Server Login Start](#server-login-start):
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ClientLogin, CredentialFinalization, Identifiers, ServerSetup,
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand::{rngs::OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_setup = ServerSetup::<Default>::new(&mut server_rng);
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&server_setup, client_registration_start_result.message, b"alice@example.com")?;
//! # let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message, ClientRegistrationFinishParameters::new(Some(Identifiers::ClientAndServerIdentifiers(b"Alice_the_Cryptographer".to_vec(), b"Facebook".to_vec())), None))?;
//! # let password_file_bytes = ServerRegistration::<Default>::finish(client_registration_finish_result.message).serialize();
//! # let client_login_start_result = ClientLogin::<Default>::start(
//! #   &mut client_rng,
//! #   b"password",
//! # )?;
//! # use opaque_ke::{ServerLogin, ServerLoginStartParameters};
//! # let password_file = ServerRegistration::<Default>::deserialize(&password_file_bytes[..])?;
//! # let mut server_rng = OsRng;
//! let server_login_start_result = ServerLogin::start(
//!     &mut server_rng,
//!     &server_setup,
//!     Some(password_file),
//!     client_login_start_result.message,
//!     b"alice@example.com",
//!     ServerLoginStartParameters::WithIdentifiers(
//!         Identifiers::ClientAndServerIdentifiers(
//!             b"Alice_the_Cryptographer".to_vec(),
//!             b"Facebook".to_vec(),
//!         ),
//!     ),
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//!
//! as well as [ClientLoginFinishParameters] in [Client Login Finish](#client-login-finish):
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ClientLogin, ClientLoginFinishParameters, Identifiers, ServerLogin, ServerLoginStartParameters, CredentialFinalization, ServerSetup,
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand::{rngs::OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let client_registration_start_result = ClientRegistration::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let mut server_rng = OsRng;
//! # let server_setup = ServerSetup::<Default>::new(&mut server_rng);
//! # let server_registration_start_result = ServerRegistration::<Default>::start(&server_setup, client_registration_start_result.message, b"alice@example.com")?;
//! # let client_registration_finish_result = client_registration_start_result.state.finish(&mut client_rng, server_registration_start_result.message, ClientRegistrationFinishParameters::new(Some(Identifiers::ClientAndServerIdentifiers(b"Alice_the_Cryptographer".to_vec(), b"Facebook".to_vec())), None))?;
//! # let password_file_bytes = ServerRegistration::<Default>::finish(client_registration_finish_result.message).serialize();
//! # let client_login_start_result = ClientLogin::<Default>::start(
//! #     &mut client_rng,
//! #     b"password",
//! # )?;
//! # let password_file =
//! #   ServerRegistration::<Default>::deserialize(
//! #     &password_file_bytes[..],
//! #   )?;
//! # let server_login_start_result =
//! #     ServerLogin::start(&mut server_rng, &server_setup, Some(password_file), client_login_start_result.message, b"alice@example.com", ServerLoginStartParameters::WithIdentifiers(Identifiers::ClientAndServerIdentifiers(b"Alice_the_Cryptographer".to_vec(), b"Facebook".to_vec())))?;
//! let client_login_finish_result = client_login_start_result.state.finish(
//!     server_login_start_result.message,
//!     ClientLoginFinishParameters::new(
//!         None,
//!         Some(Identifiers::ClientAndServerIdentifiers(
//!             b"Alice_the_Cryptographer".to_vec(),
//!             b"Facebook".to_vec(),
//!         )),
//!         None,
//!     ),
//! )?;
//!
//! # Ok::<(), ProtocolError>(())
//! ```
//! Failing to supply the same pair of custom identifiers in any of the three steps above will result in an error in attempting to complete
//! the protocol!
//!
//! Note that if only one of the client and server identifiers are present, then [Identifiers::ClientIdentifier] and [Identifiers::ServerIdentifier] can be
//! used to specify them individually.
//!
//! ## Key Exchange Context
//!
//! A key exchange protocol typically allows for the specifying of shared "context" information between the two parties before the exchange is complete,
//! so as to bind the integrity of application-specific data or configuration parameters to the security of the key exchange.
//! During the login phase, the client and server can specify this context using:
//! - The second login message, where the server can populate [ServerLoginStartParameters::WithContext], and
//! - The third login message, where the client can populate [ClientLoginFinishParameters].
//!
//! For both of these messages, the `WithContextAndIdentifiers` variant can be used to specify these fields in addition to
//! [custom identifiers](#custom-identifiers), with the ordering of the fields as
//! `WithContextAndIdentifiers(context, Identifiers::ClientAndServerIdentifiers(username, server_name))`.
//!
//! ## Dummy Server Login
//!
//! For applications in which the server does not wish to reveal to the client whether an existing password file has been
//! registered, the server can return a "dummy" credential response message to the client for an unregistered client,
//! which is indistinguishable from the normal credential response message that the server would return for a registered client.
//! The dummy message is created by passing a `None` to the password_file parameter for [ServerLogin::start].
//!
//! ## Remote Private Keys
//!
//! Servers that want to store their private key in an external location (e.g. in an HSM or vault) can do so with the
//! [`SecretKey`](keypair::SecretKey`) trait. This allows [`ServerSetup`] to be constructed using an existing keypair
//! without exposing the bytes of the private key to this library.
//! ```
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use generic_array::{GenericArray, typenum::U32};
//! # use opaque_ke::{CipherSuite, errors::{InternalError}, keypair::{KeyPair, PrivateKey, PublicKey, SecretKey}, ServerSetup};
//! # use rand::rngs::OsRng;
//! # use zeroize::Zeroize;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type OprfGroup = RistrettoPoint;
//! #     type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
//! #     type Hash = sha2::Sha512;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # #[derive(Debug)]
//! # struct YourRemoteKeyError;
//! # #[derive(Clone, Zeroize)]
//! # struct YourRemoteKey(PrivateKey<RistrettoPoint>);
//! # impl YourRemoteKey {
//! #     fn diffie_hellman(&self, pk: &[u8]) -> Result<Vec<u8>, YourRemoteKeyError> { todo!() }
//! #     fn public_key(&self) -> Result<GenericArray<u8, U32>, YourRemoteKeyError> { Ok(GenericArray::default()) }
//! # }
//! impl SecretKey<RistrettoPoint> for YourRemoteKey {
//!     type Error = YourRemoteKeyError;
//!
//!     fn diffie_hellman(
//!         &self,
//!         pk: PublicKey<RistrettoPoint>,
//!     ) -> Result<Vec<u8>, InternalError<Self::Error>> {
//!         YourRemoteKey::diffie_hellman(self, &pk.to_arr()).map_err(InternalError::Custom)
//!     }
//!
//!     fn public_key(
//!         &self
//!     ) -> Result<PublicKey<RistrettoPoint>, InternalError<Self::Error>> {
//!         YourRemoteKey::public_key(self).map(PublicKey::from_arr)
//!             .map_err(InternalError::Custom)
//!     }
//!
//!     fn serialize(&self) -> Vec<u8> {
//!         // if you use serde and the "serialize" crate feature, you won't need this
//!         todo!()
//!     }
//!
//!     fn deserialize(input: &[u8]) -> Result<Self, InternalError<Self::Error>> {
//!         // if you use serde and the "serialize" crate feature, you won't need this
//!         todo!()
//!     }
//! }
//!
//! # let remote_key = YourRemoteKey(PrivateKey::from_arr(GenericArray::default()));
//! let keypair = KeyPair::from_private_key(remote_key).unwrap();
//! let server_setup = ServerSetup::<Default, YourRemoteKey>::new_with_key(&mut OsRng, keypair);
//! ```
//!
//! # Features
//!
//! - The `slow-hash` feature, when enabled, introduces a dependency on `argon2` and implements the `SlowHash` trait for `Argon2`
//! with a set of default parameters. In general, secure instantiations should choose to invoke a memory-hard password
//! hashing function when the client's password is expected to have low entropy, instead of relying on [slow_hash::NoOpHash]
//! as done in the above example. The more computationally intensive the `SlowHash` function is, the more resistant the server's
//! password file records will be against offline dictionary and precomputation attacks; see
//! [the OPAQUE paper](https://eprint.iacr.org/2018/163.pdf) for more details.
//!
//! - The `serialize` feature, enabled by default, provides convenience functions for serializing and deserializing with
//! [serde](https://serde.rs/).
//!
//! - The `u32_backend` and `u64_backend` features are re-exported from
//! [curve25519-dalek](https://doc.dalek.rs/curve25519_dalek/index.html#backends-and-features) and allow for selecting
//! the corresponding backend for the curve arithmetic used. The `u64_backend` feature is included as the default.
//!
//! - The `p256` feature enables the use of `p256::ProjectivePoint` as a `Group` for `CipherSuite`. Note that this
//! is currently an experimental feature ⚠️, and is not yet ready for production use.
//!
//! - The `bench` feature is used only for running performance benchmarks for this implementation.
//!

#![cfg_attr(not(feature = "bench"), deny(missing_docs))]
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(any(feature = "u64_backend", feature = "u32_backend",)))]
compile_error!(
    "no dalek arithmetic backend cargo feature enabled! \
     please enable one of: u64_backend, u32_backend"
);

extern crate alloc;

// Error types
pub mod errors;

#[macro_use]
mod impls;
#[macro_use]
mod serialization;
pub mod ciphersuite;
mod envelope;
pub mod group;
pub mod hash;
pub mod key_exchange;
pub mod keypair;
mod messages;
mod opaque;
pub mod slow_hash;

#[cfg(feature = "bench")]
pub mod oprf;
#[cfg(not(feature = "bench"))]
mod oprf;

#[cfg(test)]
mod tests;

// Exports

pub use rand;

pub use ciphersuite::CipherSuite;

pub use crate::messages::{
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    RegistrationResponse, RegistrationUpload,
};
pub use crate::opaque::{
    ClientLogin, ClientRegistration, ServerLogin, ServerRegistration, ServerSetup,
};
pub use crate::opaque::{
    ClientLoginFinishParameters, ClientRegistrationFinishParameters, ServerLoginStartParameters,
};
pub use crate::opaque::{
    ClientLoginFinishResult, ClientLoginStartResult, ClientRegistrationFinishResult,
    ClientRegistrationStartResult, Identifiers, ServerLoginFinishResult, ServerLoginStartResult,
    ServerRegistrationStartResult,
};

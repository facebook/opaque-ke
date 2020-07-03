// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of the OPAQUE asymmetric password authentication key exchange protocol
//!
//! Note: This implementation is in sync with [draft-krawczyk-cfrg-opaque-06](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-06),
//! but this specification is subject to change, until the final version published by the IETF.
//!
//! # Overview
//!
//! OPAQUE is a protocol between a client and a server. They must first agree on a collection of primitives
//! to be kept consistent throughout protocol execution. These include:
//! * a finite cyclic group along with a point representation,
//! * a keypair type, and
//! * a slow hashing function.
//!
//! We will use the following choices in this example:
//! ```
//! use opaque_ke::ciphersuite::CipherSuite;
//! struct Default;
//! impl CipherSuite for Default {
//!     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//!     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//!     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! }
//! ```
//!
//! Note that our choice of slow hashing function in this example, `NoOpHash`, is selected only to ensure
//! that the tests execute quickly. A real application should use an actual slow hashing function, such as `Scrypt`.
//!
//! We have included a concrete instantiation of the authenticated key exchange protocol using 3DH. In the future, we plan to
//! add support for other KE protocols as well.
//!
//! ## Setup
//! To setup the protocol, the server begins by generating a static keypair:
//! ```
//! # use opaque_ke::keypair::{KeyPair, X25519KeyPair, SizedBytes};
//! # use opaque_ke::errors::ProtocolError;
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
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
//! The registration protocol between the client and server consists of four steps along with three messages, denoted
//! as `r1`, `r2`, and `r3`. Before registration begins, it is expected that the server's static public key, `server_kp.public()`,
//! has been transmitted to the client in an offline step. A successful execution of the registration protocol results in the
//! server producing a password file corresponding to the tuple combination of (password, pepper, server public key) provided by
//! the client. This password file is typically stored server-side, and retrieved upon future login attempts made by the client.
//!
//! In the first step (client registration start), the client chooses a registration password and an optional "pepper", and
//! runs `ClientRegistration::start` to produce a message `r1`:
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   opaque::{ClientRegistration, ServerRegistration},
//! #   keypair::{KeyPair, X25519KeyPair, SizedBytes},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! use rand_core::{OsRng, RngCore};
//! let mut client_rng = OsRng;
//! let (r1, client_state) = ClientRegistration::<Default>::start(
//!     b"password",
//!     Some(b"pepper"),
//!     &mut client_rng,
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//! `r1` is sent to the server, and `client_state` must be persisted on the client for the final step of client
//! registration.
//!
//! In the second step (server registration start), the server takes as input the `r1` message from the client and runs
//! `ServerRegistration::start` to produce `r2`:
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   opaque::{ClientRegistration, ServerRegistration},
//! #   keypair::{KeyPair, X25519KeyPair, SizedBytes},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let (r1, client_state) = ClientRegistration::<Default>::start(
//! #     b"password",
//! #     Some(b"pepper"),
//! #     &mut client_rng,
//! # )?;
//! let mut server_rng = OsRng;
//! let (r2, server_state) = ServerRegistration::<Default>::start(r1, &mut server_rng)?;
//! # Ok::<(), ProtocolError>(())
//! ```
//! `r2` is returned to the client, and `server_state` must be persisted on the server for the final step of server
//! registration.
//!
//! In the third step (client registration finish), the client takes as input the `r2` message from the server, along
//! with the server's static public key `server_kp.public()`, and uses `client_state` from the first step to run
//! `finish` and produce a message `r3` along with the export key `export_key_registration`:
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   opaque::{ClientRegistration, ServerRegistration},
//! #   keypair::{KeyPair, X25519KeyPair, SizedBytes},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let (r1, client_state) = ClientRegistration::<Default>::start(
//! #     b"password",
//! #     Some(b"pepper"),
//! #     &mut client_rng,
//! # )?;
//! # let mut server_rng = OsRng;
//! let (r2, server_state) = ServerRegistration::<Default>::start(r1, &mut server_rng)?;
//! # let server_kp = Default::generate_random_keypair(&mut server_rng)?;
//! let (r3, export_key_registration) =
//!     client_state.finish(r2, server_kp.public(), &mut client_rng)?;
//! # Ok::<(), ProtocolError>(())
//! ```
//! `r3` is sent to the server, and the client can optionally use `export_key_registration` for applications that choose to
//! process user information beyond the OPAQUE functionality (e.g., additional secrets or credentials).
//!
//! In the fourth step of registration, the server takes as input the `r3` message from the client and uses
//! `server_state` from the second step to run `finish` and produce `password_file`:
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   opaque::{ClientRegistration, ServerRegistration},
//! #   keypair::{KeyPair, X25519KeyPair, SizedBytes},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let (r1, client_state) = ClientRegistration::<Default>::start(
//! #     b"password",
//! #     Some(b"pepper"),
//! #     &mut client_rng,
//! # )?;
//! # let mut server_rng = OsRng;
//! let (r2, server_state) = ServerRegistration::<Default>::start(r1, &mut server_rng)?;
//! # let server_kp = Default::generate_random_keypair(&mut server_rng)?;
//! # let (r3, export_key_registration) = client_state.finish(r2, server_kp.public(), &mut client_rng)?;
//! let password_file = server_state.finish(r3)?;
//! # Ok::<(), ProtocolError>(())
//! ```
//! At this point, the client can be considered as successfully registered, and the server can store
//! `password_file.to_bytes()` for use during the login protocol.
//!
//!
//! ## Login
//! The login protocol between a client and server also consists of four steps along with three messages, denoted as
//! `l1`, `l2`, and `l3`. The server is expected to have access to the a password file corresponding to an output
//! of the registration phase. The login protocol will execute successfully only if the same tuple combination of
//! (password, pepper, server public key) is presented as was used in the registration phase that produced the
//! password file that the server is testing against.
//!
//! In the first step (client login start), the client chooses a registration password and an optional "pepper", and runs
//! `ClientLogin::start` to produce a message `l1`:
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   opaque::{ClientRegistration, ServerRegistration, ClientLogin, ServerLogin, LoginThirdMessage},
//! #   keypair::{KeyPair, X25519KeyPair, SizedBytes},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! let mut client_rng = OsRng;
//! let (l1, client_state) = ClientLogin::<Default>::start(
//!   b"password",
//!   Some(b"pepper"),
//!   &mut client_rng,
//! )?;
//! # Ok::<(), ProtocolError>(())
//! ```
//! `l1` is sent to the server, and `client_state` must be persisted on the client for the final step of client login.
//!
//! In the second step (server login start), the server takes as input the `l1` message from the client, the server's
//! private key `server_kp.private()`, along with a serialized version of the password file, `password_file_bytes`, and
//! runs `ServerLogin::start` to produce `l2`:
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   opaque::{ClientRegistration, ServerRegistration, ClientLogin, ServerLogin, LoginThirdMessage},
//! #   keypair::{KeyPair, X25519KeyPair, SizedBytes},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let (r1, client_state) = ClientRegistration::<Default>::start(
//! #     b"password",
//! #     Some(b"pepper"),
//! #     &mut client_rng,
//! # )?;
//! # let mut server_rng = OsRng;
//! let (r2, server_state) = ServerRegistration::<Default>::start(r1, &mut server_rng)?;
//! # let server_kp = Default::generate_random_keypair(&mut server_rng)?;
//! # let (r3, export_key_registration) = client_state.finish(r2, server_kp.public(), &mut client_rng)?;
//! # let password_file_bytes = server_state.finish(r3)?.to_bytes();
//! # let (l1, client_state) = ClientLogin::<Default>::start(
//! #   b"password",
//! #   Some(b"pepper"),
//! #   &mut client_rng,
//! # )?;
//! use std::convert::TryFrom;
//! let password_file = ServerRegistration::<Default>::try_from(&password_file_bytes[..])?;
//! let mut server_rng = OsRng;
//! let (l2, server_state) =
//!     ServerLogin::start(password_file, &server_kp.private(), l1, &mut server_rng)?;
//! # Ok::<(), ProtocolError>(())
//! ```
//! `l2` is returned to the client, and `server_state` must be persisted on the server for the final step of server login.
//!
//! In the third step (client login finish), the client takes as input the `l2` message from the server, along with the
//! server's static public key `server_kp.public()`, and uses `client_state` from the first step to run `finish` and produce
//! a message `l3`, the shared secret `client_shared_secret`, and the export key `export_key_login`:
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   opaque::{ClientRegistration, ServerRegistration, ClientLogin, ServerLogin, LoginThirdMessage},
//! #   keypair::{KeyPair, X25519KeyPair, SizedBytes},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let (r1, client_state) = ClientRegistration::<Default>::start(
//! #     b"password",
//! #     Some(b"pepper"),
//! #     &mut client_rng,
//! # )?;
//! # let mut server_rng = OsRng;
//! let (r2, server_state) = ServerRegistration::<Default>::start(r1, &mut server_rng)?;
//! # let server_kp = Default::generate_random_keypair(&mut server_rng)?;
//! # let (r3, export_key_registration) = client_state.finish(r2, server_kp.public(), &mut client_rng)?;
//! # let password_file_bytes = server_state.finish(r3)?.to_bytes();
//! # let (l1, client_state) = ClientLogin::<Default>::start(
//! #   b"password",
//! #   Some(b"pepper"),
//! #   &mut client_rng,
//! # )?;
//! # use std::convert::TryFrom;
//! # let password_file =
//! #   ServerRegistration::<Default>::try_from(
//! #     &password_file_bytes[..],
//! #   )?;
//! # let (l2, server_state) =
//! #     ServerLogin::start(password_file, &server_kp.private(), l1, &mut server_rng)?;
//! let (l3, client_shared_secret, export_key_login) = client_state.finish(
//!   l2,
//!   &server_kp.public(),
//!   &mut client_rng,
//! )?;
//! assert_eq!(export_key_registration, export_key_login);
//! # Ok::<(), ProtocolError>(())
//! ```
//! Note that if the client supplies a tuple (password, pepper, server public key) that does not match the tuple
//! used to create the password file, then at this point the `finish` algorithm outputs the error `InvalidLoginError`.
//!
//! If `finish` completes successfully, then `l3` is sent to the server, and (similarly to registration) the client
//! can use `export_key_login` for applications that can take advantage of the fact that this key is identical to
//! `export_key_registration`.
//!
//! In the fourth step of login, the server takes as input the `l3` message from the client and uses `server_state` from
//! the second step to run `finish`:
//! ```
//! # use opaque_ke::{
//! #   errors::ProtocolError,
//! #   opaque::{ClientRegistration, ServerRegistration, ClientLogin, ServerLogin, LoginThirdMessage},
//! #   keypair::{KeyPair, X25519KeyPair, SizedBytes},
//! #   slow_hash::NoOpHash,
//! # };
//! # use opaque_ke::ciphersuite::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! #     type KeyFormat = opaque_ke::keypair::X25519KeyPair;
//! #     type SlowHash = opaque_ke::slow_hash::NoOpHash;
//! # }
//! # use rand_core::{OsRng, RngCore};
//! # let mut client_rng = OsRng;
//! # let (r1, client_state) = ClientRegistration::<Default>::start(
//! #     b"password",
//! #     Some(b"pepper"),
//! #     &mut client_rng,
//! # )?;
//! # let mut server_rng = OsRng;
//! let (r2, server_state) = ServerRegistration::<Default>::start(r1, &mut server_rng)?;
//! # let server_kp = Default::generate_random_keypair(&mut server_rng)?;
//! # let (r3, export_key) = client_state.finish(r2, server_kp.public(), &mut client_rng)?;
//! # let password_file_bytes = server_state.finish(r3)?.to_bytes();
//! # let (l1, client_state) = ClientLogin::<Default>::start(
//! #   b"password",
//! #   Some(b"pepper"),
//! #   &mut client_rng,
//! # )?;
//! # use std::convert::TryFrom;
//! # let password_file =
//! #   ServerRegistration::<Default>::try_from(
//! #     &password_file_bytes[..],
//! #   )?;
//! # let (l2, server_state) =
//! #     ServerLogin::start(password_file, &server_kp.private(), l1, &mut server_rng)?;
//! # let (l3, client_shared_secret, export_key) = client_state.finish(
//! #   l2,
//! #   &server_kp.public(),
//! #   &mut client_rng,
//! # )?;
//! let server_shared_secret = server_state.finish(l3)?;
//! assert_eq!(client_shared_secret, server_shared_secret);
//! # Ok::<(), ProtocolError>(())
//! ```
//! If the protocol completes successfully, then the server obtains a `server_shared_secret` which is guaranteed to
//! match `client_shared_secret`. Otherwise, on failure, the `finish` algorithm outputs the error `InvalidLoginError`.
//!

// Error types
pub mod errors;

// High-level API
pub mod opaque;

pub mod ciphersuite;
mod envelope;

mod group;
mod map_to_curve;

mod key_exchange;
pub mod keypair;

mod oprf;
pub mod slow_hash;

#[cfg(test)]
mod tests;

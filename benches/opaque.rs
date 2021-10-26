// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use opaque_ke::*;
use rand::rngs::OsRng;

#[cfg(all(not(feature = "p256"), feature = "u64_backend"))]
static SUFFIX: &str = "u64_backend";
#[cfg(all(not(feature = "p256"), feature = "u32_backend"))]
static SUFFIX: &str = "u32_backend";
#[cfg(feature = "p256")]
static SUFFIX: &str = "p256";

struct Default;

#[cfg(not(feature = "p256"))]
impl CipherSuite for Default {
    type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
    type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = opaque_ke::slow_hash::NoOpHash;
}

#[cfg(feature = "p256")]
impl CipherSuite for Default {
    type OprfGroup = p256_::ProjectivePoint;
    type KeGroup = p256_::ProjectivePoint;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha256;
    type SlowHash = opaque_ke::slow_hash::NoOpHash;
}

fn server_setup(c: &mut Criterion) {
    let mut rng = OsRng;

    c.bench_function(&format!("server setup ({})", SUFFIX), move |b| {
        b.iter(|| {
            ServerSetup::<Default>::new(&mut rng);
        })
    });
}

fn client_registration_start(c: &mut Criterion) {
    let mut rng = OsRng;
    let password = b"password";

    c.bench_function(
        &format!("client registration start ({})", SUFFIX),
        move |b| {
            b.iter(|| {
                ClientRegistration::<Default>::start(&mut rng, &password[..]).unwrap();
            })
        },
    );
}

fn server_registration_start(c: &mut Criterion) {
    let mut rng = OsRng;
    let username = b"username";
    let password = b"password";
    let server_setup = ServerSetup::<Default>::new(&mut rng);
    let client_registration_start_result =
        ClientRegistration::<Default>::start(&mut rng, &password[..]).unwrap();

    c.bench_function(
        &format!("server registration start ({})", SUFFIX),
        move |b| {
            b.iter(|| {
                ServerRegistration::<Default>::start(
                    &server_setup,
                    client_registration_start_result.message.clone(),
                    &username[..],
                )
                .unwrap();
            })
        },
    );
}

fn client_registration_finish(c: &mut Criterion) {
    let mut rng = OsRng;
    let username = b"username";
    let password = b"password";
    let server_setup = ServerSetup::<Default>::new(&mut rng);
    let client_registration_start_result =
        ClientRegistration::<Default>::start(&mut rng, &password[..]).unwrap();
    let server_registration_start_result = ServerRegistration::<Default>::start(
        &server_setup,
        client_registration_start_result.message.clone(),
        &username[..],
    )
    .unwrap();

    c.bench_function(
        &format!("client registration finish ({})", SUFFIX),
        move |b| {
            b.iter(|| {
                client_registration_start_result
                    .clone()
                    .state
                    .finish(
                        &mut rng,
                        server_registration_start_result.message.clone(),
                        ClientRegistrationFinishParameters::default(),
                    )
                    .unwrap();
            })
        },
    );
}

fn server_registration_finish(c: &mut Criterion) {
    let mut rng = OsRng;
    let username = b"username";
    let password = b"password";
    let server_setup = ServerSetup::<Default>::new(&mut rng);
    let client_registration_start_result =
        ClientRegistration::<Default>::start(&mut rng, &password[..]).unwrap();
    let server_registration_start_result = ServerRegistration::<Default>::start(
        &server_setup,
        client_registration_start_result.message.clone(),
        &username[..],
    )
    .unwrap();
    let client_registration_finish_result = client_registration_start_result
        .clone()
        .state
        .finish(
            &mut rng,
            server_registration_start_result.message.clone(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    c.bench_function(
        &format!("server registration finish ({})", SUFFIX),
        move |b| {
            b.iter(|| {
                ServerRegistration::finish(client_registration_finish_result.clone().message);
            })
        },
    );
}

fn client_login_start(c: &mut Criterion) {
    let mut rng = OsRng;
    let password = b"password";

    c.bench_function(&format!("client login start ({})", SUFFIX), move |b| {
        b.iter(|| {
            ClientLogin::<Default>::start(&mut rng, &password[..]).unwrap();
        })
    });
}

fn server_login_start_real(c: &mut Criterion) {
    let mut rng = OsRng;
    let username = b"username";
    let password = b"password";
    let server_setup = ServerSetup::<Default>::new(&mut rng);
    let client_registration_start_result =
        ClientRegistration::<Default>::start(&mut rng, &password[..]).unwrap();
    let server_registration_start_result = ServerRegistration::<Default>::start(
        &server_setup,
        client_registration_start_result.message.clone(),
        &username[..],
    )
    .unwrap();
    let client_registration_finish_result = client_registration_start_result
        .clone()
        .state
        .finish(
            &mut rng,
            server_registration_start_result.message.clone(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let password_file = ServerRegistration::finish(client_registration_finish_result.message);
    let client_login_start_result = ClientLogin::<Default>::start(&mut rng, &password[..]).unwrap();

    c.bench_function(
        &format!("server login start (real) ({})", SUFFIX),
        move |b| {
            b.iter(|| {
                ServerLogin::start(
                    &mut rng,
                    &server_setup,
                    Some(password_file.clone()),
                    client_login_start_result.clone().message,
                    &username[..],
                    ServerLoginStartParameters::default(),
                )
                .unwrap();
            })
        },
    );
}

fn server_login_start_fake(c: &mut Criterion) {
    let mut rng = OsRng;
    let username = b"username";
    let password = b"password";
    let server_setup = ServerSetup::<Default>::new(&mut rng);
    let client_login_start_result = ClientLogin::<Default>::start(&mut rng, &password[..]).unwrap();

    c.bench_function(
        &format!("server login start (fake) ({})", SUFFIX),
        move |b| {
            b.iter(|| {
                ServerLogin::start(
                    &mut rng,
                    &server_setup,
                    None,
                    client_login_start_result.clone().message,
                    &username[..],
                    ServerLoginStartParameters::default(),
                )
                .unwrap();
            })
        },
    );
}

fn client_login_finish(c: &mut Criterion) {
    let mut rng = OsRng;
    let username = b"username";
    let password = b"password";
    let server_setup = ServerSetup::<Default>::new(&mut rng);
    let client_registration_start_result =
        ClientRegistration::<Default>::start(&mut rng, &password[..]).unwrap();
    let server_registration_start_result = ServerRegistration::<Default>::start(
        &server_setup,
        client_registration_start_result.message.clone(),
        &username[..],
    )
    .unwrap();
    let client_registration_finish_result = client_registration_start_result
        .clone()
        .state
        .finish(
            &mut rng,
            server_registration_start_result.message.clone(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let password_file = ServerRegistration::finish(client_registration_finish_result.message);
    let client_login_start_result = ClientLogin::<Default>::start(&mut rng, &password[..]).unwrap();
    let server_login_start = ServerLogin::start(
        &mut rng,
        &server_setup,
        Some(password_file.clone()),
        client_login_start_result.clone().message,
        &username[..],
        ServerLoginStartParameters::default(),
    )
    .unwrap();

    c.bench_function(&format!("client login finish ({})", SUFFIX), move |b| {
        b.iter(|| {
            client_login_start_result
                .clone()
                .state
                .finish(
                    server_login_start.clone().message,
                    ClientLoginFinishParameters::default(),
                )
                .unwrap();
        })
    });
}

fn server_login_finish(c: &mut Criterion) {
    let mut rng = OsRng;
    let username = b"username";
    let password = b"password";
    let server_setup = ServerSetup::<Default>::new(&mut rng);
    let client_registration_start_result =
        ClientRegistration::<Default>::start(&mut rng, &password[..]).unwrap();
    let server_registration_start_result = ServerRegistration::<Default>::start(
        &server_setup,
        client_registration_start_result.message.clone(),
        &username[..],
    )
    .unwrap();
    let client_registration_finish_result = client_registration_start_result
        .clone()
        .state
        .finish(
            &mut rng,
            server_registration_start_result.message.clone(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let password_file = ServerRegistration::finish(client_registration_finish_result.message);
    let client_login_start_result = ClientLogin::<Default>::start(&mut rng, &password[..]).unwrap();
    let server_login_start_result = ServerLogin::start(
        &mut rng,
        &server_setup,
        Some(password_file.clone()),
        client_login_start_result.clone().message,
        &username[..],
        ServerLoginStartParameters::default(),
    )
    .unwrap();
    let client_login_finish_result = client_login_start_result
        .clone()
        .state
        .finish(
            server_login_start_result.clone().message,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();

    c.bench_function(&format!("server login finish ({})", SUFFIX), move |b| {
        b.iter(|| {
            server_login_start_result
                .clone()
                .state
                .finish(client_login_finish_result.clone().message)
                .unwrap();
        })
    });
}

criterion_group!(
    opaque_benches,
    server_setup,
    client_registration_start,
    server_registration_start,
    client_registration_finish,
    server_registration_finish,
    client_login_start,
    server_login_start_real,
    server_login_start_fake,
    client_login_finish,
    server_login_finish,
);
criterion_main!(opaque_benches);

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use generic_array::arr;
use opaque_ke::{
    group::Group,
    oprf::{blind_shim, evaluate_shim, unblind_and_finalize_shim},
};
use rand::{prelude::ThreadRng, thread_rng};
use sha2::Sha512;

fn oprf1(c: &mut Criterion) {
    let mut csprng: ThreadRng = thread_rng();
    let input = b"hunter2";

    c.bench_function("blind with Ristretto", move |b| {
        b.iter(|| {
            blind_shim::<_, RistrettoPoint, Sha512>(&input[..], &mut csprng).unwrap();
        })
    });
}

fn oprf2(c: &mut Criterion) {
    let mut csprng: ThreadRng = thread_rng();
    let input = b"hunter2";

    let (_, alpha) = blind_shim::<_, RistrettoPoint, Sha512>(&input[..], &mut csprng).unwrap();
    let salt_bytes = arr![
        u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32,
    ];
    let salt = RistrettoPoint::from_scalar_slice(&salt_bytes).unwrap();

    c.bench_function("evaluate with Ristretto", move |b| {
        b.iter(|| {
            let _beta = evaluate_shim::<RistrettoPoint>(alpha, &salt);
        })
    });
}

fn oprf3(c: &mut Criterion) {
    let mut csprng: ThreadRng = thread_rng();
    let input = b"hunter2";

    let (token, alpha) = blind_shim::<_, RistrettoPoint, Sha512>(&input[..], &mut csprng).unwrap();
    let salt_bytes = arr![
        u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32,
    ];
    let salt = RistrettoPoint::from_scalar_slice(&salt_bytes).unwrap();
    let beta = evaluate_shim::<RistrettoPoint>(alpha, &salt);

    c.bench_function("unblind_and_finalize with Ristretto", move |b| {
        b.iter(|| {
            let _res = unblind_and_finalize_shim::<RistrettoPoint, Sha512>(&token, beta).unwrap();
        })
    });
}

criterion_group!(oprf_benches, oprf1, oprf2, oprf3);
criterion_main!(oprf_benches);

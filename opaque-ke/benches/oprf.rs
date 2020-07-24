// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::ristretto::RistrettoPoint;
use generic_array::arr;
use opaque_ke::{
    group::Group,
    oprf::{generate_oprf1_shim, generate_oprf2_shim, generate_oprf3_shim, OprfClientBytes},
};
use rand::{prelude::ThreadRng, thread_rng};

fn oprf1(c: &mut Criterion) {
    let mut csprng: ThreadRng = thread_rng();
    let input = b"hunter2";

    c.bench_function("generate_oprf1 with Ristretto", move |b| {
        b.iter(|| {
            let OprfClientBytes {
                alpha: _alpha,
                blinding_factor: _blinding_factor,
            } = generate_oprf1_shim::<_, RistrettoPoint>(&input[..], None, &mut csprng).unwrap();
        })
    });
}

fn oprf1_edwards(c: &mut Criterion) {
    let mut csprng: ThreadRng = thread_rng();
    let input = b"hunter2";

    c.bench_function("generate_oprf1 with Edwards", move |b| {
        b.iter(|| {
            let OprfClientBytes {
                alpha: _alpha,
                blinding_factor: _blinding_factor,
            } = generate_oprf1_shim::<_, EdwardsPoint>(&input[..], None, &mut csprng).unwrap();
        })
    });
}

fn oprf2(c: &mut Criterion) {
    let mut csprng: ThreadRng = thread_rng();
    let input = b"hunter2";

    let OprfClientBytes {
        alpha,
        blinding_factor: _blinding_factor,
    } = generate_oprf1_shim::<_, RistrettoPoint>(&input[..], None, &mut csprng).unwrap();
    let salt_bytes = arr![
        u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32,
    ];
    let salt = RistrettoPoint::from_scalar_slice(&salt_bytes).unwrap();

    c.bench_function("generate_oprf2 with Ristretto", move |b| {
        b.iter(|| {
            let _beta = generate_oprf2_shim::<RistrettoPoint>(alpha, &salt).unwrap();
        })
    });
}

fn oprf2_edwards(c: &mut Criterion) {
    let mut csprng: ThreadRng = thread_rng();
    let input = b"hunter2";

    let OprfClientBytes {
        alpha,
        blinding_factor: _blinding_factor,
    } = generate_oprf1_shim::<_, EdwardsPoint>(&input[..], None, &mut csprng).unwrap();
    let salt_bytes = arr![
        u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32,
    ];
    let salt = RistrettoPoint::from_scalar_slice(&salt_bytes).unwrap();

    c.bench_function("generate_oprf2 with Edwards", move |b| {
        b.iter(|| {
            let _beta = generate_oprf2_shim::<EdwardsPoint>(alpha, &salt).unwrap();
        })
    });
}

fn oprf3(c: &mut Criterion) {
    let mut csprng: ThreadRng = thread_rng();
    let input = b"hunter2";

    let OprfClientBytes {
        alpha,
        blinding_factor,
    } = generate_oprf1_shim::<_, RistrettoPoint>(&input[..], None, &mut csprng).unwrap();
    let salt_bytes = arr![
        u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32,
    ];
    let salt = RistrettoPoint::from_scalar_slice(&salt_bytes).unwrap();
    let beta = generate_oprf2_shim::<RistrettoPoint>(alpha, &salt).unwrap();

    c.bench_function("generate_oprf3 with Ristretto", move |b| {
        b.iter(|| {
            let _res =
                generate_oprf3_shim::<RistrettoPoint>(input, beta, &blinding_factor).unwrap();
        })
    });
}

fn oprf3_edwards(c: &mut Criterion) {
    let mut csprng: ThreadRng = thread_rng();
    let input = b"hunter2";

    let OprfClientBytes {
        alpha,
        blinding_factor,
    } = generate_oprf1_shim::<_, EdwardsPoint>(&input[..], None, &mut csprng).unwrap();
    let salt_bytes = arr![
        u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32,
    ];
    let salt = RistrettoPoint::from_scalar_slice(&salt_bytes).unwrap();
    let beta = generate_oprf2_shim::<EdwardsPoint>(alpha, &salt).unwrap();

    c.bench_function("generate_oprf3 with Edwards", move |b| {
        b.iter(|| {
            let _res = generate_oprf3_shim::<EdwardsPoint>(input, beta, &blinding_factor).unwrap();
        })
    });
}

criterion_group!(
    oprf_benches,
    oprf1,
    oprf2,
    oprf3,
    oprf1_edwards,
    oprf2_edwards,
    oprf3_edwards
);
criterion_main!(oprf_benches);

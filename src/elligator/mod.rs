// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
#![allow(non_snake_case)]

mod field;

use curve25519_dalek::{edwards::EdwardsPoint, montgomery::MontgomeryPoint, scalar::Scalar};
use field::FieldElement51;
use sha2::Digest;
use subtle::{ConditionallyNegatable, ConditionallySelectable};

const MONT_A: FieldElement51 = FieldElement51([486662, 0, 0, 0, 0]);

fn elligator_signal(r_0: &FieldElement51) -> MontgomeryPoint {
    let minus_a = -&MONT_A; /* A = 486662 */
    let one = FieldElement51::one();
    let d_1 = &one + &r_0.square2(); /* 2r^2 */

    let d = &minus_a * &(d_1.invert()); /* A/(1+2r^2) */

    let d_sq = &d.square();
    let au = &MONT_A * &d;

    let inner = &(d_sq + &au) + &one;
    let eps = &d * &inner; /* eps = d^3 + Ad^2 + d */

    let (eps_is_sq, _eps) = FieldElement51::sqrt_ratio_i(&eps, &one);

    let zero = FieldElement51::zero();
    let Atemp = FieldElement51::conditional_select(&MONT_A, &zero, eps_is_sq); /* 0, or A if nonsquare*/
    let mut u = &d + &Atemp; /* d, or d+A if nonsquare */
    u.conditional_negate(!eps_is_sq); /* d, or -d-A if nonsquare */

    MontgomeryPoint(u.to_bytes())
}

fn hash_to_point(bytes: &[u8]) -> EdwardsPoint {
    let mut hash = sha2::Sha512::new();
    hash.update(bytes);
    let h = hash.finalize();
    let mut res = [0u8; 32];
    res.copy_from_slice(&h[..32]);

    let sign_bit = (res[31] & 0x80) >> 7;

    let fe = FieldElement51::from_bytes(&res);

    let M1 = elligator_signal(&fe);
    let E1_opt = M1.to_edwards(sign_bit);

    E1_opt
        .expect("Montgomery conversion to Edwards point in Elligator failed")
        .mul_by_cofactor()
}

#[cfg(test)]
mod tests {
    use super::*;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Signal tests from                                                                                                              //
    //     https://github.com/signalapp/libsignal-protocol-c/blob/master/src/curve25519/ed25519/tests/internal_fast_tests.c#L222-L282 //
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    const ELLIGATOR_CORRECT_OUTPUT: [u8; 32] = [
        0x5f, 0x35, 0x20, 0x00, 0x1c, 0x6c, 0x99, 0x36, 0xa3, 0x12, 0x06, 0xaf, 0xe7, 0xc7, 0xac,
        0x22, 0x4e, 0x88, 0x61, 0x61, 0x9b, 0xf9, 0x88, 0x72, 0x44, 0x49, 0x15, 0x89, 0x9d, 0x95,
        0xf4, 0x6e,
    ];

    #[test]
    fn elligator_correct() {
        let bytes: Vec<u8> = (0u8..32u8).collect();
        let mut bits_in = [0u8; 32];
        bits_in.copy_from_slice(&bytes);
        let fe = FieldElement51::from_bytes(&bits_in);
        let eg = elligator_signal(&fe);
        assert_eq!(eg.to_bytes(), ELLIGATOR_CORRECT_OUTPUT);
    }

    #[test]
    fn elligator_zero_zero() {
        let zero = [0u8; 32];
        let fe = FieldElement51::from_bytes(&zero);
        let eg = elligator_signal(&fe);
        assert_eq!(eg.to_bytes(), zero);
    }

    const HASHTOPOINT_CORRECT_OUTPUT1: [u8; 32] = [
        0xce, 0x89, 0x9f, 0xb2, 0x8f, 0xf7, 0x20, 0x91, 0x5e, 0x14, 0xf5, 0xb7, 0x99, 0x08, 0xab,
        0x17, 0xaa, 0x2e, 0xe2, 0x45, 0xb4, 0xfc, 0x2b, 0xf6, 0x06, 0x36, 0x29, 0x40, 0xed, 0x7d,
        0xe7, 0xed,
    ];

    const HASHTOPOINT_CORRECT_OUTPUT2: [u8; 32] = [
        0xa0, 0x35, 0xbb, 0xa9, 0x4d, 0x30, 0x55, 0x33, 0x0d, 0xce, 0xc2, 0x7f, 0x83, 0xde, 0x79,
        0xd0, 0x89, 0x67, 0x72, 0x4c, 0x07, 0x8d, 0x68, 0x9d, 0x61, 0x52, 0x1d, 0xf9, 0x2c, 0x5c,
        0xba, 0x77,
    ];

    #[test]
    fn test_hash_to_point_1() {
        let bits: Vec<u8> = (0u8..32u8).collect();
        let hashed = hash_to_point(&bits);
        assert_eq!(hashed.compress().to_bytes(), HASHTOPOINT_CORRECT_OUTPUT1);
    }

    #[test]
    fn test_hash_to_point_2() {
        let bits: Vec<u8> = (0u8..32u8).map(|u| u + 1).collect();
        let hashed = hash_to_point(&bits);
        assert_eq!(hashed.compress().to_bytes(), HASHTOPOINT_CORRECT_OUTPUT2);
    }
}

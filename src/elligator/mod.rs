// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
#![allow(non_snake_case)]

mod field;

use curve25519_dalek::{edwards::EdwardsPoint, montgomery::MontgomeryPoint};
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

pub fn hash_to_point(bytes: &[u8]) -> EdwardsPoint {
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
    use std::convert::TryInto;

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
        let bits_in: [u8; 32] = (&bytes[..]).try_into().expect("Range invariant broken");

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

    /////////////////////////////////////////
    // Additional test vectors from Signal //
    /////////////////////////////////////////

    fn test_vectors() -> Vec<Vec<&'static str>> {
        vec![
            vec![
                "214f306e1576f5a7577636fe303ca2c625b533319f52442b22a9fa3b7ede809f",
                "c95becf0f93595174633b9d4d6bbbeb88e16fa257176f877ce426e1424626052",
            ],
            vec![
                "2eb10d432702ea7f79207da95d206f82d5a3b374f5f89f17a199531f78d3bea6",
                "d8f8b508edffbb8b6dab0f602f86a9dd759f800fe18f782fdcac47c234883e7f",
            ],
            vec![
                "84cbe9accdd32b46f4a8ef51c85fd39d028711f77fb00e204a613fc235fd68b9",
                "93c73e0289afd1d1fc9e4e78a505d5d1b2642fbdf91a1eff7d281930654b1453",
            ],
            vec![
                "c85165952490dc1839cb69012a3d9f2cc4b02343613263ab93a26dc89fd58267",
                "43cbe8685fd3c90665b91835debb89ff1477f906f5170f38a192f6a199556537",
            ],
            vec![
                "26e7fc4a78d863b1a4ccb2ce0951fbcd021e106350730ee4157bacb4502e1b76",
                "b6fc3d738c2c40719479b2f23818180cdafa72a14254d4016bbed8f0b788a835",
            ],
            vec![
                "1618c08ef0233f94f0f163f9435ec7457cd7a8cd4bb6b160315d15818c30f7a2",
                "da0b703593b29dbcd28ebd6e7baea17b6f61971f3641cae774f6a5137a12294c",
            ],
            vec![
                "48b73039db6fcdcb6030c4a38e8be80b6390d8ae46890e77e623f87254ef149c",
                "ca11b25acbc80566603eabeb9364ebd50e0306424c61049e1ce9385d9f349966",
            ],
            vec![
                "a744d582b3a34d14d311b7629da06d003045ae77cebceeb4e0e72734d63bd07d",
                "fad25a5ea15d4541258af8785acaf697a886c1b872c793790e60a6837b1adbc0",
            ],
            vec![
                "80a6ff33494c471c5eff7efb9febfbcf30a946fe6535b3451cda79f2154a7095",
                "57ac03913309b3f8cd3c3d4c49d878bb21f4d97dc74a1eaccbe5c601f7f06f47",
            ],
            vec![
                "f06fc939bc10551a0fd415aebf107ef0b9c4ee1ef9a164157bdd089127782617",
                "785b2a6a00a5579cc9da1ff997ce8339b6f9fb46c6f10cf7a12ff2986341a6e0",
            ],
        ]
    }

    #[test]
    fn additional_signal_test_vectors() {
        for vector in test_vectors().iter() {
            let input = hex::decode(vector[0]).unwrap();
            let output = hex::decode(vector[1]).unwrap();

            let point = hash_to_point(&input);
            assert_eq!(point.compress().to_bytes(), output[..]);
        }
    }
}

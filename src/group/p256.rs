// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#![allow(
    clippy::borrow_interior_mutable_const,
    clippy::declare_interior_mutable_const
)]

use super::Group;
use crate::errors::{InternalError, ProtocolError};
use crate::hash::Hash;
use core::ops::{Add, Div, Mul, Neg, Sub};
use core::str::FromStr;
use generic_array::typenum::{U32, U33};
use generic_array::{ArrayLength, GenericArray};
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{One, ToPrimitive};
use once_cell::unsync::Lazy;
use p256_::elliptic_curve::group::prime::PrimeCurveAffine;
use p256_::elliptic_curve::group::GroupEncoding;
use p256_::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256_::elliptic_curve::subtle::ConstantTimeEq;
use p256_::elliptic_curve::Field;
use p256_::{AffinePoint, EncodedPoint, ProjectivePoint};
use rand::{CryptoRng, RngCore};

// `L: 48`
pub const L: usize = 48;

impl Group for ProjectivePoint {
    const SUITE_ID: usize = 0x0003;

    // Implements the `hash_to_curve()` function from
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-3
    fn map_to_curve<H: Hash>(msg: &[u8], dst: &[u8]) -> Result<Self, ProtocolError> {
        // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-8.2
        // `p: 2^256 - 2^224 + 2^192 + 2^96 - 1`
        const P: Lazy<BigInt> = Lazy::new(|| {
            BigInt::from_str(
                "115792089210356248762697446949407573530086143415290314195533631308867097853951",
            )
            .unwrap()
        });
        // `A: -3`
        const A: Lazy<BigInt> = Lazy::new(|| BigInt::from(-3));
        // `B: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b`
        const B: Lazy<BigInt> = Lazy::new(|| {
            BigInt::parse_bytes(
                b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                16,
            )
            .unwrap()
        });
        // `Z: -10`
        const Z: Lazy<BigInt> = Lazy::new(|| BigInt::from(-10));

        // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-3
        // `hash_to_curve` calls `hash_to_field` with a `count` of `2`
        // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3
        // `hash_to_field` calls `expand_message` with a `len_in_bytes` of `count * L`
        let uniform_bytes = super::expand::expand_message_xmd::<H>(msg, dst, 2 * L)?;

        // map to curve
        let (q0x, q0y) = map_to_curve_simple_swu(&uniform_bytes[..L], &A, &B, &P, &Z);
        let (q1x, q1y) = map_to_curve_simple_swu(&uniform_bytes[L..], &A, &B, &P, &Z);

        // convert to `p256` types
        let p0 = AffinePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(
            &q0x, &q0y, false,
        ))
        .ok_or(InternalError::PointError)?
        .to_curve();
        let p1 = AffinePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(
            &q1x, &q1y, false,
        ))
        .ok_or(InternalError::PointError)?;

        Ok(p0 + p1)
    }

    // Implements the `HashToScalar()` function from
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-07.html#section-4.3
    fn hash_to_scalar<H: Hash>(input: &[u8], dst: &[u8]) -> Result<Self::Scalar, ProtocolError> {
        // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf#[{%22num%22:211,%22gen%22:0},{%22name%22:%22XYZ%22},70,700,0]
        // P-256 `n` is defined as `115792089210356248762697446949407573529996955224135760342 422259061068512044369`
        const N: once_cell::unsync::Lazy<BigInt> = once_cell::unsync::Lazy::new(|| {
            BigInt::from_str(
                "115792089210356248762697446949407573529996955224135760342422259061068512044369",
            )
            .unwrap()
        });

        // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3
        // `HashToScalar` is `hash_to_field`
        let uniform_bytes = super::expand::expand_message_xmd::<H>(input, dst, L)?;
        let mut bytes = BigInt::from_bytes_be(Sign::Plus, &uniform_bytes)
            .mod_floor(&N)
            .to_bytes_be()
            .1;
        bytes.resize(32, 0);

        Ok(p256_::Scalar::from_bytes_reduced(GenericArray::from_slice(
            &bytes,
        )))
    }

    type ElemLen = U33;
    type Scalar = p256_::Scalar;
    type ScalarLen = U32;

    fn from_scalar_slice(
        scalar_bits: &GenericArray<u8, Self::ScalarLen>,
    ) -> Result<Self::Scalar, InternalError> {
        Ok(Self::Scalar::from_bytes_reduced(scalar_bits))
    }

    fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Self::Scalar::random(rng)
    }

    fn scalar_as_bytes(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
        scalar.into()
    }

    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        scalar.invert().unwrap_or(Self::Scalar::zero())
    }

    fn from_element_slice(
        element_bits: &GenericArray<u8, Self::ElemLen>,
    ) -> Result<Self, InternalError> {
        Option::from(Self::from_bytes(element_bits)).ok_or(InternalError::PointError)
    }

    fn to_arr(&self) -> GenericArray<u8, Self::ElemLen> {
        let mut bytes = self.to_affine().to_encoded_point(true).as_bytes().to_vec();
        bytes.resize(33, 0);
        *GenericArray::from_slice(&bytes)
    }

    fn base_point() -> Self {
        Self::generator()
    }

    fn mult_by_slice(&self, scalar: &GenericArray<u8, Self::ScalarLen>) -> Self {
        self * &Self::Scalar::from_bytes_reduced(scalar)
    }

    fn is_identity(&self) -> bool {
        self == &Self::identity()
    }
    fn ct_equal(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

/// Corresponds to the map_to_curve_simple_swu() function defined in
/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-F.2>
#[allow(clippy::many_single_char_names)]
fn map_to_curve_simple_swu<N: ArrayLength<u8>>(
    u: &[u8],
    a: &BigInt,
    b: &BigInt,
    p: &BigInt,
    z: &BigInt,
) -> (GenericArray<u8, N>, GenericArray<u8, N>) {
    #[derive(Clone)]
    struct Field<'a>(&'a BigInt);

    impl<'a> Field<'a> {
        fn new(p: &'a BigInt) -> Self {
            Self(p)
        }

        fn element(&'a self, number: &BigInt) -> FieldElement<'a> {
            FieldElement {
                number: number.mod_floor(self.0),
                f: self,
            }
        }

        fn one(&'a self) -> FieldElement<'a> {
            self.element(&BigInt::one())
        }

        /// See <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-4>
        fn inv0(&'a self, number: &FieldElement<'a>) -> FieldElement<'a> {
            number.pow_internal(&(self.0 - 2))
        }
    }

    /// Finite field arithmetic
    #[derive(Clone)]
    struct FieldElement<'a> {
        number: BigInt,
        f: &'a Field<'a>,
    }

    impl<'a> Add for FieldElement<'a> {
        type Output = FieldElement<'a>;

        fn add(self, rhs: Self) -> Self::Output {
            &self + &rhs
        }
    }

    impl<'a> Add for &FieldElement<'a> {
        type Output = FieldElement<'a>;

        fn add(self, rhs: Self) -> Self::Output {
            self.f.element(&(&self.number + &rhs.number))
        }
    }

    impl<'a> Sub for &FieldElement<'a> {
        type Output = FieldElement<'a>;

        fn sub(self, rhs: Self) -> Self::Output {
            self.f.element(&(&self.number - &rhs.number))
        }
    }

    impl<'a> Neg for FieldElement<'a> {
        type Output = FieldElement<'a>;

        fn neg(self) -> Self::Output {
            -&self
        }
    }

    impl<'a> Neg for &FieldElement<'a> {
        type Output = FieldElement<'a>;

        fn neg(self) -> Self::Output {
            self.f.element(&-&self.number)
        }
    }

    impl<'a> Mul for FieldElement<'a> {
        type Output = FieldElement<'a>;

        fn mul(self, rhs: Self) -> Self::Output {
            &self * &rhs
        }
    }

    impl<'a> Mul<&Self> for FieldElement<'a> {
        type Output = FieldElement<'a>;

        fn mul(self, rhs: &Self) -> Self::Output {
            &self * rhs
        }
    }

    impl<'a> Mul<FieldElement<'a>> for &FieldElement<'a> {
        type Output = FieldElement<'a>;

        fn mul(self, rhs: FieldElement<'a>) -> Self::Output {
            self * &rhs
        }
    }

    impl<'a> Mul for &FieldElement<'a> {
        type Output = FieldElement<'a>;

        fn mul(self, rhs: Self) -> Self::Output {
            self.f.element(&(&self.number * &rhs.number))
        }
    }

    impl<'a> Div<&Self> for FieldElement<'a> {
        type Output = FieldElement<'a>;

        #[allow(clippy::suspicious_arithmetic_impl)]
        fn div(self, rhs: &Self) -> Self::Output {
            self * rhs.f.inv0(rhs)
        }
    }

    impl<'a> FieldElement<'a> {
        fn square(&self) -> Self {
            self * self
        }

        fn pow_internal(&self, exponent: &BigInt) -> Self {
            let exponent = exponent.mod_floor(&(self.f.0 - 1));
            self.f.element(&self.number.modpow(&exponent, self.f.0))
        }

        /// Corresponds to the sqrt_3mod4() function defined in
        /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-I.1>
        fn sqrt(&self) -> Self {
            // constant
            let c1 = (self.f.0 + 1) >> 2;

            self.pow_internal(&c1)
        }

        /// Corresponds to the sgn0_m_eq_1() function defined in
        /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-4.1>
        fn sgn0(&self) -> i32 {
            (&self.number % 2_usize).to_i32().unwrap()
        }

        fn is_zero(&self) -> bool {
            self.number.is_one()
        }

        /// Corresponds to the is_square() function defined in
        /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-4>
        fn is_square(&self) -> bool {
            // constant
            let exponent = (self.f.0 - 1) >> 1;

            let result = self.pow_internal(&exponent);
            result.number.is_one() || result.is_zero()
        }

        fn to_bytes<N: ArrayLength<u8>>(&self) -> GenericArray<u8, N> {
            GenericArray::clone_from_slice(&self.number.mod_floor(self.f.0).to_bytes_be().1)
        }
    }

    fn cmov<'a>(x: &FieldElement<'a>, y: &FieldElement<'a>, b: bool) -> FieldElement<'a> {
        if b {
            y.clone()
        } else {
            x.clone()
        }
    }

    let f = Field::new(p);
    let a = f.element(a);
    let b = f.element(b);
    let z = f.element(z);
    let u = f.element(&BigInt::from_bytes_be(Sign::Plus, u));

    // Constants:
    // 1.  c1 = -B / A
    let c1 = -&b / &a;
    // 2.  c2 = -1 / Z
    let c2 = -f.one() / &z;

    // Steps:
    // 1.  tv1 = Z * u^2
    let tv1 = z * u.square();
    // 2.  tv2 = tv1^2
    let mut tv2 = tv1.square();
    // 3.   x1 = tv1 + tv2
    let mut x1 = &tv1 + &tv2;
    // 4.   x1 = inv0(x1)
    x1 = f.inv0(&x1);
    // 5.   e1 = x1 == 0
    let e1 = x1.is_zero();
    // 6.   x1 = x1 + 1
    x1 = x1 + f.one();
    // 7.   x1 = CMOV(x1, c2, e1)    # If (tv1 + tv2) == 0, set x1 = -1 / Z
    x1 = cmov(&x1, &c2, e1);
    // 8.   x1 = x1 * c1      # x1 = (-B / A) * (1 + (1 / (Z^2 * u^4 + Z * u^2)))
    x1 = x1 * c1;
    // 9.  gx1 = x1^2
    let mut gx1 = x1.square();
    // 10. gx1 = gx1 + A
    gx1 = gx1 + a;
    // 11. gx1 = gx1 * x1
    gx1 = gx1 * &x1;
    // 12. gx1 = gx1 + B             # gx1 = g(x1) = x1^3 + A * x1 + B
    gx1 = gx1 + b;
    // 13.  x2 = tv1 * x1            # x2 = Z * u^2 * x1
    let x2 = &tv1 * &x1;
    // 14. tv2 = tv1 * tv2
    tv2 = tv1 * tv2;
    // 15. gx2 = gx1 * tv2           # gx2 = (Z * u^2)^3 * gx1
    let gx2 = &gx1 * tv2;
    // 16.  e2 = is_square(gx1)
    let e2 = gx1.is_square();
    // 17.   x = CMOV(x2, x1, e2)    # If is_square(gx1), x = x1, else x = x2
    let x = cmov(&x2, &x1, e2);
    // 18.  y2 = CMOV(gx2, gx1, e2)  # If is_square(gx1), y2 = gx1, else y2 = gx2
    let y2 = cmov(&gx2, &gx1, e2);
    // 19.   y = sqrt(y2)
    let mut y = y2.sqrt();
    // 20.  e3 = sgn0(u) == sgn0(y)  # Fix sign of y
    let e3 = u.sgn0() == y.sgn0();
    // 21.   y = CMOV(-y, y, e3)
    y = cmov(&-&y, &y, e3);
    // 22. return (x, y)
    (x.to_bytes(), y.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Params {
        msg: &'static str,
        px: &'static str,
        py: &'static str,
        u0: &'static str,
        u1: &'static str,
        q0x: &'static str,
        q0y: &'static str,
        q1x: &'static str,
        q1y: &'static str,
    }

    #[test]
    fn map_to_curve_simple_swu() {
        const P: Lazy<BigInt> = Lazy::new(|| {
            BigInt::from_str(
                "115792089210356248762697446949407573530086143415290314195533631308867097853951",
            )
            .unwrap()
        });
        const A: Lazy<BigInt> = Lazy::new(|| BigInt::from(-3));
        const B: Lazy<BigInt> = Lazy::new(|| {
            BigInt::parse_bytes(
                b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                16,
            )
            .unwrap()
        });
        const Z: Lazy<BigInt> = Lazy::new(|| BigInt::from(-10));

        // Test vectors taken from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-J.1.1
        let test_vectors = alloc::vec![
            Params {
                msg: "",
                px: "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
                py: "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
                u0: "ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009",
                u1: "8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a",
                q0x: "ab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5",
                q0y: "dccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565b19b1",
                q1x: "51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5",
                q1y: "b45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b66aac",
            },
            Params {
                msg: "abc",
                px: "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
                py: "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
                u0: "afe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1",
                u1: "379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9e46e0",
                q0x: "5219ad0ddef3cc49b714145e91b2f7de6ce0a7a7dc7406c7726c7e373c58cb48",
                q0y: "7950144e52d30acbec7b624c203b1996c99617d0b61c2442354301b191d93ecf",
                q1x: "019b7cb4efcfeaf39f738fe638e31d375ad6837f58a852d032ff60c69ee3875f",
                q1y: "589a62d2b22357fed5449bc38065b760095ebe6aeac84b01156ee4252715446e",
            },
            Params {
                msg: "abcdef0123456789",
                px: "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
                py: "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
                u0: "0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d651f53d312c",
                u1: "b68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c9d2196c0fb",
                q0x: "a17bdf2965eb88074bc01157e644ed409dac97cfcf0c61c998ed0fa45e79e4a2",
                q0y: "4f1bc80c70d411a3cc1d67aeae6e726f0f311639fee560c7f5a664554e3c9c2e",
                q1x: "7da48bb67225c1a17d452c983798113f47e438e4202219dd0715f8419b274d66",
                q1y: "b765696b2913e36db3016c47edb99e24b1da30e761a8a3215dc0ec4d8f96e6f9",
            },
            Params {
                msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                      qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                      qqqqqqqqqqqqqqqqqqqqqqqqq",
                px: "4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
                py: "98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e",
                u0: "3bbc30446f39a7befad080f4d5f32ed116b9534626993d2cc5033f6f8d805919",
                u1: "76bb02db019ca9d3c1e02f0c17f8baf617bbdae5c393a81d9ce11e3be1bf1d33",
                q0x: "c76aaa823aeadeb3f356909cb08f97eee46ecb157c1f56699b5efebddf0e6398",
                q0y: "776a6f45f528a0e8d289a4be12c4fab80762386ec644abf2bffb9b627e4352b1",
                q1x: "418ac3d85a5ccc4ea8dec14f750a3a9ec8b85176c95a7022f391826794eb5a75",
                q1y: "fd6604f69e9d9d2b74b072d14ea13050db72c932815523305cb9e807cc900aff",
            },
            Params {
                msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                px: "457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
                py: "ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc",
                u0: "4ebc95a6e839b1ae3c63b847798e85cb3c12d3817ec6ebc10af6ee51adb29fec",
                u1: "4e21af88e22ea80156aff790750121035b3eefaa96b425a8716e0d20b4e269ee",
                q0x: "d88b989ee9d1295df413d4456c5c850b8b2fb0f5402cc5c4c7e815412e926db8",
                q0y: "bb4a1edeff506cf16def96afff41b16fc74f6dbd55c2210e5b8f011ba32f4f40",
                q1x: "a281e34e628f3a4d2a53fa87ff973537d68ad4fbc28d3be5e8d9f6a2571c5a4b",
                q1y: "f6ed88a7aab56a488100e6f1174fa9810b47db13e86be999644922961206e184",
            },
        ];
        let dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";

        for tv in test_vectors {
            let uniform_bytes = super::super::expand::expand_message_xmd::<sha2::Sha256>(
                tv.msg.as_bytes(),
                dst.as_bytes(),
                96,
            )
            .unwrap();

            let u0 = BigInt::from_bytes_be(Sign::Plus, &uniform_bytes[..48]).mod_floor(&P);
            let u1 = BigInt::from_bytes_be(Sign::Plus, &uniform_bytes[48..]).mod_floor(&P);

            assert_eq!(BigInt::parse_bytes(tv.u0.as_bytes(), 16).unwrap(), u0);
            assert_eq!(BigInt::parse_bytes(tv.u1.as_bytes(), 16).unwrap(), u1);

            let (q0x, q0y) = super::map_to_curve_simple_swu(&u0.to_bytes_be().1, &A, &B, &P, &Z);
            let (q1x, q1y) = super::map_to_curve_simple_swu(&u1.to_bytes_be().1, &A, &B, &P, &Z);

            assert_eq!(tv.q0x, hex::encode(q0x));
            assert_eq!(tv.q0y, hex::encode(q0y));
            assert_eq!(tv.q1x, hex::encode(q1x));
            assert_eq!(tv.q1y, hex::encode(q1y));

            let p0 = AffinePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(
                &q0x, &q0y, false,
            ))
            .unwrap()
            .to_curve();
            let p1 = AffinePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(
                &q1x, &q1y, false,
            ))
            .unwrap();

            let p = (p0 + p1).to_encoded_point(false);

            assert_eq!(tv.px, hex::encode(p.x().unwrap()));
            assert_eq!(tv.py, hex::encode(p.y().unwrap()));
        }
    }
}

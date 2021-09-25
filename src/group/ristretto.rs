// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::Group;
use crate::errors::{InternalError, ProtocolError};
use crate::hash::Hash;
use core::convert::TryInto;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use generic_array::{typenum::U32, GenericArray};
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

/// The implementation of such a subgroup for Ristretto
impl Group for RistrettoPoint {
    const SUITE_ID: usize = 0x0001;

    // Implements the `hash_to_ristretto255()` function from
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.txt
    fn map_to_curve<H: Hash>(msg: &[u8], dst: &[u8]) -> Result<Self, ProtocolError> {
        let uniform_bytes = super::expand::expand_message_xmd::<H>(msg, dst, 64)?;

        Ok(RistrettoPoint::from_uniform_bytes(
            uniform_bytes
                .as_slice()
                .try_into()
                .map_err(|_| InternalError::HashToCurveError)?,
        ))
    }

    // Implements the `HashToScalar()` function from
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-07.html#section-4.1
    fn hash_to_scalar<H: Hash>(input: &[u8], dst: &[u8]) -> Result<Self::Scalar, ProtocolError> {
        let uniform_bytes = super::expand::expand_message_xmd::<H>(input, dst, 64)?;

        Ok(Scalar::from_bytes_mod_order_wide(
            uniform_bytes
                .as_slice()
                .try_into()
                .map_err(|_| InternalError::HashToCurveError)?,
        ))
    }

    type Scalar = Scalar;
    type ScalarLen = U32;
    fn from_scalar_slice(
        scalar_bits: &GenericArray<u8, Self::ScalarLen>,
    ) -> Result<Self::Scalar, InternalError> {
        Ok(Scalar::from_bytes_mod_order(*scalar_bits.as_ref()))
    }

    fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        loop {
            let scalar = {
                #[cfg(not(test))]
                {
                    let mut scalar_bytes = [0u8; 64];
                    rng.fill_bytes(&mut scalar_bytes);
                    Scalar::from_bytes_mod_order_wide(&scalar_bytes)
                }

                // Tests need an exact conversion from bytes to scalar, sampling only 32 bytes from rng
                #[cfg(test)]
                {
                    let mut scalar_bytes = [0u8; 32];
                    rng.fill_bytes(&mut scalar_bytes);
                    Scalar::from_bytes_mod_order(scalar_bytes)
                }
            };

            if scalar != Scalar::zero() {
                break scalar;
            }
        }
    }

    fn scalar_as_bytes(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
        scalar.to_bytes().into()
    }

    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    // The byte length necessary to represent group elements
    type ElemLen = U32;
    fn from_element_slice(
        element_bits: &GenericArray<u8, Self::ElemLen>,
    ) -> Result<Self, InternalError> {
        CompressedRistretto::from_slice(element_bits)
            .decompress()
            .ok_or(InternalError::PointError)
    }

    // serialization of a group element
    fn to_arr(&self) -> GenericArray<u8, Self::ElemLen> {
        self.compress().to_bytes().into()
    }

    fn base_point() -> Self {
        RISTRETTO_BASEPOINT_POINT
    }

    fn mult_by_slice(&self, scalar: &GenericArray<u8, Self::ScalarLen>) -> Self {
        self * Scalar::from_bits(*scalar.as_ref())
    }

    /// Returns if the group element is equal to the identity (1)
    fn is_identity(&self) -> bool {
        self == &Self::identity()
    }

    fn ct_equal(&self, other: &Self) -> bool {
        ConstantTimeEq::ct_eq(self, other).into()
    }
}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::Group;
use crate::errors::{InternalPakeError, ProtocolError};
use crate::hash::Hash;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use generic_array::{typenum::U32, GenericArray};
use rand::{CryptoRng, RngCore};
use std::convert::TryInto;

/// The implementation of such a subgroup for Ristretto
impl Group for RistrettoPoint {
    const SUITE_ID: usize = 0x0001;

    // Implements the hash_to_ristretto255() function from
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.txt
    fn map_to_curve<H: Hash>(msg: &[u8], dst: &[u8]) -> Result<Self, ProtocolError> {
        let uniform_bytes = super::expand::expand_message_xmd::<H>(msg, dst, 64)?;

        Ok(RistrettoPoint::from_uniform_bytes(
            uniform_bytes
                .as_slice()
                .try_into()
                .map_err(|_| InternalPakeError::HashToCurveError)?,
        ))
    }

    fn hash_to_scalar<H: Hash>(input: &[u8], dst: &[u8]) -> Result<Self::Scalar, ProtocolError> {
        const LEN_IN_BYTES: usize = 64;
        let uniform_bytes = super::expand::expand_message_xmd::<H>(input, dst, LEN_IN_BYTES)?;
        let mut bits = [0u8; LEN_IN_BYTES];
        bits.copy_from_slice(&uniform_bytes[..]);

        Ok(Self::Scalar::from_bytes_mod_order_wide(&bits))
    }

    type Scalar = Scalar;
    type ScalarLen = U32;
    fn from_scalar_slice(
        scalar_bits: &GenericArray<u8, Self::ScalarLen>,
    ) -> Result<Self::Scalar, InternalPakeError> {
        let mut bits = [0u8; 32];
        bits.copy_from_slice(scalar_bits);
        Ok(Scalar::from_bytes_mod_order(bits))
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
    ) -> Result<Self, InternalPakeError> {
        CompressedRistretto::from_slice(element_bits)
            .decompress()
            .ok_or(InternalPakeError::PointError)
    }
    // serialization of a group element
    fn to_arr(&self) -> GenericArray<u8, Self::ElemLen> {
        let c = self.compress();
        *GenericArray::from_slice(c.as_bytes())
    }

    fn base_point() -> Self {
        RISTRETTO_BASEPOINT_POINT
    }

    fn mult_by_slice(&self, scalar: &GenericArray<u8, Self::ScalarLen>) -> Self {
        let arr: [u8; 32] = scalar.as_slice().try_into().expect("Wrong length");
        self * Scalar::from_bits(arr)
    }

    /// Returns if the group element is equal to the identity (1)
    fn is_identity(&self) -> bool {
        self == &Self::identity()
    }

    fn ct_equal(&self, other: &Self) -> bool {
        constant_time_eq::constant_time_eq(&self.to_arr(), &other.to_arr())
    }
}

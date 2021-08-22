// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Defines the Group trait to specify the underlying prime order group used in
//! OPAQUE's OPRF

mod expand;
#[cfg(feature = "p256")]
pub(crate) mod p256;
mod ristretto;
mod x25519;

use crate::errors::{InternalError, ProtocolError};
use crate::hash::Hash;
use core::ops::Mul;
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// A prime-order subgroup of a base field (EC, prime-order field ...). This
/// subgroup is noted additively — as in the draft RFC — in this trait.
pub trait Group: Copy + Sized + for<'a> Mul<&'a <Self as Group>::Scalar, Output = Self> {
    /// The ciphersuite identifier as dictated by
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-05.txt>
    const SUITE_ID: usize;

    /// transforms a password and domain separation tag (DST) into a curve point
    fn map_to_curve<H: Hash>(msg: &[u8], dst: &[u8]) -> Result<Self, ProtocolError>;

    /// Hashes a slice of pseudo-random bytes to a scalar
    fn hash_to_scalar<H: Hash>(input: &[u8], dst: &[u8]) -> Result<Self::Scalar, ProtocolError>;

    /// Generates the contextString parameter as defined in
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-05.txt>
    fn get_context_string(mode: u8) -> Result<alloc::vec::Vec<u8>, ProtocolError> {
        use crate::serialization::i2osp;

        Ok([i2osp(mode as usize, 1)?, i2osp(Self::SUITE_ID, 2)?].concat())
    }

    /// The type of base field scalars
    type Scalar: Zeroize + Copy;
    /// The byte length necessary to represent scalars
    type ScalarLen: ArrayLength<u8> + 'static;
    /// Return a scalar from its fixed-length bytes representation
    fn from_scalar_slice(
        scalar_bits: &GenericArray<u8, Self::ScalarLen>,
    ) -> Result<Self::Scalar, InternalError>;
    /// picks a scalar at random
    fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar;
    /// Serializes a scalar to bytes
    fn scalar_as_bytes(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen>;
    /// The multiplicative inverse of this scalar
    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar;

    /// The byte length necessary to represent group elements
    type ElemLen: ArrayLength<u8> + 'static;
    /// Return an element from its fixed-length bytes representation
    fn from_element_slice(
        element_bits: &GenericArray<u8, Self::ElemLen>,
    ) -> Result<Self, InternalError>;
    /// Serializes the `self` group element
    fn to_arr(&self) -> GenericArray<u8, Self::ElemLen>;

    /// Get the base point for the group
    fn base_point() -> Self;

    /// Multiply the point by a scalar, represented as a slice
    fn mult_by_slice(&self, scalar: &GenericArray<u8, Self::ScalarLen>) -> Self;

    /// Returns if the group element is equal to the identity (1)
    fn is_identity(&self) -> bool;

    /// Compares in constant time if the group elements are equal
    fn ct_equal(&self, other: &Self) -> bool;
}

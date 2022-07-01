// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Includes the KeGroup trait and definitions for the key exchange groups

mod elliptic_curve;
#[cfg(feature = "ristretto255")]
pub mod ristretto255;
#[cfg(feature = "x25519")]
pub mod x25519;

use digest::core_api::BlockSizeUser;
use digest::{Digest, OutputSizeUser};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, IsLessOrEqual, U11, U256};
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::errors::InternalError;

/// A group representation for use in the key exchange
pub trait KeGroup {
    /// Public key
    type Pk: Copy + Zeroize;
    /// Length of the public key
    type PkLen: ArrayLength<u8>;
    /// Secret key
    type Sk: Copy + Zeroize;
    /// Length of the secret key
    type SkLen: ArrayLength<u8>;

    /// Serializes `self`
    fn serialize_pk(pk: Self::Pk) -> GenericArray<u8, Self::PkLen>;

    /// Return a public key from its fixed-length bytes representation
    fn deserialize_pk(bytes: &[u8]) -> Result<Self::Pk, InternalError>;

    /// Generate a random secret key
    fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Sk;

    /// Hashes a slice of pseudo-random bytes to a scalar
    ///
    /// # Errors
    /// [`InternalError::HashToScalar`] if the `input` is empty or longer then
    /// [`u16::MAX`].
    fn hash_to_scalar<H>(input: &[&[u8]], dst: &[u8]) -> Result<Self::Sk, InternalError>
    where
        H: Digest + BlockSizeUser,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>;

    /// Corresponds to the DeriveAuthKeyPair() function defined in
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-08.html#section-6.4.2>
    ///
    /// Note that we cannot call the voprf crate directly since we need to
    /// ensure that the KeGroup is used for the hash_to_scalar operation (as
    /// opposed to the OprfGroup).
    fn derive_auth_keypair<CS: voprf::CipherSuite>(
        seed: &[u8],
        info: &[u8],
    ) -> Result<Self::Sk, InternalError>
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let context_string = create_context_string::<CS>(voprf::Mode::Oprf);
        let dst = GenericArray::from(STR_DERIVE_KEYPAIR).concat(context_string);

        let info_len = i2osp_2(info.len())
            .map_err(|_| InternalError::OprfError(voprf::Error::DeriveKeyPair))?;

        for counter in 0_u8..=u8::MAX {
            // deriveInput = seed || I2OSP(len(info), 2) || info
            // skS = G.HashToScalar(deriveInput || I2OSP(counter, 1), DST = "DeriveKeyPair"
            // || contextString)
            let sk_s = Self::hash_to_scalar::<CS::Hash>(
                &[seed, &info_len, info, &counter.to_be_bytes()],
                &dst,
            )
            .map_err(|_| InternalError::OprfError(voprf::Error::DeriveKeyPair))?;

            if !bool::from(Self::is_zero_scalar(sk_s)) {
                return Ok(sk_s);
            }
        }

        Err(InternalError::OprfError(voprf::Error::DeriveKeyPair))
    }

    /// Returns `true` if the scalar is zero.
    fn is_zero_scalar(scalar: Self::Sk) -> subtle::Choice;

    /// Return a public key from its secret key
    fn public_key(sk: Self::Sk) -> Self::Pk;

    /// Diffie-Hellman key exchange
    fn diffie_hellman(pk: Self::Pk, sk: Self::Sk) -> GenericArray<u8, Self::PkLen>;

    /// Serializes `self`
    fn serialize_sk(sk: Self::Sk) -> GenericArray<u8, Self::SkLen>;

    /// Return a public key from its fixed-length bytes representation
    fn deserialize_sk(bytes: &[u8]) -> Result<Self::Sk, InternalError>;
}

// Helper functions used to compute DeriveAuthKeyPair() (taken from the voprf
// crate)

const STR_VOPRF: [u8; 8] = *b"VOPRF10-";
const STR_DERIVE_KEYPAIR: [u8; 13] = *b"DeriveKeyPair";

/// Generates the contextString parameter as defined in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/>
fn create_context_string<CS: voprf::CipherSuite>(mode: voprf::Mode) -> GenericArray<u8, U11>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    GenericArray::from(STR_VOPRF)
        .concat([mode.to_u8()].into())
        .concat(CS::ID.to_be_bytes().into())
}

fn i2osp_2(input: usize) -> Result<[u8; 2], InternalError> {
    u16::try_from(input)
        .map(|input| input.to_be_bytes())
        .map_err(|_| InternalError::OprfInternalError(voprf::InternalError::I2osp))
}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Defines the GroupWithMapToCurve trait to specify how to map a password to a
//! curve point

use crate::group::Group;
use curve25519_dalek::{edwards::EdwardsPoint, ristretto::RistrettoPoint};

use hkdf::Hkdf;
use sha2::{Sha256, Sha512};

/// A subtrait of Group specifying how to hash a password into a point
pub trait GroupWithMapToCurve: Group {
    /// transforms a password and optional pepper into a curve point
    fn map_to_curve(password: &[u8], pepper: Option<&[u8]>) -> Self;
}

impl GroupWithMapToCurve for RistrettoPoint {
    fn map_to_curve(password: &[u8], pepper: Option<&[u8]>) -> Self {
        let (hashed_input, _) = Hkdf::<Sha512>::extract(pepper, password);
        <Self as Group>::hash_to_curve(&hashed_input)
    }
}

impl GroupWithMapToCurve for EdwardsPoint {
    fn map_to_curve(password: &[u8], pepper: Option<&[u8]>) -> Self {
        let (hashed_input, _) = Hkdf::<Sha256>::extract(pepper, password);
        <Self as Group>::hash_to_curve(&hashed_input)
    }
}

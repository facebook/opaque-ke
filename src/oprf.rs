// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    errors::InternalPakeError, group::Group, hash::Hash, map_to_curve::GroupWithMapToCurve,
};
use digest::Digest;
use generic_array::GenericArray;
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};

pub struct OprfClientBytes<Grp: Group> {
    pub alpha: Grp,
    pub blinding_factor: Grp::Scalar,
}

/// Computes the first step for the multiplicative blinding version of DH-OPRF. This
/// message is sent from the client (who holds the input) to the server (who holds the OPRF key).
/// The client can also pass in an optional "pepper" string to be mixed in with the input through
/// an HKDF computation.
pub(crate) fn generate_oprf1<R: RngCore + CryptoRng, G: GroupWithMapToCurve>(
    input: &[u8],
    pepper: Option<&[u8]>,
    blinding_factor_rng: &mut R,
) -> Result<OprfClientBytes<G>, InternalPakeError> {
    let mapped_point = G::map_to_curve(input, pepper);
    let blinding_factor = G::random_scalar(blinding_factor_rng);
    let alpha = mapped_point * &blinding_factor;
    Ok(OprfClientBytes {
        alpha,
        blinding_factor,
    })
}

/// Computes the second step for the multiplicative blinding version of DH-OPRF. This
/// message is sent from the server (who holds the OPRF key) to the client.
pub(crate) fn generate_oprf2<G: Group>(
    point: G,
    oprf_key: &G::Scalar,
) -> Result<G, InternalPakeError> {
    Ok(point * oprf_key)
}

/// Computes the third step for the multiplicative blinding version of DH-OPRF, in which
/// the client unblinds the server's message.
pub(crate) fn generate_oprf3<G: Group, H: Hash>(
    input: &[u8],
    point: G,
    blinding_factor: &G::Scalar,
) -> Result<GenericArray<u8, <H as Digest>::OutputSize>, InternalPakeError> {
    let unblinded = point * &G::scalar_invert(&blinding_factor);
    let ikm: Vec<u8> = [&unblinded.to_arr()[..], input].concat();
    let (prk, _) = Hkdf::<H>::extract(None, &ikm);
    Ok(prk)
}

// Benchmarking shims
#[cfg(feature = "bench")]
#[inline]
pub fn generate_oprf1_shim<R: RngCore + CryptoRng, G: GroupWithMapToCurve>(
    input: &[u8],
    pepper: Option<&[u8]>,
    blinding_factor_rng: &mut R,
) -> Result<OprfClientBytes<G>, InternalPakeError> {
    generate_oprf1(input, pepper, blinding_factor_rng)
}

#[cfg(feature = "bench")]
#[inline]
pub fn generate_oprf2_shim<G: Group>(
    point: G,
    oprf_key: &G::Scalar,
) -> Result<G, InternalPakeError> {
    generate_oprf2(point, oprf_key)
}

#[cfg(feature = "bench")]
#[inline]
pub fn generate_oprf3_shim<G: Group, H: Hash>(
    input: &[u8],
    point: G,
    blinding_factor: &G::Scalar,
) -> Result<GenericArray<u8, <H as Digest>::OutputSize>, InternalPakeError> {
    generate_oprf3::<G, H>(input, point, blinding_factor)
}

// Tests
// =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::Group;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use generic_array::{arr, GenericArray};
    use hkdf::Hkdf;
    use rand_core::OsRng;
    use sha2::{Sha256, Sha512};

    fn prf(
        input: &[u8],
        oprf_key: &[u8; 32],
    ) -> GenericArray<u8, <RistrettoPoint as Group>::ElemLen> {
        let (hashed_input, _) = Hkdf::<Sha512>::extract(None, &input);
        let point = RistrettoPoint::hash_to_curve(GenericArray::from_slice(&hashed_input));
        let scalar =
            RistrettoPoint::from_scalar_slice(GenericArray::from_slice(&oprf_key[..])).unwrap();
        let res = point * scalar;
        let ikm: Vec<u8> = [&res.to_arr()[..], &input].concat();

        let (prk, _) = Hkdf::<Sha256>::extract(None, &ikm);
        prk
    }

    #[test]
    fn oprf_retrieval() -> Result<(), InternalPakeError> {
        let input = b"hunter2";
        let mut rng = OsRng;
        let OprfClientBytes {
            alpha,
            blinding_factor,
        } = generate_oprf1::<_, RistrettoPoint>(&input[..], None, &mut rng)?;
        let salt_bytes = arr![
            u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let salt = RistrettoPoint::from_scalar_slice(&salt_bytes)?;
        let beta = generate_oprf2::<RistrettoPoint>(alpha, &salt)?;
        let res = generate_oprf3::<RistrettoPoint, sha2::Sha256>(input, beta, &blinding_factor)?;
        let res2 = prf(&input[..], &salt.as_bytes());
        assert_eq!(res, res2);
        Ok(())
    }

    #[test]
    fn oprf_inversion_unsalted() {
        let mut rng = OsRng;
        let mut input = vec![0u8; 64];
        rng.fill_bytes(&mut input);
        let OprfClientBytes {
            alpha,
            blinding_factor,
        } = generate_oprf1::<_, RistrettoPoint>(&input, None, &mut rng).unwrap();
        let res = generate_oprf3::<RistrettoPoint, sha2::Sha256>(&input, alpha, &blinding_factor)
            .unwrap();

        let (hashed_input, _) = Hkdf::<Sha512>::extract(None, &input);
        let mut bits = [0u8; 64];
        bits.copy_from_slice(&hashed_input);

        let point = RistrettoPoint::from_uniform_bytes(&bits);
        let mut ikm: Vec<u8> = Vec::new();
        ikm.extend_from_slice(&point.to_arr());
        ikm.extend_from_slice(&input);
        let (prk, _) = Hkdf::<Sha256>::extract(None, &ikm);

        assert_eq!(res, prk);
    }
}

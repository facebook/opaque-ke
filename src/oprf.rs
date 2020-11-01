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

/// Used to store the OPRF input and blinding factor
pub struct Token<Grp: Group> {
    pub(crate) data: Vec<u8>,
    pub(crate) blind: Grp::Scalar,
}

static STR_VOPRF: &[u8] = b"VOPRF05";

/// Computes the first step for the multiplicative blinding version of DH-OPRF. This
/// message is sent from the client (who holds the input) to the server (who holds the OPRF key).
/// The client can also pass in an optional "pepper" string to be mixed in with the input through
/// an HKDF computation.
pub(crate) fn blind_with_postprocessing<R: RngCore + CryptoRng, G: GroupWithMapToCurve>(
    input: &[u8],
    blinding_factor_rng: &mut R,
    postprocess: fn(G::Scalar) -> G::Scalar,
) -> Result<(Token<G>, G), InternalPakeError> {
    let mapped_point = G::map_to_curve(input, Some(STR_VOPRF)); // TODO: add contextString from RFC
    let blinding_factor = G::random_scalar(blinding_factor_rng);
    let blind = postprocess(blinding_factor);
    let blind_token = mapped_point * &blind;
    Ok((
        Token {
            data: input.to_vec(),
            blind,
        },
        blind_token,
    ))
}

/// Computes the second step for the multiplicative blinding version of DH-OPRF. This
/// message is sent from the server (who holds the OPRF key) to the client.
pub(crate) fn evaluate<G: Group>(point: G, oprf_key: &G::Scalar) -> Result<G, InternalPakeError> {
    Ok(point * oprf_key)
}

/// Computes the third step for the multiplicative blinding version of DH-OPRF, in which
/// the client unblinds the server's message.
pub(crate) fn unblind_and_finalize<G: Group, H: Hash>(
    token: &Token<G>,
    point: G,
) -> Result<GenericArray<u8, <H as Digest>::OutputSize>, InternalPakeError> {
    let unblinded = point * &G::scalar_invert(&token.blind);
    let ikm: Vec<u8> = [&unblinded.to_arr()[..], &token.data].concat();
    // TODO: implement proper finalizing code here
    let (prk, _) = Hkdf::<H>::extract(None, &ikm);
    Ok(prk)
}

// Benchmarking shims
#[cfg(feature = "bench")]
#[inline]
pub fn blind_shim<R: RngCore + CryptoRng, G: GroupWithMapToCurve>(
    input: &[u8],
    blinding_factor_rng: &mut R,
) -> Result<(Token<G>, G), InternalPakeError> {
    blind_with_postprocessing(input, blinding_factor_rng, std::convert::identity)
}

#[cfg(feature = "bench")]
#[inline]
pub fn evaluate_shim<G: Group>(point: G, oprf_key: &G::Scalar) -> Result<G, InternalPakeError> {
    evaluate(point, oprf_key)
}

#[cfg(feature = "bench")]
#[inline]
pub fn unblind_and_finalize_shim<G: Group, H: Hash>(
    token: &Token<G>,
    point: G,
) -> Result<GenericArray<u8, <H as Digest>::OutputSize>, InternalPakeError> {
    unblind_and_finalize::<G, H>(token, point)
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
        let (hashed_input, _) = Hkdf::<Sha512>::extract(Some(STR_VOPRF), &input);
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
        let (token, alpha) = blind_with_postprocessing::<_, RistrettoPoint>(
            &input[..],
            &mut rng,
            std::convert::identity,
        )?;
        let oprf_key_bytes = arr![
            u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let oprf_key = RistrettoPoint::from_scalar_slice(&oprf_key_bytes)?;
        let beta = evaluate::<RistrettoPoint>(alpha, &oprf_key)?;
        let res = unblind_and_finalize::<RistrettoPoint, sha2::Sha256>(&token, beta)?;
        let res2 = prf(&input[..], &oprf_key.as_bytes());
        assert_eq!(res, res2);
        Ok(())
    }

    #[test]
    fn oprf_inversion_unsalted() {
        let mut rng = OsRng;
        let mut input = vec![0u8; 64];
        rng.fill_bytes(&mut input);
        let (token, alpha) = blind_with_postprocessing::<_, RistrettoPoint>(
            &input,
            &mut rng,
            std::convert::identity,
        )
        .unwrap();
        let res = unblind_and_finalize::<RistrettoPoint, sha2::Sha256>(&token, alpha).unwrap();

        let (hashed_input, _) = Hkdf::<Sha512>::extract(Some(STR_VOPRF), &input);
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

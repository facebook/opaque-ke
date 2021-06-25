// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    errors::InternalPakeError, group::Group, hash::Hash, map_to_curve::GroupWithMapToCurve,
    serialization::serialize,
};
use digest::Digest;
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};

/// Used to store the OPRF input and blinding factor
#[cfg_attr(feature = "serialize", derive(serde::Deserialize, serde::Serialize))]
pub struct Token<Grp: Group> {
    pub(crate) data: Vec<u8>,
    pub(crate) blind: Grp::Scalar,
}

impl_clone_for!(struct Token<Grp: Group>, [data, blind]);
impl_debug_eq_hash_for!(struct Token<Grp: Group>, [data, blind], [Grp::Scalar]);

static STR_VOPRF: &[u8] = b"VOPRF06-HashToGroup-";
static STR_VOPRF_FINALIZE: &[u8] = b"VOPRF06-Finalize-";
static MODE_BASE: u8 = 0x00;

/// Computes the first step for the multiplicative blinding version of DH-OPRF. This
/// message is sent from the client (who holds the input) to the server (who holds the OPRF key).
/// The client can also pass in an optional "pepper" string to be mixed in with the input through
/// an HKDF computation.
pub(crate) fn blind<R: RngCore + CryptoRng, G: GroupWithMapToCurve, H: Hash>(
    input: &[u8],
    blinding_factor_rng: &mut R,
) -> Result<(Token<G>, G), InternalPakeError> {
    // Choose a random scalar that must be non-zero
    let blind = G::random_nonzero_scalar(blinding_factor_rng);
    let dst = [STR_VOPRF, &G::get_context_string(MODE_BASE)].concat();
    let mapped_point = G::map_to_curve::<H>(input, &dst)?;
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
pub(crate) fn evaluate<G: Group>(point: G, oprf_key: &G::Scalar) -> G {
    point * oprf_key
}

/// Computes the third step for the multiplicative blinding version of DH-OPRF, in which
/// the client unblinds the server's message.
pub(crate) fn finalize<G: GroupWithMapToCurve, H: Hash>(
    input: &[u8],
    blind: &G::Scalar,
    evaluated_element: G,
) -> GenericArray<u8, <H as Digest>::OutputSize> {
    let unblinded_element = evaluated_element * &G::scalar_invert(blind);
    finalize_after_unblind::<G, H>(input, unblinded_element)
}

fn finalize_after_unblind<G: GroupWithMapToCurve, H: Hash>(
    input: &[u8],
    unblinded_element: G,
) -> GenericArray<u8, <H as Digest>::OutputSize> {
    let finalize_dst = [STR_VOPRF_FINALIZE, &G::get_context_string(MODE_BASE)].concat();
    let hash_input = [
        serialize(input, 2),
        serialize(&unblinded_element.to_arr().to_vec(), 2),
        serialize(&finalize_dst, 2),
    ]
    .concat();
    <H as Digest>::digest(&hash_input)
}

////////////////////////
// Benchmarking shims //
////////////////////////

#[cfg(feature = "bench")]
#[doc(hidden)]
#[inline]
pub fn blind_shim<R: RngCore + CryptoRng, G: GroupWithMapToCurve, H: Hash>(
    input: &[u8],
    blinding_factor_rng: &mut R,
) -> Result<(Token<G>, G), InternalPakeError> {
    blind::<R, G, H>(input, blinding_factor_rng)
}

#[cfg(feature = "bench")]
#[doc(hidden)]
#[inline]
pub fn evaluate_shim<G: Group>(point: G, oprf_key: &G::Scalar) -> G {
    evaluate(point, oprf_key)
}

#[cfg(feature = "bench")]
#[doc(hidden)]
#[inline]
pub fn finalize_shim<G: GroupWithMapToCurve, H: Hash>(
    token: &Token<G>,
    point: G,
) -> Result<GenericArray<u8, <H as Digest>::OutputSize>, InternalPakeError> {
    Ok(finalize::<G, H>(&token.data, &token.blind, point))
}

///////////
// Tests //
// ===== //
///////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::Group;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use generic_array::{arr, GenericArray};
    use rand::rngs::OsRng;
    use sha2::Sha512;

    fn prf(input: &[u8], oprf_key: &[u8; 32]) -> GenericArray<u8, <Sha512 as Digest>::OutputSize> {
        let dst = [STR_VOPRF, &RistrettoPoint::get_context_string(MODE_BASE)].concat();
        let point = RistrettoPoint::map_to_curve::<Sha512>(input, &dst).unwrap();
        let scalar =
            RistrettoPoint::from_scalar_slice(GenericArray::from_slice(&oprf_key[..])).unwrap();
        let res = point * scalar;

        finalize_after_unblind::<RistrettoPoint, sha2::Sha512>(&input, res)
    }

    #[test]
    fn oprf_retrieval() -> Result<(), InternalPakeError> {
        let input = b"hunter2";
        let mut rng = OsRng;
        let (token, alpha) = blind::<_, RistrettoPoint, Sha512>(&input[..], &mut rng)?;
        let oprf_key_bytes = arr![
            u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let oprf_key = RistrettoPoint::from_scalar_slice(&oprf_key_bytes)?;
        let beta = evaluate::<RistrettoPoint>(alpha, &oprf_key);
        let res = finalize::<RistrettoPoint, sha2::Sha512>(&token.data, &token.blind, beta);
        let res2 = prf(&input[..], &oprf_key.as_bytes());
        assert_eq!(res, res2);
        Ok(())
    }

    #[test]
    fn oprf_inversion_unsalted() {
        let mut rng = OsRng;
        let mut input = vec![0u8; 64];
        rng.fill_bytes(&mut input);
        let (token, alpha) = blind::<_, RistrettoPoint, sha2::Sha512>(&input, &mut rng).unwrap();
        let res = finalize::<RistrettoPoint, sha2::Sha512>(&token.data, &token.blind, alpha);

        let dst = [STR_VOPRF, &RistrettoPoint::get_context_string(MODE_BASE)].concat();
        let point = RistrettoPoint::map_to_curve::<Sha512>(&input, &dst).unwrap();
        let res2 = finalize_after_unblind::<RistrettoPoint, sha2::Sha512>(&input, point);

        assert_eq!(res, res2);
    }
}

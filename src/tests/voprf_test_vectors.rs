// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::group::Group;
use crate::hash::Hash;
use crate::tests::mock_rng::CycleRng;
use crate::{errors::*, oprf};
use alloc::string::ToString;
use alloc::vec::Vec;
use curve25519_dalek::ristretto::RistrettoPoint;
use generic_array::GenericArray;
use serde_json::Value;
use sha2::Sha512;

struct VOPRFTestVectorParameters {
    sksm: Vec<u8>,
    input: Vec<u8>,
    blind: Vec<u8>,
    blinded_element: Vec<u8>,
    evaluation_element: Vec<u8>,
    output: Vec<u8>,
}

// Taken from https://github.com/cfrg/draft-irtf-cfrg-voprf/blob/master/draft-irtf-cfrg-voprf.md
// in base mode
static OPRF_RISTRETTO255_SHA512: &[&str] = &[
    r#"
    {
        "sksm": "caeff69352df4905a9121a4997704ca8cee1524a110819eb87deba1a39ec1701",
        "input": "00",
        "blind": "c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03",
        "blinded_element": "fc20e03aff3a9de9b37e8d35886ade11ec7d85c2a1fb5bb0b1686c64e07ac467",
        "evaluation_element": "7c72cc293cd7d44c0b57c273f27befd598b132edc665694bdc9c42a4d3083c0a",
        "output": "e3a209dce2d3ea3d84fcddb282818caebb756a341e08a310d9904314f5392085d13c3f76339d745db0f46974a6049c3ea9546305af55d37760b2136d9b3f0134"
    }
    "#,
    r#"
    {
        "sksm": "caeff69352df4905a9121a4997704ca8cee1524a110819eb87deba1a39ec1701",
        "input": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "blind": "5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b",
        "blinded_element": "483d4f39de5ff77fa0f9a0ad2334dd5bf87f2cda868539d21de67ce49e7d1536",
        "evaluation_element": "026f2758fc62f02a7ff95f35ec6f20186aa57c0274361655543ea235d7b2aa34",
        "output": "2c17dc3e9398dadb44bb2d3360c446302e99f1fe0ec40f0b1ad25c9cf002be1e4b41b4900ef056537fe8c14532ccea4d796f5feab9541af48057d83c0db86fe9"
    }
    "#,
];
#[cfg(feature = "p256")]
static OPRF_P256_SHA256: &[&str] = &[
    r#"
    {
        "sksm": "a1b2355828f2c76de6749af9d093bd9fe0f2cada3ec653cd9a6d3126a7a7827b",
        "input": "00",
        "blind": "5d9e7f6efd3093c32ecceabd57fb03cf760c926d2a7bfa265babf29ec98af0d0",
        "blinded_element": "03e3c379698da853d9844098fa0ac676970d5ec24167b598714cd2ee188604ddd2",
        "evaluation_element": "03ea54e8d095332d1a601a3f8a5013188aea036bf9b563236f7fd3b046908b42fd",
        "output": "464e3e51e4086a824d9a2f939524d7069ae4072a788bc9d5daa0762b25826437"
    }
    "#,
    r#"
    {
        "sksm": "a1b2355828f2c76de6749af9d093bd9fe0f2cada3ec653cd9a6d3126a7a7827b",
        "input": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "blind": "825155ab61f17605af2ae2e935c78d857c9407bcd45128d57d338f1671b5fcbe",
        "blinded_element": "030b40be181ffbb3c3ae4a4911287c43261f5e4034781def69c51608f372a02102",
        "evaluation_element": "03115ad70ea55dbb4006da0ee3589a3582f31ef9cd143996d1e31a25ad3abdcf6f",
        "output": "b597d58c843d0f9d2712121b0a3e2912ebee1c829eed3089eade9af4359ab275"
    }
    "#,
];

fn decode(values: &Value, key: &str) -> Option<Vec<u8>> {
    values[key]
        .as_str()
        .and_then(|s| hex::decode(&s.to_string()).ok())
}

fn populate_test_vectors(values: &Value) -> VOPRFTestVectorParameters {
    VOPRFTestVectorParameters {
        sksm: decode(&values, "sksm").unwrap(),
        input: decode(&values, "input").unwrap(),
        blind: decode(&values, "blind").unwrap(),
        blinded_element: decode(&values, "blinded_element").unwrap(),
        evaluation_element: decode(&values, "evaluation_element").unwrap(),
        output: decode(&values, "output").unwrap(),
    }
}

#[test]
fn tests() -> Result<(), ProtocolError> {
    test_blind::<RistrettoPoint, Sha512>(OPRF_RISTRETTO255_SHA512)?;
    test_evaluate::<RistrettoPoint>(OPRF_RISTRETTO255_SHA512)?;
    test_finalize::<RistrettoPoint, Sha512>(OPRF_RISTRETTO255_SHA512)?;

    #[cfg(feature = "p256")]
    {
        use p256_::ProjectivePoint;
        use sha2::Sha256;

        test_blind::<ProjectivePoint, Sha256>(OPRF_P256_SHA256)?;
        test_evaluate::<ProjectivePoint>(OPRF_P256_SHA256)?;
        test_finalize::<ProjectivePoint, Sha256>(OPRF_P256_SHA256)?;
    }

    Ok(())
}

// Tests input -> blind, blinded_element
fn test_blind<G: Group, H: Hash>(tvs: &[&str]) -> Result<(), ProtocolError> {
    for tv in tvs {
        let parameters = populate_test_vectors(&serde_json::from_str(tv).unwrap());
        let mut rng = CycleRng::new(parameters.blind.to_vec());

        let (token, blinded_element) = oprf::blind::<_, G, H>(&parameters.input, &mut rng)?;

        assert_eq!(&parameters.blind, &G::scalar_as_bytes(token.blind).to_vec());
        assert_eq!(
            &parameters.blinded_element,
            &blinded_element.to_arr().to_vec()
        );
    }
    Ok(())
}

// Tests sksm, blinded_element -> evaluation_element
fn test_evaluate<G: Group>(tvs: &[&str]) -> Result<(), ProtocolError> {
    for tv in tvs {
        let parameters = populate_test_vectors(&serde_json::from_str(tv).unwrap());
        let evaluation_element = oprf::evaluate::<G>(
            G::from_element_slice(GenericArray::from_slice(&parameters.blinded_element)).unwrap(),
            &G::from_scalar_slice(GenericArray::from_slice(&parameters.sksm)).unwrap(),
        );

        assert_eq!(
            &parameters.evaluation_element,
            &evaluation_element.to_arr().to_vec()
        );
    }
    Ok(())
}

// Tests input, blind, evaluation_element -> output
fn test_finalize<G: Group, H: Hash>(tvs: &[&str]) -> Result<(), ProtocolError> {
    for tv in tvs {
        let parameters = populate_test_vectors(&serde_json::from_str(tv).unwrap());

        let output = oprf::finalize::<G, H>(
            &parameters.input,
            &G::from_scalar_slice(GenericArray::from_slice(&parameters.blind))?,
            G::from_element_slice(GenericArray::from_slice(&parameters.evaluation_element))?,
        )?;

        assert_eq!(&parameters.output, &output.to_vec());
    }
    Ok(())
}

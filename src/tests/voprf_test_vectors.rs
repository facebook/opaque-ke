// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::tests::mock_rng::CycleRng;
use crate::{errors::*, group::Group, oprf};
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

// Tests input -> blind, blinded_element
#[test]
fn test_blind() -> Result<(), ProtocolError> {
    for tv in OPRF_RISTRETTO255_SHA512 {
        let parameters = populate_test_vectors(&serde_json::from_str(tv).unwrap());
        let mut rng = CycleRng::new(parameters.blind.to_vec());

        let (token, blinded_element) =
            oprf::blind::<_, RistrettoPoint, Sha512>(&parameters.input, &mut rng)?;

        assert_eq!(
            &parameters.blind,
            &RistrettoPoint::scalar_as_bytes(token.blind).to_vec()
        );
        assert_eq!(
            &parameters.blinded_element,
            &blinded_element.to_arr().to_vec()
        );
    }
    Ok(())
}

// Tests sksm, blinded_element -> evaluation_element
#[test]
fn test_evaluate() -> Result<(), PakeError> {
    for tv in OPRF_RISTRETTO255_SHA512 {
        let parameters = populate_test_vectors(&serde_json::from_str(tv).unwrap());
        let evaluation_element = oprf::evaluate::<RistrettoPoint>(
            RistrettoPoint::from_element_slice(GenericArray::from_slice(
                &parameters.blinded_element,
            ))
            .unwrap(),
            &RistrettoPoint::from_scalar_slice(GenericArray::from_slice(&parameters.sksm)).unwrap(),
        );

        assert_eq!(
            &parameters.evaluation_element,
            &evaluation_element.to_arr().to_vec()
        );
    }
    Ok(())
}

// Tests input, blind, evaluation_element -> output
#[test]
fn test_finalize() -> Result<(), ProtocolError> {
    for tv in OPRF_RISTRETTO255_SHA512 {
        let parameters = populate_test_vectors(&serde_json::from_str(tv).unwrap());

        let output = oprf::finalize::<RistrettoPoint, Sha512>(
            &parameters.input,
            &RistrettoPoint::from_scalar_slice(GenericArray::from_slice(&parameters.blind))?,
            RistrettoPoint::from_element_slice(GenericArray::from_slice(
                &parameters.evaluation_element,
            ))?,
        )?;

        assert_eq!(&parameters.output, &output.to_vec());
    }
    Ok(())
}

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
        "sksm": "758cbac0e1eb4265d80f6e6489d9a74d788f7ddeda67d7fb3c08b08f44bda30a",
        "input": "00",
        "blind": "c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03",
        "blinded_element": "3c7f2d901c0d4f245503a186086fbdf5d8b4408432b25c5163e8b5a19c258348",
        "evaluation_element": "fc6c2b854553bf1ed6674072ed0bde1a9911e02b4bd64aa02cfb428f30251e77",
        "output": "d8ed12382086c74564ae19b7a2b5ed9bdc52656d1fc151faaae51aaba86291e8df0b2143a92f24d44d5efd0892e2e26721d27d88745343493634a66d3a925e3a"
    }
    "#,
    r#"
    {
        "sksm": "758cbac0e1eb4265d80f6e6489d9a74d788f7ddeda67d7fb3c08b08f44bda30a",
        "input": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "blind": "5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b",
        "blinded_element": "28a5e797b710f76d20a52507145fbf320a574ec2c8ab0e33e65dd2c277d0ee56",
        "evaluation_element": "345e140b707257ae83d4911f7ead3177891e7a62c54097732802c4c7a98ab25a",
        "output": "4d5f4221b5ebfd4d1a9dd54830e1ed0bce5a8f30a792723a6fddfe6cfe9f86bb1d95a3725818aeb725eb0b1b52e01ee9a72f47042372ef66c307770054d674fc"
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
fn test_blind() -> Result<(), PakeError> {
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
fn test_finalize() -> Result<(), PakeError> {
    for tv in OPRF_RISTRETTO255_SHA512 {
        let parameters = populate_test_vectors(&serde_json::from_str(tv).unwrap());

        let output = oprf::finalize::<RistrettoPoint, Sha512>(
            &parameters.input,
            &RistrettoPoint::from_scalar_slice(GenericArray::from_slice(&parameters.blind))?,
            RistrettoPoint::from_element_slice(GenericArray::from_slice(
                &parameters.evaluation_element,
            ))?,
        );

        assert_eq!(&parameters.output, &output.to_vec());
    }
    Ok(())
}

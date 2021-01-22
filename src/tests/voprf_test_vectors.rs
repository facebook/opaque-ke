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
    unblinded_element: Vec<u8>,
    info: Vec<u8>,
    output: Vec<u8>,
}

// Taken from https://github.com/cfrg/draft-irtf-cfrg-voprf/blob/master/draft-irtf-cfrg-voprf.md
// in base mode
static OPRF_RISTRETTO255_SHA512: &'static [&str] = &[
    r#"
    {
        "sksm": "c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03",
        "input": "00",
        "blind": "5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b",
        "blinded_element": "5cccd309ec729aebe398c53e19c0ab09c24a29f01036960bdad109852e7bdb44",
        "evaluation_element": "86bd5eeabf29a87cb4a5c7207cb3ade5297e65f9b74c979bd3551891f4b21515",
        "unblinded_element": "3c7f2d901c0d4f245503a186086fbdf5d8b4408432b25c5163e8b5a19c258348",
        "info": "4f505246207465737420766563746f7273",
        "output": "0bb570873cc0402ca38f1a2c395301f2a3627616e305f2bc54bb08c3f6ea9871eb71074e52e36b90778ba7c3e3429ef7170245c9e01647f3827fdef84d3ba930"
    }
    "#,
    r#"
    {
        "sksm": "c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03",
        "input": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "blind": "ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e3263503",
        "blinded_element": "227d63ca69e93bd062193c1e97fff3d5ebf628f646009d77c4e22ba6429be154",
        "evaluation_element": "063b91a12e7cbb98dfeb75d8a7eeb83aacf9fd6df7e0b4197466fb77a27fa631",
        "unblinded_element": "804ec6774764ed50a0bbad0a5f477aa04df7323acab8f98ca6e468b7790bca4c",
        "info": "4f505246207465737420766563746f7273",
        "output": "af7cc264dbc96a6b898ba0fa33bfa9e1407bf1dcfbf8772204d470d4458b8f047806679dbfa251f656b906edf9fa638e268adf979bd0e2380a092047d61f9db9"
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
        unblinded_element: decode(&values, "unblinded_element").unwrap(),
        info: decode(&values, "info").unwrap(),
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
            &RistrettoPoint::scalar_as_bytes(&token.blind).to_vec()
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

// Tests sksm, evaluation_element -> evaluation_element
#[test]
fn test_unblind() -> Result<(), PakeError> {
    for tv in OPRF_RISTRETTO255_SHA512 {
        let parameters = populate_test_vectors(&serde_json::from_str(tv).unwrap());

        let token = oprf::Token {
            data: parameters.input,
            blind: RistrettoPoint::from_scalar_slice(GenericArray::from_slice(
                &parameters.blind[..],
            ))
            .unwrap(),
        };

        let unblinded_element = oprf::unblind::<RistrettoPoint>(
            &token,
            RistrettoPoint::from_element_slice(GenericArray::from_slice(
                &parameters.evaluation_element,
            ))
            .unwrap(),
        );

        assert_eq!(&parameters.unblinded_element, &unblinded_element);
    }
    Ok(())
}

// Tests input, unblinded_element, info -> output
#[test]
fn test_finalize() -> Result<(), PakeError> {
    for tv in OPRF_RISTRETTO255_SHA512 {
        let parameters = populate_test_vectors(&serde_json::from_str(tv).unwrap());

        let output = oprf::finalize::<RistrettoPoint, Sha512>(
            &parameters.input,
            &parameters.unblinded_element,
            &parameters.info,
        );

        assert_eq!(&parameters.output, &output.to_vec());
    }
    Ok(())
}

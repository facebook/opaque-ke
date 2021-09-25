// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::Group;
use crate::errors::{InternalError, ProtocolError};
use crate::hash::Hash;
use curve25519_dalek::{constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar};
use generic_array::{typenum::U32, GenericArray};
use rand::{CryptoRng, RngCore};

/// The implementation of such a subgroup for Ristretto
impl Group for MontgomeryPoint {
    const SUITE_ID: usize = 0xFFFF;

    fn map_to_curve<H: Hash>(_msg: &[u8], _dst: &[u8]) -> Result<Self, ProtocolError> {
        unreachable!("this algorithm should only be used as the `KeGroup`")
    }

    fn hash_to_scalar<H: Hash>(_input: &[u8], _dst: &[u8]) -> Result<Self::Scalar, ProtocolError> {
        unreachable!("this algorithm should only be used as the `KeGroup`")
    }

    type Scalar = Scalar;
    type ScalarLen = U32;
    fn from_scalar_slice(
        scalar_bits: &GenericArray<u8, Self::ScalarLen>,
    ) -> Result<Self::Scalar, InternalError> {
        Ok(Scalar::from_bytes_mod_order(*scalar_bits.as_ref()))
    }

    fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        loop {
            let scalar = {
                #[cfg(not(test))]
                {
                    let mut scalar_bytes = [0u8; 64];
                    rng.fill_bytes(&mut scalar_bytes);
                    Scalar::from_bytes_mod_order_wide(&scalar_bytes)
                }

                // Tests need an exact conversion from bytes to scalar, sampling only 32 bytes from rng
                #[cfg(test)]
                {
                    let mut scalar_bytes = [0u8; 32];
                    rng.fill_bytes(&mut scalar_bytes);
                    Scalar::from_bytes_mod_order(scalar_bytes)
                }
            };

            if scalar != Scalar::zero() {
                break scalar;
            }
        }
    }

    fn scalar_as_bytes(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
        scalar.to_bytes().into()
    }

    fn scalar_invert(_scalar: &Self::Scalar) -> Self::Scalar {
        unreachable!("this algorithm should only be used as the `KeGroup`")
    }

    // The byte length necessary to represent group elements
    type ElemLen = U32;
    fn from_element_slice(
        element_bits: &GenericArray<u8, Self::ElemLen>,
    ) -> Result<Self, InternalError> {
        Ok(Self(*element_bits.as_ref()))
    }

    // serialization of a group element
    fn to_arr(&self) -> GenericArray<u8, Self::ElemLen> {
        self.to_bytes().into()
    }

    fn base_point() -> Self {
        X25519_BASEPOINT
    }

    fn mult_by_slice(&self, scalar: &GenericArray<u8, Self::ScalarLen>) -> Self {
        self * Scalar::from_bits(*scalar.as_ref())
    }

    /// Returns if the group element is equal to the identity (1)
    fn is_identity(&self) -> bool {
        unreachable!("this algorithm should only be used as the `KeGroup`")
    }

    fn ct_equal(&self, _other: &Self) -> bool {
        unreachable!("this algorithm should only be used as the `KeGroup`")
    }
}

#[test]
fn test() -> Result<(), ProtocolError> {
    use crate::{
        key_exchange::tripledh::TripleDH, slow_hash::NoOpHash, CipherSuite, ClientLogin,
        ClientLoginFinishParameters, ClientLoginFinishResult, ClientLoginStartResult,
        ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationFinishResult,
        ClientRegistrationStartResult, ServerLogin, ServerLoginStartParameters,
        ServerLoginStartResult, ServerRegistration, ServerSetup,
    };
    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand::rngs::OsRng;

    struct X25519Sha512NoSlowHash;
    impl CipherSuite for X25519Sha512NoSlowHash {
        type OprfGroup = RistrettoPoint;
        type KeGroup = MontgomeryPoint;
        type KeyExchange = TripleDH;
        type Hash = sha2::Sha512;
        type SlowHash = NoOpHash;
    }

    const PASSWORD: &[u8] = b"1234";

    let server_setup = ServerSetup::<X25519Sha512NoSlowHash>::new(&mut OsRng);

    let ClientRegistrationStartResult {
        message,
        state: client,
    } = ClientRegistration::start(&mut OsRng, PASSWORD)?;
    let message = ServerRegistration::start(&server_setup, message, &[])?.message;
    let ClientRegistrationFinishResult {
        message,
        export_key: register_export_key,
        ..
    } = client.finish(
        &mut OsRng,
        message,
        ClientRegistrationFinishParameters::default(),
    )?;
    let server_registration = ServerRegistration::finish(message);

    let ClientLoginStartResult {
        message,
        state: client,
    } = ClientLogin::start(&mut OsRng, PASSWORD)?;
    let ServerLoginStartResult {
        message,
        state: server,
        ..
    } = ServerLogin::start(
        &mut OsRng,
        &server_setup,
        Some(server_registration),
        message,
        &[],
        ServerLoginStartParameters::default(),
    )?;
    let ClientLoginFinishResult {
        message,
        session_key: client_session_key,
        export_key: login_export_key,
        ..
    } = client.finish(message, ClientLoginFinishParameters::default())?;
    let server_session_key = server.finish(message)?.session_key;

    assert_eq!(register_export_key, login_export_key);
    assert_eq!(client_session_key, server_session_key);

    let ClientLoginStartResult {
        message,
        state: client,
    } = ClientLogin::start(&mut OsRng, PASSWORD)?;
    let ServerLoginStartResult { message, .. } = ServerLogin::start(
        &mut OsRng,
        &server_setup,
        None,
        message,
        &[],
        ServerLoginStartParameters::default(),
    )?;

    assert!(matches!(
        client.finish(message, ClientLoginFinishParameters::default()),
        Err(ProtocolError::InvalidLoginError)
    ));

    Ok(())
}

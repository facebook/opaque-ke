// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    envelope::{Envelope, EnvelopeLen, InnerEnvelopeMode},
    errors::*,
    hash::{OutputSize, ProxyHash},
    key_exchange::{
        group::KeGroup,
        traits::{Ke1MessageLen, Ke2MessageLen},
    },
    key_exchange::{
        traits::{FromBytes, KeyExchange, ToBytes},
        tripledh::{NonceLen, TripleDH},
    },
    keypair::KeyPair,
    messages::CredentialResponseWithoutKeLen,
    opaque::MaskedResponseLen,
    serialization::{i2osp, os2ip, Serialize},
    *,
};
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Add;

use digest::core_api::{BlockSizeUser, CoreProxy};
use digest::Output;
use generic_array::{
    typenum::{IsLess, Le, NonZero, Sum, Unsigned, U2, U256},
    ArrayLength,
};
use proptest::{collection::vec, prelude::*};
use rand::{rngs::OsRng, RngCore};
use voprf::Group;

#[cfg(feature = "ristretto255")]
struct Ristretto255;
#[cfg(feature = "ristretto255")]
impl CipherSuite for Ristretto255 {
    type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
    type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = crate::slow_hash::NoOpHash;
}

#[cfg(feature = "p256")]
struct P256;
#[cfg(feature = "p256")]
impl CipherSuite for P256 {
    type OprfGroup = p256_::ProjectivePoint;
    type KeGroup = p256_::PublicKey;
    type KeyExchange = TripleDH;
    type Hash = sha2::Sha256;
    type SlowHash = crate::slow_hash::NoOpHash;
}

fn random_point<CS: CipherSuite>() -> CS::KeGroup
where
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let mut rng = OsRng;
    let sk = CS::KeGroup::random_sk(&mut rng);
    CS::KeGroup::public_key(&sk)
}

#[test]
fn client_registration_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let pw = b"hunter2";
        let mut rng = OsRng;

        let blind_result =
            &voprf::NonVerifiableClient::<CS::OprfGroup, CS::Hash>::blind(pw, &mut rng)?;

        let bytes: Vec<u8> = chain!(
            Serialize::<U2>::from(&blind_result.state.serialize())?.iter(),
            Serialize::<U2>::from(&blind_result.message.serialize())?.iter(),
        )
        .flatten()
        .cloned()
        .collect();

        let reg = ClientRegistration::<CS>::deserialize(&bytes)?;
        let reg_bytes = reg.serialize()?;
        assert_eq!(reg_bytes, bytes);
        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;

    Ok(())
}

#[test]
fn server_registration_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<CS::Hash>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <CS::KeGroup as KeGroup>::PkLen: Add<OutputSize<CS::Hash>>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, OutputSize<CS::Hash>>:
            ArrayLength<u8> + Add<EnvelopeLen<CS>>,
        RegistrationUploadLen<CS>: ArrayLength<u8>,
        // ServerRegistration = RegistrationUpload
    {
        // If we don't have envelope and client_pk, the server registration just
        // contains the prf key
        let mut rng = OsRng;
        let mut masking_key = Output::<CS::Hash>::default();
        rng.fill_bytes(&mut masking_key);

        // Construct a mock envelope
        let mut mock_envelope_bytes = Vec::new();
        mock_envelope_bytes.extend_from_slice(&[0; NonceLen::USIZE]); // empty nonce
                                                                      // mock_envelope_bytes.extend_from_slice(&ciphertext); // ciphertext which is an encrypted private key
        mock_envelope_bytes.extend_from_slice(&Output::<CS::Hash>::default()); // length-MAC_SIZE hmac

        let mock_client_kp = KeyPair::<CS::KeGroup>::generate_random(&mut rng);
        // serialization order: oprf_key, public key, envelope
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&mock_client_kp.public().to_arr());
        bytes.extend_from_slice(&masking_key);
        bytes.extend_from_slice(&mock_envelope_bytes);
        let reg = ServerRegistration::<CS>::deserialize(&bytes)?;
        let reg_bytes = reg.serialize();
        assert_eq!(*reg_bytes, bytes);
        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;

    Ok(())
}

#[test]
fn registration_request_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let pt = random_point::<CS>();
        let pt_bytes = pt.to_arr().to_vec();

        let mut input = Vec::new();
        input.extend_from_slice(&pt_bytes);

        let r1 = RegistrationRequest::<CS>::deserialize(&input)?;
        let r1_bytes = r1.serialize();
        assert_eq!(input, *r1_bytes);

        // Assert that identity group element is rejected
        let identity = CS::OprfGroup::identity();
        let identity_bytes = identity.to_arr().to_vec();

        assert!(matches!(
            RegistrationRequest::<CS>::deserialize(&identity_bytes),
            Err(ProtocolError::LibraryError(InternalError::OprfError(
                voprf::Error::PointError,
            )))
        ));

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;

    Ok(())
}

#[test]
fn registration_response_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // RegistrationResponse: KgPk + KePk
        <CS::OprfGroup as Group>::ElemLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
        RegistrationResponseLen<CS>: ArrayLength<u8>,
    {
        let pt = random_point::<CS>();
        let beta_bytes = pt.to_arr();
        let mut rng = OsRng;
        let skp = KeyPair::<CS::KeGroup>::generate_random(&mut rng);
        let pubkey_bytes = skp.public().to_arr();

        let mut input = Vec::new();
        input.extend_from_slice(&beta_bytes);
        input.extend_from_slice(&pubkey_bytes);

        let r2 = RegistrationResponse::<CS>::deserialize(&input)?;
        let r2_bytes = r2.serialize();
        assert_eq!(input, *r2_bytes);

        // Assert that identity group element is rejected
        let identity = CS::OprfGroup::identity();
        let identity_bytes = identity.to_arr().to_vec();

        assert!(matches!(
            RegistrationResponse::<CS>::deserialize(
                &[identity_bytes, pubkey_bytes.to_vec()].concat()
            ),
            Err(ProtocolError::LibraryError(InternalError::OprfError(
                voprf::Error::PointError,
            )))
        ));

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;

    Ok(())
}

#[test]
fn registration_upload_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // Envelope: Nonce + Hash
        NonceLen: Add<OutputSize<CS::Hash>>,
        EnvelopeLen<CS>: ArrayLength<u8>,
        // RegistrationUpload: (KePk + Hash) + Envelope
        <CS::KeGroup as KeGroup>::PkLen: Add<OutputSize<CS::Hash>>,
        Sum<<CS::KeGroup as KeGroup>::PkLen, OutputSize<CS::Hash>>:
            ArrayLength<u8> + Add<EnvelopeLen<CS>>,
        RegistrationUploadLen<CS>: ArrayLength<u8>,
    {
        let mut rng = OsRng;
        let skp = KeyPair::<CS::KeGroup>::generate_random(&mut rng);
        let pubkey_bytes = skp.public().to_arr();

        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let mut nonce = [0u8; NonceLen::USIZE];
        rng.fill_bytes(&mut nonce);

        let mut masking_key = Output::<CS::Hash>::default();
        rng.fill_bytes(&mut masking_key);

        let randomized_pwd_hasher = hkdf::Hkdf::new(None, &key);

        let (envelope, _, _) = Envelope::<CS>::seal_raw(
            randomized_pwd_hasher,
            nonce.into(),
            Some(pubkey_bytes.as_slice()).into_iter(),
            InnerEnvelopeMode::Internal,
        )
        .unwrap();
        let envelope_bytes = envelope.serialize();

        let mut input = Vec::new();
        input.extend_from_slice(&pubkey_bytes);
        input.extend_from_slice(&masking_key);
        input.extend_from_slice(&envelope_bytes);

        let r3 = RegistrationUpload::<CS>::deserialize(&input)?;
        let r3_bytes = r3.serialize();
        assert_eq!(input, *r3_bytes);

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;

    Ok(())
}

#[test]
fn credential_request_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // CredentialRequest: KgPk + Ke1Message
        <CS::OprfGroup as Group>::ElemLen: Add<Ke1MessageLen<CS>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
    {
        let mut rng = OsRng;
        let alpha = random_point::<CS>();
        let alpha_bytes = alpha.to_arr();

        let client_e_kp = KeyPair::<CS::KeGroup>::generate_random(&mut rng);
        let mut client_nonce = [0u8; NonceLen::USIZE];
        rng.fill_bytes(&mut client_nonce);

        let ke1m: Vec<u8> = [client_nonce.as_ref(), client_e_kp.public()].concat();

        let mut input = Vec::new();
        input.extend_from_slice(&alpha_bytes);
        input.extend_from_slice(&ke1m);

        let l1 = CredentialRequest::<CS>::deserialize(&input)?;
        let l1_bytes = l1.serialize();
        assert_eq!(input, *l1_bytes);

        // Assert that identity group element is rejected
        let identity = CS::OprfGroup::identity();
        let identity_bytes = identity.to_arr().to_vec();

        assert!(matches!(
            CredentialRequest::<CS>::deserialize(&[identity_bytes, ke1m.to_vec()].concat()),
            Err(ProtocolError::LibraryError(InternalError::OprfError(
                voprf::Error::PointError,
            )))
        ));

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;

    Ok(())
}

#[test]
fn credential_response_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // CredentialResponseWithoutKeLen: (KgPk + Nonce) + MaskedResponse
        <CS::OprfGroup as Group>::ElemLen: Add<NonceLen>,
        Sum<<CS::OprfGroup as Group>::ElemLen, NonceLen>:
            ArrayLength<u8> + Add<MaskedResponseLen<CS>>,
        CredentialResponseWithoutKeLen<CS>: ArrayLength<u8>,
        // MaskedResponse: (Nonce + Hash) + KePk
        NonceLen: Add<OutputSize<CS::Hash>>,
        Sum<NonceLen, OutputSize<CS::Hash>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
        MaskedResponseLen<CS>: ArrayLength<u8>,
        // CredentialResponse: CredentialResponseWithoutKeLen + Ke2Message
        CredentialResponseWithoutKeLen<CS>: Add<Ke2MessageLen<CS>>,
        CredentialResponseLen<CS>: ArrayLength<u8>,
    {
        let pt = random_point::<CS>();
        let pt_bytes = pt.to_arr();

        let mut rng = OsRng;

        let mut masking_nonce = [0u8; 32];
        rng.fill_bytes(&mut masking_nonce);

        let mut masked_response =
            vec![0u8; <CS::OprfGroup as Group>::ElemLen::USIZE + Envelope::<CS>::len()];
        rng.fill_bytes(&mut masked_response);

        let server_e_kp = KeyPair::<CS::KeGroup>::generate_random(&mut rng);
        let mut mac = Output::<CS::Hash>::default();
        rng.fill_bytes(&mut mac);
        let mut server_nonce = [0u8; NonceLen::USIZE];
        rng.fill_bytes(&mut server_nonce);

        let ke2m: Vec<u8> = [server_nonce.as_ref(), server_e_kp.public(), &mac].concat();

        let mut input = Vec::new();
        input.extend_from_slice(&pt_bytes);
        input.extend_from_slice(&masking_nonce);
        input.extend_from_slice(&masked_response);
        input.extend_from_slice(&ke2m);

        let l2 = CredentialResponse::<CS>::deserialize(&input)?;
        let l2_bytes = l2.serialize();
        assert_eq!(input, *l2_bytes);

        // Assert that identity group element is rejected
        let identity = CS::OprfGroup::identity();
        let identity_bytes = identity.to_arr().to_vec();

        assert!(matches!(
            CredentialResponse::<CS>::deserialize(
                &[
                    identity_bytes,
                    masking_nonce.to_vec(),
                    masked_response,
                    ke2m.to_vec()
                ]
                .concat()
            ),
            Err(ProtocolError::LibraryError(InternalError::OprfError(
                voprf::Error::PointError,
            )))
        ));

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;

    Ok(())
}

#[test]
fn credential_finalization_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let mut rng = OsRng;
        let mut mac = Output::<CS::Hash>::default();
        rng.fill_bytes(&mut mac);

        let input = mac;

        let l3 = CredentialFinalization::<CS>::deserialize(&input)?;
        let l3_bytes = l3.serialize();
        assert_eq!(input.as_slice(), l3_bytes.as_slice());

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;

    Ok(())
}

#[test]
fn client_login_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        // CredentialRequest: KgPk + Ke1Message
        <CS::OprfGroup as Group>::ElemLen: Add<Ke1MessageLen<CS>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
    {
        let pw = b"hunter2";
        let mut rng = OsRng;

        let client_e_kp = KeyPair::<CS::KeGroup>::generate_random(&mut rng);
        let mut client_nonce = [0; NonceLen::USIZE];
        rng.fill_bytes(&mut client_nonce);

        let l1_data = [
            client_e_kp.private().to_arr().to_vec(),
            client_nonce.to_vec(),
        ]
        .concat();

        let blind_result =
            voprf::NonVerifiableClient::<CS::OprfGroup, CS::Hash>::blind(pw, &mut rng)?;

        let credential_request = CredentialRequest::<CS> {
            blinded_element: blind_result.message,
            ke1_message:
                <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1Message::from_bytes(
                    &[client_nonce.as_ref(), client_e_kp.public()].concat(),
                )?,
        };

        let bytes: Vec<u8> = chain!(
            Serialize::<U2>::from(&blind_result.state.serialize())?.iter(),
            Serialize::<U2>::from(&credential_request.serialize())?.iter(),
            Serialize::<U2>::from(&l1_data)?.iter(),
        )
        .flatten()
        .cloned()
        .collect();
        let reg = ClientLogin::<CS>::deserialize(&bytes)?;
        let reg_bytes = reg.serialize()?;
        assert_eq!(reg_bytes, bytes);
        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;

    Ok(())
}

#[test]
fn ke1_message_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let mut rng = OsRng;

        let client_e_kp = KeyPair::<CS::KeGroup>::generate_random(&mut rng);
        let mut client_nonce = vec![0u8; NonceLen::USIZE];
        rng.fill_bytes(&mut client_nonce);

        let ke1m = [client_nonce.as_slice(), client_e_kp.public()].concat();
        let reg =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE1Message::from_bytes(&ke1m)?;
        let reg_bytes = reg.to_bytes();
        assert_eq!(*reg_bytes, ke1m);

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;

    Ok(())
}

#[test]
fn ke2_message_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let mut rng = OsRng;

        let server_e_kp = KeyPair::<CS::KeGroup>::generate_random(&mut rng);
        let mut mac = Output::<CS::Hash>::default();
        rng.fill_bytes(&mut mac);
        let mut server_nonce = vec![0u8; NonceLen::USIZE];
        rng.fill_bytes(&mut server_nonce);

        let ke2m: Vec<u8> = [server_nonce.as_slice(), server_e_kp.public(), &mac].concat();

        let reg =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE2Message::from_bytes(&ke2m)?;
        let reg_bytes = reg.to_bytes();
        assert_eq!(*reg_bytes, ke2m);

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;

    Ok(())
}

#[test]
fn ke3_message_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::Hash as CoreProxy>::Core: ProxyHash,
        <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let mut rng = OsRng;
        let mut mac = Output::<CS::Hash>::default();
        rng.fill_bytes(&mut mac);

        let ke3m: Vec<u8> = [mac].concat();

        let reg =
            <CS::KeyExchange as KeyExchange<CS::Hash, CS::KeGroup>>::KE3Message::from_bytes(&ke3m)?;
        let reg_bytes = reg.to_bytes();
        assert_eq!(*reg_bytes, ke3m);

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<Ristretto255>()?;
    #[cfg(feature = "p256")]
    inner::<P256>()?;

    Ok(())
}

proptest! {
    #[test]
    fn test_i2osp_os2ip(bytes in vec(any::<u8>(), 0..core::mem::size_of::<usize>())) {
        use generic_array::typenum::{U0, U1, U2, U3, U4, U5, U6, U7};

        let input = os2ip(&bytes).unwrap();

        let output = match bytes.len() {
            0 => i2osp::<U0>(input).unwrap().to_vec(),
            1 => i2osp::<U1>(input).unwrap().to_vec(),
            2 => i2osp::<U2>(input).unwrap().to_vec(),
            3 => i2osp::<U3>(input).unwrap().to_vec(),
            4 => i2osp::<U4>(input).unwrap().to_vec(),
            5 => i2osp::<U5>(input).unwrap().to_vec(),
            6 => i2osp::<U6>(input).unwrap().to_vec(),
            7 => i2osp::<U7>(input).unwrap().to_vec(),
            _ => unreachable!("unexpected size")
        };

        assert_eq!(output, bytes);
    }
}

macro_rules! test {
    ($mod:ident, $CS:ty) => {
        mod $mod {
            use super::*;

            proptest! {
                #[test]
                fn test_nocrash_registration_request(bytes in vec(any::<u8>(), 0..200)) {
                    RegistrationRequest::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_registration_response(bytes in vec(any::<u8>(), 0..200)) {
                    RegistrationResponse::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_registration_upload(bytes in vec(any::<u8>(), 0..200)) {
                    RegistrationUpload::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_credential_request(bytes in vec(any::<u8>(), 0..500)) {
                    CredentialRequest::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_credential_response(bytes in vec(any::<u8>(), 0..500)) {
                    CredentialResponse::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_credential_finalization(bytes in vec(any::<u8>(), 0..500)) {
                    CredentialFinalization::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_client_registration(bytes in vec(any::<u8>(), 0..700)) {
                    ClientRegistration::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_server_registration(bytes in vec(any::<u8>(), 0..700)) {
                    ServerRegistration::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_client_login(bytes in vec(any::<u8>(), 0..700)) {
                    ClientLogin::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_server_login(bytes in vec(any::<u8>(), 0..700)) {
                    ServerLogin::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }
            }
        }
    };
}

#[cfg(feature = "ristretto255")]
test!(ristretto255, Ristretto255);
#[cfg(feature = "p256")]
test!(p256, P256);

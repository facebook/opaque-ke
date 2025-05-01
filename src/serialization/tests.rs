// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use core::ops::Add;
use std::vec;
use std::vec::Vec;

use digest::Output;
use generic_array::typenum::{Sum, Unsigned};
use generic_array::ArrayLength;
use proptest::collection::vec;
use proptest::prelude::*;
use rand::rngs::OsRng;
use rand::RngCore;
use voprf::Group as _;

use crate::ciphersuite::{CipherSuite, KeGroup, OprfGroup, OprfHash};
use crate::envelope::{Envelope, EnvelopeLen, InnerEnvelopeMode};
use crate::errors::*;
use crate::hash::OutputSize;
use crate::key_exchange::group::Group;
use crate::key_exchange::shared::NonceLen;
use crate::key_exchange::traits::{
    Deserialize, Ke1MessageLen, Ke1StateLen, Ke2MessageLen, KeyExchange, Serialize,
};
use crate::keypair::KeyPair;
use crate::messages::CredentialResponseWithoutKeLen;
use crate::opaque::{ClientLoginLen, ClientRegistrationLen, MaskedResponseLen};
use crate::serialization::{i2osp, os2ip};
use crate::*;

#[cfg(feature = "ristretto255")]
struct TripleDhRistretto255;

#[cfg(feature = "ristretto255")]
impl CipherSuite for TripleDhRistretto255 {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = crate::ksf::Identity;
}

#[cfg(all(feature = "ristretto255", feature = "curve25519"))]
struct TripleDhCurve25519;

#[cfg(all(feature = "ristretto255", feature = "curve25519"))]
impl CipherSuite for TripleDhCurve25519 {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Curve25519, sha2::Sha512>;
    type Ksf = crate::ksf::Identity;
}

struct TripleDhP256;

impl CipherSuite for TripleDhP256 {
    type OprfCs = ::p256::NistP256;
    type KeyExchange = TripleDh<::p256::NistP256, sha2::Sha256>;
    type Ksf = crate::ksf::Identity;
}

struct TripleDhP384;

impl CipherSuite for TripleDhP384 {
    type OprfCs = ::p384::NistP384;
    type KeyExchange = TripleDh<::p384::NistP384, sha2::Sha384>;
    type Ksf = crate::ksf::Identity;
}

struct TripleDhP521;

impl CipherSuite for TripleDhP521 {
    type OprfCs = ::p521::NistP521;
    type KeyExchange = TripleDh<::p521::NistP521, sha2::Sha512>;
    type Ksf = crate::ksf::Identity;
}

#[cfg(feature = "ecdsa")]
struct SigmaIP256;

#[cfg(feature = "ecdsa")]
impl CipherSuite for SigmaIP256 {
    type OprfCs = ::p256::NistP256;
    type KeyExchange =
        SigmaI<Ecdsa<::p256::NistP256, sha2::Sha256>, ::p256::NistP256, sha2::Sha256>;
    type Ksf = crate::ksf::Identity;
}

#[cfg(feature = "ecdsa")]
struct SigmaIP384;

#[cfg(feature = "ecdsa")]
impl CipherSuite for SigmaIP384 {
    type OprfCs = ::p384::NistP384;
    type KeyExchange =
        SigmaI<Ecdsa<::p384::NistP384, sha2::Sha384>, ::p384::NistP384, sha2::Sha384>;
    type Ksf = crate::ksf::Identity;
}

#[cfg(all(feature = "ristretto255", feature = "ed25519",))]
struct SigmaIEd25519;

#[cfg(all(feature = "ristretto255", feature = "ed25519",))]
impl CipherSuite for SigmaIEd25519 {
    type OprfCs = Ristretto255;
    type KeyExchange = SigmaI<PureEddsa<Ed25519>, Ristretto255, sha2::Sha512>;
    type Ksf = crate::ksf::Identity;
}

#[cfg(all(feature = "ristretto255", feature = "ed25519"))]
struct SigmaIEd25519Ph;

#[cfg(all(feature = "ristretto255", feature = "ed25519",))]
impl CipherSuite for SigmaIEd25519Ph {
    type OprfCs = Ristretto255;
    type KeyExchange = SigmaI<HashEddsa<Ed25519>, Ristretto255, sha2::Sha512>;
    type Ksf = crate::ksf::Identity;
}

fn random_point<CS: CipherSuite>() -> <KeGroup<CS> as Group>::Pk {
    let mut rng = OsRng;
    let sk = KeGroup::<CS>::random_sk(&mut rng);
    KeGroup::<CS>::public_key(sk)
}

fn random_element<CS: CipherSuite>() -> <OprfGroup<CS> as voprf::Group>::Elem {
    let mut rng = OsRng;
    let scalar = OprfGroup::<CS>::random_scalar(&mut rng);
    OprfGroup::<CS>::base_elem() * &scalar
}

#[test]
fn client_registration_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        // ClientRegistration: KgSk + KgPk
        <OprfGroup<CS> as voprf::Group>::ScalarLen: Add<<OprfGroup<CS> as voprf::Group>::ElemLen>,
        ClientRegistrationLen<CS>: ArrayLength<u8>,
    {
        let pw = b"hunter2";
        let mut rng = OsRng;

        let blind_result = &voprf::OprfClient::<CS::OprfCs>::blind(pw, &mut rng)?;

        let bytes: Vec<u8> = blind_result
            .state
            .serialize()
            .iter()
            .chain(blind_result.message.serialize().iter())
            .cloned()
            .collect();

        let reg = ClientRegistration::<CS>::deserialize(&bytes)?;
        let reg_bytes = reg.serialize();
        assert_eq!(*reg_bytes, bytes);
        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<TripleDhRistretto255>()?;
    #[cfg(all(feature = "ristretto255", feature = "curve25519"))]
    inner::<TripleDhCurve25519>()?;
    inner::<TripleDhP256>()?;
    inner::<TripleDhP384>()?;
    inner::<TripleDhP521>()?;
    #[cfg(feature = "ecdsa")]
    inner::<SigmaIP256>()?;
    #[cfg(feature = "ecdsa")]
    inner::<SigmaIP384>()?;
    #[cfg(all(feature = "ristretto255", feature = "ed25519"))]
    inner::<SigmaIEd25519>()?;
    #[cfg(all(feature = "ristretto255", feature = "ed25519"))]
    inner::<SigmaIEd25519Ph>()?;

    Ok(())
}

#[test]
fn server_registration_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        // RegistrationUpload: (KePk + Hash) + Envelope
        <KeGroup<CS> as Group>::PkLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<<KeGroup<CS> as Group>::PkLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<EnvelopeLen<CS>>,
        RegistrationUploadLen<CS>: ArrayLength<u8>,
        // ServerRegistration = RegistrationUpload
    {
        // If we don't have envelope and client_pk, the server registration just
        let mut rng = OsRng;
        let mut masking_key = Output::<OprfHash<CS>>::default();
        rng.fill_bytes(&mut masking_key);

        // Construct a mock envelope
        let mut mock_envelope_bytes = Vec::new();
        // empty nonce
        mock_envelope_bytes.extend_from_slice(&[0; NonceLen::USIZE]);
        // ciphertext which is an encrypted private key
        //mock_envelope_bytes.extend_from_slice(&ciphertext);
        // length-MAC_SIZE hmac
        mock_envelope_bytes.extend_from_slice(&Output::<OprfHash<CS>>::default());

        let mock_client_kp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
        // serialization order: oprf_key, public key, envelope
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&mock_client_kp.public().serialize());
        bytes.extend_from_slice(&masking_key);
        bytes.extend_from_slice(&mock_envelope_bytes);
        let reg = ServerRegistration::<CS>::deserialize(&bytes)?;
        let reg_bytes = reg.serialize();
        assert_eq!(*reg_bytes, bytes);
        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<TripleDhRistretto255>()?;
    #[cfg(all(feature = "ristretto255", feature = "curve25519"))]
    inner::<TripleDhCurve25519>()?;
    inner::<TripleDhP256>()?;
    inner::<TripleDhP384>()?;
    inner::<TripleDhP521>()?;
    #[cfg(feature = "ecdsa")]
    inner::<SigmaIP256>()?;
    #[cfg(feature = "ecdsa")]
    inner::<SigmaIP384>()?;
    #[cfg(all(feature = "ristretto255", feature = "ed25519"))]
    inner::<SigmaIEd25519>()?;
    #[cfg(all(feature = "ristretto255", feature = "ed25519"))]
    inner::<SigmaIEd25519Ph>()?;

    Ok(())
}

#[test]
fn registration_request_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError> {
        let elem = random_element::<CS>();
        let elem_bytes = OprfGroup::<CS>::serialize_elem(elem);

        let mut input = Vec::new();
        input.extend_from_slice(&elem_bytes);

        let r1 = RegistrationRequest::<CS>::deserialize(&input)?;
        let r1_bytes = r1.serialize();
        assert_eq!(input, *r1_bytes);

        // Assert that identity group element is rejected
        let identity = OprfGroup::<CS>::identity_elem();
        let identity_bytes = OprfGroup::<CS>::serialize_elem(identity).to_vec();

        assert!(matches!(
            RegistrationRequest::<CS>::deserialize(&identity_bytes),
            Err(ProtocolError::LibraryError(InternalError::OprfError(
                voprf::Error::Deserialization,
            )))
        ));

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<TripleDhRistretto255>()?;
    #[cfg(all(feature = "ristretto255", feature = "curve25519"))]
    inner::<TripleDhCurve25519>()?;
    inner::<TripleDhP256>()?;
    inner::<TripleDhP384>()?;
    inner::<TripleDhP521>()?;
    #[cfg(feature = "ecdsa")]
    inner::<SigmaIP256>()?;
    #[cfg(feature = "ecdsa")]
    inner::<SigmaIP384>()?;
    #[cfg(all(feature = "ristretto255", feature = "ed25519"))]
    inner::<SigmaIEd25519>()?;
    #[cfg(all(feature = "ristretto255", feature = "ed25519"))]
    inner::<SigmaIEd25519Ph>()?;

    Ok(())
}

#[test]
fn registration_response_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        // RegistrationResponse: KgPk + KePk
        <OprfGroup<CS> as voprf::Group>::ElemLen: Add<<KeGroup<CS> as Group>::PkLen>,
        RegistrationResponseLen<CS>: ArrayLength<u8>,
    {
        let elem = random_element::<CS>();
        let beta_bytes = OprfGroup::<CS>::serialize_elem(elem);
        let mut rng = OsRng;
        let skp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
        let pubkey_bytes = skp.public().serialize();

        let mut input = Vec::new();
        input.extend_from_slice(&beta_bytes);
        input.extend_from_slice(&pubkey_bytes);

        let r2 = RegistrationResponse::<CS>::deserialize(&input)?;
        let r2_bytes = r2.serialize();
        assert_eq!(input, *r2_bytes);

        // Assert that identity group element is rejected
        let identity = OprfGroup::<CS>::identity_elem();
        let identity_bytes = OprfGroup::<CS>::serialize_elem(identity).to_vec();

        assert!(matches!(
            RegistrationResponse::<CS>::deserialize(
                &[identity_bytes, pubkey_bytes.to_vec()].concat()
            ),
            Err(ProtocolError::LibraryError(InternalError::OprfError(
                voprf::Error::Deserialization,
            )))
        ));

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<TripleDhRistretto255>()?;
    #[cfg(all(feature = "ristretto255", feature = "curve25519"))]
    inner::<TripleDhCurve25519>()?;
    inner::<TripleDhP256>()?;
    inner::<TripleDhP384>()?;
    inner::<TripleDhP521>()?;
    #[cfg(feature = "ecdsa")]
    inner::<SigmaIP256>()?;
    #[cfg(feature = "ecdsa")]
    inner::<SigmaIP384>()?;
    #[cfg(all(feature = "ristretto255", feature = "ed25519"))]
    inner::<SigmaIEd25519>()?;
    #[cfg(all(feature = "ristretto255", feature = "ed25519"))]
    inner::<SigmaIEd25519Ph>()?;

    Ok(())
}

#[test]
fn registration_upload_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        // RegistrationUpload: (KePk + Hash) + Envelope
        <KeGroup<CS> as Group>::PkLen: Add<OutputSize<OprfHash<CS>>>,
        Sum<<KeGroup<CS> as Group>::PkLen, OutputSize<OprfHash<CS>>>:
            ArrayLength<u8> + Add<EnvelopeLen<CS>>,
        RegistrationUploadLen<CS>: ArrayLength<u8>,
    {
        let mut rng = OsRng;
        let skp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
        let pubkey_bytes = skp.public().serialize();

        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let mut nonce = [0u8; NonceLen::USIZE];
        rng.fill_bytes(&mut nonce);

        let mut masking_key = Output::<OprfHash<CS>>::default();
        rng.fill_bytes(&mut masking_key);

        let randomized_pwd_hasher = hkdf::Hkdf::new(None, &key);

        let (envelope, _, _) = Envelope::<CS>::seal_raw(
            randomized_pwd_hasher,
            nonce.into(),
            [pubkey_bytes.as_slice()].into_iter(),
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
    inner::<TripleDhRistretto255>()?;
    #[cfg(all(feature = "ristretto255", feature = "curve25519"))]
    inner::<TripleDhCurve25519>()?;
    inner::<TripleDhP256>()?;
    inner::<TripleDhP384>()?;
    inner::<TripleDhP521>()?;
    #[cfg(feature = "ecdsa")]
    inner::<SigmaIP256>()?;
    #[cfg(feature = "ecdsa")]
    inner::<SigmaIP384>()?;
    #[cfg(all(feature = "ristretto255", feature = "ed25519"))]
    inner::<SigmaIEd25519>()?;
    #[cfg(all(feature = "ristretto255", feature = "ed25519"))]
    inner::<SigmaIEd25519Ph>()?;

    Ok(())
}

#[test]
fn triple_dh_credential_request_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE1Message: Deserialize + Serialize,
        // CredentialRequest: KgPk + Ke1Message
        <OprfGroup<CS> as voprf::Group>::ElemLen: Add<Ke1MessageLen<CS>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
    {
        let mut rng = OsRng;
        let alpha = random_element::<CS>();
        let alpha_bytes = OprfGroup::<CS>::serialize_elem(alpha);

        let client_e_kp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
        let mut client_nonce = [0u8; NonceLen::USIZE];
        rng.fill_bytes(&mut client_nonce);

        let ke1m: Vec<u8> = [
            client_nonce.as_ref(),
            client_e_kp.public().serialize().as_ref(),
        ]
        .concat();

        let mut input = Vec::new();
        input.extend_from_slice(&alpha_bytes);
        input.extend_from_slice(&ke1m);

        let l1 = CredentialRequest::<CS>::deserialize(&input)?;
        let l1_bytes = l1.serialize();
        assert_eq!(input, *l1_bytes);

        // Assert that identity group element is rejected
        let identity = OprfGroup::<CS>::identity_elem();
        let identity_bytes = OprfGroup::<CS>::serialize_elem(identity).to_vec();

        assert!(matches!(
            CredentialRequest::<CS>::deserialize(&[identity_bytes, ke1m.to_vec()].concat()),
            Err(ProtocolError::LibraryError(InternalError::OprfError(
                voprf::Error::Deserialization,
            )))
        ));

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<TripleDhRistretto255>()?;
    #[cfg(all(feature = "ristretto255", feature = "curve25519"))]
    inner::<TripleDhCurve25519>()?;
    inner::<TripleDhP256>()?;
    inner::<TripleDhP384>()?;
    inner::<TripleDhP521>()?;

    Ok(())
}

#[test]
fn triple_dh_credential_response_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE2Message: Deserialize,
        // CredentialResponseWithoutKeLen: (KgPk + Nonce) + MaskedResponse
        <OprfGroup<CS> as voprf::Group>::ElemLen: Add<NonceLen>,
        Sum<<OprfGroup<CS> as voprf::Group>::ElemLen, NonceLen>:
            ArrayLength<u8> + Add<MaskedResponseLen<CS>>,
        CredentialResponseWithoutKeLen<CS>: ArrayLength<u8>,
        // CredentialResponse: CredentialResponseWithoutKeLen + Ke2Message
        <CS::KeyExchange as KeyExchange>::KE2Message: Serialize,
        CredentialResponseWithoutKeLen<CS>: Add<Ke2MessageLen<CS>>,
        CredentialResponseLen<CS>: ArrayLength<u8>,
    {
        let elem = random_element::<CS>();
        let elem_bytes = OprfGroup::<CS>::serialize_elem(elem);

        let mut rng = OsRng;

        let mut masking_nonce = [0u8; 32];
        rng.fill_bytes(&mut masking_nonce);

        let mut masked_response =
            vec![0u8; <OprfGroup<CS> as voprf::Group>::ElemLen::USIZE + Envelope::<CS>::len()];
        rng.fill_bytes(&mut masked_response);

        let server_e_kp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
        let mut mac = Output::<OprfHash<CS>>::default();
        rng.fill_bytes(&mut mac);
        let mut server_nonce = [0u8; NonceLen::USIZE];
        rng.fill_bytes(&mut server_nonce);

        let ke2m: Vec<u8> = [
            server_nonce.as_ref(),
            server_e_kp.public().serialize().as_ref(),
            &mac,
        ]
        .concat();

        let mut input = Vec::new();
        input.extend_from_slice(&elem_bytes);
        input.extend_from_slice(&masking_nonce);
        input.extend_from_slice(&masked_response);
        input.extend_from_slice(&ke2m);

        let l2 = CredentialResponse::<CS>::deserialize(&input).unwrap();
        let l2_bytes = l2.serialize();
        assert_eq!(input, *l2_bytes);

        // Assert that identity group element is rejected
        let identity = OprfGroup::<CS>::identity_elem();
        let identity_bytes = OprfGroup::<CS>::serialize_elem(identity).to_vec();

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
                voprf::Error::Deserialization,
            )))
        ));

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<TripleDhRistretto255>()?;
    #[cfg(all(feature = "ristretto255", feature = "curve25519"))]
    inner::<TripleDhCurve25519>()?;
    inner::<TripleDhP256>()?;
    inner::<TripleDhP384>()?;
    inner::<TripleDhP521>()?;

    Ok(())
}

#[test]
#[cfg(feature = "ecdsa")]
fn sigma_i_ecdsa_credential_response_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE2Message: Deserialize,
        // CredentialResponseWithoutKeLen: (KgPk + Nonce) + MaskedResponse
        <OprfGroup<CS> as voprf::Group>::ElemLen: Add<NonceLen>,
        Sum<<OprfGroup<CS> as voprf::Group>::ElemLen, NonceLen>:
            ArrayLength<u8> + Add<MaskedResponseLen<CS>>,
        CredentialResponseWithoutKeLen<CS>: ArrayLength<u8>,
        // CredentialResponse: CredentialResponseWithoutKeLen + Ke2Message
        <CS::KeyExchange as KeyExchange>::KE2Message: Serialize,
        CredentialResponseWithoutKeLen<CS>: Add<Ke2MessageLen<CS>>,
        CredentialResponseLen<CS>: ArrayLength<u8>,
    {
        let pt = random_point::<CS>();
        let pt_bytes = KeGroup::<CS>::serialize_pk(pt);

        let mut rng = OsRng;

        let mut masking_nonce = [0u8; 32];
        rng.fill_bytes(&mut masking_nonce);

        let mut masked_response =
            vec![0u8; <OprfGroup<CS> as voprf::Group>::ElemLen::USIZE + Envelope::<CS>::len()];
        rng.fill_bytes(&mut masked_response);

        let server_e_kp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
        let r = KeGroup::<CS>::serialize_sk(KeGroup::<CS>::random_sk(&mut rng));
        let s = KeGroup::<CS>::serialize_sk(KeGroup::<CS>::random_sk(&mut rng));
        let mut mac = Output::<OprfHash<CS>>::default();
        rng.fill_bytes(&mut mac);
        let mut server_nonce = [0u8; NonceLen::USIZE];
        rng.fill_bytes(&mut server_nonce);

        let ke2m: Vec<u8> = [
            server_nonce.as_ref(),
            server_e_kp.public().serialize().as_ref(),
            &r,
            &s,
            &mac,
        ]
        .concat();

        let mut input = Vec::new();
        input.extend_from_slice(&pt_bytes);
        input.extend_from_slice(&masking_nonce);
        input.extend_from_slice(&masked_response);
        input.extend_from_slice(&ke2m);

        let l2 = CredentialResponse::<CS>::deserialize(&input)?;
        let l2_bytes = l2.serialize();
        assert_eq!(input, *l2_bytes);

        // Assert that identity group element is rejected
        let identity = OprfGroup::<CS>::identity_elem();
        let identity_bytes = OprfGroup::<CS>::serialize_elem(identity).to_vec();

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
                voprf::Error::Deserialization,
            )))
        ));

        Ok(())
    }

    inner::<SigmaIP256>()?;
    inner::<SigmaIP384>()?;

    Ok(())
}

#[test]
fn triple_dh_credential_finalization_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE3Message: Deserialize + Serialize,
    {
        let mut rng = OsRng;
        let mut mac = Output::<OprfHash<CS>>::default();
        rng.fill_bytes(&mut mac);

        let input = mac;

        let l3 = CredentialFinalization::<CS>::deserialize(&input)?;
        let l3_bytes = l3.serialize();
        assert_eq!(input.as_slice(), l3_bytes.as_slice());

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<TripleDhRistretto255>()?;
    #[cfg(all(feature = "ristretto255", feature = "curve25519"))]
    inner::<TripleDhCurve25519>()?;
    inner::<TripleDhP256>()?;
    inner::<TripleDhP384>()?;
    inner::<TripleDhP521>()?;

    Ok(())
}

#[test]
#[cfg(feature = "ecdsa")]
fn sigma_i_ecdsa_credential_finalization_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE3Message: Deserialize + Serialize,
    {
        let mut rng = OsRng;

        let r = KeGroup::<CS>::serialize_sk(KeGroup::<CS>::random_sk(&mut rng));
        let s = KeGroup::<CS>::serialize_sk(KeGroup::<CS>::random_sk(&mut rng));

        let mut mac = Output::<OprfHash<CS>>::default();
        rng.fill_bytes(&mut mac);

        let mut input = Vec::new();
        input.extend_from_slice(&r);
        input.extend_from_slice(&s);
        input.extend_from_slice(&mac);

        let l3 = CredentialFinalization::<CS>::deserialize(&input)?;
        let l3_bytes = l3.serialize();
        assert_eq!(input.as_slice(), l3_bytes.as_slice());

        Ok(())
    }

    inner::<SigmaIP256>()?;
    inner::<SigmaIP384>()?;

    Ok(())
}

#[test]
fn triple_dh_client_login_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE1Message: Deserialize,
        <CS::KeyExchange as KeyExchange>::KE1State: Deserialize,
        // CredentialRequest: KgPk + Ke1Message
        <CS::KeyExchange as KeyExchange>::KE1Message: Serialize,
        <OprfGroup<CS> as voprf::Group>::ElemLen: Add<Ke1MessageLen<CS>>,
        CredentialRequestLen<CS>: ArrayLength<u8>,
        // ClientLogin: KgSk + CredentialRequest + Ke1State
        <OprfGroup<CS> as voprf::Group>::ScalarLen: Add<CredentialRequestLen<CS>>,
        <CS::KeyExchange as KeyExchange>::KE1State: Serialize,
        Sum<<OprfGroup<CS> as voprf::Group>::ScalarLen, CredentialRequestLen<CS>>:
            ArrayLength<u8> + Add<Ke1StateLen<CS>>,
        ClientLoginLen<CS>: ArrayLength<u8>,
    {
        let pw = b"hunter2";
        let mut rng = OsRng;

        let client_e_kp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
        let mut client_nonce = [0; NonceLen::USIZE];
        rng.fill_bytes(&mut client_nonce);

        let l1_data = [
            client_e_kp.private().serialize().to_vec(),
            client_nonce.to_vec(),
        ]
        .concat();

        let blind_result = voprf::OprfClient::<CS::OprfCs>::blind(pw, &mut rng)?;

        let credential_request = CredentialRequest::<CS> {
            blinded_element: blind_result.message,
            ke1_message: <CS::KeyExchange as KeyExchange>::KE1Message::deserialize_take(
                &mut ([
                    client_nonce.as_ref(),
                    client_e_kp.public().serialize().as_ref(),
                ]
                .concat()
                .as_slice()),
            )?,
        };

        let bytes: Vec<u8> = blind_result
            .state
            .serialize()
            .iter()
            .chain(credential_request.serialize().iter())
            .chain(l1_data.iter())
            .cloned()
            .collect();
        let reg = ClientLogin::<CS>::deserialize(&bytes)?;
        let reg_bytes = reg.serialize();
        assert_eq!(*reg_bytes, bytes);
        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<TripleDhRistretto255>()?;
    #[cfg(all(feature = "ristretto255", feature = "curve25519"))]
    inner::<TripleDhCurve25519>()?;
    inner::<TripleDhP256>()?;
    inner::<TripleDhP384>()?;
    inner::<TripleDhP521>()?;

    Ok(())
}

#[test]
fn triple_dh_ke1_message_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE1Message: Deserialize + Serialize,
    {
        let mut rng = OsRng;

        let client_e_kp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
        let mut client_nonce = vec![0u8; NonceLen::USIZE];
        rng.fill_bytes(&mut client_nonce);

        let ke1m = [
            client_nonce.as_slice(),
            client_e_kp.public().serialize().as_ref(),
        ]
        .concat();
        let reg =
            <CS::KeyExchange as KeyExchange>::KE1Message::deserialize_take(&mut (ke1m.as_slice()))?;
        let reg_bytes = reg.serialize();
        assert_eq!(*reg_bytes, ke1m);

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<TripleDhRistretto255>()?;
    #[cfg(all(feature = "ristretto255", feature = "curve25519"))]
    inner::<TripleDhCurve25519>()?;
    inner::<TripleDhP256>()?;
    inner::<TripleDhP384>()?;
    inner::<TripleDhP521>()?;

    Ok(())
}

#[test]
fn triple_dh_ke2_message_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE2Message: Deserialize + Serialize,
    {
        let mut rng = OsRng;

        let server_e_kp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
        let mut mac = Output::<OprfHash<CS>>::default();
        rng.fill_bytes(&mut mac);
        let mut server_nonce = vec![0u8; NonceLen::USIZE];
        rng.fill_bytes(&mut server_nonce);

        let ke2m: Vec<u8> = [
            server_nonce.as_slice(),
            server_e_kp.public().serialize().as_ref(),
            &mac,
        ]
        .concat();

        let reg =
            <CS::KeyExchange as KeyExchange>::KE2Message::deserialize_take(&mut (ke2m.as_slice()))?;
        let reg_bytes = reg.serialize();
        assert_eq!(*reg_bytes, ke2m);

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<TripleDhRistretto255>()?;
    #[cfg(all(feature = "ristretto255", feature = "curve25519"))]
    inner::<TripleDhCurve25519>()?;
    inner::<TripleDhP256>()?;
    inner::<TripleDhP384>()?;
    inner::<TripleDhP521>()?;

    Ok(())
}

#[test]
#[cfg(feature = "ecdsa")]
fn sigma_i_ecdsa_ke2_message_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE2Message: Deserialize + Serialize,
    {
        let mut rng = OsRng;

        let server_e_kp = KeyPair::<KeGroup<CS>>::derive_random(&mut rng);
        let mut mac = Output::<OprfHash<CS>>::default();
        rng.fill_bytes(&mut mac);
        let mut server_nonce = vec![0u8; NonceLen::USIZE];
        rng.fill_bytes(&mut server_nonce);
        let r = KeGroup::<CS>::serialize_sk(KeGroup::<CS>::random_sk(&mut rng));
        let s = KeGroup::<CS>::serialize_sk(KeGroup::<CS>::random_sk(&mut rng));

        let ke2m: Vec<u8> = [
            server_nonce.as_slice(),
            server_e_kp.public().serialize().as_ref(),
            &r,
            &s,
            &mac,
        ]
        .concat();

        let reg =
            <CS::KeyExchange as KeyExchange>::KE2Message::deserialize_take(&mut (ke2m.as_slice()))?;
        let reg_bytes = reg.serialize();
        assert_eq!(*reg_bytes, ke2m);

        Ok(())
    }

    inner::<SigmaIP256>()?;
    inner::<SigmaIP384>()?;

    Ok(())
}

#[test]
fn triple_dh_ke3_message_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE3Message: Deserialize + Serialize,
    {
        let mut rng = OsRng;
        let mut mac = Output::<OprfHash<CS>>::default();
        rng.fill_bytes(&mut mac);

        let ke3m: Vec<u8> = [mac].concat();

        let reg =
            <CS::KeyExchange as KeyExchange>::KE3Message::deserialize_take(&mut (ke3m.as_slice()))?;
        let reg_bytes = reg.serialize();
        assert_eq!(*reg_bytes, ke3m);

        Ok(())
    }

    #[cfg(feature = "ristretto255")]
    inner::<TripleDhRistretto255>()?;
    #[cfg(all(feature = "ristretto255", feature = "curve25519"))]
    inner::<TripleDhCurve25519>()?;
    inner::<TripleDhP256>()?;
    inner::<TripleDhP384>()?;
    inner::<TripleDhP521>()?;

    Ok(())
}

#[test]
#[cfg(feature = "ecdsa")]
fn sigma_i_ecdsa_ke3_message_roundtrip() -> Result<(), ProtocolError> {
    fn inner<CS: CipherSuite>() -> Result<(), ProtocolError>
    where
        <CS::KeyExchange as KeyExchange>::KE3Message: Deserialize + Serialize,
    {
        let mut rng = OsRng;
        let r = KeGroup::<CS>::serialize_sk(KeGroup::<CS>::random_sk(&mut rng));
        let s = KeGroup::<CS>::serialize_sk(KeGroup::<CS>::random_sk(&mut rng));
        let mut mac = Output::<OprfHash<CS>>::default();
        rng.fill_bytes(&mut mac);

        let ke3m: Vec<u8> = [mac.as_slice(), &r, &s].concat();

        let reg =
            <CS::KeyExchange as KeyExchange>::KE3Message::deserialize_take(&mut (ke3m.as_slice()))?;
        let reg_bytes = reg.serialize();
        assert_eq!(*reg_bytes, ke3m);

        Ok(())
    }

    inner::<SigmaIP256>()?;
    inner::<SigmaIP384>()?;

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
                    let _ = RegistrationRequest::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_registration_response(bytes in vec(any::<u8>(), 0..200)) {
                    let _ = RegistrationResponse::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_registration_upload(bytes in vec(any::<u8>(), 0..200)) {
                    let _ = RegistrationUpload::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_credential_request(bytes in vec(any::<u8>(), 0..500)) {
                    let _ = CredentialRequest::<$CS>::deserialize(&mut (bytes.as_slice())).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_credential_response(bytes in vec(any::<u8>(), 0..500)) {
                    let _ = CredentialResponse::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_credential_finalization(bytes in vec(any::<u8>(), 0..500)) {
                    let _ = CredentialFinalization::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_client_registration(bytes in vec(any::<u8>(), 0..700)) {
                    let _ = ClientRegistration::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_server_registration(bytes in vec(any::<u8>(), 0..700)) {
                    let _ = ServerRegistration::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_client_login(bytes in vec(any::<u8>(), 0..700)) {
                    let _ = ClientLogin::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }

                #[test]
                fn test_nocrash_server_login(bytes in vec(any::<u8>(), 0..700)) {
                    let _ = ServerLogin::<$CS>::deserialize(&bytes).map_or(true, |_| true);
                }
            }
        }
    };
}

#[cfg(feature = "ristretto255")]
test!(triple_dh_ristretto255, TripleDhRistretto255);
#[cfg(all(feature = "ristretto255", feature = "curve25519"))]
test!(triple_dh_curve25519, TripleDhCurve25519);
test!(triple_dh_p256, TripleDhP256);
test!(triple_dh_p384, TripleDhP384);
test!(triple_dh_p521, TripleDhP521);
#[cfg(feature = "ecdsa")]
test!(sigma_i_p256, SigmaIP256);
#[cfg(feature = "ecdsa")]
test!(sigma_i_p384, SigmaIP384);
#[cfg(all(feature = "ristretto255", feature = "ed25519",))]
test!(sigma_i_ed25519, SigmaIEd25519);
#[cfg(all(feature = "ristretto255", feature = "ed25519"))]
test!(sigma_i_ed25519_ph, SigmaIEd25519Ph);

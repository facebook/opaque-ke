// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use std::env;
use std::ops::Add;
use std::sync::{LazyLock, Mutex};
use std::vec::Vec;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use elliptic_curve::group::Curve;
use elliptic_curve::pkcs8::der::asn1::{OctetString, OctetStringRef};
use elliptic_curve::pkcs8::der::{Decode, Encode};
use elliptic_curve::pkcs8::{AssociatedOid, ObjectIdentifier};
use elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use elliptic_curve::sec1::{ModulusSize, Tag, ToEncodedPoint};
use elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, Group, ProjectivePoint};
use generic_array::typenum::Sum;
use generic_array::{ArrayLength, GenericArray};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use rand::rngs::OsRng;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::ciphersuite::OprfHash;
use crate::envelope::NonceLen;
use crate::hash::OutputSize;
use crate::key_exchange::group::KeGroup;
use crate::key_exchange::tripledh::{DiffieHellman, TripleDh};
use crate::keypair::{KeyPair, PublicKey};
use crate::ksf::Identity;
use crate::opaque::MaskedResponseLen;
use crate::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientLoginStartResult,
    ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationStartResult,
    ServerLogin, ServerLoginStartParameters, ServerLoginStartResult, ServerRegistration,
    ServerSetup,
};
#[cfg(all(feature = "curve25519", feature = "ristretto255"))]
use crate::{Curve25519, Ristretto255};

#[test]
fn p256() {
    struct Suite;

    impl CipherSuite for Suite {
        type OprfCs = NistP256;
        type KeGroup = NistP256;
        type KeyExchange = TripleDh;
        type Ksf = Identity;
    }

    test::<Suite>(Mechanism::EccKeyPairGen, NistP256::OID);
}

#[test]
fn p384() {
    struct Suite;

    impl CipherSuite for Suite {
        type OprfCs = NistP384;
        type KeGroup = NistP384;
        type KeyExchange = TripleDh;
        type Ksf = Identity;
    }

    test::<Suite>(Mechanism::EccKeyPairGen, NistP384::OID);
}

#[test]
fn p521() {
    struct Suite;

    impl CipherSuite for Suite {
        type OprfCs = NistP521;
        type KeGroup = NistP521;
        type KeyExchange = TripleDh;
        type Ksf = Identity;
    }

    test::<Suite>(Mechanism::EccKeyPairGen, NistP521::OID);
}

#[test]
#[cfg(all(feature = "curve25519", feature = "ristretto255"))]
fn curve25519() {
    struct Suite;

    impl CipherSuite for Suite {
        type OprfCs = Ristretto255;
        type KeGroup = Curve25519;
        type KeyExchange = TripleDh;
        type Ksf = Identity;
    }

    test::<Suite>(
        // This should be [`Mechanism::EccMontgomeryKeyPairGen`], but SoftHSM has an incorrect
        // implementation. See https://github.com/softhsm/SoftHSMv2/issues/647.
        Mechanism::EccEdwardsKeyPairGen,
        ObjectIdentifier::new("1.3.101.110").unwrap(),
    );
}

#[derive(Clone)]
struct RemoteKey(ObjectHandle);

trait Pkcs11DiffieHellman<KG: KeGroup> {
    fn pkcs11_diffie_hellman(
        &self,
        server_pk: &PublicKey<KG>,
        client_pk: &PublicKey<KG>,
    ) -> GenericArray<u8, KG::PkLen>;
}

fn test<CS: CipherSuite<KeyExchange = TripleDh>>(mechanism: Mechanism, oid: ObjectIdentifier)
where
    RemoteKey: Pkcs11DiffieHellman<CS::KeGroup>,
    <CS::KeGroup as KeGroup>::Sk: DiffieHellman<CS::KeGroup>,
    // MaskedResponse: (Nonce + Hash) + KePk
    NonceLen: Add<OutputSize<OprfHash<CS>>>,
    Sum<NonceLen, OutputSize<OprfHash<CS>>>: ArrayLength<u8> + Add<<CS::KeGroup as KeGroup>::PkLen>,
    MaskedResponseLen<CS>: ArrayLength<u8>,
    // Ke1State: KeSk + Nonce
    <CS::KeGroup as KeGroup>::SkLen: Add<NonceLen>,
    Sum<<CS::KeGroup as KeGroup>::SkLen, NonceLen>: ArrayLength<u8>,
    // Ke1Message: Nonce + KePk
    NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
    Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>: ArrayLength<u8>,
    // Ke2State: (Hash + Hash) + Hash
    OutputSize<OprfHash<CS>>: Add<OutputSize<OprfHash<CS>>>,
    Sum<OutputSize<OprfHash<CS>>, OutputSize<OprfHash<CS>>>:
        ArrayLength<u8> + Add<OutputSize<OprfHash<CS>>>,
    Sum<Sum<OutputSize<OprfHash<CS>>, OutputSize<OprfHash<CS>>>, OutputSize<OprfHash<CS>>>:
        ArrayLength<u8>,
    // Ke2Message: (Nonce + KePk) + Hash
    NonceLen: Add<<CS::KeGroup as KeGroup>::PkLen>,
    Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>: ArrayLength<u8> + Add<OutputSize<OprfHash<CS>>>,
    Sum<Sum<NonceLen, <CS::KeGroup as KeGroup>::PkLen>, OutputSize<OprfHash<CS>>>: ArrayLength<u8>,
{
    let (remote_key, pk) = pkcs11_generate_key_pair(mechanism, oid);

    let keypair = KeyPair::new(RemoteKey(remote_key), pk);
    let server_setup = ServerSetup::new_with_key_pair(&mut OsRng, keypair);

    const PASSWORD: &str = "password";

    let ClientRegistrationStartResult {
        message,
        state: client,
    } = ClientRegistration::<CS>::start(&mut OsRng, PASSWORD.as_bytes()).unwrap();
    let message = ServerRegistration::start(&server_setup, message, &[])
        .unwrap()
        .message;
    let message = client
        .finish(
            &mut OsRng,
            PASSWORD.as_bytes(),
            message,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap()
        .message;
    let file = ServerRegistration::finish(message);

    let ClientLoginStartResult {
        message,
        state: client,
    } = ClientLogin::<CS>::start(&mut OsRng, PASSWORD.as_bytes()).unwrap();
    let builder = ServerLogin::builder(
        &mut OsRng,
        &server_setup,
        Some(file),
        message,
        &[],
        ServerLoginStartParameters::default(),
    )
    .unwrap();
    let shared_secret = builder
        .private_key()
        .pkcs11_diffie_hellman(server_setup.keypair().public(), builder.data());

    let ServerLoginStartResult {
        message,
        state: server,
        ..
    } = builder.clone().build(shared_secret).unwrap();

    let message = client
        .clone()
        .finish(
            PASSWORD.as_bytes(),
            message,
            ClientLoginFinishParameters::default(),
        )
        .map(|result| result.message);

    message
        .map(|message| server.finish(message).unwrap())
        .unwrap();
}

static SESSION: LazyLock<Mutex<Session>> = LazyLock::new(|| {
    let module = env::var("PKCS11_MODULE").expect("`PKCS11_MODULE` environment variable");
    let pkcs11 = Pkcs11::new(module).unwrap();
    pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

    let slot = pkcs11.get_slots_with_token().unwrap()[0];

    let so_pin = AuthPin::new("abcdef".into());
    pkcs11.init_token(slot, &so_pin, "Test Token").unwrap();

    let user_pin = AuthPin::new("fedcba".into());

    {
        let session = pkcs11.open_rw_session(slot).unwrap();
        session.login(UserType::So, Some(&so_pin)).unwrap();
        session.init_pin(&user_pin).unwrap();
    }

    let session = pkcs11.open_rw_session(slot).unwrap();
    session.login(UserType::User, Some(&user_pin)).unwrap();

    Mutex::new(session)
});

fn pkcs11_generate_key_pair<KG: KeGroup>(
    mechanism: Mechanism,
    oid: ObjectIdentifier,
) -> (ObjectHandle, PublicKey<KG>) {
    let session = SESSION.lock().unwrap();
    let (pk, remote_key) = session
        .generate_key_pair(
            &mechanism,
            &[
                Attribute::Token(false),
                Attribute::EcParams(oid.to_der().unwrap()),
            ],
            &[Attribute::Token(false), Attribute::Derive(true)],
        )
        .unwrap();

    let Attribute::EcPoint(pk) = session
        .get_attributes(pk, &[AttributeType::EcPoint])
        .unwrap()
        .pop()
        .unwrap()
    else {
        unreachable!()
    };
    drop(session);

    let pk = OctetString::from_der(&pk).unwrap();
    let pk = PublicKey::deserialize(pk.as_bytes()).unwrap();

    (remote_key, pk)
}

impl Pkcs11DiffieHellman<NistP256> for RemoteKey {
    fn pkcs11_diffie_hellman(
        &self,
        server_pk: &PublicKey<NistP256>,
        client_pk: &PublicKey<NistP256>,
    ) -> GenericArray<u8, <NistP256 as KeGroup>::PkLen> {
        ec_pkcs_11_derive_secret::<NistP256>(self.0, server_pk, client_pk)
    }
}

impl Pkcs11DiffieHellman<NistP384> for RemoteKey {
    fn pkcs11_diffie_hellman(
        &self,
        server_pk: &PublicKey<NistP384>,
        client_pk: &PublicKey<NistP384>,
    ) -> GenericArray<u8, <NistP384 as KeGroup>::PkLen> {
        ec_pkcs_11_derive_secret::<NistP384>(self.0, server_pk, client_pk)
    }
}

impl Pkcs11DiffieHellman<NistP521> for RemoteKey {
    fn pkcs11_diffie_hellman(
        &self,
        server_pk: &PublicKey<NistP521>,
        client_pk: &PublicKey<NistP521>,
    ) -> GenericArray<u8, <NistP521 as KeGroup>::PkLen> {
        ec_pkcs_11_derive_secret::<NistP521>(self.0, server_pk, client_pk)
    }
}

#[cfg(all(feature = "curve25519", feature = "ristretto255"))]
impl Pkcs11DiffieHellman<Curve25519> for RemoteKey {
    fn pkcs11_diffie_hellman(
        &self,
        _: &PublicKey<Curve25519>,
        pk: &PublicKey<Curve25519>,
    ) -> GenericArray<u8, <Curve25519 as KeGroup>::PkLen> {
        let shared_secret = pkcs11_derive_secret(self.0, &pk.serialize());

        GenericArray::clone_from_slice(&shared_secret)
    }
}

fn pkcs11_derive_secret(sk: ObjectHandle, pk: &[u8]) -> Vec<u8> {
    let session = SESSION.lock().unwrap();
    let shared_secret = session
        .derive_key(
            &Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), pk)),
            sk,
            &[
                Attribute::Token(false),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::Extractable(true),
            ],
        )
        .unwrap();

    let Attribute::Value(shared_secret) = session
        .get_attributes(shared_secret, &[AttributeType::Value])
        .unwrap()
        .pop()
        .unwrap()
    else {
        unreachable!()
    };
    drop(session);

    shared_secret
}

fn ec_pkcs_11_derive_secret<KG>(
    server_sk: ObjectHandle,
    server_pk: &PublicKey<KG>,
    client_pk: &PublicKey<KG>,
) -> GenericArray<u8, <KG as KeGroup>::PkLen>
where
    KG: KeGroup<Pk = ProjectivePoint<KG>> + CurveArithmetic,
    AffinePoint<KG>: DecompressPoint<KG> + ToEncodedPoint<KG>,
    FieldBytesSize<KG>: ModulusSize,
{
    let client_pk_point = client_pk.to_group_type();
    let client_pk = client_pk.serialize();
    let client_pk = OctetStringRef::new(&client_pk).unwrap();
    let client_pk = client_pk.to_der().unwrap();

    let shared_secret_bytes = pkcs11_derive_secret(server_sk, &client_pk);
    let shared_secret_point = AffinePoint::<KG>::decompress(
        &GenericArray::clone_from_slice(&shared_secret_bytes),
        Choice::from(0),
    )
    .unwrap();
    let mut shared_secret = GenericArray::default();
    shared_secret[1..].copy_from_slice(&shared_secret_bytes);

    let shifted_client_pk = client_pk_point + ProjectivePoint::<KG>::generator();
    let shifted_client_pk = shifted_client_pk.to_affine().to_encoded_point(true);
    let shifted_client_pk = OctetStringRef::new(shifted_client_pk.as_bytes()).unwrap();
    let shifted_client_pk = shifted_client_pk.to_der().unwrap();

    let check_point = pkcs11_derive_secret(server_sk, &shifted_client_pk);

    let shifted_server_pk = server_pk.to_group_type() + shared_secret_point;
    let shifted_server_pk = shifted_server_pk.to_affine();

    let tag = u8::conditional_select(
        &(Tag::CompressedEvenY as u8),
        &(Tag::CompressedOddY as u8),
        check_point.ct_ne(&shifted_server_pk.x()),
    );
    shared_secret[0] = tag;

    shared_secret
}

// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

#![cfg(test_hsm)]
#![allow(type_alias_bounds)]

use std::env;
use std::sync::{LazyLock, Mutex};
use std::vec::Vec;

#[cfg(feature = "ecdsa")]
use ::ecdsa::SignatureSize;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
#[cfg(feature = "ecdsa")]
use digest::Digest;
use digest::OutputSizeUser;
use elliptic_curve::group::prime::PrimeCurveAffine;
use elliptic_curve::group::Curve;
use elliptic_curve::pkcs8::der::asn1::{OctetString, OctetStringRef};
use elliptic_curve::pkcs8::der::{Decode, Encode};
use elliptic_curve::pkcs8::{AssociatedOid, ObjectIdentifier};
use elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, Tag, ToEncodedPoint};
#[cfg(feature = "ecdsa")]
use elliptic_curve::PrimeCurve;
use elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, Group as _, ProjectivePoint};
use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};
#[cfg(all(feature = "ristretto255", feature = "ed25519"))]
use opaque_ke::key_exchange::group::ed25519::{self, Ed25519};
use opaque_ke::key_exchange::group::elliptic_curve::NonIdentity;
use opaque_ke::key_exchange::group::Group;
#[cfg(feature = "ecdsa")]
use opaque_ke::key_exchange::sigma_i::ecdsa::{self, Ecdsa, PreHash};
#[cfg(all(feature = "ristretto255", feature = "ed25519"))]
use opaque_ke::key_exchange::sigma_i::pure_eddsa::PureEddsa;
#[cfg(feature = "ecdsa")]
use opaque_ke::key_exchange::sigma_i::{CachedMessage, HashOutput, Message, SigmaI};
use opaque_ke::key_exchange::tripledh::TripleDh;
use opaque_ke::key_exchange::KeyExchange;
use opaque_ke::keypair::{KeyPair, PublicKey};
use opaque_ke::ksf::Identity;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientLoginStartResult,
    ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationStartResult,
    ServerLogin, ServerLoginParameters, ServerLoginStartResult, ServerRegistration, ServerSetup,
};
#[cfg(all(feature = "curve25519", feature = "ristretto255"))]
use opaque_ke::{Curve25519, Ristretto255};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use rand::rngs::OsRng;
use sha2::{Sha256, Sha384, Sha512};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

type OprfGroup<CS: CipherSuite> = <CS::OprfCs as voprf::CipherSuite>::Group;
type OprfHash<CS: CipherSuite> = <CS::OprfCs as voprf::CipherSuite>::Hash;
type KeGroup<CS: CipherSuite> = <CS::KeyExchange as KeyExchange>::Group;

#[test]
fn triple_dh_p256() {
    struct Suite;

    impl CipherSuite for Suite {
        type OprfCs = NistP256;
        type KeyExchange = TripleDh<NistP256, Sha256>;
        type Ksf = Identity;
    }

    test::<Suite>(
        Mechanism::EccKeyPairGen,
        NistP256::OID,
        Attribute::Derive(true),
        Mechanism::Sha256Hmac,
    );
}

#[test]
fn triple_dh_p384() {
    struct Suite;

    impl CipherSuite for Suite {
        type OprfCs = NistP384;
        type KeyExchange = TripleDh<NistP384, Sha384>;
        type Ksf = Identity;
    }

    test::<Suite>(
        Mechanism::EccKeyPairGen,
        NistP384::OID,
        Attribute::Derive(true),
        Mechanism::Sha384Hmac,
    );
}

#[test]
fn triple_dh_p521() {
    struct Suite;

    impl CipherSuite for Suite {
        type OprfCs = NistP521;
        type KeyExchange = TripleDh<NistP521, Sha512>;
        type Ksf = Identity;
    }

    test::<Suite>(
        Mechanism::EccKeyPairGen,
        NistP521::OID,
        Attribute::Derive(true),
        Mechanism::Sha512Hmac,
    );
}

#[test]
#[cfg(all(feature = "curve25519", feature = "ristretto255"))]
fn triple_dh_curve25519() {
    struct Suite;

    impl CipherSuite for Suite {
        type OprfCs = Ristretto255;
        type KeyExchange = TripleDh<Curve25519, Sha512>;
        type Ksf = Identity;
    }

    test::<Suite>(
        // This should be [`Mechanism::EccMontgomeryKeyPairGen`], but SoftHSM has an incorrect
        // implementation. See https://github.com/softhsm/SoftHSMv2/issues/647.
        Mechanism::EccEdwardsKeyPairGen,
        ObjectIdentifier::new("1.3.101.110").unwrap(),
        Attribute::Derive(true),
        Mechanism::Sha512Hmac,
    );
}

#[test]
#[cfg(feature = "ecdsa")]
fn sigma_i_p256() {
    struct Suite;

    impl CipherSuite for Suite {
        type OprfCs = NistP256;
        type KeyExchange = SigmaI<Ecdsa<NistP256, Sha256>, NistP256, Sha256>;
        type Ksf = Identity;
    }

    test::<Suite>(
        Mechanism::EccKeyPairGen,
        NistP256::OID,
        Attribute::Sign(true),
        Mechanism::Sha256Hmac,
    );
}

#[test]
#[cfg(feature = "ecdsa")]
fn sigma_i_p384() {
    struct Suite;

    impl CipherSuite for Suite {
        type OprfCs = NistP384;
        type KeyExchange = SigmaI<Ecdsa<NistP384, Sha384>, NistP384, Sha384>;
        type Ksf = Identity;
    }

    test::<Suite>(
        Mechanism::EccKeyPairGen,
        NistP384::OID,
        Attribute::Sign(true),
        Mechanism::Sha384Hmac,
    );
}

#[test]
#[cfg(all(feature = "ristretto255", feature = "ed25519"))]
fn sigma_i_ed25519() {
    struct Suite;

    impl CipherSuite for Suite {
        type OprfCs = Ristretto255;
        type KeyExchange = SigmaI<PureEddsa<Ed25519>, Ristretto255, Sha512>;
        type Ksf = Identity;
    }

    test::<Suite>(
        Mechanism::EccEdwardsKeyPairGen,
        ObjectIdentifier::new_unwrap("1.3.101.112"),
        Attribute::Sign(true),
        Mechanism::Sha512Hmac,
    );
}

#[derive(Clone)]
struct RemoteKey(ObjectHandle);

trait Pkcs11PublicKey
where
    Self: Group + Sized,
{
    fn pkcs11_public_key(data: &[u8]) -> PublicKey<Self>;
}

trait Pkcs11KeyExchange<KE: KeyExchange> {
    fn pkcs11_key_exchange<CS: CipherSuite>(
        &self,
        server_pk: &PublicKey<KE::Group>,
        data: KE::KE2BuilderData<'_, CS>,
    ) -> KE::KE2BuilderInput<CS>;
}

fn test<CS: 'static + CipherSuite>(
    dh_mechanism: Mechanism,
    oid: ObjectIdentifier,
    attribute: Attribute,
    hmac_mechanism: Mechanism,
) where
    KeGroup<CS>: Pkcs11PublicKey,
    RemoteKey: Pkcs11KeyExchange<CS::KeyExchange>,
{
    let (remote_key, pk) = pkcs11_generate_key_pair(dh_mechanism, oid, attribute);

    let keypair = KeyPair::new(RemoteKey(remote_key), pk);
    let oprf_seed = pkcs11_generate_oprf_seed(<OprfHash<CS> as OutputSizeUser>::OutputSize::U64);
    let server_setup = ServerSetup::new_with_key_pair_and_seed(&mut OsRng, keypair, oprf_seed);

    const PASSWORD: &str = "password";

    let ClientRegistrationStartResult {
        message,
        state: client,
    } = ClientRegistration::<CS>::start(&mut OsRng, PASSWORD.as_bytes()).unwrap();
    let key_material_info = server_setup.key_material_info(&[]);
    let key_material = pkcs11_hkdf::<CS>(
        key_material_info.ikm,
        hmac_mechanism,
        Vec::from_iter(key_material_info.info.into_iter().flatten().copied()),
    );
    let message = ServerRegistration::start_with_key_material(&server_setup, key_material, message)
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
    let key_material_info = server_setup.key_material_info(&[]);
    let key_material = pkcs11_hkdf::<CS>(
        key_material_info.ikm,
        hmac_mechanism,
        Vec::from_iter(key_material_info.info.into_iter().flatten().copied()),
    );
    let builder = ServerLogin::builder_with_key_material(
        &mut OsRng,
        &server_setup,
        key_material,
        Some(file),
        message,
        ServerLoginParameters::default(),
    )
    .unwrap();
    let shared_secret = builder
        .private_key()
        .pkcs11_key_exchange(server_setup.keypair().public(), builder.data());

    let ServerLoginStartResult {
        message,
        state: server,
        ..
    } = builder.clone().build(shared_secret).unwrap();

    let message = client
        .clone()
        .finish(
            &mut OsRng,
            PASSWORD.as_bytes(),
            message,
            ClientLoginFinishParameters::default(),
        )
        .map(|result| result.message);

    message
        .map(|message| {
            server
                .finish(message, ServerLoginParameters::default())
                .unwrap()
        })
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

fn pkcs11_generate_key_pair<G: Group + Pkcs11PublicKey>(
    mechanism: Mechanism,
    oid: ObjectIdentifier,
    attribute: Attribute,
) -> (ObjectHandle, PublicKey<G>) {
    let session = SESSION.lock().unwrap();
    let (pk, remote_key) = session
        .generate_key_pair(
            &mechanism,
            &[
                Attribute::Token(false),
                Attribute::EcParams(oid.to_der().unwrap()),
            ],
            &[Attribute::Token(false), attribute],
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
    let pk = G::pkcs11_public_key(pk.as_bytes());

    (remote_key, pk)
}

fn pkcs11_generate_oprf_seed(length: u64) -> ObjectHandle {
    SESSION
        .lock()
        .unwrap()
        .generate_key(
            &Mechanism::GenericSecretKeyGen,
            &[Attribute::Token(false), Attribute::ValueLen(length.into())],
        )
        .unwrap()
}

// SoftHSM, nor any other popular HSM at the time of writing, supports HKDF. So
// we instead implement HKDF by hand on top of the HSMs HMAC, which is supported
// by almost all HSMs and still protects the OPRF seed.
fn pkcs11_hkdf<CS: CipherSuite>(
    hmac: ObjectHandle,
    mechanism: Mechanism,
    info: Vec<u8>,
) -> GenericArray<u8, <OprfGroup<CS> as voprf::Group>::ScalarLen> {
    let mut okm = GenericArray::default();
    let mut prev: Option<Vec<u8>> = None;
    let chunk_len = <OprfHash<CS> as OutputSizeUser>::OutputSize::USIZE;

    if okm.len() > chunk_len * 255 {
        panic!("invalid length");
    }

    let session = SESSION.lock().unwrap();

    for (block_n, block) in (0..).zip(okm.chunks_mut(chunk_len)) {
        let mut data = Vec::new();

        if let Some(ref prev) = prev {
            data.extend(prev.as_slice())
        };

        data.extend(&info);
        data.extend(&[block_n + 1]);

        let output = session.sign(&mechanism, hmac, &data).unwrap();
        block.copy_from_slice(&output[..block.len()]);
        prev = Some(output);
    }

    okm
}

impl Pkcs11PublicKey for NistP256 {
    fn pkcs11_public_key(data: &[u8]) -> PublicKey<NistP256> {
        pkcs11_ec_public_key(data)
    }
}

impl Pkcs11PublicKey for NistP384 {
    fn pkcs11_public_key(data: &[u8]) -> PublicKey<NistP384> {
        pkcs11_ec_public_key(data)
    }
}

impl Pkcs11PublicKey for NistP521 {
    fn pkcs11_public_key(data: &[u8]) -> PublicKey<NistP521> {
        pkcs11_ec_public_key(data)
    }
}

#[cfg(all(feature = "curve25519", feature = "ristretto255"))]
impl Pkcs11PublicKey for Curve25519 {
    fn pkcs11_public_key(data: &[u8]) -> PublicKey<Curve25519> {
        PublicKey::deserialize(data).unwrap()
    }
}

#[cfg(all(feature = "ristretto255", feature = "ed25519"))]
impl Pkcs11PublicKey for Ed25519 {
    fn pkcs11_public_key(data: &[u8]) -> PublicKey<Ed25519> {
        PublicKey::deserialize(data).unwrap()
    }
}

impl Pkcs11KeyExchange<TripleDh<NistP256, Sha256>> for RemoteKey {
    fn pkcs11_key_exchange<CS: CipherSuite>(
        &self,
        server_pk: &PublicKey<NistP256>,
        client_pk: &PublicKey<NistP256>,
    ) -> GenericArray<u8, <NistP256 as Group>::PkLen> {
        pkcs_11_ecdsa_derive_secret::<NistP256>(self.0, server_pk, client_pk)
    }
}

impl Pkcs11KeyExchange<TripleDh<NistP384, Sha384>> for RemoteKey {
    fn pkcs11_key_exchange<CS: CipherSuite>(
        &self,
        server_pk: &PublicKey<NistP384>,
        client_pk: &PublicKey<NistP384>,
    ) -> GenericArray<u8, <NistP384 as Group>::PkLen> {
        pkcs_11_ecdsa_derive_secret::<NistP384>(self.0, server_pk, client_pk)
    }
}

impl Pkcs11KeyExchange<TripleDh<NistP521, Sha512>> for RemoteKey {
    fn pkcs11_key_exchange<CS: CipherSuite>(
        &self,
        server_pk: &PublicKey<NistP521>,
        client_pk: &PublicKey<NistP521>,
    ) -> GenericArray<u8, <NistP521 as Group>::PkLen> {
        pkcs_11_ecdsa_derive_secret::<NistP521>(self.0, server_pk, client_pk)
    }
}

#[cfg(all(feature = "curve25519", feature = "ristretto255"))]
impl Pkcs11KeyExchange<TripleDh<Curve25519, Sha512>> for RemoteKey {
    fn pkcs11_key_exchange<CS: CipherSuite>(
        &self,
        _: &PublicKey<Curve25519>,
        pk: &PublicKey<Curve25519>,
    ) -> GenericArray<u8, <Curve25519 as Group>::PkLen> {
        let shared_secret = pkcs_11_dh_derive_secret(self.0, &pk.serialize());

        GenericArray::clone_from_slice(&shared_secret)
    }
}

#[cfg(feature = "ecdsa")]
impl Pkcs11KeyExchange<SigmaI<Ecdsa<NistP256, Sha256>, NistP256, Sha256>> for RemoteKey {
    fn pkcs11_key_exchange<CS: CipherSuite>(
        &self,
        _: &PublicKey<NistP256>,
        message: &Message<CS, NistP256>,
    ) -> (ecdsa::Signature<NistP256>, PreHash<Sha256>) {
        pkcs_11_ecdsa_sign::<NistP256, Sha256>(self.0, message.hash())
    }
}

#[cfg(feature = "ecdsa")]
impl Pkcs11KeyExchange<SigmaI<Ecdsa<NistP384, Sha384>, NistP384, Sha384>> for RemoteKey {
    fn pkcs11_key_exchange<CS: CipherSuite>(
        &self,
        _: &PublicKey<NistP384>,
        message: &Message<CS, NistP384>,
    ) -> (ecdsa::Signature<NistP384>, PreHash<Sha384>) {
        pkcs_11_ecdsa_sign::<NistP384, Sha384>(self.0, message.hash())
    }
}

#[cfg(all(feature = "ristretto255", feature = "ed25519"))]
impl Pkcs11KeyExchange<SigmaI<PureEddsa<Ed25519>, Ristretto255, Sha512>> for RemoteKey {
    fn pkcs11_key_exchange<CS: CipherSuite>(
        &self,
        _: &PublicKey<Ed25519>,
        message: &Message<CS, Ristretto255>,
    ) -> (ed25519::Signature, CachedMessage<CS, Ristretto255>) {
        pkcs_11_eddsa_sign(self.0, message)
    }
}

fn pkcs11_ec_public_key<G>(data: &[u8]) -> PublicKey<G>
where
    G: Group<Pk = NonIdentity<G>> + CurveArithmetic,
    FieldBytesSize<G>: ModulusSize,
    AffinePoint<G>:
        FromEncodedPoint<G> + ToEncodedPoint<G> + PrimeCurveAffine<Curve = ProjectivePoint<G>>,
{
    PublicKey::deserialize(
        elliptic_curve::PublicKey::<G>::from_sec1_bytes(data)
            .unwrap()
            .to_encoded_point(true)
            .as_bytes(),
    )
    .unwrap()
}

fn pkcs_11_dh_derive_secret(sk: ObjectHandle, pk: &[u8]) -> Vec<u8> {
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

fn pkcs_11_ecdsa_derive_secret<G>(
    server_sk: ObjectHandle,
    server_pk: &PublicKey<G>,
    client_pk: &PublicKey<G>,
) -> GenericArray<u8, <G as Group>::PkLen>
where
    G: Group<Pk = NonIdentity<G>> + CurveArithmetic,
    AffinePoint<G>: DecompressPoint<G> + ToEncodedPoint<G>,
    FieldBytesSize<G>: ModulusSize,
{
    let client_pk_point = client_pk.to_group_type();
    let client_pk = client_pk.serialize();
    let client_pk = OctetStringRef::new(&client_pk).unwrap();
    let client_pk = client_pk.to_der().unwrap();

    let shared_secret_bytes = pkcs_11_dh_derive_secret(server_sk, &client_pk);
    let shared_secret_point = AffinePoint::<G>::decompress(
        &GenericArray::clone_from_slice(&shared_secret_bytes),
        Choice::from(0),
    )
    .unwrap();
    let mut shared_secret = GenericArray::default();
    shared_secret[1..].copy_from_slice(&shared_secret_bytes);

    let shifted_client_pk = client_pk_point.0.to_point() + ProjectivePoint::<G>::generator();
    let shifted_client_pk = shifted_client_pk.to_affine().to_encoded_point(true);
    let shifted_client_pk = OctetStringRef::new(shifted_client_pk.as_bytes()).unwrap();
    let shifted_client_pk = shifted_client_pk.to_der().unwrap();

    let check_point = pkcs_11_dh_derive_secret(server_sk, &shifted_client_pk);

    let shifted_server_pk = server_pk.to_group_type().0.to_point() + shared_secret_point;
    let shifted_server_pk = shifted_server_pk.to_affine();

    let tag = u8::conditional_select(
        &(Tag::CompressedEvenY as u8),
        &(Tag::CompressedOddY as u8),
        check_point.ct_ne(&shifted_server_pk.x()),
    );
    shared_secret[0] = tag;

    shared_secret
}

#[cfg(feature = "ecdsa")]
fn pkcs_11_ecdsa_sign<G: CurveArithmetic + PrimeCurve, H: Clone + Digest>(
    sk: ObjectHandle,
    hashes: HashOutput<H>,
) -> (ecdsa::Signature<G>, PreHash<H>)
where
    SignatureSize<G>: ArrayLength<u8>,
{
    let sign_pre_hash = hashes.sign.finalize();

    let session = SESSION.lock().unwrap();
    let signature = session.sign(&Mechanism::Ecdsa, sk, &sign_pre_hash).unwrap();
    drop(session);

    let signature = ::ecdsa::Signature::from_slice(&signature).unwrap();

    (
        ecdsa::Signature(signature),
        PreHash(hashes.verify.finalize()),
    )
}

#[cfg(all(feature = "ristretto255", feature = "ed25519"))]
fn pkcs_11_eddsa_sign<CS: CipherSuite>(
    sk: ObjectHandle,
    message: &Message<CS, Ristretto255>,
) -> (ed25519::Signature, CachedMessage<CS, Ristretto255>) {
    use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};

    let mut message_bytes = Vec::new();
    message
        .sign_message()
        .for_each(|bytes| message_bytes.extend_from_slice(bytes));

    let session = SESSION.lock().unwrap();
    let signature = session
        .sign(
            &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
            sk,
            &message_bytes,
        )
        .unwrap();
    drop(session);

    let signature = ed25519::Signature::from_slice(&signature).unwrap();

    (signature, message.to_cached())
}

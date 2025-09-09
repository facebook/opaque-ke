use digest::OutputSizeUser;
use generic_array::GenericArray;
use generic_array::sequence::{Concat, Split};
use generic_array::typenum::Sum;
use opaque_ke::ksf::Identity;
use opaque_ke::{CipherSuite, ClientLogin, ServerLogin, ServerRegistration, ServerSetup, TripleDh};
use opaque_ke_3::key_exchange::group::KeGroup as v3KeGroup;
use opaque_ke_3::key_exchange::tripledh::TripleDh as v3TripleDh;
use opaque_ke_3::keypair::KeyPair;
use opaque_ke_3::ksf::Identity as v3Identity;
use opaque_ke_3::{
    CipherSuite as v3CipherSuite, ClientRegistration as v3ClientRegistration,
    ServerRegistration as v3ServerRegistration, ServerSetup as v3ServerSetup,
};
use p256::NistP256;
use rand::rngs::OsRng;
use sha2::Sha256;

const PASSWORD: &[u8] = b"test password";
const CLIENT_IDENTIFIER: &[u8] = b"test client identifier";

struct OldCipherSuite;

impl v3CipherSuite for OldCipherSuite {
    type OprfCs = NistP256;
    type KeGroup = NistP256;
    type KeyExchange = v3TripleDh;
    type Ksf = v3Identity;
}

struct NewCipherSuite;

impl CipherSuite for NewCipherSuite {
    type OprfCs = NistP256;
    type KeyExchange = TripleDh<NistP256, Sha256>;
    type Ksf = Identity;
}

#[test]
fn registration_upload() {
    // V3 registration.
    let result = v3ClientRegistration::<OldCipherSuite>::start(&mut OsRng, PASSWORD).unwrap();
    let client = result.state;

    let old_server_setup = v3ServerSetup::<OldCipherSuite>::new(&mut OsRng);
    let response =
        v3ServerRegistration::start(&old_server_setup, result.message, CLIENT_IDENTIFIER)
            .unwrap()
            .message;

    let upload = client
        .finish(&mut OsRng, PASSWORD, response, Default::default())
        .unwrap()
        .message;

    let old_registration = v3ServerRegistration::finish(upload);

    // `ServerSetup` migration.
    let server_setup = {
        let old_serialized = old_server_setup.serialize();

        type OldSeedLen = <<<OldCipherSuite as v3CipherSuite>::OprfCs as voprf::CipherSuite>::Hash as OutputSizeUser>::OutputSize;
        type OldSkLen = <<OldCipherSuite as v3CipherSuite>::KeGroup as v3KeGroup>::SkLen;
        let (old_serialied_rest, old_fake_keypair_serialized): (
            GenericArray<u8, Sum<OldSeedLen, OldSkLen>>,
            _,
        ) = old_serialized.split();
        let old_fake_keypair =
            KeyPair::<<OldCipherSuite as v3CipherSuite>::KeGroup>::from_private_key_slice(
                &old_fake_keypair_serialized,
            )
            .unwrap();
        let old_fake_pk_serialized = old_fake_keypair.public().serialize();

        let new_serialized = old_serialied_rest.concat(old_fake_pk_serialized);
        ServerSetup::<NewCipherSuite>::deserialize(&new_serialized).unwrap()
    };

    // `ServerRegistration` migration.
    let old_registration_serialized = old_registration.serialize();
    let registration =
        ServerRegistration::<NewCipherSuite>::deserialize(&old_registration_serialized).unwrap();

    // Check if new `ServerRegistration` still works.
    let result = ClientLogin::<NewCipherSuite>::start(&mut OsRng, PASSWORD).unwrap();
    let client = result.state;

    let result = ServerLogin::start(
        &mut OsRng,
        &server_setup,
        Some(registration),
        result.message,
        CLIENT_IDENTIFIER,
        Default::default(),
    )
    .unwrap();
    let server = result.state;

    let result = client
        .finish(&mut OsRng, PASSWORD, result.message, Default::default())
        .unwrap();

    server.finish(result.message, Default::default()).unwrap();
}

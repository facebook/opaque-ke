use crate::{
    errors::{InternalPakeError, ProtocolError},
    key_exchange_traits::*,
    keypair::{KeyPair, SizedBytes},
};
use core_extensions::TransparentNewtype;
use generic_array::{
    typenum::{Unsigned, U32},
    GenericArray,
};

use std::ops::Deref;

use rand_core::{CryptoRng, RngCore};
use snow::{params::NoiseParams, Builder, HandshakeState, Keypair as SnowKeypair, TransportState};

mod noise_utils;
use noise_utils::StateIO;

/// A Noise DH Key type on 32 bits, owing to its associated
/// `NoiseKey::HANDSHAKE_PARAMS` which specifies a Curve22519
/// representation.
#[repr(transparent)]
#[derive(PartialEq, Eq, Clone)]
pub struct NoiseKey(Vec<u8>);

unsafe impl TransparentNewtype for NoiseKey {
    type Inner = Vec<u8>;
}

impl NoiseKey {
    pub const HANDSHAKE_PARAMS: &'static str = "Noise_XX_25519_ChaChaPoly_SHA512";

    // TODO: declare this const_fn once this feature hits stable
    pub fn noise_params() -> NoiseParams {
        NoiseKey::HANDSHAKE_PARAMS
            .parse::<NoiseParams>()
            .expect("Noise parameter source string incorrect!")
    }
}

impl Deref for NoiseKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SizedBytes for NoiseKey {
    // Change this if you change the Noise parameters
    type Len = U32;

    fn to_arr(&self) -> GenericArray<u8, Self::Len> {
        GenericArray::clone_from_slice(&self.0)
    }

    fn from_bytes(key_bytes: &[u8]) -> Result<Self, InternalPakeError> {
        let target_len: usize = <Self::Len as Unsigned>::to_usize();
        if key_bytes.len() == target_len {
            Ok(NoiseKey(key_bytes.to_vec()))
        } else {
            Err(InternalPakeError::SizeError {
                name: "key_bytes",
                len: target_len,
                actual_len: key_bytes.len(),
            })
        }
    }
}

impl KeyPair for SnowKeypair {
    type Repr = NoiseKey;

    fn public(&self) -> &Self::Repr {
        NoiseKey::convert_ref_from(&self.public)
    }

    fn private(&self) -> &Self::Repr {
        NoiseKey::convert_ref_from(&self.private)
    }

    fn new(public: Self::Repr, private: Self::Repr) -> Result<Self, InternalPakeError> {
        Ok(SnowKeypair {
            public: public.0,
            private: private.0,
        })
    }

    fn generate_random<R: RngCore + CryptoRng>(_rng: &mut R) -> Result<Self, InternalPakeError> {
        Builder::new(NoiseKey::noise_params())
            .generate_keypair()
            .map_err(|_| InternalPakeError::NoiseError)
    }

    fn public_from_private(secret: &Self::Repr) -> Self::Repr {
        let mut secret_data = [0u8; 32];
        secret_data.copy_from_slice(&secret.0[..]);
        let base_data = ::x25519_dalek::X25519_BASEPOINT_BYTES;
        NoiseKey(::x25519_dalek::x25519(secret_data, base_data).to_vec())
    }

    fn check_public_key(key: Self::Repr) -> Result<Self::Repr, InternalPakeError> {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key);
        let point = ::curve25519_dalek::montgomery::MontgomeryPoint(key_bytes)
            .to_edwards(1)
            .ok_or(InternalPakeError::PointError)?;
        if !point.is_torsion_free() {
            Err(InternalPakeError::SubGroupError)
        } else {
            Ok(key)
        }
    }

    fn diffie_hellman(pk: Self::Repr, sk: Self::Repr) -> Vec<u8> {
        let mut pk_data = [0; 32];
        pk_data.copy_from_slice(&pk);
        let mut sk_data = [0; 32];
        sk_data.copy_from_slice(&sk);
        ::x25519_dalek::x25519(sk_data, pk_data).to_vec()
    }
}

// This contains what we need before generating for the client ephemeral, i.e. nothing
pub struct SnowInitiatorFirst {}

impl IStateTR for SnowInitiatorFirst {
    type Initial = ();
    // We need to remember the ephemeral and feed it to the Builder, which will
    // only have the keys on the Final Initiator Step
    type Next = Vec<u8>;
    type Output = Vec<u8>;
    type Error = ProtocolError;

    fn generate(self, _init_state: ()) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
        let builder = Builder::new(NoiseKey::noise_params());
        let mut noise: HandshakeState = builder
            .build_initiator()
            .map_err(|_| InternalPakeError::NoiseError)?;
        // client: -> e
        let ephemeral = noise
            // here if we want to be fancier, we can use l1_component as ikm
            .fwrite_message(&[])
            .map_err(|_| InternalPakeError::NoiseError)?;
        Ok((ephemeral.clone(), ephemeral))
    }
}

impl InitiatorFirstStep for SnowInitiatorFirst {
    fn new(_l1_component: Vec<u8>) -> Self {
        SnowInitiatorFirst {}
    }
}

pub struct SnowResponderFirst {
    client_s_pk: Vec<u8>,
    server_s_sk: Vec<u8>,
    ke1m: Vec<u8>,
}

impl IStateTR for SnowResponderFirst {
    type Initial = ();
    // We need to remember the handshake state
    type Next = HandshakeState;
    type Output = Vec<u8>;
    type Error = ProtocolError;

    fn generate(self, _init_state: ()) -> Result<(HandshakeState, Vec<u8>), ProtocolError> {
        let builder = Builder::new(NoiseKey::noise_params())
            .local_private_key(&self.server_s_sk)
            .remote_public_key(&self.client_s_pk);
        let mut noise: HandshakeState = builder
            .build_responder()
            .map_err(|_| InternalPakeError::NoiseError)?;
        // read the client ephemeral
        let _ = noise
            .fread_message(&self.ke1m[..])
            .map_err(|_| InternalPakeError::NoiseError)?;
        // server: -> e, ee, s, es
        let response = noise
            // here if we want to be fancier, we can use l1_component, l2_component as ikm
            .fwrite_message(&[])
            .map_err(|_| InternalPakeError::NoiseError)?;
        Ok((noise, response))
    }
}

impl ResponderFirstStep<SnowKeypair> for SnowResponderFirst {
    type Proposer = SnowInitiatorFirst;
    fn new(
        _l1_component: Vec<u8>,
        _l2_component: Vec<u8>,
        client_s_pk: NoiseKey,
        server_s_sk: NoiseKey,
        ke1m: Vec<u8>,
    ) -> Self {
        SnowResponderFirst {
            client_s_pk: client_s_pk.to_vec(),
            server_s_sk: server_s_sk.to_vec(),
            ke1m,
        }
    }
}

pub struct SnowInitiatorFinal {
    ke2m: Vec<u8>,
    // We finally learn our own SK! That lets us re-construct our HandshakeState
    server_s_pk: Vec<u8>,
    client_s_sk: Vec<u8>,
}

impl IStateTR for SnowInitiatorFinal {
    type Initial = Vec<u8>; // the ephemeral from the first step
    type Next = TransportState;
    type Output = Vec<u8>;
    type Error = ProtocolError;

    fn generate(self, ephemeral: Vec<u8>) -> Result<(TransportState, Vec<u8>), ProtocolError> {
        let builder = Builder::new(NoiseKey::noise_params())
            .fixed_ephemeral_key_for_testing_only(&ephemeral)
            .local_private_key(&self.client_s_sk)
            .remote_public_key(&self.server_s_pk);
        let mut noise: HandshakeState = builder
            .build_initiator()
            .map_err(|_| InternalPakeError::NoiseError)?;
        // replay generating the ephemeral, which we fixed from the prior step
        let _ephemeral = noise
            // here if we want to be fancier, we can use l1_component as ikm
            .fwrite_message(&[])
            .map_err(|_| InternalPakeError::NoiseError)?;
        // read the response
        let _ = noise
            .fread_message(&self.ke2m)
            .map_err(|_| InternalPakeError::NoiseError)?;
        // client: -> s, se
        let final_message = noise
            .fwrite_message(&[])
            .map_err(|_| InternalPakeError::NoiseError)?;
        let transport = noise
            .into_transport_mode()
            .map_err(|_| InternalPakeError::NoiseError)?;
        Ok((transport, final_message))
    }
}

impl InitiatorFinalStep<SnowInitiatorFirst, SnowKeypair> for SnowInitiatorFinal {
    type Proposer = SnowResponderFirst;

    fn new(
        _l2_component: Vec<u8>,
        ke2m: Vec<u8>,
        server_s_pk: NoiseKey,
        client_s_sk: NoiseKey,
    ) -> Self {
        SnowInitiatorFinal {
            ke2m,
            server_s_pk: server_s_pk.to_vec(),
            client_s_sk: client_s_sk.to_vec(),
        }
    }
}

pub struct SnowResponderFinal {
    ke3m: Vec<u8>,
}

impl IStateTR for SnowResponderFinal {
    type Initial = HandshakeState;
    type Next = TransportState;
    type Output = ();
    type Error = ProtocolError;

    fn generate(
        self,
        handshake_state: HandshakeState,
    ) -> Result<(TransportState, ()), ProtocolError> {
        let mut noise = handshake_state;
        // read the client final message
        let _ = noise
            .fread_message(&self.ke3m)
            .map_err(|_| InternalPakeError::NoiseError)?;
        let transport = noise
            .into_transport_mode()
            .map_err(|_| InternalPakeError::NoiseError)?;
        Ok((transport, ()))
    }
}

impl ResponderFinalStep<SnowResponderFirst, SnowKeypair> for SnowResponderFinal {
    type Proposer = SnowInitiatorFinal;

    fn new(ke3m: Vec<u8>) -> Self {
        SnowResponderFinal { ke3m }
    }
}

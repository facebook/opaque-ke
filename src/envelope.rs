// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    errors::{utils::check_slice_size, InternalPakeError, PakeError, ProtocolError},
    group::Group,
    hash::Hash,
    keypair::{Key, KeyPair},
    map_to_curve::GroupWithMapToCurve,
    serialization::serialize,
};
use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};
use generic_bytes::SizedBytes;
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use rand::{CryptoRng, RngCore};
use std::convert::TryFrom;

// Constant string used as salt for HKDF computation
const STR_PAD: &[u8] = b"Pad";
const STR_AUTH_KEY: &[u8] = b"AuthKey";
const STR_EXPORT_KEY: &[u8] = b"ExportKey";
const STR_PRIVATE_KEY: &[u8] = b"PrivateKey";
const STR_OPAQUE_HASH_TO_SCALAR: &[u8] = b"OPAQUE-HashToScalar";

const NONCE_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum InnerEnvelopeMode {
    Unused = 0,
    Base = 1,
    CustomIdentifier = 2,
}

impl TryFrom<u8> for InnerEnvelopeMode {
    type Error = PakeError;
    fn try_from(x: u8) -> Result<Self, Self::Error> {
        match x {
            1 => Ok(InnerEnvelopeMode::Base), // FIXME these need to be updated to reflect new modes
            2 => Ok(InnerEnvelopeMode::CustomIdentifier),
            _ => Err(PakeError::SerializationError),
        }
    }
}

pub(crate) struct InnerEnvelope {
    mode: InnerEnvelopeMode,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl InnerEnvelope {
    pub(crate) fn serialize(&self) -> Vec<u8> {
        [&[self.mode as u8], &self.nonce[..], &self.ciphertext[..]].concat()
    }

    pub(crate) fn deserialize(input: &[u8]) -> Result<(Self, Vec<u8>), ProtocolError> {
        if input.is_empty() {
            return Err(ProtocolError::VerificationError(
                PakeError::SerializationError,
            ));
        }
        let mode = InnerEnvelopeMode::try_from(input[0])?;

        let bytes = &input[1..];
        if bytes.len() < NONCE_LEN {
            return Err(ProtocolError::VerificationError(
                PakeError::SerializationError,
            ));
        }

        // FIXME
        // if external mode:
        // let key_len = <Key as SizedBytes>::Len::to_usize();
        //

        let envelope_len = NONCE_LEN;


        Ok((
            Self {
                mode,
                nonce: bytes[..NONCE_LEN].to_vec(),
                ciphertext: bytes[NONCE_LEN..envelope_len].to_vec(),
            },
            bytes[envelope_len..].to_vec(),
        ))
    }
}

/// This struct is an instantiation of the envelope as described in
/// https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-06#section-4
///
/// Note that earlier versions of this specification described an
/// implementation of this envelope using an encryption scheme that
/// satisfied random-key robustness
/// (https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-05#section-4).
/// The specification update has simplified this assumption by taking
/// an XOR-based approach without compromising on security, and to avoid
/// the confusion around the implementation of an RKR-secure encryption.
pub(crate) struct Envelope<CS: CipherSuite> {
    inner_envelope: InnerEnvelope,
    hmac: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
}

// Note that this struct represents an envelope that has been "opened" with the asssociated
// key. This key is also used to derive the export_key parameter, which is technically
// unrelated to the envelope's encrypted and authenticated contents.
pub(crate) struct OpenedEnvelope<CS: CipherSuite> {
    pub(crate) client_static_keypair: KeyPair<CS::Group>,
    pub(crate) export_key: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
}

pub(crate) struct OpenedInnerEnvelope<D: Hash> {
    pub(crate) plaintext: Vec<u8>,
    pub(crate) export_key: GenericArray<u8, <D as Digest>::OutputSize>,
}

impl<CS: CipherSuite> Envelope<CS> {
    fn hmac_key_size() -> usize {
        <CS::Hash as Digest>::OutputSize::to_usize()
    }

    fn export_key_size() -> usize {
        <CS::Hash as Digest>::OutputSize::to_usize()
    }

    pub(crate) fn len() -> usize {
        1
            + <CS::Hash as Digest>::OutputSize::to_usize()
            + NONCE_LEN
    }

    pub(crate) fn get_mode(&self) -> InnerEnvelopeMode {
        self.inner_envelope.mode
    }

    pub(crate) fn serialize(&self) -> Vec<u8> {
        [&self.inner_envelope.serialize(), &self.hmac[..]].concat()
    }

    pub(crate) fn deserialize(input: &[u8]) -> Result<Self, ProtocolError> {
        let (inner_envelope, remainder) = InnerEnvelope::deserialize(input)
            .map_err(|_| ProtocolError::InvalidInnerEnvelopeError)?;

        let hmac_key_size = Self::hmac_key_size();
        let hmac = check_slice_size(&remainder, hmac_key_size, "hmac_key_size")?;

        Ok(Self {
            inner_envelope,
            hmac: GenericArray::clone_from_slice(&hmac),
        })
    }

    // Creates a dummy envelope object that serializes to the all-zeros byte string
    pub(crate) fn dummy() -> Self {
        Self {
            inner_envelope: InnerEnvelope {
                mode: InnerEnvelopeMode::Unused,
                nonce: vec![0u8; NONCE_LEN],
                ciphertext: vec![0u8; <Key as SizedBytes>::Len::to_usize()],
            },
            hmac: GenericArray::clone_from_slice(&vec![
                0u8;
                <CS::Hash as Digest>::OutputSize::to_usize()
            ]),
        }
    }

    pub(crate) fn seal<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &[u8],
        // client_keypair: KeyPair<CS::Group>, // FIXME make this optional and mode-dependent
        server_s_pk: &[u8],
        optional_ids: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<
        (
            Self,
            Key,
            GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
        ),
        InternalPakeError,
    > {
        let mut nonce = vec![0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let h = Hkdf::<CS::Hash>::new(None, &key);
        let mut keypair_seed = vec![0u8; <Key as SizedBytes>::Len::to_usize()];
        h.expand(&[&nonce, STR_PRIVATE_KEY].concat(), &mut keypair_seed)
            .map_err(|_| InternalPakeError::HkdfError)?;
        let client_static_keypair = KeyPair::<CS::Group>::from_private_key_slice(
            CS::Group::scalar_as_bytes(&CS::Group::hash_to_scalar::<CS::Hash>(
                &keypair_seed[..],
                STR_OPAQUE_HASH_TO_SCALAR,
            )?),
        )?;

        println!("seal key: {}", hex::encode(&key));
        println!("seal nonce: {}", hex::encode(&nonce));
        println!("seal keypair_seed: {}", hex::encode(&keypair_seed));
        println!("envelope_nonce: {}", hex::encode(&nonce));
        println!("client_s_sk: {}", hex::encode(client_static_keypair.private().to_arr()));
        println!("client_s_pk: {}", hex::encode(client_static_keypair.public().to_arr()));

        let aad = construct_aad(
            &client_static_keypair.public().to_arr().to_vec(),
            server_s_pk,
            &optional_ids,
        );

        println!("aad: {}", hex::encode(&aad));

        let (envelope, export_key) = Self::seal_raw(
            key,
            &nonce,
            &[], /* FIXME: depending on mode, use &client_s_sk */
            &aad,
            InnerEnvelopeMode::Base, // mode_from_ids(&optional_ids), // FIXME
        )?;

        Ok((envelope, client_static_keypair.public().clone(), export_key))
    }

    /// Uses a key to convert the plaintext into an envelope, authenticated by the aad field.
    /// Note that a new nonce is sampled for each call to seal.
    pub(crate) fn seal_raw(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        mode: InnerEnvelopeMode,
    ) -> Result<(Self, GenericArray<u8, <CS::Hash as Digest>::OutputSize>), InternalPakeError> {
        let h = Hkdf::<CS::Hash>::new(None, &key);
        let mut xor_key = vec![0u8; plaintext.len()]; // FIXME delete this
        let mut hmac_key = vec![0u8; Self::hmac_key_size()];
        let mut export_key = vec![0u8; Self::export_key_size()];

        h.expand(&[&nonce, STR_PAD].concat(), &mut xor_key)
            .map_err(|_| InternalPakeError::HkdfError)?;
        h.expand(&[&nonce, STR_AUTH_KEY].concat(), &mut hmac_key)
            .map_err(|_| InternalPakeError::HkdfError)?;
        h.expand(&[&nonce, STR_EXPORT_KEY].concat(), &mut export_key)
            .map_err(|_| InternalPakeError::HkdfError)?;

        // FIXME: Only do this if keypair hasn't been supplied

        let ciphertext: Vec<u8> = xor_key
            .iter()
            .zip(plaintext.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        let inner_envelope = InnerEnvelope {
            mode,
            nonce: nonce.to_vec(),
            ciphertext,
        };

        println!("auth_key: {}", hex::encode(&hmac_key));
        println!("inner_envelope: {}", hex::encode(&inner_envelope.serialize()));

        let mut hmac =
            Hmac::<CS::Hash>::new_varkey(&hmac_key).map_err(|_| InternalPakeError::HmacError)?;
        hmac.update(&inner_envelope.serialize());
        hmac.update(&aad);

        let hmac_bytes = hmac.finalize().into_bytes();

        Ok((
            Self {
                inner_envelope,
                hmac: hmac_bytes,
            },
            GenericArray::clone_from_slice(&export_key),
        ))
    }

    pub(crate) fn open(
        &self,
        key: &[u8],
        server_s_pk: &[u8],
        optional_ids: &Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<OpenedEnvelope<CS>, InternalPakeError> {

        /*
        // FIXME restore this later
        // First, check that mode matches
        if self.inner_envelope.mode != mode_from_ids(optional_ids) {
            return Err(InternalPakeError::IncompatibleEnvelopeModeError);
        }
        */

        let h = Hkdf::<CS::Hash>::new(None, &key);
        let mut keypair_seed = vec![0u8; <Key as SizedBytes>::Len::to_usize()];
        h.expand(
            &[&self.inner_envelope.nonce, STR_PRIVATE_KEY].concat(),
            &mut keypair_seed,
        )
        .map_err(|_| InternalPakeError::HkdfError)?;
        let client_static_keypair = KeyPair::<CS::Group>::from_private_key_slice(
            CS::Group::scalar_as_bytes(&CS::Group::hash_to_scalar::<CS::Hash>(
                &keypair_seed[..],
                STR_OPAQUE_HASH_TO_SCALAR,
            )?),
        )?;

        println!("open key: {}", hex::encode(&key));
        println!("open nonce: {}", hex::encode(&self.inner_envelope.nonce));
        println!("open keypair_seed: {}", hex::encode(&keypair_seed));

        let aad = construct_aad(
            &client_static_keypair.public().to_arr().to_vec(),
            server_s_pk,
            optional_ids,
        );
        let opened = self.open_raw(key, &aad)?;

        /*
        FIXME: Plaintext is going to be empty in internal mode
        if opened.plaintext.len() != <Key as SizedBytes>::Len::to_usize() {
            // Plaintext should consist of a single key
            return Err(InternalPakeError::UnexpectedEnvelopeContentsError);
        }
        */

        Ok(OpenedEnvelope {
            client_static_keypair, // FIXME: for external mode, use: opened.plaintext,
            export_key: opened.export_key,
        })
    }

    /// Attempts to decrypt the envelope using a key, which is successful only if the key and
    /// aad used to construct the envelope are the same.
    pub(crate) fn open_raw(
        &self,
        key: &[u8],
        aad: &[u8],
    ) -> Result<OpenedInnerEnvelope<CS::Hash>, InternalPakeError> {
        let h = Hkdf::<CS::Hash>::new(None, &key);
        let mut xor_key = vec![0u8; self.inner_envelope.ciphertext.len()];
        let mut hmac_key = vec![0u8; Self::hmac_key_size()];
        let mut export_key = vec![0u8; Self::export_key_size()];

        h.expand(
            &[&self.inner_envelope.nonce, STR_PAD].concat(),
            &mut xor_key,
        )
        .map_err(|_| InternalPakeError::HkdfError)?;
        h.expand(
            &[&self.inner_envelope.nonce, STR_AUTH_KEY].concat(),
            &mut hmac_key,
        )
        .map_err(|_| InternalPakeError::HkdfError)?;
        h.expand(
            &[&self.inner_envelope.nonce, STR_EXPORT_KEY].concat(),
            &mut export_key,
        )
        .map_err(|_| InternalPakeError::HkdfError)?;

        let mut hmac =
            Hmac::<CS::Hash>::new_varkey(&hmac_key).map_err(|_| InternalPakeError::HmacError)?;
        hmac.update(&self.inner_envelope.serialize());
        hmac.update(aad);
        if hmac.verify(&self.hmac).is_err() {
            return Err(InternalPakeError::SealOpenHmacError);
        }

        let plaintext: Vec<u8> = xor_key
            .iter()
            .zip(self.inner_envelope.ciphertext.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        Ok(OpenedInnerEnvelope {
            plaintext,
            export_key: GenericArray::<u8, <CS::Hash as Digest>::OutputSize>::clone_from_slice(
                &export_key,
            ),
        })
    }
}

// Helper functions

fn construct_aad(
    client_s_pk: &[u8],
    server_s_pk: &[u8],
    optional_ids: &Option<(Vec<u8>, Vec<u8>)>,
) -> Vec<u8> {
    // FIXME support mixed ids possibility through potential enum?
    let ids = optional_ids
        .iter()
        .flat_map(|(l, r)| [serialize(l, 2), serialize(r, 2)].concat())
        .collect();
    [server_s_pk.to_vec(), ids].concat()
}

pub(crate) fn mode_from_ids(optional_ids: &Option<(Vec<u8>, Vec<u8>)>) -> InnerEnvelopeMode {
    match optional_ids {
        Some(_) => InnerEnvelopeMode::CustomIdentifier,
        None => InnerEnvelopeMode::Base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    struct RistrettoSha5123dhNoSlowHash;
    impl CipherSuite for RistrettoSha5123dhNoSlowHash {
        type Group = curve25519_dalek::ristretto::RistrettoPoint;
        type KeyExchange = crate::key_exchange::tripledh::TripleDH;
        type Hash = sha2::Sha512;
        type SlowHash = crate::slow_hash::NoOpHash;
    }

    #[test]
    fn seal_and_open() {
        let mut rng = OsRng;
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        let mut msg = [0u8; 100];
        rng.fill_bytes(&mut msg);

        let (envelope, export_key) = Envelope::<RistrettoSha5123dhNoSlowHash>::seal_raw(
            &key,
            &nonce,
            &msg,
            b"aad",
            InnerEnvelopeMode::Base,
        )
        .unwrap();
        let opened_envelope = envelope.open_raw(&key, b"aad").unwrap();
        assert_eq!(&msg.to_vec(), &opened_envelope.plaintext);
        assert_eq!(&export_key.to_vec(), &opened_envelope.export_key.to_vec());
    }
}

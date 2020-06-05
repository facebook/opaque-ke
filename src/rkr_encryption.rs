// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::{utils::check_slice_size, InternalPakeError, PakeError};
use aead::{Aead, NewAead};
use generic_array::{typenum::Unsigned, GenericArray};
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// This trait encapsulates an encryption scheme that satisfies random-key robustness (RKR), which is implemented
/// through encrypt-then-HMAC -- see Section 3.1.1 of
/// https://www.ietf.org/id/draft-krawczyk-cfrg-opaque-03.txt
/// We require an Aead implementation with a 32-bit key size, since we
/// will derive the symmetric key from pw using Sha256
pub trait RKRCipher: Sized {
    /// The requirement of KeySize = U32 is so that we can use a 32-bit hash
    /// for key derivation form the user's password
    type AEAD: NewAead<KeySize = <Sha256 as Digest>::OutputSize> + Aead;

    // Required members
    fn new(
        aead_output: Vec<u8>,
        hmac: &GenericArray<u8, <Sha256 as Digest>::OutputSize>,
        nonce: &GenericArray<u8, <Self::AEAD as Aead>::NonceSize>,
    ) -> Self;

    fn aead_output(&self) -> &Vec<u8>;
    fn hmac(&self) -> &GenericArray<u8, <Sha256 as Digest>::OutputSize>;
    fn nonce(&self) -> &GenericArray<u8, <Self::AEAD as Aead>::NonceSize>;

    fn to_bytes(&self) -> Vec<u8>;

    // Provided members for enc / dec
    fn key_len() -> usize {
        <Self::AEAD as NewAead>::KeySize::to_usize()
    }

    fn nonce_size() -> usize {
        <Self::AEAD as Aead>::NonceSize::to_usize()
    }

    fn hmac_size() -> usize {
        <Sha256 as Digest>::OutputSize::to_usize()
    }

    /// This estimates the size of the ciphertext once we encode —very specifically—
    /// the payload we have planned for the protocol's env_u
    fn ciphertest_size() -> usize {
        Self::key_len() + <Self::AEAD as Aead>::TagSize::to_usize() + Self::hmac_size()
    }

    fn rkr_with_nonce_size() -> usize {
        Self::ciphertest_size() + Self::nonce_size()
    }

    /// The format of the output ciphertext here is:
    /// encryption_output | tag                 | hmac             | nonce
    /// variable length   | AEAD_TAG_SIZE bytes | HMAC_SIZE bytes  | NONCE_SIZE bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, InternalPakeError> {
        let checked_bytes = check_slice_size(&bytes[..], Self::rkr_with_nonce_size(), "bytes")?;
        let nonce_start = bytes.len() - Self::nonce_size();
        let hmac_start = nonce_start - Self::hmac_size();

        Ok(<Self as RKRCipher>::new(
            bytes[..hmac_start].to_vec(),
            GenericArray::from_slice(&checked_bytes[hmac_start..nonce_start]),
            GenericArray::from_slice(&checked_bytes[nonce_start..]),
        ))
    }

    /// Encrypt with AEAD. Note that this encryption scheme needs to satisfy "random-key robustness" (RKR).
    fn encrypt<R: RngCore + CryptoRng>(
        encryption_key: &[u8],
        hmac_key: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        rng: &mut R,
    ) -> Result<Self, PakeError> {
        let mut nonce = vec![0u8; Self::nonce_size()];
        rng.fill_bytes(&mut nonce);
        let gen_nonce = GenericArray::from_slice(&nonce[..]);

        let ciphertext = <Self::AEAD as NewAead>::new(*GenericArray::from_slice(&encryption_key))
            .encrypt(
                GenericArray::from_slice(&nonce),
                aead::Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| PakeError::EncryptionError)?;

        let mut mac =
            Hmac::<Sha256>::new_varkey(&hmac_key).map_err(|_| InternalPakeError::HmacError)?;
        mac.input(&ciphertext);

        Ok(<Self as RKRCipher>::new(
            ciphertext,
            &mac.result().code(),
            gen_nonce,
        ))
    }

    fn decrypt(
        &self,
        encryption_key: &[u8],
        hmac_key: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PakeError> {
        let mut mac =
            Hmac::<Sha256>::new_varkey(&hmac_key).map_err(|_| InternalPakeError::HmacError)?;
        mac.input(self.aead_output());
        if mac.verify(self.hmac()).is_err() {
            return Err(PakeError::DecryptionHmacError);
        }

        Aead::decrypt(
            &<Self::AEAD as NewAead>::new(*GenericArray::from_slice(&encryption_key)),
            self.nonce(),
            aead::Payload {
                msg: self.aead_output(),
                aad: &aad,
            },
        )
        .map_err(|_| PakeError::DecryptionError)
    }
}

/// This struct is a straightforward instantiation of the trait separating the
/// three components in Vecs
pub struct RKRCiphertext<T> {
    aead_choice: std::marker::PhantomData<T>,
    aead_output: Vec<u8>,
    hmac: Vec<u8>,
    nonce: Vec<u8>,
}

impl<T: NewAead<KeySize = <Sha256 as Digest>::OutputSize> + Aead> RKRCipher for RKRCiphertext<T> {
    type AEAD = T;

    fn new(
        aead_output: Vec<u8>,
        hmac: &GenericArray<u8, <Sha256 as Digest>::OutputSize>,
        nonce: &GenericArray<u8, <Self::AEAD as Aead>::NonceSize>,
    ) -> Self {
        Self {
            aead_choice: std::marker::PhantomData,
            aead_output,
            hmac: hmac.to_vec(),
            nonce: nonce.to_vec(),
        }
    }

    fn aead_output(&self) -> &Vec<u8> {
        &self.aead_output
    }

    fn to_bytes(&self) -> Vec<u8> {
        [&self.aead_output[..], &self.hmac[..], &self.nonce[..]].concat()
    }

    fn hmac(&self) -> &GenericArray<u8, <Sha256 as Digest>::OutputSize> {
        GenericArray::from_slice(&self.hmac[..])
    }

    fn nonce(&self) -> &GenericArray<u8, <T as Aead>::NonceSize> {
        GenericArray::from_slice(&self.nonce[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::ChaCha20Poly1305;
    use rand_core::OsRng;

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = OsRng;
        let mut encryption_key = [0u8; 32];
        rng.fill_bytes(&mut encryption_key);
        let mut hmac_key = [0u8; 32];
        rng.fill_bytes(&mut hmac_key);

        let mut msg = [0u8; 100];
        rng.fill_bytes(&mut msg);

        let ciphertext = RKRCiphertext::<ChaCha20Poly1305>::encrypt(
            &encryption_key,
            &hmac_key,
            &msg,
            b"",
            &mut rng,
        )
        .unwrap();
        let decrypted = ciphertext.decrypt(&encryption_key, &hmac_key, b"").unwrap();
        assert_eq!(&msg.to_vec(), &decrypted);
    }
}

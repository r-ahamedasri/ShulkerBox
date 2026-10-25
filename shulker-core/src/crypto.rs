use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};
use crate::keys::SecretKey32;

pub const NONCE_LEN: usize = 24;

/// An AEAD-encrypted payload: a random 24-byte XChaCha20 nonce plus the
/// ciphertext (which includes the 16-byte Poly1305 tag appended by the
/// `aead` crate). Safe to store or transmit as-is; on its own it reveals
/// nothing about the plaintext beyond its length.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Encrypts `plaintext` under `key` with a fresh random nonce.
///
/// `aad` (associated data) is authenticated but not encrypted — callers use
/// it for domain separation (e.g. binding a wrapped VEK to the vault's
/// format version) so ciphertexts can't be silently moved between contexts.
pub fn encrypt(key: &SecretKey32, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedBlob> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::KeyDerivation)?;

    Ok(EncryptedBlob {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypts and authenticates `blob` under `key`.
///
/// Returns [`VaultError::AuthenticationFailed`] on *any* failure — wrong
/// key, tampered ciphertext, or mismatched `aad` — so callers can't
/// distinguish "wrong password" from "corrupted file" via the error type.
pub fn decrypt(key: &SecretKey32, blob: &EncryptedBlob, aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(&blob.nonce);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &blob.ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = SecretKey32::random();
        let plaintext = b"top secret entry data";
        let blob = encrypt(&key, plaintext, b"aad-context").unwrap();
        let decrypted = decrypt(&key, &blob, b"aad-context").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = SecretKey32::random();
        let mut blob = encrypt(&key, b"hello vault", b"ctx").unwrap();
        blob.ciphertext[0] ^= 0xFF;
        assert!(matches!(
            decrypt(&key, &blob, b"ctx"),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let key = SecretKey32::random();
        let blob = encrypt(&key, b"hello vault", b"ctx-a").unwrap();
        assert!(matches!(
            decrypt(&key, &blob, b"ctx-b"),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let key = SecretKey32::random();
        let other = SecretKey32::random();
        let blob = encrypt(&key, b"hello vault", b"ctx").unwrap();
        assert!(matches!(
            decrypt(&other, &blob, b"ctx"),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn nonces_are_not_reused() {
        let key = SecretKey32::random();
        let b1 = encrypt(&key, b"same plaintext", b"ctx").unwrap();
        let b2 = encrypt(&key, b"same plaintext", b"ctx").unwrap();
        assert_ne!(b1.nonce, b2.nonce);
        assert_ne!(b1.ciphertext, b2.ciphertext);
    }
}

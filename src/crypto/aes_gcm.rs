//! AES-256-GCM encryption implementation.
//!
//! Provides authenticated encryption using AES-256 in Galois/Counter Mode.

use super::Encryptor;
use crate::config::NONCE_LEN;
use crate::error::{CryptorError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

/// AES-256-GCM encryptor.
///
/// Provides authenticated encryption with associated data (AEAD) using:
/// - 256-bit keys
/// - 96-bit (12-byte) nonces
/// - 128-bit authentication tags
#[derive(Debug, Clone, Copy)]
pub struct AesGcmEncryptor;

impl AesGcmEncryptor {
    /// Creates a new AES-256-GCM encryptor.
    pub fn new() -> Self {
        Self
    }
}

impl Default for AesGcmEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

impl Encryptor for AesGcmEncryptor {
    fn encrypt(&self, key: &[u8; 32], nonce_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if nonce_bytes.len() != NONCE_LEN {
            return Err(CryptorError::Cryptography(format!(
                "Invalid nonce length: expected {}, got {}",
                NONCE_LEN,
                nonce_bytes.len()
            )));
        }

        let cipher = Aes256Gcm::new(key.into());
        let nonce_array: &[u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|_| {
            CryptorError::Cryptography("Invalid nonce length for array conversion".to_string())
        })?;
        let nonce = Nonce::from(*nonce_array);

        cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| CryptorError::Cryptography(e.to_string()))
    }

    fn decrypt(&self, key: &[u8; 32], nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if nonce_bytes.len() != NONCE_LEN {
            return Err(CryptorError::Cryptography(format!(
                "Invalid nonce length: expected {}, got {}",
                NONCE_LEN,
                nonce_bytes.len()
            )));
        }

        let cipher = Aes256Gcm::new(key.into());
        let nonce_array: &[u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|_| {
            CryptorError::Cryptography("Invalid nonce length for array conversion".to_string())
        })?;
        let nonce = Nonce::from(*nonce_array);

        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| CryptorError::Decryption)
    }

    fn nonce_len(&self) -> usize {
        NONCE_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let encryptor = AesGcmEncryptor::new();
        let key = [0u8; 32];
        let nonce = [1u8; 12];
        let plaintext = b"Hello, World!";

        let ciphertext = encryptor.encrypt(&key, &nonce, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);

        let decrypted = encryptor.decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let encryptor = AesGcmEncryptor::new();
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let nonce = [1u8; 12];
        let plaintext = b"Secret message";

        let ciphertext = encryptor.encrypt(&key1, &nonce, plaintext).unwrap();
        let result = encryptor.decrypt(&key2, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_nonce() {
        let encryptor = AesGcmEncryptor::new();
        let key = [0u8; 32];
        let nonce1 = [1u8; 12];
        let nonce2 = [2u8; 12];
        let plaintext = b"Secret message";

        let ciphertext = encryptor.encrypt(&key, &nonce1, plaintext).unwrap();
        let result = encryptor.decrypt(&key, &nonce2, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_nonce_length() {
        let encryptor = AesGcmEncryptor::new();
        let key = [0u8; 32];
        let invalid_nonce = [1u8; 10]; // Wrong length
        let plaintext = b"Test";

        let result = encryptor.encrypt(&key, &invalid_nonce, plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_len() {
        let encryptor = AesGcmEncryptor::new();
        assert_eq!(encryptor.nonce_len(), 12);
    }

    #[test]
    fn test_tampered_ciphertext() {
        let encryptor = AesGcmEncryptor::new();
        let key = [0u8; 32];
        let nonce = [1u8; 12];
        let plaintext = b"Important data";

        let mut ciphertext = encryptor.encrypt(&key, &nonce, plaintext).unwrap();

        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 1;
        }

        let result = encryptor.decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err(), "Tampered ciphertext should fail authentication");
    }
}

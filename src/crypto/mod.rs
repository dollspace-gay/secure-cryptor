//! Cryptographic operations for encryption, decryption, and key derivation.
//!
//! This module provides trait-based abstractions for cryptographic operations,
//! allowing for pluggable implementations of different encryption algorithms.

pub mod aes_gcm;
pub mod kdf;
pub mod pqc;
pub mod signatures;
pub mod streaming;

use crate::error::Result;
use zeroize::Zeroizing;

/// Trait for symmetric encryption and decryption operations.
///
/// Implementors provide authenticated encryption using AEAD algorithms.
pub trait Encryptor: Send + Sync {
    /// Encrypt plaintext with a given key and nonce.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte encryption key
    /// * `nonce` - Nonce (size depends on algorithm)
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    ///
    /// Ciphertext with authentication tag appended.
    fn encrypt(&self, key: &[u8; 32], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext with a given key and nonce.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte encryption key
    /// * `nonce` - Nonce (size depends on algorithm)
    /// * `ciphertext` - Data to decrypt (includes authentication tag)
    ///
    /// # Returns
    ///
    /// Decrypted plaintext if authentication succeeds.
    fn decrypt(&self, key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Returns the required nonce length for this encryptor.
    fn nonce_len(&self) -> usize;
}

/// Trait for password-based key derivation.
///
/// Implementors derive cryptographic keys from passwords using KDFs.
pub trait KeyDerivation: Send + Sync {
    /// Derive a 32-byte key from a password and salt.
    ///
    /// # Arguments
    ///
    /// * `password` - User password
    /// * `salt` - Cryptographic salt
    ///
    /// # Returns
    ///
    /// 32-byte derived key in zeroizing memory.
    fn derive_key(&self, password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>>;

    /// Generate a new random salt.
    fn generate_salt(&self) -> Vec<u8>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test that traits are object-safe
    #[test]
    fn test_encryptor_object_safe() {
        let _: Option<Box<dyn Encryptor>> = None;
    }

    #[test]
    fn test_kdf_object_safe() {
        let _: Option<Box<dyn KeyDerivation>> = None;
    }
}

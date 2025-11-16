//! Key derivation functions for password-based cryptography.
//!
//! Provides Argon2id implementation for deriving encryption keys from passwords.

use super::KeyDerivation;
use crate::config::CryptoConfig;
use crate::error::{CryptorError, Result};
use argon2::{
    password_hash::{rand_core::OsRng as ArgonRng, SaltString},
    Argon2, Params,
};
use zeroize::Zeroizing;

/// Argon2id key derivation function.
///
/// Uses Argon2id (hybrid mode) which provides resistance to both
/// side-channel and GPU/ASIC attacks.
#[derive(Debug, Clone)]
pub struct Argon2Kdf {
    config: CryptoConfig,
}

impl Argon2Kdf {
    /// Creates a new Argon2 KDF with the given configuration.
    pub fn new(config: CryptoConfig) -> Self {
        Self { config }
    }

    /// Creates a new Argon2 KDF with default configuration.
    pub fn default_config() -> Self {
        Self::new(CryptoConfig::default())
    }

    /// Derive a key from password and salt string.
    ///
    /// This is a convenience method that accepts a `SaltString`.
    pub fn derive_key_with_salt_string(
        &self,
        password: &[u8],
        salt: &SaltString,
    ) -> Result<Zeroizing<[u8; 32]>> {
        self.derive_key(password, salt.as_str().as_bytes())
    }
}

impl Default for Argon2Kdf {
    fn default() -> Self {
        Self::default_config()
    }
}

impl KeyDerivation for Argon2Kdf {
    fn derive_key(&self, password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let params = Params::new(
            self.config.argon2_mem_cost_kib,
            self.config.argon2_time_cost,
            self.config.argon2_lanes,
            None,
        )
        .map_err(|e| CryptorError::Argon2(e.to_string()))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password, salt, &mut *key)
            .map_err(|e| CryptorError::Argon2(e.to_string()))?;

        Ok(key)
    }

    fn generate_salt(&self) -> Vec<u8> {
        let salt = SaltString::generate(&mut ArgonRng);
        salt.as_str().as_bytes().to_vec()
    }
}

/// Generate a new random salt as a `SaltString`.
///
/// This is a convenience function for generating salts in the proper format.
pub fn generate_salt_string() -> SaltString {
    SaltString::generate(&mut ArgonRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let kdf = Argon2Kdf::default();
        let password = b"test_password";
        let salt = b"test_salt_123456";

        let key1 = kdf.derive_key(password, salt).unwrap();
        let key2 = kdf.derive_key(password, salt).unwrap();

        assert_eq!(*key1, *key2, "Same password and salt should produce same key");
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let kdf = Argon2Kdf::default();
        let password1 = b"password1";
        let password2 = b"password2";
        let salt = b"test_salt_123456";

        let key1 = kdf.derive_key(password1, salt).unwrap();
        let key2 = kdf.derive_key(password2, salt).unwrap();

        assert_ne!(*key1, *key2, "Different passwords should produce different keys");
    }

    #[test]
    fn test_different_salts_different_keys() {
        let kdf = Argon2Kdf::default();
        let password = b"test_password";
        let salt1 = b"salt1___________";
        let salt2 = b"salt2___________";

        let key1 = kdf.derive_key(password, salt1).unwrap();
        let key2 = kdf.derive_key(password, salt2).unwrap();

        assert_ne!(*key1, *key2, "Different salts should produce different keys");
    }

    #[test]
    fn test_generate_salt() {
        let kdf = Argon2Kdf::default();
        let salt1 = kdf.generate_salt();
        let salt2 = kdf.generate_salt();

        assert!(!salt1.is_empty());
        assert!(!salt2.is_empty());
        assert_ne!(salt1, salt2, "Generated salts should be unique");
    }

    #[test]
    fn test_custom_config() {
        let config = CryptoConfig::fast();
        let kdf = Argon2Kdf::new(config);
        let password = b"test_password";
        let salt = b"test_salt_123456";

        let key = kdf.derive_key(password, salt);
        assert!(key.is_ok(), "Fast config should still work");
    }

    #[test]
    fn test_key_length() {
        let kdf = Argon2Kdf::default();
        let password = b"test_password";
        let salt = b"test_salt_123456";

        let key = kdf.derive_key(password, salt).unwrap();
        assert_eq!(key.len(), 32, "Derived key should be 32 bytes");
    }

    #[test]
    fn test_generate_salt_string() {
        let salt1 = generate_salt_string();
        let salt2 = generate_salt_string();

        assert_ne!(salt1.as_str(), salt2.as_str(), "Generated salt strings should be unique");
    }
}

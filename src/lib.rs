//! Tesseract - A secure file encryption library
//!
//! This library provides secure file encryption and decryption using
//! AES-256-GCM with Argon2id key derivation.
//!
//! # Features
//!
//! - **Strong encryption**: AES-256-GCM (authenticated encryption)
//! - **Memory-hard KDF**: Argon2id key derivation
//! - **Password validation**: Enforces strong password requirements
//! - **Atomic operations**: Prevents partial file writes
//! - **Memory safety**: Zeroizes sensitive data
//! - **Timing-attack resistance**: Constant-time password comparison
//!
//! # Example
//!
//! ```no_run
//! use tesseract_lib::{encrypt_file, decrypt_file};
//! use std::path::Path;
//!
//! // Encrypt a file
//! encrypt_file(Path::new("secret.txt"), Path::new("secret.enc"), "MyStr0ng!Pass").unwrap();
//!
//! // Decrypt a file
//! decrypt_file(Path::new("secret.enc"), Path::new("secret.txt"), "MyStr0ng!Pass").unwrap();
//! ```

pub mod config;
pub mod crypto;
pub mod daemon;
pub mod error;
pub mod memory;
pub mod power;
pub mod progress;
pub mod storage;
pub mod validation;
pub mod volume;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(not(target_arch = "wasm32"))]
pub mod hsm;

// Re-export commonly used types
pub use config::{CryptoConfig, MAGIC_BYTES, NONCE_LEN};
pub use crypto::aes_gcm::AesGcmEncryptor;
pub use crypto::kdf::{Argon2Kdf, generate_salt_string};
pub use crypto::streaming::{
    ChunkedDecryptor, ChunkedEncryptor, ChunkedReader, StreamConfig, StreamHeader, MAGIC_BYTES_V3,
};
pub use crypto::{Encryptor, KeyDerivation};
pub use error::{CryptorError, Result};
pub use memory::allocator::{SecureAllocator, AllocatorStats};
pub use memory::pool::{EncryptedAllocation, EncryptedMemoryPool, SecurityLevel};
pub use memory::scrub::{scrub_bytes, scrub_bytes_pattern, scrub_and_verify, ScrubPattern, ScrubStats, ScrubGuard};
pub use memory::LockedMemory;
pub use progress::{format_bytes, format_duration, ProgressCallback, ProgressReporter, ProgressTracker};
#[cfg(not(target_arch = "wasm32"))]
pub use validation::{get_and_validate_password, get_password};
pub use validation::validate_password;

use rand::rngs::OsRng;
use rand_core::TryRngCore;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Encrypts a file with a password using streaming (chunked) encryption.
///
/// This is the high-level API for file encryption. It:
/// 1. Opens the input file for streaming
/// 2. Derives a key from the password using Argon2id
/// 3. Encrypts the data in chunks using AES-256-GCM (memory-efficient)
/// 4. Writes the encrypted file atomically
///
/// Uses the V3 file format with chunked encryption and NIST-compliant nonce
/// construction, which allows encrypting files of any size without loading
/// the entire file into memory.
///
/// # Arguments
///
/// * `input_path` - Path to the file to encrypt
/// * `output_path` - Path where the encrypted file will be written
/// * `password` - Password for encryption
///
/// # Errors
///
/// Returns an error if:
/// - Input file cannot be read
/// - Password is invalid (for validation, use `encrypt_file_validated`)
/// - Encryption fails
/// - Output file cannot be written
///
/// # Examples
///
/// ```no_run
/// # use tesseract_lib::encrypt_file;
/// # use std::path::Path;
/// encrypt_file(
///     Path::new("document.pdf"),
///     Path::new("document.pdf.enc"),
///     "MyStrongPassword123!"
/// ).unwrap();
/// ```
pub fn encrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    // Derive encryption key from password
    let salt = generate_salt_string();
    let kdf = Argon2Kdf::default();
    let key = kdf.derive_key_with_salt_string(password.as_bytes(), &salt)?;

    // Generate base nonce for chunk nonce derivation
    let mut base_nonce = [0u8; NONCE_LEN];
    OsRng.try_fill_bytes(&mut base_nonce)
        .map_err(|e| CryptorError::Cryptography(format!("RNG error: {}", e)))?;

    // Open input file for chunked reading
    let config = StreamConfig::default();
    let reader = ChunkedReader::open(input_path, config)?;

    // Create chunked encryptor
    let encryptor = Box::new(AesGcmEncryptor::new());
    let salt_string = salt.as_str().to_string();
    let key_clone = key.clone();
    let chunked_encryptor = ChunkedEncryptor::new(reader, encryptor, key, base_nonce, salt_string)
        .with_pqc_enabled(&key_clone)?; // Enable post-quantum hybrid encryption

    // Encrypt to output file atomically
    storage::write_atomically(output_path, |file| {
        chunked_encryptor
            .encrypt_to(file)
            .map_err(|e| std::io::Error::other(e.to_string()))
    })?;

    Ok(())
}

/// Encrypts a file with password validation.
///
/// Same as `encrypt_file` but validates password strength first.
///
/// # Arguments
///
/// * `input_path` - Path to the file to encrypt
/// * `output_path` - Path where the encrypted file will be written
/// * `password` - Password for encryption (will be validated)
///
/// # Errors
///
/// Returns an error if:
/// - Password fails validation
/// - Any error from `encrypt_file`
pub fn encrypt_file_validated(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    validation::validate_password(password)?;
    encrypt_file(input_path, output_path, password)
}

/// Decrypts a file with a password.
///
/// This is the high-level API for file decryption. It:
/// 1. Detects the file format (v1 or v3)
/// 2. Reads and parses the encrypted file header
/// 3. Derives the key from the password
/// 4. Decrypts and authenticates the data (streaming for v3, in-memory for v1)
/// 5. Writes the plaintext atomically
///
/// Supports both v1 (legacy, in-memory) and v3 (streaming, memory-efficient) formats.
///
/// # Arguments
///
/// * `input_path` - Path to the encrypted file
/// * `output_path` - Path where the decrypted file will be written
/// * `password` - Password for decryption
///
/// # Errors
///
/// Returns an error if:
/// - Input file cannot be read or has invalid format
/// - Password is incorrect
/// - Decryption or authentication fails
/// - Output file cannot be written
///
/// # Examples
///
/// ```no_run
/// # use tesseract_lib::decrypt_file;
/// # use std::path::Path;
/// decrypt_file(
///     Path::new("document.pdf.enc"),
///     Path::new("document.pdf"),
///     "MyStrongPassword123!"
/// ).unwrap();
/// ```
pub fn decrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    use crate::config::MAGIC_BYTES;

    let mut file = File::open(input_path)?;

    // Read magic bytes to detect format version
    let mut magic_buf = [0u8; 8];
    file.read_exact(&mut magic_buf)?;

    // Check which format version
    if magic_buf == MAGIC_BYTES_V3 {
        // V3 format: Use streaming decryption with NIST-compliant nonces
        decrypt_file_v3(input_path, output_path, password)
    } else if magic_buf == MAGIC_BYTES {
        // V1 format: Use legacy in-memory decryption
        // Reset file to beginning for v1 parsing
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(0))?;
        decrypt_file_v1(file, output_path, password)
    } else {
        Err(CryptorError::InvalidFormat)
    }
}

/// Decrypts a v1 format file (legacy, in-memory).
fn decrypt_file_v1(mut file: File, output_path: &Path, password: &str) -> Result<()> {
    let header = storage::format::read_encrypted_header(&mut file)?;

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;

    let kdf = Argon2Kdf::default();
    let key = kdf.derive_key_with_salt_string(password.as_bytes(), &header.salt)?;

    let encryptor = AesGcmEncryptor::new();
    let plaintext = encryptor.decrypt(&key, &header.nonce, &ciphertext)?;

    storage::write_file_atomic(output_path, &plaintext)?;

    Ok(())
}

/// Decrypts a v3 format file (streaming, memory-efficient, NIST-compliant).
fn decrypt_file_v3(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    // First, read just the header to get the salt for key derivation
    let mut file = File::open(input_path)?;
    let header = StreamHeader::read_from(&mut file)?;

    // Derive key from password using salt from header
    let kdf = Argon2Kdf::default();
    let salt = argon2::password_hash::SaltString::from_b64(&header.salt)
        .map_err(|e| CryptorError::PasswordHash(e.to_string()))?;
    let key = kdf.derive_key_with_salt_string(password.as_bytes(), &salt)?;

    // Reopen file for full decryption with correct key
    let file = File::open(input_path)?;
    let encryptor = Box::new(AesGcmEncryptor::new());
    let mut chunked_decryptor = ChunkedDecryptor::new(file, encryptor, key)?;

    // Decrypt to output file atomically
    storage::write_atomically(output_path, |output_file| {
        chunked_decryptor
            .decrypt_to(output_file)
            .map_err(|e| std::io::Error::other(e.to_string()))
    })?;

    Ok(())
}

/// Encrypts data in memory (without file I/O).
///
/// Useful for encrypting data that's already in memory.
///
/// # Returns
///
/// A tuple of `(salt, nonce, ciphertext)` needed for decryption.
pub fn encrypt_bytes(plaintext: &[u8], password: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let salt = generate_salt_string();
    let kdf = Argon2Kdf::default();
    let key = kdf.derive_key_with_salt_string(password.as_bytes(), &salt)?;

    let encryptor = AesGcmEncryptor::new();
    let mut nonce = vec![0u8; encryptor.nonce_len()];
    OsRng.try_fill_bytes(&mut nonce)
        .map_err(|e| CryptorError::Cryptography(format!("RNG error: {}", e)))?;

    let ciphertext = encryptor.encrypt(&key, &nonce, plaintext)?;

    Ok((salt.as_str().as_bytes().to_vec(), nonce, ciphertext))
}

/// Decrypts data in memory (without file I/O).
///
/// # Arguments
///
/// * `salt` - Salt bytes (from encryption)
/// * `nonce` - Nonce bytes (from encryption)
/// * `ciphertext` - Encrypted data
/// * `password` - Password for decryption
pub fn decrypt_bytes(
    salt: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    let salt_str = std::str::from_utf8(salt).map_err(|_| CryptorError::InvalidFormat)?;
    let salt_string = argon2::password_hash::SaltString::from_b64(salt_str)
        .map_err(|e| CryptorError::PasswordHash(e.to_string()))?;

    let kdf = Argon2Kdf::default();
    let key = kdf.derive_key_with_salt_string(password.as_bytes(), &salt_string)?;

    let encryptor = AesGcmEncryptor::new();
    encryptor.decrypt(&key, nonce, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_file_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("input.txt");
        let encrypted_path = temp_dir.path().join("encrypted.bin");
        let output_path = temp_dir.path().join("output.txt");

        let test_data = b"This is a secret message!";
        std::fs::write(&input_path, test_data).unwrap();

        let password = "TestPassword123!";

        encrypt_file(&input_path, &encrypted_path, password).unwrap();
        decrypt_file(&encrypted_path, &output_path, password).unwrap();

        let decrypted_data = std::fs::read(&output_path).unwrap();
        assert_eq!(decrypted_data, test_data);
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("input.txt");
        let encrypted_path = temp_dir.path().join("encrypted.bin");
        let output_path = temp_dir.path().join("output.txt");

        let test_data = b"Secret";
        std::fs::write(&input_path, test_data).unwrap();

        encrypt_file(&input_path, &encrypted_path, "CorrectPass123!").unwrap();
        let result = decrypt_file(&encrypted_path, &output_path, "WrongPass123!");

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_bytes_decrypt_bytes() {
        let plaintext = b"Memory encryption test";
        let password = "TestPassword123!";

        let (salt, nonce, ciphertext) = encrypt_bytes(plaintext, password).unwrap();
        let decrypted = decrypt_bytes(&salt, &nonce, &ciphertext, password).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_file_validated() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("input.txt");
        let encrypted_path = temp_dir.path().join("encrypted.bin");

        std::fs::write(&input_path, b"test data").unwrap();

        // Weak password should fail
        let result = encrypt_file_validated(&input_path, &encrypted_path, "weak");
        assert!(result.is_err());

        // Strong password should succeed
        let result = encrypt_file_validated(&input_path, &encrypted_path, "StrongPass123!");
        assert!(result.is_ok());
    }
}

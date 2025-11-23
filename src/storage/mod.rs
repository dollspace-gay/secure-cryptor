//! File I/O and storage operations.
//!
//! This module provides functionality for safely reading and writing files,
//! including atomic file operations to prevent corruption.

use crate::error::{CryptorError, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
#[cfg(not(target_arch = "wasm32"))]
use tempfile::Builder;

// WASM stub implementations (file operations not supported in browsers)
#[cfg(target_arch = "wasm32")]
pub fn write_file_atomic(_path: &Path, _data: &[u8]) -> Result<()> {
    Err(CryptorError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "File operations are not supported in WebAssembly"
    )))
}

#[cfg(target_arch = "wasm32")]
pub fn write_atomically<F>(_path: &Path, _write_fn: F) -> Result<()>
where
    F: FnOnce(&mut File) -> std::result::Result<(), std::io::Error>,
{
    Err(CryptorError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "File operations are not supported in WebAssembly"
    )))
}

/// Reads the entire contents of a file into a vector.
///
/// # Arguments
///
/// * `path` - Path to the file to read
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read.
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;
    Ok(data)
}

/// Writes data to a file atomically using a temporary file.
///
/// This ensures that the output file is either completely written or not
/// modified at all, preventing partial writes from corrupting data.
///
/// # Arguments
///
/// * `path` - Path where the file should be written
/// * `data` - Data to write to the file
///
/// # Errors
///
/// Returns an error if:
/// - The output path is invalid
/// - The temporary file cannot be created
/// - Writing fails
/// - The temporary file cannot be persisted
///
/// # Examples
///
/// ```no_run
/// # use tesseract::storage::write_file_atomic;
/// # use std::path::Path;
/// let data = b"important data";
/// write_file_atomic(Path::new("output.txt"), data).unwrap();
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub fn write_file_atomic(path: &Path, data: &[u8]) -> Result<()> {
    write_atomically(path, |file| file.write_all(data))
}

/// Performs an atomic file write operation using a closure.
///
/// Creates a temporary file in the same directory as the target,
/// calls the provided function to write data, and then atomically
/// renames the temporary file to the target path.
///
/// # Arguments
///
/// * `path` - Target file path
/// * `write_fn` - Function that writes data to the file
///
/// # Errors
///
/// Returns an error if any step of the operation fails.
#[cfg(not(target_arch = "wasm32"))]
pub fn write_atomically<F>(path: &Path, write_fn: F) -> Result<()>
where
    F: FnOnce(&mut File) -> std::result::Result<(), std::io::Error>,
{
    let output_dir = path.parent().ok_or(CryptorError::InvalidOutputPath)?;

    let mut temp_file = Builder::new()
        .prefix("secure-cryptor")
        .suffix(".tmp")
        .tempfile_in(output_dir)?;

    write_fn(temp_file.as_file_mut())?;

    temp_file.persist(path)?;
    Ok(())
}

/// File format for encrypted files.
pub mod format {
    use crate::config::{MAGIC_BYTES, MAX_SALT_LEN, NONCE_LEN};
    use crate::error::{CryptorError, Result};
    use argon2::password_hash::SaltString;
    use std::fs::File;
    use std::io::{Read, Write};

    /// Write encrypted file header and ciphertext.
    ///
    /// Format:
    /// - Magic bytes (8 bytes): "SCRYPTv1"
    /// - Salt length (1 byte): Length of salt string
    /// - Salt (variable): Base64-encoded salt
    /// - Nonce (12 bytes): Encryption nonce
    /// - Ciphertext (variable): Encrypted data with auth tag
    pub fn write_encrypted_file(
        file: &mut File,
        salt: &SaltString,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<()> {
        let salt_str = salt.as_str();
        let salt_len = salt_str.len() as u8;

        file.write_all(MAGIC_BYTES)?;
        file.write_all(&[salt_len])?;
        file.write_all(salt_str.as_bytes())?;
        file.write_all(nonce)?;
        file.write_all(ciphertext)?;
        Ok(())
    }

    /// Encrypted file header information.
    #[derive(Debug, Clone)]
    pub struct EncryptedHeader {
        /// Salt string for key derivation.
        pub salt: SaltString,
        /// Nonce used for encryption.
        pub nonce: Vec<u8>,
    }

    /// Read and validate encrypted file header.
    ///
    /// Returns the header information and leaves the file positioned
    /// at the start of the ciphertext.
    pub fn read_encrypted_header(file: &mut File) -> Result<EncryptedHeader> {
        // Verify magic bytes
        let mut magic_buf = [0u8; MAGIC_BYTES.len()];
        file.read_exact(&mut magic_buf)?;
        if magic_buf != MAGIC_BYTES {
            return Err(CryptorError::InvalidFormat);
        }

        // Read salt length
        let mut salt_len_byte = [0u8; 1];
        file.read_exact(&mut salt_len_byte)?;
        let salt_len = salt_len_byte[0] as usize;

        if salt_len > MAX_SALT_LEN {
            return Err(CryptorError::InvalidFormat);
        }

        // Read salt
        let mut salt_bytes = vec![0u8; salt_len];
        file.read_exact(&mut salt_bytes)?;
        let salt_str =
            std::str::from_utf8(&salt_bytes).map_err(|_| CryptorError::InvalidFormat)?;
        let salt =
            SaltString::from_b64(salt_str).map_err(|e| CryptorError::PasswordHash(e.to_string()))?;

        // Read nonce
        let mut nonce = vec![0u8; NONCE_LEN];
        file.read_exact(&mut nonce)?;

        Ok(EncryptedHeader { salt, nonce })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = b"test data";
        temp_file.write_all(test_data).unwrap();
        temp_file.flush().unwrap();

        let data = read_file(temp_file.path()).unwrap();
        assert_eq!(data, test_data);
    }

    #[test]
    fn test_write_file_atomic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path().join("test_file.txt");
        let test_data = b"atomic write test";

        write_file_atomic(&temp_path, test_data).unwrap();

        let data = read_file(&temp_path).unwrap();
        assert_eq!(data, test_data);
    }

    #[test]
    fn test_write_atomically_custom() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path().join("test_file.txt");

        write_atomically(&temp_path, |file| {
            file.write_all(b"line 1\n")?;
            file.write_all(b"line 2\n")?;
            Ok(())
        })
        .unwrap();

        let data = read_file(&temp_path).unwrap();
        assert_eq!(data, b"line 1\nline 2\n");
    }
}

/// Sector-based encryption using XTS-AES-256
///
/// This module implements XTS-AES-256 (IEEE P1619) for transparent disk encryption.
/// XTS mode is specifically designed for storage encryption and provides better
/// security properties than other modes for fixed-size sectors.
///
/// ## Key Features
///
/// - **XTS-AES-256**: Industry standard for disk encryption (used by BitLocker, FileVault, dm-crypt)
/// - **Fixed Sector Size**: Typically 512 or 4096 bytes
/// - **Sector Addressing**: Each sector encrypted with its index for diffusion
/// - **No Expansion**: Ciphertext is same size as plaintext (no authentication tag)
/// - **Random Access**: Can encrypt/decrypt individual sectors independently
///
/// ## Security Properties
///
/// - **Tweakable**: Each sector uses a unique tweak (sector index)
/// - **No Patterns**: Identical plaintext sectors at different positions produce different ciphertext
/// - **Performance**: Fast encryption/decryption with hardware AES acceleration
///
/// ## Note on Authentication
///
/// XTS-AES does NOT provide authentication (unlike GCM). This is by design for
/// disk encryption where sector sizes must be fixed. Authentication can be
/// added at a higher layer if needed (e.g., in the filesystem).

use aes::Aes256;
use aes::cipher::{KeyInit, generic_array::GenericArray};
use thiserror::Error;
use xts_mode::{get_tweak_default, Xts128};
use zeroize::Zeroizing;

use super::keyslot::MasterKey;

/// Common sector sizes
pub const SECTOR_SIZE_512: usize = 512;
pub const SECTOR_SIZE_4K: usize = 4096;

/// Errors that can occur during sector encryption/decryption
#[derive(Debug, Error)]
pub enum SectorError {
    /// Invalid sector size
    #[error("Invalid sector size: {0} (must be multiple of 16 bytes)")]
    InvalidSectorSize(usize),

    /// Data size doesn't match sector size
    #[error("Data size ({actual}) doesn't match sector size ({expected})")]
    SizeMismatch { expected: usize, actual: usize },

    /// Invalid key size
    #[error("Invalid key size: expected 64 bytes for XTS-AES-256")]
    InvalidKeySize,

    /// Sector index out of range
    #[error("Sector index out of range: {0}")]
    IndexOutOfRange(u64),
}

pub type Result<T> = std::result::Result<T, SectorError>;

/// Sector-based encryption engine using XTS-AES-256
pub struct SectorCipher {
    /// XTS cipher instance (uses two AES-256 keys internally)
    cipher: Xts128<Aes256>,

    /// Sector size in bytes (must be multiple of 16)
    sector_size: usize,
}

impl SectorCipher {
    /// Creates a new sector cipher from a master key
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master encryption key (32 bytes)
    /// * `sector_size` - Size of each sector in bytes (must be multiple of 16)
    ///
    /// # Returns
    ///
    /// A new `SectorCipher` instance
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The sector size is not a multiple of 16 bytes
    /// - The key derivation fails
    ///
    /// # Security Note
    ///
    /// XTS-AES requires two 256-bit keys (64 bytes total). We derive these from
    /// the master key using HKDF to ensure proper key separation.
    pub fn new(master_key: &MasterKey, sector_size: usize) -> Result<Self> {
        // Validate sector size (must be multiple of AES block size)
        if sector_size % 16 != 0 {
            return Err(SectorError::InvalidSectorSize(sector_size));
        }

        // XTS-AES requires two keys: one for encryption, one for tweak
        // We derive 64 bytes (512 bits) from the master key
        let xts_key = Self::derive_xts_key(master_key)?;

        // Create XTS cipher
        let key1 = Aes256::new(GenericArray::from_slice(&xts_key[0..32]));
        let key2 = Aes256::new(GenericArray::from_slice(&xts_key[32..64]));

        let cipher = Xts128::<Aes256>::new(key1, key2);

        Ok(Self {
            cipher,
            sector_size,
        })
    }

    /// Derives a 64-byte XTS key from the master key using HKDF
    fn derive_xts_key(master_key: &MasterKey) -> Result<Zeroizing<[u8; 64]>> {
        use crate::crypto::kdf::Argon2Kdf;
        use crate::crypto::KeyDerivation;
        use crate::config::CryptoConfig;

        // Use a fixed salt for XTS key derivation
        // This is safe because the master key is already randomly generated
        let salt = b"secure-cryptor-xts-v1-2025-salt-";

        let kdf = Argon2Kdf::new(CryptoConfig::default());
        let derived = kdf.derive_key(master_key.as_bytes(), salt)
            .map_err(|_| SectorError::InvalidKeySize)?;

        // Extend to 64 bytes using a second derivation if needed
        let mut xts_key = Zeroizing::new([0u8; 64]);

        // First 32 bytes
        xts_key[0..32].copy_from_slice(&derived[..]);

        // Second 32 bytes (derived with different salt)
        let salt2 = b"secure-cryptor-xts-v1-2025-slt2-";
        let derived2 = kdf.derive_key(master_key.as_bytes(), salt2)
            .map_err(|_| SectorError::InvalidKeySize)?;
        xts_key[32..64].copy_from_slice(&derived2[..]);

        Ok(xts_key)
    }

    /// Encrypts a single sector
    ///
    /// # Arguments
    ///
    /// * `sector_index` - The sector index (used as tweak for diffusion)
    /// * `plaintext` - The plaintext data (must be exactly `sector_size` bytes)
    ///
    /// # Returns
    ///
    /// Encrypted sector data (same size as input)
    ///
    /// # Errors
    ///
    /// Returns an error if the data size doesn't match the sector size
    pub fn encrypt_sector(&self, sector_index: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() != self.sector_size {
            return Err(SectorError::SizeMismatch {
                expected: self.sector_size,
                actual: plaintext.len(),
            });
        }

        // Clone plaintext to mutable buffer for in-place encryption
        let mut buffer = plaintext.to_vec();

        // Encrypt in place with tweak function
        self.cipher.encrypt_area(
            &mut buffer,
            self.sector_size,
            0, // offset within the buffer
            |_| get_tweak_default(sector_index as u128),
        );

        Ok(buffer)
    }

    /// Decrypts a single sector
    ///
    /// # Arguments
    ///
    /// * `sector_index` - The sector index (must match encryption index)
    /// * `ciphertext` - The encrypted data (must be exactly `sector_size` bytes)
    ///
    /// # Returns
    ///
    /// Decrypted sector data (same size as input)
    ///
    /// # Errors
    ///
    /// Returns an error if the data size doesn't match the sector size
    pub fn decrypt_sector(&self, sector_index: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() != self.sector_size {
            return Err(SectorError::SizeMismatch {
                expected: self.sector_size,
                actual: ciphertext.len(),
            });
        }

        // Clone ciphertext to mutable buffer for in-place decryption
        let mut buffer = ciphertext.to_vec();

        // Decrypt in place with tweak function
        self.cipher.decrypt_area(
            &mut buffer,
            self.sector_size,
            0, // offset within the buffer
            |_| get_tweak_default(sector_index as u128),
        );

        Ok(buffer)
    }

    /// Encrypts multiple contiguous sectors
    ///
    /// # Arguments
    ///
    /// * `start_sector` - Index of the first sector
    /// * `data` - Data to encrypt (size must be multiple of sector_size)
    ///
    /// # Returns
    ///
    /// Encrypted data (same size as input)
    ///
    /// # Errors
    ///
    /// Returns an error if data size is not a multiple of sector_size
    pub fn encrypt_sectors(&self, start_sector: u64, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() % self.sector_size != 0 {
            return Err(SectorError::SizeMismatch {
                expected: self.sector_size,
                actual: data.len(),
            });
        }

        let mut result = Vec::with_capacity(data.len());
        let sector_count = data.len() / self.sector_size;

        for i in 0..sector_count {
            let start = i * self.sector_size;
            let end = start + self.sector_size;
            let sector_data = &data[start..end];
            let encrypted = self.encrypt_sector(start_sector + i as u64, sector_data)?;
            result.extend_from_slice(&encrypted);
        }

        Ok(result)
    }

    /// Decrypts multiple contiguous sectors
    ///
    /// # Arguments
    ///
    /// * `start_sector` - Index of the first sector
    /// * `data` - Data to decrypt (size must be multiple of sector_size)
    ///
    /// # Returns
    ///
    /// Decrypted data (same size as input)
    ///
    /// # Errors
    ///
    /// Returns an error if data size is not a multiple of sector_size
    pub fn decrypt_sectors(&self, start_sector: u64, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() % self.sector_size != 0 {
            return Err(SectorError::SizeMismatch {
                expected: self.sector_size,
                actual: data.len(),
            });
        }

        let mut result = Vec::with_capacity(data.len());
        let sector_count = data.len() / self.sector_size;

        for i in 0..sector_count {
            let start = i * self.sector_size;
            let end = start + self.sector_size;
            let sector_data = &data[start..end];
            let decrypted = self.decrypt_sector(start_sector + i as u64, sector_data)?;
            result.extend_from_slice(&decrypted);
        }

        Ok(result)
    }

    /// Returns the sector size
    pub fn sector_size(&self) -> usize {
        self.sector_size
    }
}

impl Drop for SectorCipher {
    fn drop(&mut self) {
        // Zeroize is handled by the Xts128 type
        // Additional cleanup if needed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sector_cipher_creation() {
        let master_key = MasterKey::generate();
        let cipher = SectorCipher::new(&master_key, SECTOR_SIZE_4K).unwrap();
        assert_eq!(cipher.sector_size(), SECTOR_SIZE_4K);
    }

    #[test]
    fn test_invalid_sector_size() {
        let master_key = MasterKey::generate();
        // Try to create cipher with non-16-byte-aligned sector size
        let result = SectorCipher::new(&master_key, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_sector() {
        let master_key = MasterKey::generate();
        let cipher = SectorCipher::new(&master_key, SECTOR_SIZE_512).unwrap();

        let plaintext = vec![0x42u8; SECTOR_SIZE_512];
        let sector_index = 100;

        // Encrypt
        let ciphertext = cipher.encrypt_sector(sector_index, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), SECTOR_SIZE_512);
        assert_ne!(ciphertext, plaintext); // Should be different

        // Decrypt
        let decrypted = cipher.decrypt_sector(sector_index, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_sectors_different_ciphertext() {
        let master_key = MasterKey::generate();
        let cipher = SectorCipher::new(&master_key, SECTOR_SIZE_512).unwrap();

        let plaintext = vec![0x42u8; SECTOR_SIZE_512];

        // Encrypt same plaintext at different sector indices
        let ct1 = cipher.encrypt_sector(0, &plaintext).unwrap();
        let ct2 = cipher.encrypt_sector(1, &plaintext).unwrap();
        let ct3 = cipher.encrypt_sector(100, &plaintext).unwrap();

        // All ciphertexts should be different
        assert_ne!(ct1, ct2);
        assert_ne!(ct1, ct3);
        assert_ne!(ct2, ct3);

        // But all should decrypt to same plaintext
        assert_eq!(cipher.decrypt_sector(0, &ct1).unwrap(), plaintext);
        assert_eq!(cipher.decrypt_sector(1, &ct2).unwrap(), plaintext);
        assert_eq!(cipher.decrypt_sector(100, &ct3).unwrap(), plaintext);
    }

    #[test]
    fn test_wrong_sector_index() {
        let master_key = MasterKey::generate();
        let cipher = SectorCipher::new(&master_key, SECTOR_SIZE_512).unwrap();

        let plaintext = vec![0x42u8; SECTOR_SIZE_512];

        // Encrypt at sector 10
        let ciphertext = cipher.encrypt_sector(10, &plaintext).unwrap();

        // Decrypt at wrong sector index
        let wrong_decrypted = cipher.decrypt_sector(11, &ciphertext).unwrap();

        // Should NOT match original plaintext
        assert_ne!(wrong_decrypted, plaintext);
    }

    #[test]
    fn test_size_mismatch() {
        let master_key = MasterKey::generate();
        let cipher = SectorCipher::new(&master_key, SECTOR_SIZE_512).unwrap();

        // Try to encrypt data that's not sector-sized
        let wrong_size = vec![0x42u8; 256];
        let result = cipher.encrypt_sector(0, &wrong_size);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_multiple_sectors() {
        let master_key = MasterKey::generate();
        let cipher = SectorCipher::new(&master_key, SECTOR_SIZE_4K).unwrap();

        // Create 4 sectors of data (16 KB)
        let mut plaintext = Vec::new();
        for i in 0..4 {
            plaintext.extend(vec![i as u8; SECTOR_SIZE_4K]);
        }

        let start_sector = 50;

        // Encrypt
        let ciphertext = cipher.encrypt_sectors(start_sector, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len());

        // Decrypt
        let decrypted = cipher.decrypt_sectors(start_sector, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_4k_sectors() {
        let master_key = MasterKey::generate();
        let cipher = SectorCipher::new(&master_key, SECTOR_SIZE_4K).unwrap();

        let plaintext = vec![0xAAu8; SECTOR_SIZE_4K];
        let ciphertext = cipher.encrypt_sector(0, &plaintext).unwrap();
        let decrypted = cipher.decrypt_sector(0, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_deterministic_encryption() {
        let master_key = MasterKey::generate();
        let cipher = SectorCipher::new(&master_key, SECTOR_SIZE_512).unwrap();

        let plaintext = vec![0x42u8; SECTOR_SIZE_512];
        let sector_index = 42;

        // Encrypt same data twice
        let ct1 = cipher.encrypt_sector(sector_index, &plaintext).unwrap();
        let ct2 = cipher.encrypt_sector(sector_index, &plaintext).unwrap();

        // Should produce identical ciphertext (deterministic for same index)
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_different_keys() {
        let key1 = MasterKey::generate();
        let key2 = MasterKey::generate();

        let cipher1 = SectorCipher::new(&key1, SECTOR_SIZE_512).unwrap();
        let cipher2 = SectorCipher::new(&key2, SECTOR_SIZE_512).unwrap();

        let plaintext = vec![0x42u8; SECTOR_SIZE_512];
        let sector_index = 0;

        let ct1 = cipher1.encrypt_sector(sector_index, &plaintext).unwrap();
        let ct2 = cipher2.encrypt_sector(sector_index, &plaintext).unwrap();

        // Different keys should produce different ciphertext
        assert_ne!(ct1, ct2);

        // Each key should decrypt its own ciphertext
        assert_eq!(cipher1.decrypt_sector(sector_index, &ct1).unwrap(), plaintext);
        assert_eq!(cipher2.decrypt_sector(sector_index, &ct2).unwrap(), plaintext);

        // But not the other's ciphertext
        assert_ne!(cipher1.decrypt_sector(sector_index, &ct2).unwrap(), plaintext);
        assert_ne!(cipher2.decrypt_sector(sector_index, &ct1).unwrap(), plaintext);
    }
}

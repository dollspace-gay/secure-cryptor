//! Encrypted container format
//!
//! This module defines the on-disk format for encrypted containers.
//!
//! ## Container Layout (V2)
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │ Offset: 0x0000 (0 KB)                                    │
//! │ Primary Volume Header (4 KB)                             │
//! │ - Magic bytes: SECVOL01                                  │
//! │ - Version: 2 (with post-quantum support)                 │
//! │ - Cipher algorithm (AES-256-GCM)                         │
//! │ - Volume size, sector size                               │
//! │ - Timestamps, PQ metadata reference                      │
//! │ - BLAKE3 checksum for integrity verification             │
//! └──────────────────────────────────────────────────────────┘
//! ┌──────────────────────────────────────────────────────────┐
//! │ Offset: 0x1000 (4 KB)                                    │
//! │ PQ Metadata (variable size, ~1KB typical)                │
//! │ - ML-KEM-1024 encapsulation key                          │
//! │ - Ciphertext and encrypted decapsulation key             │
//! │ - Provides post-quantum resistance                       │
//! └──────────────────────────────────────────────────────────┘
//! ┌──────────────────────────────────────────────────────────┐
//! │ Offset: 0x2000 (8 KB)                                    │
//! │ Key Slots (8 KB - 8 slots × 1KB each)                    │
//! │ - Up to 8 independent passwords                          │
//! │ - Each slot: active flag, salt, nonce, encrypted MK      │
//! │ - Supports multi-user access                             │
//! └──────────────────────────────────────────────────────────┘
//! ┌──────────────────────────────────────────────────────────┐
//! │ Offset: 0x4000 (16 KB)                                   │
//! │ Encrypted Data Area (user-specified size)                │
//! │ - Encrypted filesystem/application data                  │
//! │ - Each sector encrypted with AES-256-GCM                 │
//! │ - Sector size from header (typically 4096 bytes)         │
//! │ - Hybrid encryption: ML-KEM-1024 + AES-256-GCM           │
//! └──────────────────────────────────────────────────────────┘
//! ┌──────────────────────────────────────────────────────────┐
//! │ Offset: volume_size - HEADER_SIZE                        │
//! │ Backup Volume Header (4 KB)                              │
//! │ - Duplicate of primary header for corruption recovery    │
//! │ - Located at end of file (LUKS/VeraCrypt style)          │
//! │ - Verified on volume open, used for recovery if needed   │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! Total metadata size: 16 KB front + 4 KB backup header at end
//!
//! ## Security Features
//!
//! - **Master Key Protection**: The volume's master key is encrypted separately
//!   in each active key slot using a user-derived key (Argon2id KDF)
//! - **Multi-User Support**: Up to 8 different passwords can unlock the same volume
//! - **Authenticated Encryption**: AES-256-GCM provides both confidentiality and integrity
//! - **Key Derivation**: Argon2id with high memory/time parameters prevents brute-force
//! - **Secure Deletion**: Master keys are zeroized in memory on drop

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

use super::header::{VolumeHeader, PqVolumeMetadata, HEADER_SIZE};
use super::keyslot::{KeySlots, MasterKey};
use crate::crypto::pqc::{MlKemKeyPair, encapsulate};
use crate::crypto::streaming::{derive_hybrid_key};
use crate::crypto::kdf::Argon2Kdf;
use crate::crypto::{KeyDerivation, Encryptor};
use crate::crypto::aes_gcm::AesGcmEncryptor;
use crate::config::CryptoConfig;

// ===================================================================
// Volume Layout Constants
// ===================================================================
//
// Explicit on-disk layout for encrypted volumes:
//
// ┌─────────────────────────────────────────────────────────────────┐
// │ Offset        │ Size    │ Section                              │
// ├─────────────────────────────────────────────────────────────────┤
// │ 0x0000        │ 4 KB    │ Primary Volume Header                │
// │ 0x1000        │ ~1 KB   │ PQ Metadata (V2 only)                │
// │ 0x2000        │ 8 KB    │ Key Slots (8 slots × 1KB each)       │
// │ 0x4000        │ ...     │ Encrypted Data Area                  │
// │ EOF-4KB       │ 4 KB    │ Backup Volume Header (end of file)  │
// └─────────────────────────────────────────────────────────────────┘
//
// Total metadata size: 16 KB front + 4 KB backup header at end
//
// This layout provides:
// - Header redundancy for corruption recovery (backup at end of file)
// - Multi-user support via 8 independent key slots
// - Clear separation of metadata and data
// - Post-quantum resistance via ML-KEM-1024 (V2 volumes)
// - BLAKE3 header checksums for integrity verification

/// Offset to primary volume header (always at start of file)
pub const PRIMARY_HEADER_OFFSET: u64 = 0;

// Location strategy for backup volume header:
// The backup header is stored at the END of the volume file to avoid conflicts
// with PQ metadata and provide better corruption resistance.
// Calculation: volume_file_size - HEADER_SIZE
// This follows the LUKS/VeraCrypt convention of end-of-volume backup headers.

/// Offset to PQ metadata section (for V2 volumes with post-quantum cryptography)
/// Located after the primary header at 4KB offset
/// Size: 8KB reserved (actual data ~6.3KB for ML-KEM-1024)
pub const PQ_METADATA_OFFSET: u64 = HEADER_SIZE as u64; // 4KB

/// Reserved size for PQ metadata section (8KB aligned)
pub const PQ_METADATA_RESERVED: usize = 2 * HEADER_SIZE; // 8KB

/// Offset to key slots section
/// V2 layout: Header (4KB) + PQ Metadata (8KB) + Key Slots (8KB) = 20KB
pub const KEYSLOTS_OFFSET: u64 = (HEADER_SIZE + PQ_METADATA_RESERVED) as u64; // 12KB

/// Size of the key slots section in bytes (8KB for 8 slots)
pub const KEYSLOTS_SIZE: usize = 8192;

/// Offset to encrypted data area (after all metadata)
pub const DATA_AREA_OFFSET: u64 = KEYSLOTS_OFFSET + KEYSLOTS_SIZE as u64; // 20KB

/// Total size of container metadata (headers + PQ metadata + key slots)
pub const METADATA_SIZE: usize = DATA_AREA_OFFSET as usize;

/// Errors that can occur with encrypted containers
#[derive(Debug, Error)]
pub enum ContainerError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Header error
    #[error("Header error: {0}")]
    Header(#[from] super::header::HeaderError),

    /// Key slot error
    #[error("Key slot error: {0}")]
    KeySlot(#[from] super::keyslot::KeySlotError),

    /// Container file not found
    #[error("Container file not found: {0}")]
    NotFound(PathBuf),

    /// Container already exists
    #[error("Container already exists: {0}")]
    AlreadyExists(PathBuf),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    /// Invalid container size
    #[error("Invalid container size: {0}")]
    InvalidSize(String),

    /// Container is locked (already mounted)
    #[error("Container is locked (already mounted)")]
    Locked,

    /// Other error
    #[error("Container error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ContainerError>;

/// Encrypted container that can be mounted as a filesystem
pub struct Container {
    /// Path to the container file
    path: PathBuf,

    /// Volume header
    header: VolumeHeader,

    /// Key slots for multi-user access
    key_slots: KeySlots,

    /// Master encryption key (only available when unlocked)
    master_key: Option<MasterKey>,

    /// PQ shared secret (V2 volumes only, available when unlocked)
    pq_shared_secret: Option<Zeroizing<[u8; 32]>>,

    /// File handle (kept open while container is in use)
    file: Option<File>,
}

impl Container {
    /// Creates a new encrypted container file with V2 PQC support
    ///
    /// # Arguments
    ///
    /// * `path` - Path where the container file will be created
    /// * `size` - Size of the container in bytes (excluding metadata)
    /// * `password` - Initial password for the first key slot
    /// * `sector_size` - Sector size for encryption (typically 4096)
    ///
    /// # Returns
    ///
    /// A new `Container` instance with the master key unlocked
    ///
    /// # Security
    ///
    /// This creates a V2 volume with ML-KEM-1024 post-quantum hybrid encryption:
    /// - Master key is protected by hybrid key = HKDF(password_key || pq_shared_secret)
    /// - ML-KEM decapsulation key is encrypted with password_key
    /// - Provides quantum resistance via defense-in-depth
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file already exists
    /// - The size is invalid
    /// - File creation fails
    /// - Cryptographic operations fail
    pub fn create(
        path: impl AsRef<Path>,
        size: u64,
        password: &str,
        sector_size: u32,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Check if file already exists
        if path.exists() {
            return Err(ContainerError::AlreadyExists(path));
        }

        // Validate size
        if size < sector_size as u64 {
            return Err(ContainerError::InvalidSize(format!(
                "Container size ({} bytes) must be at least one sector ({})",
                size, sector_size
            )));
        }

        // Generate master key
        let master_key = MasterKey::generate();

        // Generate random salt and IV for header
        let mut salt = [0u8; 32];
        let mut header_iv = [0u8; 12];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut header_iv);

        // === V2 PQC: Generate ML-KEM-1024 keypair ===
        let keypair = MlKemKeyPair::generate();
        let (ciphertext, pq_shared_secret) = encapsulate(keypair.encapsulation_key())
            .map_err(|e| ContainerError::Other(format!("ML-KEM encapsulation failed: {}", e)))?;

        // Derive password key via Argon2
        let kdf = Argon2Kdf::new(CryptoConfig::default());
        let password_key = Zeroizing::new(kdf.derive_key(password.as_bytes(), &salt)
            .map_err(|e| ContainerError::Other(format!("Key derivation failed: {}", e)))?);

        #[cfg(test)]
        eprintln!("DEBUG CREATE: salt first 4: {:?}, password_key first 4: {:?}",
            &salt[..4], &password_key[..4]);

        // Encrypt ML-KEM decapsulation key with password key
        let encryptor = AesGcmEncryptor::new();
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);

        let dk_bytes = keypair.decapsulation_key();
        let encrypted_dk = encryptor.encrypt(&password_key, &nonce, dk_bytes)
            .map_err(|e| ContainerError::Other(format!("DK encryption failed: {}", e)))?;

        // Combine nonce + encrypted_dk for storage (matches streaming.rs format)
        let mut encrypted_dk_with_nonce = Vec::with_capacity(12 + encrypted_dk.len());
        encrypted_dk_with_nonce.extend_from_slice(&nonce);
        encrypted_dk_with_nonce.extend_from_slice(&encrypted_dk);

        // Create PQ metadata with raw byte arrays
        let mut ek_bytes = [0u8; 1568];
        let mut ct_bytes = [0u8; 1568];
        let mut edk_bytes = [0u8; 3196]; // nonce (12) + encrypted DK (3168) + tag (16)

        ek_bytes.copy_from_slice(keypair.encapsulation_key());
        ct_bytes.copy_from_slice(&ciphertext);

        // Verify sizes match exactly
        debug_assert_eq!(encrypted_dk_with_nonce.len(), 3196,
            "encrypted_dk_with_nonce should be exactly 3196 bytes: nonce(12) + ciphertext(3168+16)");

        #[cfg(test)]
        eprintln!("DEBUG WRITE: nonce: {:?}, edk_with_nonce len: {}, edk first 4: {:?}",
            &nonce[..4], encrypted_dk_with_nonce.len(), &encrypted_dk[..4]);

        edk_bytes.copy_from_slice(&encrypted_dk_with_nonce);

        let pq_metadata = PqVolumeMetadata {
            algorithm: super::header::PqAlgorithm::MlKem1024,
            encapsulation_key: ek_bytes,
            ciphertext: ct_bytes,
            encrypted_decapsulation_key: edk_bytes,
        };

        // Serialize PQ metadata to get size
        let pq_metadata_bytes = pq_metadata.to_bytes()?;
        let pq_metadata_size = pq_metadata_bytes.len() as u32;

        // SECURITY CHECK: Ensure PQ metadata fits in reserved space
        // This prevents overwriting key slots if future PQ algorithms have larger keys
        if pq_metadata_bytes.len() > PQ_METADATA_RESERVED {
            return Err(ContainerError::InvalidSize(format!(
                "PQ metadata ({} bytes) exceeds reserved space ({} bytes). \
                 This may indicate an incompatible PQ algorithm or corrupted data.",
                pq_metadata_bytes.len(),
                PQ_METADATA_RESERVED
            )));
        }

        // Derive hybrid key: password_key + pq_shared_secret
        let hybrid_key = derive_hybrid_key(&password_key, &pq_shared_secret);

        // Create V2 volume header with PQ metadata
        let header = VolumeHeader::new_with_pqc(
            size,
            sector_size,
            salt,
            header_iv,
            pq_metadata_size,
        );

        // Create key slots and add first password using hybrid key
        let mut key_slots = KeySlots::new();
        key_slots.add_slot_with_derived_key(&master_key, &hybrid_key)?;

        // Create the container file
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;

        // Write header
        header.write_to(&mut file)?;

        // Write PQ metadata at PQ_METADATA_OFFSET (immediately after header)
        // Then pad to align key slots at KEYSLOTS_OFFSET
        let pq_bytes = pq_metadata.to_bytes()?;
        let mut pq_section = pq_bytes;
        pq_section.resize(PQ_METADATA_RESERVED, 0); // Pad to 8KB
        file.write_all(&pq_section)?;

        // Key slots written at KEYSLOTS_OFFSET (12KB)
        // Serialize and write key slots
        let keyslots_bytes = bincode::serialize(&key_slots)?;
        if keyslots_bytes.len() > KEYSLOTS_SIZE {
            return Err(ContainerError::InvalidSize(format!(
                "Key slots data ({} bytes) exceeds maximum size ({})",
                keyslots_bytes.len(),
                KEYSLOTS_SIZE
            )));
        }

        // Pad to KEYSLOTS_SIZE and write
        let mut padded_keyslots = keyslots_bytes;
        padded_keyslots.resize(KEYSLOTS_SIZE, 0);
        file.write_all(&padded_keyslots)?;

        // Initialize data area with zeros (encrypted later by filesystem)
        // V2 metadata size = PRIMARY_HEADER + BACKUP_HEADER + KEYSLOTS = 16KB
        let v2_metadata_size = DATA_AREA_OFFSET;
        // Reserve space for backup header at end of file
        file.set_len(v2_metadata_size + size + HEADER_SIZE as u64)?;
        file.sync_all()?;

        // Create the container instance
        let mut container = Self {
            path,
            header,
            key_slots,
            master_key: Some(master_key),
            pq_shared_secret: Some(pq_shared_secret),
            file: Some(file),
        };

        // Write backup header to end of file
        container.write_backup_header()?;

        Ok(container)
    }

    /// Opens an existing encrypted container (supports both V1 and V2 formats)
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the container file
    /// * `password` - Password to unlock the container
    ///
    /// # Returns
    ///
    /// A `Container` instance with the master key unlocked
    ///
    /// # Security
    ///
    /// - V1 volumes: Uses password-based key derivation (Argon2id)
    /// - V2 volumes: Uses hybrid key = HKDF(password_key || pq_shared_secret)
    ///   providing post-quantum resistance via ML-KEM-1024
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file doesn't exist
    /// - The file is not a valid container
    /// - The password is incorrect
    pub fn open(path: impl AsRef<Path>, password: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Open the file
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|_| ContainerError::NotFound(path.clone()))?;

        // Read header
        let header = VolumeHeader::read_from(&mut file)?;

        // Determine master key and PQ shared secret based on header version
        let (master_key, pq_shared_secret) = if header.has_pqc() {
            // === V2 PQC: Derive hybrid key ===

            // Read PQ metadata
            let pq_metadata = PqVolumeMetadata::read_from(&mut file, header.pq_metadata_size())?;

            // Derive password key via Argon2
            let kdf = Argon2Kdf::new(CryptoConfig::default());
            let password_key = Zeroizing::new(kdf.derive_key(password.as_bytes(), header.salt())
                .map_err(|e| ContainerError::Other(format!("Key derivation failed: {}", e)))?);

            #[cfg(test)]
            eprintln!("DEBUG READ: salt first 4: {:?}, password_key first 4: {:?}",
                &header.salt()[..4], &password_key[..4]);

            // Decrypt ML-KEM decapsulation key with password key
            // encrypted_decapsulation_key format: nonce (12 bytes) + encrypted_dk (3168) + auth tag (16)
            let encrypted_dk = &pq_metadata.encrypted_decapsulation_key;

            let encryptor = AesGcmEncryptor::new();
            // Extract nonce from encrypted data (first 12 bytes)
            let nonce = &encrypted_dk[0..12];
            // ciphertext = encrypted_dk (3168) + tag (16) = 3184 bytes
            let ciphertext = &encrypted_dk[12..];

            #[cfg(test)]
            eprintln!("DEBUG: encrypted_dk total len: {}, nonce: {:?}, ciphertext len: {}",
                encrypted_dk.len(), &nonce[..4], ciphertext.len());

            let dk_bytes = encryptor.decrypt(&password_key, nonce, ciphertext)
                .map_err(|_| ContainerError::KeySlot(super::keyslot::KeySlotError::DecryptionFailed))?;

            // Decapsulate to get PQ shared secret using raw ciphertext bytes
            let ciphertext_bytes = &pq_metadata.ciphertext;

            let pq_shared_secret = crate::crypto::pqc::decapsulate(&dk_bytes, ciphertext_bytes)
                .map_err(|e| ContainerError::Other(format!("ML-KEM decapsulation failed: {}", e)))?;

            // Derive hybrid key
            let hybrid_key = derive_hybrid_key(&password_key, &pq_shared_secret);

            // Seek to key slots position (fixed offset in V2 layout)
            // Key slots are always at KEYSLOTS_OFFSET (12KB), NOT after PQ metadata data
            file.seek(SeekFrom::Start(KEYSLOTS_OFFSET))?;

            // Read key slots
            let mut keyslots_bytes = vec![0u8; KEYSLOTS_SIZE];
            file.read_exact(&mut keyslots_bytes)?;
            let key_slots: KeySlots = bincode::deserialize(&keyslots_bytes)?;

            // Unlock with hybrid key
            let master_key = key_slots.unlock_with_derived_key(&hybrid_key)?;
            (master_key, Some(pq_shared_secret))
        } else {
            // === V1 Classical: Password-based unlock ===

            // Read key slots (immediately after header in V1)
            let mut keyslots_bytes = vec![0u8; KEYSLOTS_SIZE];
            file.read_exact(&mut keyslots_bytes)?;
            let mut key_slots: KeySlots = bincode::deserialize(&keyslots_bytes)?;

            // Unlock with password
            // WARNING: This may destroy all keys if duress password is entered
            let master_key = key_slots.unlock(password)?;

            // If key slots were modified (duress password entered), write them back
            // This persists the key destruction to disk
            let keyslots_bytes = bincode::serialize(&key_slots)?;
            file.seek(SeekFrom::Start(KEYSLOTS_OFFSET))?;
            file.write_all(&keyslots_bytes)?;
            file.sync_all()?;
            (master_key, None)
        };

        // Re-read key slots for storage in Container struct
        // Key slots are always at fixed offset in the new layout
        file.seek(SeekFrom::Start(KEYSLOTS_OFFSET))?;
        let mut keyslots_bytes = vec![0u8; KEYSLOTS_SIZE];
        file.read_exact(&mut keyslots_bytes)?;
        let key_slots: KeySlots = bincode::deserialize(&keyslots_bytes)?;

        // Create container instance
        let mut container = Self {
            path,
            header,
            key_slots,
            master_key: Some(master_key),
            pq_shared_secret,
            file: Some(file),
        };

        // Verify backup header (if volume has one)
        // V2 volumes with backup headers will have file_size > metadata_size + data_size
        if let Ok(file_metadata) = container.file.as_ref().unwrap().metadata() {
            let expected_size_without_backup = DATA_AREA_OFFSET + container.header.volume_size();
            let actual_size = file_metadata.len();

            // Check if file has space for backup header
            if actual_size >= expected_size_without_backup + HEADER_SIZE as u64 {
                // Backup header exists, verify it matches primary
                match container.verify_headers() {
                    Ok(true) => {
                        // Headers match - all good
                    }
                    Ok(false) => {
                        // Headers don't match - warn but don't fail
                        // (could be normal if header was just updated)
                        eprintln!("Warning: Backup header doesn't match primary header");
                    }
                    Err(_) => {
                        // Backup header read failed - warn but continue
                        eprintln!("Warning: Could not read backup header");
                    }
                }
            }
        }

        Ok(container)
    }

    /// Writes the backup header to the end of the volume file
    ///
    /// This writes a duplicate copy of the primary header to the end of the volume
    /// (at offset: file_size - HEADER_SIZE) for redundancy and corruption recovery.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The container file is not open
    /// - Writing fails
    fn write_backup_header(&mut self) -> Result<()> {
        let file = self.file.as_mut()
            .ok_or_else(|| ContainerError::Other("Container file not open".to_string()))?;

        // Get file size to calculate backup header offset
        let file_size = file.metadata()?.len();
        let backup_offset = file_size.saturating_sub(HEADER_SIZE as u64);

        // Seek to backup header location (end of file - header size)
        file.seek(SeekFrom::Start(backup_offset))?;

        // Write header
        self.header.write_to(file)?;

        // Sync to ensure it's written to disk
        file.sync_all()?;

        Ok(())
    }

    /// Reads the backup header from the end of the volume file
    ///
    /// # Returns
    ///
    /// The backup header if it exists and is valid
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The container file is not open
    /// - Reading fails
    /// - The backup header is invalid
    fn read_backup_header(&mut self) -> Result<VolumeHeader> {
        let file = self.file.as_mut()
            .ok_or_else(|| ContainerError::Other("Container file not open".to_string()))?;

        // Get file size to calculate backup header offset
        let file_size = file.metadata()?.len();
        let backup_offset = file_size.saturating_sub(HEADER_SIZE as u64);

        // Seek to backup header location (end of file - header size)
        file.seek(SeekFrom::Start(backup_offset))?;

        // Read header
        let backup_header = VolumeHeader::read_from(file)?;

        Ok(backup_header)
    }

    /// Verifies that primary and backup headers match
    ///
    /// Compares the primary header (in memory) with the backup header on disk
    /// to detect corruption or tampering.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if headers match
    /// - `Ok(false)` if headers don't match (corruption detected)
    /// - `Err(...)` if reading the backup header fails
    ///
    /// # Errors
    ///
    /// Returns an error if reading the backup header fails
    fn verify_headers(&mut self) -> Result<bool> {
        let backup_header = self.read_backup_header()?;

        // Compare primary and backup headers byte-by-byte
        let primary_bytes = self.header.to_bytes()?;
        let backup_bytes = backup_header.to_bytes()?;

        Ok(primary_bytes == backup_bytes)
    }

    /// Adds a new password/key slot to the container
    ///
    /// # Arguments
    ///
    /// * `password` - The new password to add
    ///
    /// # Errors
    ///
    /// Returns an error if all key slots are full or if the container is locked
    ///
    /// # Security
    ///
    /// - V1 volumes: Password-based key derivation via Argon2id
    /// - V2 volumes: Hybrid key derivation (password + PQ shared secret)
    pub fn add_password(&mut self, password: &str) -> Result<usize> {
        let master_key = self.master_key.as_ref()
            .ok_or_else(|| super::keyslot::KeySlotError::NoActiveSlots)?;

        let slot_index = if self.header.has_pqc() {
            // === V2 PQC: Use hybrid key ===
            let pq_shared_secret = self.pq_shared_secret.as_ref()
                .ok_or_else(|| ContainerError::Other("PQ shared secret not available".to_string()))?;

            // Derive password key via Argon2
            let kdf = Argon2Kdf::new(CryptoConfig::default());
            let password_key = Zeroizing::new(kdf.derive_key(password.as_bytes(), self.header.salt())
                .map_err(|e| ContainerError::Other(format!("Key derivation failed: {}", e)))?);

            // Derive hybrid key
            let hybrid_key = derive_hybrid_key(&password_key, pq_shared_secret);

            // Add slot with hybrid key
            self.key_slots.add_slot_with_derived_key(master_key, &hybrid_key)?
        } else {
            // === V1 Classical: Password-based ===
            self.key_slots.add_slot(master_key, password)?
        };

        // Write updated key slots to disk
        self.write_keyslots()?;

        Ok(slot_index)
    }

    /// Removes a password/key slot from the container
    ///
    /// # Arguments
    ///
    /// * `slot_index` - The index of the slot to remove (0-7)
    ///
    /// # Errors
    ///
    /// Returns an error if the slot index is invalid
    pub fn remove_password(&mut self, slot_index: usize) -> Result<()> {
        self.key_slots.remove_slot(slot_index)?;

        // Write updated key slots to disk
        self.write_keyslots()?;

        Ok(())
    }

    /// Sets a duress password for this volume
    ///
    /// When this password is entered during unlock, all key slots will be
    /// immediately and permanently destroyed, making the volume unrecoverable.
    /// The operation returns the same error as an incorrect password, providing
    /// plausible deniability.
    ///
    /// # Arguments
    ///
    /// * `duress_password` - The password that triggers key destruction
    ///
    /// # Security Considerations
    ///
    /// **WARNING**: Setting a duress password creates a "self-destruct" mechanism
    /// for your volume. When triggered:
    /// - All key slots are overwritten with zeros
    /// - The volume becomes permanently inaccessible
    /// - The operation appears identical to entering a wrong password
    /// - Data recovery is mathematically impossible
    ///
    /// **Recommended**: Generate and securely store a recovery key BEFORE
    /// setting a duress password, in case it is triggered accidentally.
    ///
    /// # Errors
    ///
    /// Returns an error if the volume is not unlocked or if encryption fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tesseract_lib::volume::Container;
    /// # use std::path::Path;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut container = Container::open(Path::new("vault.enc"), "password")?;
    /// container.set_duress_password("panic_password_123!")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_duress_password(&mut self, duress_password: &str) -> Result<()> {
        // Ensure volume is unlocked (need access to modify key slots)
        if self.master_key.is_none() {
            return Err(ContainerError::Other(
                "Cannot set duress password: volume must be unlocked".to_string(),
            ));
        }

        // Set the duress password in key slots
        self.key_slots.set_duress_password(duress_password)?;

        // Write updated key slots to disk immediately
        // This ensures the duress password is persisted
        self.write_keyslots()?;

        Ok(())
    }

    /// Removes the duress password from this volume
    ///
    /// # Errors
    ///
    /// Returns an error if the volume is not unlocked
    pub fn remove_duress_password(&mut self) -> Result<()> {
        // Ensure volume is unlocked
        if self.master_key.is_none() {
            return Err(ContainerError::Other(
                "Cannot remove duress password: volume must be unlocked".to_string(),
            ));
        }

        // Remove the duress password
        self.key_slots.remove_duress_password();

        // Write updated key slots to disk
        self.write_keyslots()?;

        Ok(())
    }

    /// Returns whether this volume has a duress password set
    pub fn has_duress_password(&self) -> bool {
        self.key_slots.has_duress_password()
    }

    /// Returns the master key (if unlocked)
    pub fn master_key(&self) -> Option<&MasterKey> {
        self.master_key.as_ref()
    }

    /// Returns the volume header
    pub fn header(&self) -> &VolumeHeader {
        &self.header
    }

    /// Returns the key slots
    pub fn key_slots(&self) -> &KeySlots {
        &self.key_slots
    }

    /// Returns the container file path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the total size of the data area (excluding metadata)
    pub fn data_size(&self) -> u64 {
        self.header.volume_size()
    }

    /// Returns the sector size
    pub fn sector_size(&self) -> u32 {
        self.header.sector_size()
    }

    /// Returns the offset to the data area in the container file
    pub fn data_offset(&self) -> u64 {
        DATA_AREA_OFFSET
    }

    /// Creates and initializes a new in-memory filesystem for this container
    ///
    /// # Returns
    ///
    /// An initialized `InMemoryFilesystem` with the root directory created
    ///
    /// # Errors
    ///
    /// Returns an error if the container is locked or filesystem initialization fails
    pub fn mount_filesystem(&self) -> Result<super::operations::InMemoryFilesystem> {
        use super::operations::InMemoryFilesystem;
        use super::filesystem::EncryptedFilesystem;

        let master_key = self.master_key.as_ref()
            .ok_or_else(|| super::keyslot::KeySlotError::NoActiveSlots)?;

        let mut fs = InMemoryFilesystem::new();
        fs.init(master_key, &self.path)
            .map_err(|e| ContainerError::Io(io::Error::other(e.to_string())))?;

        Ok(fs)
    }

    /// Writes updated key slots to disk
    fn write_keyslots(&mut self) -> Result<()> {
        let file = self.file.as_mut()
            .ok_or_else(|| io::Error::other("Container file not open"))?;

        // Seek to key slots position (fixed offset in new layout)
        file.seek(SeekFrom::Start(KEYSLOTS_OFFSET))?;

        // Serialize and write
        let keyslots_bytes = bincode::serialize(&self.key_slots)?;
        let mut padded_keyslots = keyslots_bytes;
        padded_keyslots.resize(KEYSLOTS_SIZE, 0);
        file.write_all(&padded_keyslots)?;
        file.sync_all()?;

        Ok(())
    }

    /// Exports an encrypted backup of the volume header and key slots
    ///
    /// This creates a portable backup file that can be used to recover
    /// the volume if the header becomes corrupted. The backup is encrypted
    /// with the provided password.
    ///
    /// # Arguments
    ///
    /// * `backup_path` - Path where the backup file will be created
    /// * `password` - Password to encrypt the backup (can be different from volume password)
    ///
    /// # Returns
    ///
    /// Ok(()) if the backup was created successfully
    ///
    /// # Security Note
    ///
    /// The backup contains all key slots and volume metadata. It should be
    /// stored securely. Anyone with access to the backup and the backup password
    /// can decrypt the volume.
    pub fn export_header_backup(&self, backup_path: impl AsRef<Path>, password: &str) -> Result<()> {
        use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
        use crate::crypto::kdf::Argon2Kdf;
        use crate::crypto::KeyDerivation;
        use crate::config::CryptoConfig;
        use zeroize::Zeroizing;

        // Serialize header and key slots
        let header_bytes = self.header.to_bytes()?;
        let keyslots_bytes = bincode::serialize(&self.key_slots)?;

        // Combine header + keyslots
        let mut backup_data = Vec::new();
        backup_data.extend_from_slice(&header_bytes);
        backup_data.extend_from_slice(&keyslots_bytes);

        // Generate salt and nonce for backup encryption
        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce_bytes);

        // Derive encryption key from password
        let kdf = Argon2Kdf::new(CryptoConfig::default());
        let key = Zeroizing::new(kdf.derive_key(password.as_bytes(), &salt)
            .map_err(|e| ContainerError::Other(format!("Key derivation failed: {}", e)))?);

        // Encrypt the backup
        let cipher = Aes256Gcm::new_from_slice(&key[..])
            .map_err(|e| ContainerError::Other(format!("Cipher creation failed: {}", e)))?;
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher.encrypt(&nonce, backup_data.as_ref())
            .map_err(|e| ContainerError::Other(format!("Encryption failed: {}", e)))?;

        // Create backup file with magic header
        let mut backup_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(backup_path)?;

        // Write backup format:
        // - Magic: "SCBAK01\0" (8 bytes)
        // - Salt: 32 bytes
        // - Nonce: 12 bytes
        // - Ciphertext: variable length
        backup_file.write_all(b"SCBAK01\0")?;
        backup_file.write_all(&salt)?;
        backup_file.write_all(&nonce_bytes)?;
        backup_file.write_all(&ciphertext)?;
        backup_file.sync_all()?;

        Ok(())
    }

    /// Restores the volume header and key slots from an encrypted backup
    ///
    /// # Arguments
    ///
    /// * `backup_path` - Path to the backup file
    /// * `password` - Password used to encrypt the backup
    ///
    /// # Returns
    ///
    /// Ok(()) if the restore was successful
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The backup file is invalid
    /// - The password is incorrect
    /// - The backup data is corrupted
    ///
    /// # Warning
    ///
    /// This overwrites the current header and key slots. Use with caution!
    pub fn restore_from_backup(&mut self, backup_path: impl AsRef<Path>, password: &str) -> Result<()> {
        use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
        use crate::crypto::kdf::Argon2Kdf;
        use crate::crypto::KeyDerivation;
        use crate::config::CryptoConfig;
        use zeroize::Zeroizing;

        // Read backup file
        let mut backup_file = File::open(backup_path)?;

        // Read and verify magic
        let mut magic = [0u8; 8];
        backup_file.read_exact(&mut magic)?;
        if &magic != b"SCBAK01\0" {
            return Err(ContainerError::Other("Invalid backup file format".to_string()));
        }

        // Read salt and nonce
        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        backup_file.read_exact(&mut salt)?;
        backup_file.read_exact(&mut nonce_bytes)?;

        // Read ciphertext
        let mut ciphertext = Vec::new();
        backup_file.read_to_end(&mut ciphertext)?;

        // Derive decryption key from password
        let kdf = Argon2Kdf::new(CryptoConfig::default());
        let key = Zeroizing::new(kdf.derive_key(password.as_bytes(), &salt)
            .map_err(|e| ContainerError::Other(format!("Key derivation failed: {}", e)))?);

        // Decrypt the backup
        let cipher = Aes256Gcm::new_from_slice(&key[..])
            .map_err(|e| ContainerError::Other(format!("Cipher creation failed: {}", e)))?;
        let nonce = Nonce::from(nonce_bytes);
        let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())
            .map_err(|_| ContainerError::Other("Decryption failed: incorrect password or corrupted backup".to_string()))?;

        // Split into header and keyslots
        if plaintext.len() < HEADER_SIZE {
            return Err(ContainerError::Other("Backup data too small".to_string()));
        }

        let header_bytes = &plaintext[0..HEADER_SIZE];
        let keyslots_bytes = &plaintext[HEADER_SIZE..];

        // Deserialize header and keyslots
        let header = VolumeHeader::from_bytes(header_bytes)?;
        let key_slots: KeySlots = bincode::deserialize(keyslots_bytes)?;

        // Write to container file
        let file = self.file.as_mut()
            .ok_or_else(|| ContainerError::Other("Container file not open".to_string()))?;

        // Write header
        file.seek(SeekFrom::Start(PRIMARY_HEADER_OFFSET))?;
        header.write_to(file)?;

        // Write key slots at fixed offset
        file.seek(SeekFrom::Start(KEYSLOTS_OFFSET))?;
        let mut padded_keyslots = bincode::serialize(&key_slots)?;
        padded_keyslots.resize(KEYSLOTS_SIZE, 0);
        file.write_all(&padded_keyslots)?;
        file.sync_all()?;

        // Update in-memory copies
        self.header = header;
        self.key_slots = key_slots;

        Ok(())
    }

    /// Verifies the integrity of the volume header
    ///
    /// # Returns
    ///
    /// Ok(()) if the header is valid, Err otherwise
    pub fn verify_header(&self) -> Result<()> {
        // Check magic bytes are preserved
        if self.header.salt().len() != 32 {
            return Err(ContainerError::Other("Invalid header: bad salt size".to_string()));
        }

        if self.header.header_iv().len() != 12 {
            return Err(ContainerError::Other("Invalid header: bad IV size".to_string()));
        }

        if self.header.sector_size() == 0 || !self.header.sector_size().is_multiple_of(512) {
            return Err(ContainerError::Other("Invalid header: bad sector size".to_string()));
        }

        // Verify at least one key slot is active
        if self.key_slots.active_count() == 0 {
            return Err(ContainerError::Other("Invalid header: no active key slots".to_string()));
        }

        Ok(())
    }

    /// Locks the container (clears master key, PQ shared secret, and closes file)
    pub fn lock(&mut self) {
        self.master_key = None;
        self.pq_shared_secret = None;
        self.file = None;
    }

    /// Returns whether the container is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    /// Resizes the encrypted container
    ///
    /// This changes the size of the data area in the container. The header
    /// and key slots remain unchanged.
    ///
    /// # Arguments
    ///
    /// * `new_size` - The new size for the data area in bytes
    ///
    /// # Returns
    ///
    /// Ok(()) if the resize was successful
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The container is locked
    /// - The new size is invalid (smaller than sector size)
    /// - File operations fail
    ///
    /// # Safety Note
    ///
    /// When shrinking a container, any data beyond the new size will be lost.
    /// Ensure you have backed up important data before shrinking.
    pub fn resize(&mut self, new_size: u64) -> Result<()> {
        // Ensure container is unlocked
        if !self.is_unlocked() {
            return Err(ContainerError::Other(
                "Container must be unlocked to resize".to_string()
            ));
        }

        // Validate new size
        let sector_size = self.header.sector_size();
        if new_size < sector_size as u64 {
            return Err(ContainerError::InvalidSize(format!(
                "New size ({} bytes) must be at least one sector ({})",
                new_size, sector_size
            )));
        }

        // Calculate new total size including backup header
        // File layout: front metadata (20KB) + data + backup header (4KB)
        let new_total_size = self.metadata_size() + new_size + HEADER_SIZE as u64;

        // Get file handle
        let file = self.file.as_mut()
            .ok_or_else(|| ContainerError::Other("Container file not open".to_string()))?;

        // Resize the file
        file.set_len(new_total_size)?;
        file.sync_all()?;

        // Update header with new volume size, preserving V2 PQC metadata if present
        if self.header.has_pqc() {
            // V2: preserve PQC settings
            self.header = VolumeHeader::new_with_pqc(
                new_size,
                sector_size,
                *self.header.salt(),
                *self.header.header_iv(),
                self.header.pq_metadata_size(),
            );
        } else {
            // V1: classical header
            self.header = VolumeHeader::new(
                new_size,
                sector_size,
                *self.header.salt(),
                *self.header.header_iv(),
            );
        }

        // Write updated header
        file.seek(SeekFrom::Start(0))?;
        self.header.write_to(file)?;
        file.sync_all()?;

        Ok(())
    }

    /// Returns the current data area size in bytes (excluding metadata)
    pub fn size(&self) -> u64 {
        self.header.volume_size()
    }

    /// Returns the front metadata size in bytes (header + PQ metadata + keyslots = 20KB)
    pub fn metadata_size(&self) -> u64 {
        METADATA_SIZE as u64
    }

    /// Returns the total file size in bytes (including all metadata and backup header)
    ///
    /// File layout: front metadata (20KB) + data + backup header (4KB)
    pub fn total_size(&self) -> u64 {
        self.metadata_size() + self.header.volume_size() + HEADER_SIZE as u64
    }

    /// Creates a hidden volume within this container
    ///
    /// A hidden volume provides plausible deniability by storing an encrypted
    /// volume inside the free space of the outer (decoy) volume. The hidden
    /// volume has its own password and encryption key, independent of the outer
    /// volume.
    ///
    /// # Arguments
    ///
    /// * `hidden_size` - Size of the hidden volume in bytes
    /// * `hidden_password` - Password for the hidden volume (different from outer)
    /// * `hidden_offset` - Offset from start of outer data area where hidden volume begins
    ///
    /// # Returns
    ///
    /// Ok(()) if the hidden volume was created successfully
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The container is locked
    /// - The hidden volume size is too large for the available space
    /// - The offset is invalid
    ///
    /// # Security Note
    ///
    /// To maintain plausible deniability:
    /// - Use a different password for the hidden volume
    /// - Fill the outer volume with decoy data to hide the hidden volume
    /// - Never reveal the hidden volume password under duress
    pub fn create_hidden_volume(
        &mut self,
        hidden_size: u64,
        hidden_password: &str,
        hidden_offset: u64,
    ) -> Result<()> {
        // Ensure container is unlocked
        if !self.is_unlocked() {
            return Err(ContainerError::Other(
                "Container must be unlocked to create hidden volume".to_string()
            ));
        }

        // Validate sizes
        let sector_size = self.header.sector_size();
        if hidden_size < sector_size as u64 {
            return Err(ContainerError::InvalidSize(format!(
                "Hidden volume size ({} bytes) must be at least one sector ({})",
                hidden_size, sector_size
            )));
        }

        let hidden_total_size = METADATA_SIZE as u64 + hidden_size;
        let outer_data_size = self.header.volume_size();

        if hidden_offset + hidden_total_size > outer_data_size {
            return Err(ContainerError::InvalidSize(format!(
                "Hidden volume ({} bytes) does not fit in outer volume (offset: {}, available: {})",
                hidden_total_size, hidden_offset, outer_data_size
            )));
        }

        // Generate master key for hidden volume
        let hidden_master_key = MasterKey::generate();

        // Generate salt and IV for hidden volume
        let mut hidden_salt = [0u8; 32];
        let mut hidden_iv = [0u8; 12];
        rand::rng().fill_bytes(&mut hidden_salt);
        rand::rng().fill_bytes(&mut hidden_iv);

        // Create hidden volume header
        let hidden_header = VolumeHeader::new(
            hidden_size,
            sector_size,
            hidden_salt,
            hidden_iv,
        );

        // Create key slots for hidden volume
        let mut hidden_keyslots = KeySlots::new();
        hidden_keyslots.add_slot(&hidden_master_key, hidden_password)?;

        // Calculate absolute file offset (outer metadata + outer data offset + hidden offset)
        let absolute_offset = METADATA_SIZE as u64 + hidden_offset;

        // Get file handle
        let file = self.file.as_mut()
            .ok_or_else(|| ContainerError::Other("Container file not open".to_string()))?;

        // Write hidden volume header
        file.seek(SeekFrom::Start(absolute_offset))?;
        hidden_header.write_to(file)?;

        // Write hidden volume key slots
        let keyslots_bytes = bincode::serialize(&hidden_keyslots)?;
        let mut padded_keyslots = keyslots_bytes;
        padded_keyslots.resize(KEYSLOTS_SIZE, 0);
        file.write_all(&padded_keyslots)?;

        file.sync_all()?;

        Ok(())
    }

    /// Opens a hidden volume from within this container
    ///
    /// # Arguments
    ///
    /// * `hidden_password` - Password for the hidden volume
    /// * `hidden_offset` - Offset from start of outer data area where hidden volume begins
    ///
    /// # Returns
    ///
    /// A new Container instance for the hidden volume
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The hidden volume cannot be found at the specified offset
    /// - The password is incorrect
    /// - The file cannot be read
    pub fn open_hidden_volume(
        &self,
        hidden_password: &str,
        hidden_offset: u64,
    ) -> Result<Container> {
        let outer_data_size = self.header.volume_size();

        // Validate offset
        if hidden_offset + METADATA_SIZE as u64 > outer_data_size {
            return Err(ContainerError::Other(
                "Invalid offset for hidden volume".to_string()
            ));
        }

        // Calculate absolute file offset
        let absolute_offset = METADATA_SIZE as u64 + hidden_offset;

        // Open the file
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)?;

        // Seek to hidden volume header
        file.seek(SeekFrom::Start(absolute_offset))?;

        // Read hidden volume header
        let hidden_header = VolumeHeader::read_from(&mut file)?;

        // Read hidden volume key slots
        let mut keyslots_bytes = vec![0u8; KEYSLOTS_SIZE];
        file.read_exact(&mut keyslots_bytes)?;
        let mut hidden_keyslots: KeySlots = bincode::deserialize(&keyslots_bytes)?;

        // Unlock with hidden password
        // WARNING: This may destroy all keys if duress password is entered
        let hidden_master_key = hidden_keyslots.unlock(hidden_password)?;

        // If key slots were modified (duress password entered), write them back
        let keyslots_bytes = bincode::serialize(&hidden_keyslots)?;
        file.seek(SeekFrom::Start(absolute_offset + HEADER_SIZE as u64))?;
        file.write_all(&keyslots_bytes)?;
        file.sync_all()?;

        // Create a Container instance for the hidden volume
        // Note: The hidden volume shares the same file as the outer volume
        // TODO: Add PQC support for hidden volumes
        Ok(Container {
            path: self.path.clone(),
            header: hidden_header,
            key_slots: hidden_keyslots,
            master_key: Some(hidden_master_key),
            pq_shared_secret: None,  // Hidden volumes don't support PQC yet
            file: Some(file),
        })
    }

    /// Checks if a hidden volume exists at the specified offset
    ///
    /// This checks if there's a valid volume header at the expected location
    /// without attempting to decrypt it.
    ///
    /// # Arguments
    ///
    /// * `hidden_offset` - Offset from start of outer data area where to check
    ///
    /// # Returns
    ///
    /// true if a valid header signature is found, false otherwise
    pub fn has_hidden_volume(&self, hidden_offset: u64) -> bool {
        let outer_data_size = self.header.volume_size();

        if hidden_offset + METADATA_SIZE as u64 > outer_data_size {
            return false;
        }

        let absolute_offset = METADATA_SIZE as u64 + hidden_offset;

        // Try to read the header
        if let Ok(mut file) = OpenOptions::new().read(true).open(&self.path) {
            if file.seek(SeekFrom::Start(absolute_offset)).is_ok() {
                // Try to read and validate the header
                if let Ok(_header) = VolumeHeader::read_from(&mut file) {
                    return true;
                }
            }
        }

        false
    }

    /// Generates a cryptographically secure recovery key
    ///
    /// The recovery key is a 32-byte (256-bit) random value encoded as
    /// a 64-character hexadecimal string. This can be used like a password
    /// to add a recovery key slot or reset passwords.
    ///
    /// # Returns
    ///
    /// A hex-encoded recovery key string (64 characters)
    ///
    /// # Security Note
    ///
    /// Store this recovery key in a secure location (e.g., password manager,
    /// encrypted backup, or printed and stored in a safe). Anyone with this
    /// recovery key can unlock the volume.
    pub fn generate_recovery_key() -> String {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        hex::encode(key)
    }

    /// Exports a recovery key to a file with metadata
    ///
    /// Creates a human-readable file containing the recovery key and
    /// instructions for use.
    ///
    /// # Arguments
    ///
    /// * `recovery_key` - The hex-encoded recovery key
    /// * `output_path` - Path where the recovery key file will be created
    /// * `container_name` - Optional name/description of the container
    ///
    /// # Returns
    ///
    /// Ok(()) if the file was created successfully
    pub fn export_recovery_key_file(
        recovery_key: &str,
        output_path: impl AsRef<Path>,
        container_name: Option<&str>,
    ) -> Result<()> {
        use std::time::SystemTime;

        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let name = container_name.unwrap_or("Encrypted Volume");

        let content = format!(
            "SECURE CRYPTOR RECOVERY KEY\n\
             =============================\n\n\
             Container: {}\n\
             Generated: {}\n\n\
             RECOVERY KEY:\n\
             {}\n\n\
             INSTRUCTIONS:\n\
             1. Store this file in a secure location\n\
             2. Do not share this key with unauthorized persons\n\
             3. Use this key to reset your password if forgotten\n\
             4. To reset password, use: secure-cryptor recover <container> --recovery-key <key>\n\n\
             WARNING: Anyone with this recovery key can access your encrypted volume.\n",
            name,
            timestamp,
            recovery_key
        );

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)?;

        file.write_all(content.as_bytes())?;
        file.sync_all()?;

        Ok(())
    }

    /// Resets a password using a recovery key
    ///
    /// This allows resetting a password if the original password is forgotten,
    /// as long as the recovery key is available. The recovery key must have
    /// been previously added to a key slot.
    ///
    /// # Arguments
    ///
    /// * `recovery_key` - The hex-encoded recovery key
    /// * `new_password` - The new password to set
    ///
    /// # Returns
    ///
    /// Ok(()) if the password was reset successfully
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The recovery key is invalid or not found in any key slot
    /// - The container is locked
    /// - File operations fail
    pub fn reset_password_with_recovery_key(
        &mut self,
        recovery_key: &str,
        new_password: &str,
    ) -> Result<()> {
        // Validate recovery key format (should be 64 hex characters)
        if recovery_key.len() != 64 {
            return Err(ContainerError::Other(
                "Invalid recovery key: must be 64 hex characters".to_string()
            ));
        }

        // Validate that it's valid hex
        if hex::decode(recovery_key).is_err() {
            return Err(ContainerError::Other(
                "Invalid recovery key: contains non-hex characters".to_string()
            ));
        }

        // Try to unlock with recovery key
        let master_key = self.key_slots.unlock(recovery_key)
            .map_err(|_| ContainerError::Other(
                "Recovery key not found or invalid".to_string()
            ))?;

        // Update master key in container
        self.master_key = Some(master_key.clone());

        // Find the first non-recovery key slot (or first free slot) to update
        // We'll update the first user password slot (typically slot 1)
        let slot_index = if self.key_slots.active_count() > 1 {
            // Update the first non-recovery slot
            1
        } else {
            // Add new password slot
            self.key_slots.find_free_slot()
                .ok_or_else(|| ContainerError::KeySlot(
                    super::keyslot::KeySlotError::AllSlotsFull
                ))?
        };

        // Update or add the password slot
        if self.key_slots.is_slot_active(slot_index) {
            self.key_slots.change_password(&master_key, slot_index, new_password)?;
        } else {
            self.key_slots.add_slot(&master_key, new_password)?;
        }

        // Write updated key slots to disk
        self.write_keyslots()?;

        Ok(())
    }

    /// Adds a recovery key to the first available key slot
    ///
    /// This should be called during container creation or when adding
    /// a recovery mechanism to an existing container.
    ///
    /// # Arguments
    ///
    /// * `recovery_key` - The hex-encoded recovery key to add
    ///
    /// # Returns
    ///
    /// Ok(slot_index) with the index of the slot where the recovery key was added
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The container is locked (master key not available)
    /// - All key slots are full
    /// - The recovery key format is invalid
    pub fn add_recovery_key(&mut self, recovery_key: &str) -> Result<usize> {
        // Validate recovery key format
        if recovery_key.len() != 64 {
            return Err(ContainerError::Other(
                "Invalid recovery key: must be 64 hex characters".to_string()
            ));
        }

        // Validate that it's valid hex
        if hex::decode(recovery_key).is_err() {
            return Err(ContainerError::Other(
                "Invalid recovery key: contains non-hex characters".to_string()
            ));
        }

        // Get master key
        let master_key = self.master_key.as_ref()
            .ok_or_else(|| ContainerError::Other(
                "Container must be unlocked to add recovery key".to_string()
            ))?;

        // Add recovery key to a slot
        let slot_index = self.key_slots.add_slot(master_key, recovery_key)?;

        // Write updated key slots to disk
        self.write_keyslots()?;

        Ok(slot_index)
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // Ensure file is synced before dropping
        if let Some(file) = &mut self.file {
            let _ = file.sync_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("test_container_{}.scv", name))
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_create_container() {
        let path = temp_path("create");
        cleanup(&path);

        let container = Container::create(
            &path,
            1024 * 1024, // 1 MB
            "TestPassword123!",
            4096,
        ).unwrap();

        assert!(path.exists());
        assert_eq!(container.data_size(), 1024 * 1024);
        assert_eq!(container.sector_size(), 4096);
        assert!(container.is_unlocked());
        assert_eq!(container.key_slots().active_count(), 1);

        cleanup(&path);
    }

    #[test]
    fn test_open_container() {
        let path = temp_path("open");
        cleanup(&path);

        // Create a container
        {
            Container::create(&path, 1024 * 1024, "TestPassword123!", 4096).unwrap();
        }

        // Open it
        let container = Container::open(&path, "TestPassword123!").unwrap();
        assert!(container.is_unlocked());
        assert_eq!(container.data_size(), 1024 * 1024);

        // Try wrong password
        let result = Container::open(&path, "WrongPassword");
        assert!(result.is_err());

        cleanup(&path);
    }

    #[test]
    fn test_lock_unlock() {
        let path = temp_path("lock");
        cleanup(&path);

        let mut container = Container::create(
            &path,
            1024 * 1024,
            "TestPassword!",
            4096,
        ).unwrap();

        assert!(container.is_unlocked());

        container.lock();
        assert!(!container.is_unlocked());
        assert!(container.master_key().is_none());

        cleanup(&path);
    }

    #[test]
    fn test_invalid_size() {
        let path = temp_path("invalid_size");
        cleanup(&path);

        // Try to create container smaller than one sector
        let result = Container::create(&path, 1024, "Test!", 4096);
        assert!(result.is_err());

        cleanup(&path);
    }

    #[test]
    fn test_pq_metadata_size_within_limits() {
        // Verify that current ML-KEM-1024 PQ metadata fits within reserved space
        use super::super::header::{PQ_METADATA_SIZE, PqVolumeMetadata, PqAlgorithm};

        // Current PQ metadata size should be well under the 8KB limit
        assert!(PQ_METADATA_SIZE < PQ_METADATA_RESERVED,
            "PQ metadata size ({}) should be less than reserved space ({})",
            PQ_METADATA_SIZE, PQ_METADATA_RESERVED);

        // Verify actual serialization fits
        let metadata = PqVolumeMetadata {
            algorithm: PqAlgorithm::MlKem1024,
            encapsulation_key: [0u8; 1568],
            ciphertext: [0u8; 1568],
            encrypted_decapsulation_key: [0u8; 3196],
        };
        let bytes = metadata.to_bytes().unwrap();
        assert!(bytes.len() <= PQ_METADATA_RESERVED,
            "Serialized PQ metadata ({} bytes) exceeds reserved space ({} bytes)",
            bytes.len(), PQ_METADATA_RESERVED);
    }

    #[test]
    fn test_file_size() {
        let path = temp_path("file_size");
        cleanup(&path);

        let data_size = 1024 * 1024;
        let container = Container::create(&path, data_size, "Test!", 4096).unwrap();

        // V2 volumes have larger metadata due to PQ data
        let fs_metadata = fs::metadata(&path).unwrap();
        assert_eq!(fs_metadata.len(), container.total_size());
        assert_eq!(container.size(), data_size);

        cleanup(&path);
    }

    #[test]
    fn test_mount_filesystem() {
        use super::super::filesystem::EncryptedFilesystem;
        use std::path::Path;

        let path = temp_path("mount_fs");
        cleanup(&path);

        let container = Container::create(
            &path,
            1024 * 1024,
            "TestPassword!",
            4096,
        ).unwrap();

        // Mount the filesystem
        let fs = container.mount_filesystem().unwrap();

        // Verify root directory exists
        let root_attr = fs.getattr(Path::new("/")).unwrap();
        assert_eq!(root_attr.file_type, super::super::filesystem::FileType::Directory);

        cleanup(&path);
    }

    #[test]
    fn test_mount_locked_container() {
        let path = temp_path("mount_locked");
        cleanup(&path);

        let mut container = Container::create(
            &path,
            1024 * 1024,
            "TestPassword!",
            4096,
        ).unwrap();

        // Lock the container
        container.lock();

        // Try to mount - should fail
        let result = container.mount_filesystem();
        assert!(result.is_err());

        cleanup(&path);
    }

    #[test]
    fn test_header_backup_and_restore() {
        let container_path = temp_path("backup_container");
        let backup_path = temp_path("backup.scbak");
        cleanup(&container_path);
        cleanup(&backup_path);

        // Create a container
        let container = Container::create(
            &container_path,
            1024 * 1024,
            "ContainerPassword!",
            4096,
        ).unwrap();

        // Export header backup
        container.export_header_backup(&backup_path, "BackupPassword123!").unwrap();
        assert!(backup_path.exists());

        // Verify backup file has magic bytes
        let mut backup_file = File::open(&backup_path).unwrap();
        let mut magic = [0u8; 8];
        backup_file.read_exact(&mut magic).unwrap();
        assert_eq!(&magic, b"SCBAK01\0");

        drop(container);

        // Open container and restore from backup
        let mut container = Container::open(&container_path, "ContainerPassword!").unwrap();

        // Restore from backup
        container.restore_from_backup(&backup_path, "BackupPassword123!").unwrap();

        // Verify it still works
        assert!(container.verify_header().is_ok());
        assert_eq!(container.key_slots().active_count(), 1);

        cleanup(&container_path);
        cleanup(&backup_path);
    }

    #[test]
    fn test_backup_wrong_password() {
        let container_path = temp_path("backup_wrong_pw");
        let backup_path = temp_path("backup_wrong.scbak");
        cleanup(&container_path);
        cleanup(&backup_path);

        let container = Container::create(
            &container_path,
            1024 * 1024,
            "Password!",
            4096,
        ).unwrap();

        container.export_header_backup(&backup_path, "BackupPass!").unwrap();
        drop(container);

        // Try to restore with wrong password
        let mut container = Container::open(&container_path, "Password!").unwrap();
        let result = container.restore_from_backup(&backup_path, "WrongPassword!");
        assert!(result.is_err());

        cleanup(&container_path);
        cleanup(&backup_path);
    }

    #[test]
    fn test_verify_header() {
        let path = temp_path("verify");
        cleanup(&path);

        let container = Container::create(
            &path,
            1024 * 1024,
            "Test!",
            4096,
        ).unwrap();

        // Verify header is valid
        assert!(container.verify_header().is_ok());

        cleanup(&path);
    }

    #[test]
    fn test_generate_recovery_key() {
        let key1 = Container::generate_recovery_key();
        let key2 = Container::generate_recovery_key();

        // Keys should be 64 hex characters
        assert_eq!(key1.len(), 64);
        assert_eq!(key2.len(), 64);

        // Keys should be different
        assert_ne!(key1, key2);

        // Keys should be valid hex
        assert!(hex::decode(&key1).is_ok());
        assert!(hex::decode(&key2).is_ok());
    }

    #[test]
    fn test_invalid_recovery_key() {
        let path = temp_path("invalid_recovery");
        cleanup(&path);

        let mut container = Container::create(
            &path,
            1024 * 1024,
            "Password1!",
            4096,
        ).unwrap();

        // Try to add invalid recovery key (wrong length)
        let result = container.add_recovery_key("tooshort");
        assert!(result.is_err());

        // Try to add invalid recovery key (non-hex)
        let result = container.add_recovery_key("z".repeat(64).as_str());
        assert!(result.is_err());

        cleanup(&path);
    }

    #[test]
    fn test_export_recovery_key_file() {
        let recovery_key = Container::generate_recovery_key();
        let export_path = temp_path("recovery_key.txt");
        cleanup(&export_path);

        // Export recovery key
        Container::export_recovery_key_file(
            &recovery_key,
            &export_path,
            Some("Test Container"),
        ).unwrap();

        // Verify file was created
        assert!(export_path.exists());

        // Read and verify content
        let content = fs::read_to_string(&export_path).unwrap();
        assert!(content.contains("SECURE CRYPTOR RECOVERY KEY"));
        assert!(content.contains("Test Container"));
        assert!(content.contains(&recovery_key));
        assert!(content.contains("INSTRUCTIONS"));

        cleanup(&export_path);
    }

    #[test]
    fn test_reset_password_without_recovery_key() {
        let path = temp_path("no_recovery");
        cleanup(&path);

        let mut container = Container::create(
            &path,
            1024 * 1024,
            "Password1!",
            4096,
        ).unwrap();

        // Try to reset password with a recovery key that wasn't added
        let fake_recovery_key = Container::generate_recovery_key();
        let result = container.reset_password_with_recovery_key(&fake_recovery_key, "NewPass!");
        assert!(result.is_err());

        cleanup(&path);
    }

    #[test]
    fn test_resize_expand() {
        let path = temp_path("resize_expand");
        cleanup(&path);

        let initial_size = 1024 * 1024; // 1 MB
        let mut container = Container::create(
            &path,
            initial_size,
            "Password!",
            4096,
        ).unwrap();

        // Verify initial size
        assert_eq!(container.size(), initial_size);
        // total_size = front metadata (20KB) + data + backup header (4KB)
        let expected_total = container.metadata_size() + initial_size + HEADER_SIZE as u64;
        assert_eq!(container.total_size(), expected_total);

        // Expand to 2 MB
        let new_size = 2 * 1024 * 1024;
        container.resize(new_size).unwrap();

        // Verify new size (metadata size unchanged after resize)
        assert_eq!(container.size(), new_size);
        let expected_new_total = container.metadata_size() + new_size + HEADER_SIZE as u64;
        assert_eq!(container.total_size(), expected_new_total);

        // Verify file size on disk
        let fs_metadata = fs::metadata(&path).unwrap();
        assert_eq!(fs_metadata.len(), expected_new_total);

        // Close and reopen to verify persistence
        drop(container);
        let container = Container::open(&path, "Password!").unwrap();
        assert_eq!(container.size(), new_size);

        cleanup(&path);
    }

    #[test]
    fn test_resize_shrink() {
        let path = temp_path("resize_shrink");
        cleanup(&path);

        let initial_size = 2 * 1024 * 1024; // 2 MB
        let mut container = Container::create(
            &path,
            initial_size,
            "Password!",
            4096,
        ).unwrap();

        // Shrink to 1 MB
        let new_size = 1024 * 1024;
        container.resize(new_size).unwrap();

        // Verify new size
        assert_eq!(container.size(), new_size);

        // Verify file size on disk (includes backup header)
        let fs_metadata = fs::metadata(&path).unwrap();
        let expected_total = container.metadata_size() + new_size + HEADER_SIZE as u64;
        assert_eq!(fs_metadata.len(), expected_total);

        // Close and reopen to verify persistence
        drop(container);
        let container = Container::open(&path, "Password!").unwrap();
        assert_eq!(container.size(), new_size);

        cleanup(&path);
    }

    #[test]
    fn test_resize_invalid_size() {
        let path = temp_path("resize_invalid");
        cleanup(&path);

        let mut container = Container::create(
            &path,
            1024 * 1024,
            "Password!",
            4096,
        ).unwrap();

        // Try to resize to less than one sector
        let result = container.resize(1024);
        assert!(result.is_err());

        cleanup(&path);
    }

    #[test]
    fn test_resize_locked_container() {
        let path = temp_path("resize_locked");
        cleanup(&path);

        let mut container = Container::create(
            &path,
            1024 * 1024,
            "Password!",
            4096,
        ).unwrap();

        // Lock the container
        container.lock();

        // Try to resize locked container
        let result = container.resize(2 * 1024 * 1024);
        assert!(result.is_err());

        cleanup(&path);
    }

    #[test]
    fn test_size_methods() {
        let path = temp_path("size_methods");
        cleanup(&path);

        let data_size = 1024 * 1024;
        let container = Container::create(
            &path,
            data_size,
            "Password!",
            4096,
        ).unwrap();

        assert_eq!(container.size(), data_size);
        // total_size = front metadata (20KB) + data + backup header (4KB)
        let expected_total = container.metadata_size() + data_size + HEADER_SIZE as u64;
        assert_eq!(container.total_size(), expected_total);

        cleanup(&path);
    }

    #[test]
    fn test_create_hidden_volume() {
        let path = temp_path("hidden_create");
        cleanup(&path);

        let outer_size = 10 * 1024 * 1024; // 10 MB
        let mut outer = Container::create(
            &path,
            outer_size,
            "OuterPassword!",
            4096,
        ).unwrap();

        // Create hidden volume (1 MB at offset 5 MB from start of outer data)
        let hidden_size = 1024 * 1024;
        let offset = 5 * 1024 * 1024;
        outer.create_hidden_volume(hidden_size, "HiddenPassword!", offset).unwrap();

        // Drop to release file handle
        drop(outer);

        // Reopen and verify hidden volume exists
        let outer = Container::open(&path, "OuterPassword!").unwrap();
        assert!(outer.has_hidden_volume(offset));

        cleanup(&path);
    }

    #[test]
    fn test_open_hidden_volume() {
        let path = temp_path("hidden_open");
        cleanup(&path);

        let outer_size = 10 * 1024 * 1024; // 10 MB
        let mut outer = Container::create(
            &path,
            outer_size,
            "OuterPassword!",
            4096,
        ).unwrap();

        // Create hidden volume at offset 5 MB
        let hidden_size = 1024 * 1024;
        let offset = 5 * 1024 * 1024;
        outer.create_hidden_volume(hidden_size, "HiddenPassword!", offset).unwrap();

        // Drop to release file handle
        drop(outer);

        // Reopen outer and then open hidden volume
        let outer = Container::open(&path, "OuterPassword!").unwrap();
        let hidden = outer.open_hidden_volume("HiddenPassword!", offset).unwrap();
        assert!(hidden.is_unlocked());
        assert_eq!(hidden.size(), hidden_size);

        cleanup(&path);
    }

    #[test]
    fn test_hidden_volume_wrong_password() {
        let path = temp_path("hidden_wrong_pass");
        cleanup(&path);

        let outer_size = 10 * 1024 * 1024;
        let mut outer = Container::create(
            &path,
            outer_size,
            "OuterPassword!",
            4096,
        ).unwrap();

        let hidden_size = 1024 * 1024;
        let offset = 5 * 1024 * 1024;
        outer.create_hidden_volume(hidden_size, "HiddenPassword!", offset).unwrap();

        // Drop to release file handle
        drop(outer);

        // Try to open with wrong password
        let outer = Container::open(&path, "OuterPassword!").unwrap();
        let result = outer.open_hidden_volume("WrongPassword!", offset);
        assert!(result.is_err());

        cleanup(&path);
    }

    #[test]
    fn test_hidden_volume_too_large() {
        let path = temp_path("hidden_too_large");
        cleanup(&path);

        let outer_size = 10 * 1024 * 1024;
        let mut outer = Container::create(
            &path,
            outer_size,
            "OuterPassword!",
            4096,
        ).unwrap();

        // Try to create hidden volume larger than available space
        let hidden_size = 20 * 1024 * 1024; // Larger than outer
        let offset = 1024 * 1024;
        let result = outer.create_hidden_volume(hidden_size, "HiddenPassword!", offset);
        assert!(result.is_err());

        cleanup(&path);
    }

    #[test]
    fn test_hidden_volume_invalid_offset() {
        let path = temp_path("hidden_invalid_offset");
        cleanup(&path);

        let outer_size = 10 * 1024 * 1024;
        let mut outer = Container::create(
            &path,
            outer_size,
            "OuterPassword!",
            4096,
        ).unwrap();

        // Try to create hidden volume with offset beyond outer volume
        let hidden_size = 1024 * 1024;
        let offset = 20 * 1024 * 1024; // Larger than outer
        let result = outer.create_hidden_volume(hidden_size, "HiddenPassword!", offset);
        assert!(result.is_err());

        cleanup(&path);
    }

    #[test]
    fn test_hidden_volume_independence() {
        use super::super::filesystem::EncryptedFilesystem;
        use std::path::Path;

        let path = temp_path("hidden_independence");
        cleanup(&path);

        let outer_size = 10 * 1024 * 1024;
        let mut outer = Container::create(
            &path,
            outer_size,
            "OuterPassword!",
            4096,
        ).unwrap();

        // Create hidden volume at offset 5 MB
        let hidden_size = 1024 * 1024;
        let offset = 5 * 1024 * 1024;
        outer.create_hidden_volume(hidden_size, "HiddenPassword!", offset).unwrap();

        // Drop outer to release file handle
        drop(outer);

        // Open outer container and write outer data
        let outer = Container::open(&path, "OuterPassword!").unwrap();
        let mut outer_fs = outer.mount_filesystem().unwrap();
        outer_fs.create(Path::new("/outer.txt"), 0o644).unwrap();
        outer_fs.write(Path::new("/outer.txt"), 0, b"Outer data").unwrap();

        // Verify outer data
        let outer_data = outer_fs.read(Path::new("/outer.txt"), 0, 100).unwrap();
        assert_eq!(&outer_data, b"Outer data");

        drop(outer_fs);

        // Open hidden volume and write different data
        let outer = Container::open(&path, "OuterPassword!").unwrap();
        let hidden = outer.open_hidden_volume("HiddenPassword!", offset).unwrap();
        let mut hidden_fs = hidden.mount_filesystem().unwrap();
        hidden_fs.create(Path::new("/hidden.txt"), 0o644).unwrap();
        hidden_fs.write(Path::new("/hidden.txt"), 0, b"Hidden data").unwrap();

        // Verify hidden filesystem has different data
        let hidden_data = hidden_fs.read(Path::new("/hidden.txt"), 0, 100).unwrap();
        assert_eq!(&hidden_data, b"Hidden data");

        // Verify outer file doesn't exist in hidden volume
        assert!(hidden_fs.getattr(Path::new("/outer.txt")).is_err());

        cleanup(&path);
    }

    #[test]
    fn test_has_hidden_volume() {
        let path = temp_path("has_hidden");
        cleanup(&path);

        let outer_size = 10 * 1024 * 1024;
        let mut outer = Container::create(
            &path,
            outer_size,
            "OuterPassword!",
            4096,
        ).unwrap();

        let offset = 5 * 1024 * 1024;

        // Should not have hidden volume initially
        assert!(!outer.has_hidden_volume(offset));

        // Create hidden volume
        outer.create_hidden_volume(1024 * 1024, "HiddenPassword!", offset).unwrap();

        // Drop to release file handle
        drop(outer);

        // Reopen and check
        let outer = Container::open(&path, "OuterPassword!").unwrap();

        // Should now have hidden volume
        assert!(outer.has_hidden_volume(offset));

        // Check at wrong offset
        assert!(!outer.has_hidden_volume(7 * 1024 * 1024));

        cleanup(&path);
    }
}

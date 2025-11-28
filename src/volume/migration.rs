//! Volume migration utilities
//!
//! This module provides functionality to migrate existing V1 volumes
//! (classical encryption only) to V2 volumes with post-quantum cryptography support.
//!
//! # Migration Process
//!
//! 1. Read and verify V1 volume header
//! 2. Unlock volume with password to get master key
//! 3. Generate new ML-KEM-1024 keypair for PQC
//! 4. Encrypt PQC decapsulation key with master key
//! 5. Create V2 header with PQC metadata
//! 6. Backup original header for rollback
//! 7. Write new V2 header and PQC metadata
//! 8. Verify migration succeeded
//!
//! # Rollback
//!
//! If migration fails, the original V1 header can be restored from backup.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

use super::header::{VolumeHeader, PqVolumeMetadata, PqAlgorithm, HeaderError, HEADER_SIZE, PQC_PADDING_SIZE};
use super::keyslot::{KeySlots, MasterKey, KeySlotError};
use super::container::{PRIMARY_HEADER_OFFSET, KEYSLOTS_OFFSET, KEYSLOTS_SIZE};
use crate::crypto::pqc::{MlKemKeyPair, encapsulate};
use crate::crypto::aes_gcm::AesGcmEncryptor;
use crate::crypto::Encryptor;

/// Errors that can occur during volume migration
#[derive(Debug, Error)]
pub enum MigrationError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Header error
    #[error("Header error: {0}")]
    Header(#[from] HeaderError),

    /// Key slot error
    #[error("Key slot error: {0}")]
    KeySlot(#[from] KeySlotError),

    /// Volume is already V2 with PQC
    #[error("Volume is already V2 with post-quantum cryptography enabled")]
    AlreadyMigrated,

    /// Volume file not found
    #[error("Volume file not found: {0}")]
    VolumeNotFound(PathBuf),

    /// Failed to unlock volume with provided password
    #[error("Failed to unlock volume: incorrect password")]
    UnlockFailed,

    /// Verification failed after migration
    #[error("Migration verification failed: {0}")]
    VerificationFailed(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Backup creation failed
    #[error("Backup creation failed: {0}")]
    BackupFailed(String),

    /// PQC error
    #[error("PQC error: {0}")]
    Pqc(#[from] crate::error::CryptorError),
}

/// Result type for migration operations
pub type Result<T> = std::result::Result<T, MigrationError>;

/// Migration backup containing original header and keyslots
#[derive(Debug)]
pub struct MigrationBackup {
    /// Original V1 header
    pub original_header: VolumeHeader,
    /// Original keyslots
    pub original_keyslots: KeySlots,
    /// Backup file path
    pub backup_path: PathBuf,
}

impl MigrationBackup {
    /// Save backup to disk
    pub fn save(&self) -> Result<()> {
        let mut file = File::create(&self.backup_path)
            .map_err(|e| MigrationError::BackupFailed(e.to_string()))?;

        // Write header
        let header_bytes = self.original_header.to_bytes()?;
        file.write_all(&header_bytes)?;

        // Write keyslots
        let keyslots_bytes = bincode::serialize(&self.original_keyslots)
            .map_err(|e| MigrationError::Serialization(e.to_string()))?;
        file.write_all(&keyslots_bytes)?;

        Ok(())
    }

    /// Restore backup to volume
    pub fn restore(&self, volume_path: &Path) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .open(volume_path)?;

        // Restore header at offset 0
        file.seek(SeekFrom::Start(PRIMARY_HEADER_OFFSET))?;
        let header_bytes = self.original_header.to_bytes()?;
        file.write_all(&header_bytes)?;

        // Restore keyslots at offset 8KB
        file.seek(SeekFrom::Start(KEYSLOTS_OFFSET))?;
        let keyslots_bytes = bincode::serialize(&self.original_keyslots)
            .map_err(|e| MigrationError::Serialization(e.to_string()))?;
        file.write_all(&keyslots_bytes)?;

        file.sync_all()?;

        Ok(())
    }
}

/// Volume migration manager
pub struct VolumeMigration {
    /// Path to the volume file
    volume_path: PathBuf,
    /// Backup of original volume state
    backup: Option<MigrationBackup>,
}

impl VolumeMigration {
    /// Create a new migration manager for a volume
    pub fn new(volume_path: impl Into<PathBuf>) -> Self {
        Self {
            volume_path: volume_path.into(),
            backup: None,
        }
    }

    /// Read and verify V1 volume header
    fn read_v1_header(&self) -> Result<VolumeHeader> {
        let mut file = File::open(&self.volume_path)
            .map_err(|_| MigrationError::VolumeNotFound(self.volume_path.clone()))?;

        // Read header
        file.seek(SeekFrom::Start(PRIMARY_HEADER_OFFSET))?;
        let mut header_bytes = vec![0u8; HEADER_SIZE];
        file.read_exact(&mut header_bytes)?;

        let header = VolumeHeader::from_bytes(&header_bytes)?;

        // Verify it's V1 (not already migrated)
        if header.has_pqc() {
            return Err(MigrationError::AlreadyMigrated);
        }

        Ok(header)
    }

    /// Read keyslots from volume
    fn read_keyslots(&self) -> Result<KeySlots> {
        let mut file = File::open(&self.volume_path)?;

        // Read keyslots at offset 8KB
        file.seek(SeekFrom::Start(KEYSLOTS_OFFSET))?;
        let mut keyslots_bytes = vec![0u8; KEYSLOTS_SIZE];
        file.read_exact(&mut keyslots_bytes)?;

        let keyslots: KeySlots = bincode::deserialize(&keyslots_bytes)
            .map_err(|e| MigrationError::Serialization(e.to_string()))?;

        Ok(keyslots)
    }

    /// Create backup of current volume state
    fn create_backup(&mut self, header: VolumeHeader, keyslots: KeySlots) -> Result<()> {
        let backup_path = self.volume_path.with_extension("backup");

        let backup = MigrationBackup {
            original_header: header,
            original_keyslots: keyslots,
            backup_path,
        };

        backup.save()?;
        self.backup = Some(backup);

        Ok(())
    }

    /// Migrate volume to V2 with PQC support
    ///
    /// # Arguments
    ///
    /// * `password` - Password to unlock the volume
    ///
    /// # Returns
    ///
    /// The generated PQC keypair (caller should save the private key securely)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Volume is already V2
    /// - Password is incorrect
    /// - Migration fails
    /// - Verification fails
    pub fn migrate(&mut self, password: &str) -> Result<MlKemKeyPair> {
        // 1. Read V1 header
        let v1_header = self.read_v1_header()?;

        // 2. Read keyslots
        let mut keyslots = self.read_keyslots()?;

        // 3. Unlock to get master key
        // WARNING: This may destroy all keys if duress password is entered
        let master_key = keyslots.unlock(password)
            .map_err(|_| MigrationError::UnlockFailed)?;

        // 4. Create backup before making changes
        self.create_backup(v1_header.clone(), keyslots)?;

        // 5. Generate PQC keypair
        let pqc_keypair = MlKemKeyPair::generate();

        // 6. Encrypt the decapsulation key with the master key
        let encrypted_dk = self.encrypt_decapsulation_key(&master_key, &pqc_keypair)?;

        // 7. Perform encapsulation to create ciphertext
        let (ciphertext, _shared_secret) = encapsulate(pqc_keypair.encapsulation_key())?;

        // 8. Create PQC metadata with raw byte arrays
        let mut ek_bytes = [0u8; 1568];
        let mut ct_bytes = [0u8; 1568];
        let mut edk_bytes = [0u8; 3196]; // nonce (12) + encrypted DK (3168) + tag (16)

        ek_bytes.copy_from_slice(pqc_keypair.encapsulation_key());
        ct_bytes.copy_from_slice(&ciphertext);
        edk_bytes[..encrypted_dk.len()].copy_from_slice(&encrypted_dk);

        let pqc_metadata = PqVolumeMetadata {
            algorithm: PqAlgorithm::MlKem1024,
            encapsulation_key: ek_bytes,
            ciphertext: ct_bytes,
            encrypted_decapsulation_key: edk_bytes,
            reserved_padding: [0u8; PQC_PADDING_SIZE],
        };

        let pqc_metadata_bytes = pqc_metadata.to_bytes()?;
        let pqc_metadata_size = pqc_metadata_bytes.len() as u32;

        // 9. Create V2 header preserving volume settings
        let v2_header = VolumeHeader::new_with_pqc(
            v1_header.volume_size(),
            v1_header.sector_size(),
            *v1_header.salt(),
            *v1_header.header_iv(),
            pqc_metadata_size,
        );

        // 10. Write V2 header and PQC metadata to volume
        self.write_v2_volume(&v2_header, &pqc_metadata_bytes)?;

        // 11. Verify migration
        self.verify_migration(password, &pqc_keypair)?;

        Ok(pqc_keypair)
    }

    /// Encrypt the PQC decapsulation key with the master key
    fn encrypt_decapsulation_key(
        &self,
        master_key: &MasterKey,
        keypair: &MlKemKeyPair,
    ) -> Result<Vec<u8>> {
        let encryptor = AesGcmEncryptor;
        let nonce = [0u8; 12]; // Use zero nonce for deterministic encryption

        let (_, dk_bytes) = keypair.to_bytes();

        // Convert master key bytes to fixed-size array reference
        let key_array: &[u8; 32] = master_key.as_bytes()
            .try_into()
            .map_err(|_| MigrationError::Encryption("Invalid master key size".to_string()))?;

        let encrypted = encryptor
            .encrypt(key_array, &nonce, &dk_bytes)
            .map_err(|e| MigrationError::Encryption(e.to_string()))?;

        Ok(encrypted)
    }

    /// Write V2 header and PQC metadata to volume
    fn write_v2_volume(&self, header: &VolumeHeader, pqc_metadata: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.volume_path)?;

        // Write V2 header at offset 0
        file.seek(SeekFrom::Start(PRIMARY_HEADER_OFFSET))?;
        let header_bytes = header.to_bytes()?;
        file.write_all(&header_bytes)?;

        // Write PQC metadata at offset 4KB (HEADER_SIZE)
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
        file.write_all(pqc_metadata)?;

        // Sync to disk
        file.sync_all()?;

        Ok(())
    }

    /// Verify that migration succeeded
    fn verify_migration(&self, password: &str, _keypair: &MlKemKeyPair) -> Result<()> {
        // Read back the header
        let mut file = File::open(&self.volume_path)?;
        file.seek(SeekFrom::Start(PRIMARY_HEADER_OFFSET))?;
        let mut header_bytes = vec![0u8; HEADER_SIZE];
        file.read_exact(&mut header_bytes)?;

        let header = VolumeHeader::from_bytes(&header_bytes)?;

        // Verify it's V2 with PQC
        if !header.has_pqc() {
            return Err(MigrationError::VerificationFailed(
                "Header does not have PQC enabled".to_string(),
            ));
        }

        if header.pq_algorithm() != PqAlgorithm::MlKem1024 {
            return Err(MigrationError::VerificationFailed(
                "PQ algorithm is not ML-KEM-1024".to_string(),
            ));
        }

        // Verify keyslots still work
        let mut keyslots = self.read_keyslots()?;
        keyslots.unlock(password)
            .map_err(|_| MigrationError::VerificationFailed(
                "Cannot unlock volume after migration".to_string(),
            ))?;

        // Verify PQC metadata exists and is valid
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
        let mut pqc_bytes = vec![0u8; header.pq_metadata_size() as usize];
        file.read_exact(&mut pqc_bytes)?;

        let _pqc_metadata = PqVolumeMetadata::from_bytes(&pqc_bytes)
            .map_err(|e| MigrationError::VerificationFailed(format!(
                "Invalid PQC metadata: {}", e
            )))?;

        Ok(())
    }

    /// Rollback migration using backup
    pub fn rollback(&self) -> Result<()> {
        let backup = self.backup.as_ref()
            .ok_or_else(|| MigrationError::BackupFailed(
                "No backup available for rollback".to_string()
            ))?;

        backup.restore(&self.volume_path)?;

        Ok(())
    }

    /// Get the backup path if backup exists
    pub fn backup_path(&self) -> Option<&Path> {
        self.backup.as_ref().map(|b| b.backup_path.as_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    

    #[test]
    fn test_migration_manager_creation() {
        let migration = VolumeMigration::new("test.vol");
        assert_eq!(migration.volume_path, PathBuf::from("test.vol"));
        assert!(migration.backup.is_none());
    }

    // Note: Full integration tests require creating actual volume files,
    // which is complex. These should be added in integration tests.
}

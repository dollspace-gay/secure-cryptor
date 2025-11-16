/// Encrypted container format
///
/// This module defines the on-disk format for encrypted containers.
///
/// ## Container Layout
///
/// ```text
/// ┌─────────────────────────────────────────────────────┐
/// │ Volume Header (4 KB)                                │
/// │ - Magic bytes: SECVOL01                             │
/// │ - Version: 1                                        │
/// │ - Cipher algorithm                                  │
/// │ - Volume size, sector size                          │
/// │ - Timestamps                                        │
/// └─────────────────────────────────────────────────────┘
/// ┌─────────────────────────────────────────────────────┐
/// │ Key Slots (4 KB)                                    │
/// │ - Up to 8 key slots                                 │
/// │ - Each slot: active flag, salt, nonce, encrypted MK │
/// └─────────────────────────────────────────────────────┘
/// ┌─────────────────────────────────────────────────────┐
/// │ Encrypted Data Area (variable size)                │
/// │ - Encrypted filesystem data                         │
/// │ - Each sector encrypted with AES-256-GCM            │
/// │ - Sector size from header (typically 4096 bytes)    │
/// └─────────────────────────────────────────────────────┘
/// ```
///
/// Total header size: 8 KB (HEADER_SIZE + KEYSLOTS_SIZE)
///
/// ## Security Features
///
/// - **Master Key Protection**: The volume's master key is encrypted separately
///   in each active key slot using a user-derived key (Argon2id KDF)
/// - **Multi-User Support**: Up to 8 different passwords can unlock the same volume
/// - **Authenticated Encryption**: AES-256-GCM provides both confidentiality and integrity
/// - **Key Derivation**: Argon2id with high memory/time parameters prevents brute-force
/// - **Secure Deletion**: Master keys are zeroized in memory on drop

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use rand::RngCore;
use thiserror::Error;

use super::header::{VolumeHeader, HEADER_SIZE};
use super::keyslot::{KeySlots, MasterKey};

/// Size of the key slots section in bytes (4KB aligned)
pub const KEYSLOTS_SIZE: usize = 4096;

/// Total size of container metadata (header + key slots)
pub const METADATA_SIZE: usize = HEADER_SIZE + KEYSLOTS_SIZE;

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

    /// File handle (kept open while container is in use)
    file: Option<File>,
}

impl Container {
    /// Creates a new encrypted container file
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
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut header_iv);

        // Create volume header
        let header = VolumeHeader::new(size, sector_size, salt, header_iv);

        // Create key slots and add first password
        let mut key_slots = KeySlots::new();
        key_slots.add_slot(&master_key, password)?;

        // Create the container file
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;

        // Write header
        header.write_to(&mut file)?;

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
        // We'll just set the file size for now
        file.set_len(METADATA_SIZE as u64 + size)?;
        file.sync_all()?;

        Ok(Self {
            path,
            header,
            key_slots,
            master_key: Some(master_key),
            file: Some(file),
        })
    }

    /// Opens an existing encrypted container
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

        // Read key slots
        let mut keyslots_bytes = vec![0u8; KEYSLOTS_SIZE];
        file.read_exact(&mut keyslots_bytes)?;
        let key_slots: KeySlots = bincode::deserialize(&keyslots_bytes)?;

        // Unlock with password
        let master_key = key_slots.unlock(password)?;

        Ok(Self {
            path,
            header,
            key_slots,
            master_key: Some(master_key),
            file: Some(file),
        })
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
    pub fn add_password(&mut self, password: &str) -> Result<usize> {
        let master_key = self.master_key.as_ref()
            .ok_or_else(|| super::keyslot::KeySlotError::NoActiveSlots)?;

        let slot_index = self.key_slots.add_slot(master_key, password)?;

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
            .map_err(|e| ContainerError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;

        Ok(fs)
    }

    /// Writes updated key slots to disk
    fn write_keyslots(&mut self) -> Result<()> {
        let file = self.file.as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Container file not open"))?;

        // Seek to key slots position
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

        // Serialize and write
        let keyslots_bytes = bincode::serialize(&self.key_slots)?;
        let mut padded_keyslots = keyslots_bytes;
        padded_keyslots.resize(KEYSLOTS_SIZE, 0);
        file.write_all(&padded_keyslots)?;
        file.sync_all()?;

        Ok(())
    }

    /// Locks the container (clears master key and closes file)
    pub fn lock(&mut self) {
        self.master_key = None;
        self.file = None;
    }

    /// Returns whether the container is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
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
    fn test_add_remove_password() {
        let path = temp_path("passwords");
        cleanup(&path);

        let mut container = Container::create(
            &path,
            1024 * 1024,
            "Password1!",
            4096,
        ).unwrap();

        // Add second password
        let slot_index = container.add_password("Password2!").unwrap();
        assert_eq!(slot_index, 1);
        assert_eq!(container.key_slots().active_count(), 2);

        // Close and reopen with second password
        drop(container);
        let container = Container::open(&path, "Password2!").unwrap();
        assert!(container.is_unlocked());

        // Close and reopen with first password
        drop(container);
        let mut container = Container::open(&path, "Password1!").unwrap();
        assert!(container.is_unlocked());

        // Remove second password
        container.remove_password(1).unwrap();
        assert_eq!(container.key_slots().active_count(), 1);

        // Close and try to open with removed password
        drop(container);
        let result = Container::open(&path, "Password2!");
        assert!(result.is_err());

        // First password should still work
        let container = Container::open(&path, "Password1!").unwrap();
        assert!(container.is_unlocked());

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
    fn test_file_size() {
        let path = temp_path("file_size");
        cleanup(&path);

        let data_size = 1024 * 1024;
        Container::create(&path, data_size, "Test!", 4096).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), METADATA_SIZE as u64 + data_size);

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
}

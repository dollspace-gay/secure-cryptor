/// Encrypted volume management module
///
/// This module provides functionality for creating and managing encrypted
/// volumes that can be mounted as filesystems using FUSE (Linux/macOS)
/// or WinFsp (Windows).

pub mod container;
pub mod filesystem;
pub mod header;
pub mod keyslot;
pub mod operations;
pub mod sector;

pub use container::{Container, METADATA_SIZE, KEYSLOTS_SIZE};
pub use filesystem::{EncryptedFilesystem, FileAttr, FileType, FilesystemError, DirEntry};
pub use header::VolumeHeader;
pub use keyslot::{KeySlots, MasterKey, MAX_KEY_SLOTS};
pub use operations::InMemoryFilesystem;
pub use sector::{SectorCipher, SECTOR_SIZE_512, SECTOR_SIZE_4K};

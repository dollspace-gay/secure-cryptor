//! Encrypted volume management module
//!
//! This module provides functionality for creating and managing encrypted
//! volumes that can be mounted as filesystems using FUSE (Linux/macOS)
//! or WinFsp (Windows).

pub mod automount;
pub mod chunk;
pub mod container;
pub mod filesystem;
pub mod header;
pub mod io;
pub mod keyslot;
pub mod manager;
pub mod migration;
pub mod mount;
pub mod operations;
pub mod sector;

pub use automount::{AutoMountConfig, AutoMountService, AutoMountAuth, VolumeConfig, VolumeConfigBuilder};
pub use chunk::{ChunkMapper, ChunkLocation, ChunkRange, ChunkError, DEFAULT_CHUNK_SIZE};
pub use container::{Container, METADATA_SIZE, KEYSLOTS_SIZE};
pub use filesystem::{EncryptedFilesystem, FileAttr, FileType, FilesystemError, DirEntry};
pub use header::VolumeHeader;
pub use keyslot::{KeySlots, MasterKey, MAX_KEY_SLOTS};
pub use manager::{VolumeManager, VolumeManagerError, MountedVolumeInfo};
pub use migration::{VolumeMigration, MigrationBackup, MigrationError};
pub use mount::{MountOptions, MountError};
pub use operations::InMemoryFilesystem;
pub use sector::{SectorCipher, SECTOR_SIZE_512, SECTOR_SIZE_4K};
pub use io::{
    VolumeIO, VolumeIOError, StorageBackend, FileBackend, MemoryBackend, CacheStats, DEFAULT_CACHE_CAPACITY,
    AsyncStorageBackend, AsyncResult, BlockingAdapter, S3Backend, DropboxBackend, AsyncMemoryBackend,
};

#[cfg(feature = "encrypted-volumes")]
pub use mount::{mount, MountHandle};

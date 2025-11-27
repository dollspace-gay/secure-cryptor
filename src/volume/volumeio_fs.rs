//! VolumeIO-backed filesystem implementation
//!
//! This module provides a filesystem implementation that stores both metadata
//! (directory structure, file attributes) and file content using VolumeIO.
//! All operations go through the encrypted VolumeIO layer, ensuring data is
//! encrypted at rest.
//!
//! ## Architecture
//!
//! ```text
//! +-------------------------+
//! | VolumeIOFilesystem      |
//! | - Superblock            |
//! | - Block/Inode Bitmaps   |
//! | - Inode Table           |
//! | - Journal               |
//! +------------+------------+
//!              |
//!              v
//! +-------------------------+
//! |       VolumeIO          |
//! | (encrypted I/O layer)   |
//! +-------------------------+
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use thiserror::Error;

use super::filesystem::{DirEntry as FsDirEntry, EncryptedFilesystem, FileAttr, FileType, FilesystemError, Result as FsResult};
use super::format::{
    Bitmap, DirEntry, FsState, Inode, InodeType, JournalHeader, Superblock,
    BLOCK_BITMAP_BLOCKS, BLOCK_BITMAP_START, DATA_BLOCKS_START, DIRECT_BLOCKS,
    FS_BLOCK_SIZE, INODE_BITMAP_BLOCKS, INODE_BITMAP_START, INODE_SIZE,
    INODE_TABLE_START, INODES_PER_BLOCK, JOURNAL_BLOCKS,
    JOURNAL_START, MAX_FILENAME_LEN, ROOT_INODE,
};
use super::io::{StorageBackend, VolumeIO, VolumeIOError};
use super::keyslot::MasterKey;

/// Errors specific to VolumeIOFilesystem operations
#[derive(Debug, Error)]
pub enum VolumeIOFsError {
    /// VolumeIO error
    #[error("Volume I/O error: {0}")]
    VolumeIO(#[from] VolumeIOError),

    /// Filesystem format error
    #[error("Format error: {0}")]
    Format(#[from] super::format::FormatError),

    /// Filesystem error
    #[error("Filesystem error: {0}")]
    Filesystem(#[from] FilesystemError),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid operation
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    /// Lock poisoned
    #[error("Lock poisoned")]
    LockPoisoned,

    /// Not initialized
    #[error("Filesystem not initialized")]
    NotInitialized,
}

pub type Result<T> = std::result::Result<T, VolumeIOFsError>;

/// Result of a filesystem check (fsck) operation
#[derive(Debug, Default)]
pub struct FsckResult {
    /// Total inodes scanned
    pub inodes_scanned: u32,
    /// Number of corrupted inodes found
    pub corrupted_inodes: u32,
    /// Number of orphaned blocks (allocated but not referenced)
    pub orphaned_blocks: u32,
    /// Number of lost inodes (allocated but not in any directory)
    pub lost_inodes: u32,
    /// Number of bitmap inconsistencies
    pub bitmap_errors: u32,
    /// Number of errors repaired
    pub errors_repaired: u32,
    /// Detailed error messages
    pub messages: Vec<String>,
}

impl FsckResult {
    /// Returns true if no errors were found
    pub fn is_clean(&self) -> bool {
        self.corrupted_inodes == 0
            && self.orphaned_blocks == 0
            && self.lost_inodes == 0
            && self.bitmap_errors == 0
    }
}

/// VolumeIO-backed filesystem
///
/// Implements a complete filesystem using VolumeIO for encrypted storage.
/// All metadata and file content is stored encrypted.
pub struct VolumeIOFilesystem {
    /// The underlying encrypted I/O layer
    io: Arc<RwLock<Option<VolumeIO>>>,

    /// Cached superblock
    superblock: RwLock<Option<Superblock>>,

    /// Block bitmap (cached)
    block_bitmap: RwLock<Option<Bitmap>>,

    /// Inode bitmap (cached)
    inode_bitmap: RwLock<Option<Bitmap>>,

    /// Inode cache (inode number -> Inode)
    inode_cache: RwLock<HashMap<u32, Inode>>,

    /// Whether filesystem has been modified
    dirty: RwLock<bool>,
}

impl Default for VolumeIOFilesystem {
    fn default() -> Self {
        Self::new()
    }
}

impl VolumeIOFilesystem {
    /// Creates a new uninitialized VolumeIOFilesystem
    ///
    /// Call `init()` to initialize with a master key and backing file,
    /// or `mkfs()` to create a new filesystem.
    pub fn new() -> Self {
        Self {
            io: Arc::new(RwLock::new(None)),
            superblock: RwLock::new(None),
            block_bitmap: RwLock::new(None),
            inode_bitmap: RwLock::new(None),
            inode_cache: RwLock::new(HashMap::new()),
            dirty: RwLock::new(false),
        }
    }

    /// Creates a new filesystem (mkfs equivalent)
    ///
    /// Initializes all on-disk structures:
    /// - Superblock (primary and backup)
    /// - Block and inode bitmaps
    /// - Root directory inode
    /// - Journal header
    ///
    /// # Arguments
    /// * `master_key` - The master encryption key
    /// * `backend` - Storage backend for I/O
    /// * `label` - Volume label
    pub fn mkfs(
        master_key: &MasterKey,
        volume_size: u64,
        backend: Box<dyn StorageBackend>,
        label: &str,
    ) -> Result<Self> {
        // Calculate total blocks
        let total_blocks = volume_size / FS_BLOCK_SIZE as u64;

        if total_blocks < DATA_BLOCKS_START + 10 {
            return Err(VolumeIOFsError::InvalidOperation(
                "Volume too small for filesystem".to_string(),
            ));
        }

        // Create VolumeIO
        let io = VolumeIO::new(master_key, volume_size, backend)?;

        // Create superblock
        let mut superblock = Superblock::new(total_blocks, label);
        superblock.state = FsState::Dirty as u16;
        superblock.update_checksum();

        // Initialize bitmaps
        let block_bitmap_size = (BLOCK_BITMAP_BLOCKS * FS_BLOCK_SIZE as u64) as usize;
        let inode_bitmap_size = (INODE_BITMAP_BLOCKS * FS_BLOCK_SIZE as u64) as usize;

        let mut block_bitmap = Bitmap::new(block_bitmap_size * 8);
        let mut inode_bitmap = Bitmap::new(inode_bitmap_size * 8);

        // Mark metadata blocks as used in block bitmap
        for i in 0..DATA_BLOCKS_START {
            block_bitmap.set(i as usize);
        }

        // Mark reserved inode 0 as used
        inode_bitmap.set(0);

        // Create root directory
        inode_bitmap.set(ROOT_INODE as usize);
        let mut root_inode = Inode::new_directory(0o755);

        // Allocate a data block for root directory
        let root_data_block = DATA_BLOCKS_START as u32;
        block_bitmap.set(root_data_block as usize);
        root_inode.direct[0] = root_data_block;
        root_inode.size = FS_BLOCK_SIZE as u64; // Directory has one block
        root_inode.blocks = (FS_BLOCK_SIZE / 512) as u64;

        // Create filesystem instance
        let fs = Self {
            io: Arc::new(RwLock::new(Some(io))),
            superblock: RwLock::new(Some(superblock.clone())),
            block_bitmap: RwLock::new(Some(block_bitmap.clone())),
            inode_bitmap: RwLock::new(Some(inode_bitmap.clone())),
            inode_cache: RwLock::new(HashMap::new()),
            dirty: RwLock::new(true),
        };

        // Write all structures to disk
        fs.write_superblock(&superblock)?;
        fs.write_block_bitmap(&block_bitmap)?;
        fs.write_inode_bitmap(&inode_bitmap)?;
        fs.write_inode(ROOT_INODE, &root_inode)?;

        // Initialize root directory with . and .. entries
        fs.init_root_directory(ROOT_INODE)?;

        // Initialize journal
        fs.init_journal()?;

        // Cache the root inode
        {
            let mut cache = fs.inode_cache.write().map_err(|_| VolumeIOFsError::LockPoisoned)?;
            cache.insert(ROOT_INODE, root_inode);
        }

        // Mark filesystem as clean
        fs.mark_clean()?;

        // Flush everything
        fs.sync()?;

        Ok(fs)
    }

    /// Opens an existing filesystem
    ///
    /// # Arguments
    /// * `master_key` - The master encryption key
    /// * `backend` - Storage backend for I/O
    pub fn open(
        master_key: &MasterKey,
        volume_size: u64,
        backend: Box<dyn StorageBackend>,
    ) -> Result<Self> {
        // Create VolumeIO
        let io = VolumeIO::new(master_key, volume_size, backend)?;

        let fs = Self {
            io: Arc::new(RwLock::new(Some(io))),
            superblock: RwLock::new(None),
            block_bitmap: RwLock::new(None),
            inode_bitmap: RwLock::new(None),
            inode_cache: RwLock::new(HashMap::new()),
            dirty: RwLock::new(false),
        };

        // Read and validate superblock
        let superblock = fs.read_superblock()?;
        superblock.validate()?;

        if !superblock.verify_checksum() {
            // Try backup superblock
            let backup = fs.read_backup_superblock()?;
            if backup.verify_checksum() {
                *fs.superblock.write().map_err(|_| VolumeIOFsError::LockPoisoned)? = Some(backup);
            } else {
                return Err(VolumeIOFsError::Format(super::format::FormatError::ChecksumMismatch));
            }
        } else {
            *fs.superblock.write().map_err(|_| VolumeIOFsError::LockPoisoned)? = Some(superblock);
        }

        // Load bitmaps
        let block_bitmap = fs.read_block_bitmap()?;
        let inode_bitmap = fs.read_inode_bitmap()?;

        *fs.block_bitmap.write().map_err(|_| VolumeIOFsError::LockPoisoned)? = Some(block_bitmap);
        *fs.inode_bitmap.write().map_err(|_| VolumeIOFsError::LockPoisoned)? = Some(inode_bitmap);

        // Mark as dirty (mounted)
        fs.mark_dirty()?;

        Ok(fs)
    }

    // ========================================================================
    // Low-level I/O operations
    // ========================================================================

    /// Reads a block from the filesystem
    fn read_block(&self, block_num: u64) -> Result<Vec<u8>> {
        let io_guard = self.io.read().map_err(|_| VolumeIOFsError::LockPoisoned)?;
        let io = io_guard.as_ref().ok_or(VolumeIOFsError::NotInitialized)?;

        let offset = block_num * FS_BLOCK_SIZE as u64;
        let mut buf = vec![0u8; FS_BLOCK_SIZE as usize];
        io.read(offset, &mut buf)?;
        Ok(buf)
    }

    /// Writes a block to the filesystem
    fn write_block(&self, block_num: u64, data: &[u8]) -> Result<()> {
        let io_guard = self.io.read().map_err(|_| VolumeIOFsError::LockPoisoned)?;
        let io = io_guard.as_ref().ok_or(VolumeIOFsError::NotInitialized)?;

        let offset = block_num * FS_BLOCK_SIZE as u64;

        // Ensure we write a full block
        let mut block_data = vec![0u8; FS_BLOCK_SIZE as usize];
        let copy_len = data.len().min(FS_BLOCK_SIZE as usize);
        block_data[..copy_len].copy_from_slice(&data[..copy_len]);

        io.write(offset, &block_data)?;
        *self.dirty.write().map_err(|_| VolumeIOFsError::LockPoisoned)? = true;
        Ok(())
    }

    /// Reads multiple consecutive blocks
    fn read_blocks(&self, start_block: u64, count: u64) -> Result<Vec<u8>> {
        let io_guard = self.io.read().map_err(|_| VolumeIOFsError::LockPoisoned)?;
        let io = io_guard.as_ref().ok_or(VolumeIOFsError::NotInitialized)?;

        let offset = start_block * FS_BLOCK_SIZE as u64;
        let size = count * FS_BLOCK_SIZE as u64;
        let mut buf = vec![0u8; size as usize];
        io.read(offset, &mut buf)?;
        Ok(buf)
    }

    /// Writes multiple consecutive blocks
    fn write_blocks(&self, start_block: u64, data: &[u8]) -> Result<()> {
        let io_guard = self.io.read().map_err(|_| VolumeIOFsError::LockPoisoned)?;
        let io = io_guard.as_ref().ok_or(VolumeIOFsError::NotInitialized)?;

        let offset = start_block * FS_BLOCK_SIZE as u64;
        io.write(offset, data)?;
        *self.dirty.write().map_err(|_| VolumeIOFsError::LockPoisoned)? = true;
        Ok(())
    }

    // ========================================================================
    // Superblock operations
    // ========================================================================

    /// Reads the primary superblock
    fn read_superblock(&self) -> Result<Superblock> {
        let data = self.read_block(0)?;
        self.deserialize_superblock(&data)
    }

    /// Reads the backup superblock
    fn read_backup_superblock(&self) -> Result<Superblock> {
        let data = self.read_block(1)?;
        self.deserialize_superblock(&data)
    }

    /// Writes the superblock (both primary and backup)
    fn write_superblock(&self, sb: &Superblock) -> Result<()> {
        let data = self.serialize_superblock(sb)?;
        self.write_block(0, &data)?;
        self.write_block(1, &data)?; // Backup
        Ok(())
    }

    fn serialize_superblock(&self, sb: &Superblock) -> Result<Vec<u8>> {
        bincode::serialize(sb).map_err(|e| VolumeIOFsError::Serialization(e.to_string()))
    }

    fn deserialize_superblock(&self, data: &[u8]) -> Result<Superblock> {
        bincode::deserialize(data).map_err(|e| VolumeIOFsError::Serialization(e.to_string()))
    }

    /// Gets a reference to the cached superblock
    fn get_superblock(&self) -> Result<Superblock> {
        let guard = self.superblock.read().map_err(|_| VolumeIOFsError::LockPoisoned)?;
        guard.clone().ok_or(VolumeIOFsError::NotInitialized)
    }

    /// Updates the cached superblock
    fn update_superblock<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Superblock),
    {
        let mut guard = self.superblock.write().map_err(|_| VolumeIOFsError::LockPoisoned)?;
        let sb = guard.as_mut().ok_or(VolumeIOFsError::NotInitialized)?;
        f(sb);
        sb.update_checksum();
        let sb_clone = sb.clone();
        drop(guard);
        self.write_superblock(&sb_clone)
    }

    // ========================================================================
    // Bitmap operations
    // ========================================================================

    /// Reads the block bitmap from disk
    fn read_block_bitmap(&self) -> Result<Bitmap> {
        let data = self.read_blocks(BLOCK_BITMAP_START, BLOCK_BITMAP_BLOCKS)?;
        Ok(Bitmap::from_data(data))
    }

    /// Writes the block bitmap to disk
    fn write_block_bitmap(&self, bitmap: &Bitmap) -> Result<()> {
        self.write_blocks(BLOCK_BITMAP_START, bitmap.data())
    }

    /// Reads the inode bitmap from disk
    fn read_inode_bitmap(&self) -> Result<Bitmap> {
        let data = self.read_blocks(INODE_BITMAP_START, INODE_BITMAP_BLOCKS)?;
        Ok(Bitmap::from_data(data))
    }

    /// Writes the inode bitmap to disk
    fn write_inode_bitmap(&self, bitmap: &Bitmap) -> Result<()> {
        self.write_blocks(INODE_BITMAP_START, bitmap.data())
    }

    /// Allocates a free block
    fn alloc_block(&self) -> Result<u32> {
        let mut guard = self.block_bitmap.write().map_err(|_| VolumeIOFsError::LockPoisoned)?;
        let bitmap = guard.as_mut().ok_or(VolumeIOFsError::NotInitialized)?;

        // Find first free block starting after metadata
        let block = bitmap
            .find_first_clear(DATA_BLOCKS_START as usize)
            .ok_or(super::format::FormatError::NoFreeBlocks)?;

        bitmap.set(block);
        let bitmap_clone = bitmap.clone();
        drop(guard);

        // Update superblock free count
        self.update_superblock(|sb| {
            sb.free_blocks = sb.free_blocks.saturating_sub(1);
        })?;

        // Write bitmap to disk
        self.write_block_bitmap(&bitmap_clone)?;

        Ok(block as u32)
    }

    /// Frees a block
    fn free_block(&self, block: u32) -> Result<()> {
        if (block as u64) < DATA_BLOCKS_START {
            return Err(VolumeIOFsError::InvalidOperation(
                "Cannot free metadata block".to_string(),
            ));
        }

        let mut guard = self.block_bitmap.write().map_err(|_| VolumeIOFsError::LockPoisoned)?;
        let bitmap = guard.as_mut().ok_or(VolumeIOFsError::NotInitialized)?;

        bitmap.clear(block as usize);
        let bitmap_clone = bitmap.clone();
        drop(guard);

        // Update superblock free count
        self.update_superblock(|sb| {
            sb.free_blocks = sb.free_blocks.saturating_add(1);
        })?;

        self.write_block_bitmap(&bitmap_clone)?;
        Ok(())
    }

    /// Allocates a free inode
    fn alloc_inode(&self) -> Result<u32> {
        let mut guard = self.inode_bitmap.write().map_err(|_| VolumeIOFsError::LockPoisoned)?;
        let bitmap = guard.as_mut().ok_or(VolumeIOFsError::NotInitialized)?;

        // Find first free inode (skip 0 which is reserved)
        let inode = bitmap
            .find_first_clear(1)
            .ok_or(super::format::FormatError::NoFreeInodes)?;

        bitmap.set(inode);
        let bitmap_clone = bitmap.clone();
        drop(guard);

        // Update superblock free count
        self.update_superblock(|sb| {
            sb.free_inodes = sb.free_inodes.saturating_sub(1);
        })?;

        self.write_inode_bitmap(&bitmap_clone)?;

        Ok(inode as u32)
    }

    /// Frees an inode
    fn free_inode(&self, inode_num: u32) -> Result<()> {
        if inode_num == 0 || inode_num == ROOT_INODE {
            return Err(VolumeIOFsError::InvalidOperation(
                "Cannot free reserved inode".to_string(),
            ));
        }

        let mut guard = self.inode_bitmap.write().map_err(|_| VolumeIOFsError::LockPoisoned)?;
        let bitmap = guard.as_mut().ok_or(VolumeIOFsError::NotInitialized)?;

        bitmap.clear(inode_num as usize);
        let bitmap_clone = bitmap.clone();
        drop(guard);

        // Update superblock free count
        self.update_superblock(|sb| {
            sb.free_inodes = sb.free_inodes.saturating_add(1);
        })?;

        // Remove from cache
        {
            let mut cache = self.inode_cache.write().map_err(|_| VolumeIOFsError::LockPoisoned)?;
            cache.remove(&inode_num);
        }

        self.write_inode_bitmap(&bitmap_clone)?;
        Ok(())
    }

    // ========================================================================
    // Inode operations
    // ========================================================================

    /// Calculates the block and offset for an inode
    fn inode_location(&self, inode_num: u32) -> (u64, usize) {
        let inode_index = inode_num as u64;
        let block = INODE_TABLE_START + (inode_index / INODES_PER_BLOCK as u64);
        let offset = ((inode_index % INODES_PER_BLOCK as u64) * INODE_SIZE as u64) as usize;
        (block, offset)
    }

    /// Reads an inode from disk (or cache)
    fn read_inode(&self, inode_num: u32) -> Result<Inode> {
        // Check cache first
        {
            let cache = self.inode_cache.read().map_err(|_| VolumeIOFsError::LockPoisoned)?;
            if let Some(inode) = cache.get(&inode_num) {
                return Ok(inode.clone());
            }
        }

        // Read from disk
        let (block, offset) = self.inode_location(inode_num);
        let block_data = self.read_block(block)?;

        let inode: Inode = bincode::deserialize(&block_data[offset..offset + INODE_SIZE as usize])
            .map_err(|e| VolumeIOFsError::Serialization(e.to_string()))?;

        // Cache the inode
        {
            let mut cache = self.inode_cache.write().map_err(|_| VolumeIOFsError::LockPoisoned)?;
            cache.insert(inode_num, inode.clone());
        }

        Ok(inode)
    }

    /// Writes an inode to disk without updating cache (used by sync to avoid deadlock)
    fn write_inode_no_cache(&self, inode_num: u32, inode: &Inode) -> Result<()> {
        let (block, offset) = self.inode_location(inode_num);

        // Read the block, modify the inode, write back
        let mut block_data = self.read_block(block)?;

        let inode_bytes = bincode::serialize(inode)
            .map_err(|e| VolumeIOFsError::Serialization(e.to_string()))?;

        block_data[offset..offset + inode_bytes.len()].copy_from_slice(&inode_bytes);
        self.write_block(block, &block_data)?;

        Ok(())
    }

    /// Writes an inode to disk (and updates cache)
    fn write_inode(&self, inode_num: u32, inode: &Inode) -> Result<()> {
        self.write_inode_no_cache(inode_num, inode)?;

        // Update cache
        {
            let mut cache = self.inode_cache.write().map_err(|_| VolumeIOFsError::LockPoisoned)?;
            cache.insert(inode_num, inode.clone());
        }

        Ok(())
    }

    // ========================================================================
    // Directory operations
    // ========================================================================

    /// Initializes the root directory with . and .. entries
    fn init_root_directory(&self, root_inode: u32) -> Result<()> {
        let mut entries = Vec::new();

        // Add "." entry
        let dot = DirEntry::new(root_inode, ".", InodeType::Directory);
        entries.push(dot);

        // Add ".." entry (parent of root is root)
        let dotdot = DirEntry::new(root_inode, "..", InodeType::Directory);
        entries.push(dotdot);

        self.write_dir_entries(root_inode, &entries)
    }

    /// Initializes the journal
    fn init_journal(&self) -> Result<()> {
        let header = JournalHeader::new(JOURNAL_BLOCKS as u32);
        let header_bytes = bincode::serialize(&header)
            .map_err(|e| VolumeIOFsError::Serialization(e.to_string()))?;

        self.write_block(JOURNAL_START, &header_bytes)?;

        // Zero out the rest of the journal
        let zeros = vec![0u8; FS_BLOCK_SIZE as usize];
        for i in 1..JOURNAL_BLOCKS {
            self.write_block(JOURNAL_START + i, &zeros)?;
        }

        Ok(())
    }

    /// Reads directory entries from an inode's data blocks
    fn read_dir_entries(&self, inode_num: u32) -> Result<Vec<DirEntry>> {
        let inode = self.read_inode(inode_num)?;
        if !inode.is_dir() {
            return Err(VolumeIOFsError::Filesystem(FilesystemError::NotADirectory(
                PathBuf::from(format!("inode {}", inode_num)),
            )));
        }

        let mut entries = Vec::new();
        let mut bytes_read = 0u64;

        // Read from direct blocks
        for &block_num in &inode.direct {
            if block_num == 0 || bytes_read >= inode.size {
                break;
            }

            let block_data = self.read_block(block_num as u64)?;
            let block_entries = self.parse_dir_entries(&block_data)?;
            entries.extend(block_entries);
            bytes_read += FS_BLOCK_SIZE as u64;
        }

        // TODO: Handle indirect blocks for large directories

        Ok(entries)
    }

    /// Parses directory entries from a block
    fn parse_dir_entries(&self, data: &[u8]) -> Result<Vec<DirEntry>> {
        let mut entries = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            // Read entry header
            if offset + 8 > data.len() {
                break;
            }

            let inode = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
            let rec_len = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
            let name_len = data[offset + 6];
            let file_type = data[offset + 7];

            if rec_len == 0 {
                break; // End of entries
            }

            if inode != 0 && name_len > 0 {
                let name_start = offset + 8;
                let name_end = name_start + name_len as usize;
                if name_end <= data.len() {
                    let name = data[name_start..name_end].to_vec();
                    entries.push(DirEntry {
                        inode,
                        rec_len,
                        name_len,
                        file_type,
                        name,
                    });
                }
            }

            offset += rec_len as usize;
        }

        Ok(entries)
    }

    /// Writes directory entries to an inode's data blocks
    fn write_dir_entries(&self, inode_num: u32, entries: &[DirEntry]) -> Result<()> {
        let mut inode = self.read_inode(inode_num)?;

        // Serialize all entries
        let mut data = Vec::new();
        for entry in entries {
            // Write entry header
            data.extend_from_slice(&entry.inode.to_le_bytes());
            data.extend_from_slice(&entry.rec_len.to_le_bytes());
            data.push(entry.name_len);
            data.push(entry.file_type);
            data.extend_from_slice(&entry.name[..entry.name_len as usize]);

            // Pad to rec_len
            let padding = entry.rec_len as usize - 8 - entry.name_len as usize;
            data.extend(std::iter::repeat_n(0u8, padding));
        }

        // Pad to block boundary
        let block_count = data.len().div_ceil(FS_BLOCK_SIZE as usize);
        data.resize(block_count * FS_BLOCK_SIZE as usize, 0);

        // Ensure we have enough blocks allocated
        for i in 0..block_count {
            if inode.direct[i] == 0 {
                inode.direct[i] = self.alloc_block()?;
            }
        }

        // Write blocks
        for (i, chunk) in data.chunks(FS_BLOCK_SIZE as usize).enumerate() {
            self.write_block(inode.direct[i] as u64, chunk)?;
        }

        // Update inode size
        inode.size = data.len() as u64;
        inode.blocks = (data.len() / 512) as u64;
        self.write_inode(inode_num, &inode)?;

        Ok(())
    }

    /// Looks up a name in a directory
    fn dir_lookup(&self, dir_inode: u32, name: &str) -> Result<Option<u32>> {
        let entries = self.read_dir_entries(dir_inode)?;
        for entry in entries {
            if let Ok(entry_name) = entry.name_str() {
                if entry_name == name {
                    return Ok(Some(entry.inode));
                }
            }
        }
        Ok(None)
    }

    /// Adds an entry to a directory
    fn dir_add_entry(&self, dir_inode: u32, name: &str, inode: u32, file_type: InodeType) -> Result<()> {
        if name.len() > MAX_FILENAME_LEN {
            return Err(VolumeIOFsError::Format(super::format::FormatError::NameTooLong(name.len())));
        }

        let mut entries = self.read_dir_entries(dir_inode)?;
        entries.push(DirEntry::new(inode, name, file_type));
        self.write_dir_entries(dir_inode, &entries)
    }

    /// Removes an entry from a directory
    fn dir_remove_entry(&self, dir_inode: u32, name: &str) -> Result<()> {
        let entries = self.read_dir_entries(dir_inode)?;
        let new_entries: Vec<DirEntry> = entries
            .into_iter()
            .filter(|e| e.name_str().map(|n| n != name).unwrap_or(true))
            .collect();
        self.write_dir_entries(dir_inode, &new_entries)
    }

    // ========================================================================
    // Path resolution
    // ========================================================================

    /// Resolves a path to an inode number
    fn resolve_path(&self, path: &Path) -> Result<u32> {
        let mut current_inode = ROOT_INODE;

        for component in path.components() {
            use std::path::Component;
            match component {
                Component::RootDir => {
                    current_inode = ROOT_INODE;
                }
                Component::Normal(name) => {
                    let name_str = name.to_str().ok_or_else(|| {
                        VolumeIOFsError::Filesystem(FilesystemError::InvalidFileName(
                            name.to_string_lossy().to_string(),
                        ))
                    })?;

                    current_inode = self
                        .dir_lookup(current_inode, name_str)?
                        .ok_or_else(|| {
                            VolumeIOFsError::Filesystem(FilesystemError::NotFound(path.to_path_buf()))
                        })?;
                }
                Component::CurDir => {
                    // Stay in current directory
                }
                Component::ParentDir => {
                    // Look up ".."
                    current_inode = self
                        .dir_lookup(current_inode, "..")?
                        .ok_or_else(|| {
                            VolumeIOFsError::Filesystem(FilesystemError::NotFound(path.to_path_buf()))
                        })?;
                }
                Component::Prefix(_) => {
                    // Windows-specific, ignore
                }
            }
        }

        Ok(current_inode)
    }

    /// Resolves a path's parent directory and returns (parent_inode, filename)
    fn resolve_parent(&self, path: &Path) -> Result<(u32, String)> {
        let parent = path.parent().unwrap_or(Path::new("/"));
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                VolumeIOFsError::Filesystem(FilesystemError::InvalidFileName(
                    path.to_string_lossy().to_string(),
                ))
            })?
            .to_string();

        let parent_inode = self.resolve_path(parent)?;
        Ok((parent_inode, name))
    }

    // ========================================================================
    // File data operations
    // ========================================================================

    /// Reads file data at the given offset
    fn read_file_data(&self, inode_num: u32, offset: u64, size: u32) -> Result<Vec<u8>> {
        let inode = self.read_inode(inode_num)?;

        if offset >= inode.size {
            return Ok(Vec::new());
        }

        let available = (inode.size - offset) as u32;
        let to_read = size.min(available);
        let mut result = Vec::with_capacity(to_read as usize);

        let mut remaining = to_read;
        let mut current_offset = offset;

        while remaining > 0 {
            let block_index = (current_offset / FS_BLOCK_SIZE as u64) as usize;
            let block_offset = (current_offset % FS_BLOCK_SIZE as u64) as usize;

            // Get block number from inode
            let block_num = self.get_data_block(&inode, block_index)?;
            if block_num == 0 {
                // Sparse file - return zeros
                let zeros_to_add = remaining.min((FS_BLOCK_SIZE as usize - block_offset) as u32);
                result.extend(std::iter::repeat_n(0u8, zeros_to_add as usize));
                current_offset += zeros_to_add as u64;
                remaining -= zeros_to_add;
                continue;
            }

            let block_data = self.read_block(block_num as u64)?;
            let bytes_from_block = remaining.min((FS_BLOCK_SIZE as usize - block_offset) as u32);
            result.extend_from_slice(&block_data[block_offset..block_offset + bytes_from_block as usize]);

            current_offset += bytes_from_block as u64;
            remaining -= bytes_from_block;
        }

        Ok(result)
    }

    /// Writes file data at the given offset
    fn write_file_data(&self, inode_num: u32, offset: u64, data: &[u8]) -> Result<u32> {
        let mut inode = self.read_inode(inode_num)?;

        let mut written = 0u32;
        let mut current_offset = offset;

        while written < data.len() as u32 {
            let block_index = (current_offset / FS_BLOCK_SIZE as u64) as usize;
            let block_offset = (current_offset % FS_BLOCK_SIZE as u64) as usize;

            // Get or allocate block
            let block_num = self.get_or_alloc_data_block(&mut inode, block_index)?;

            // Read existing block data
            let mut block_data = self.read_block(block_num as u64)?;

            // Calculate how much to write to this block
            let bytes_to_block = (data.len() as u32 - written).min((FS_BLOCK_SIZE as usize - block_offset) as u32);

            // Copy data into block
            let src_start = written as usize;
            let src_end = src_start + bytes_to_block as usize;
            block_data[block_offset..block_offset + bytes_to_block as usize]
                .copy_from_slice(&data[src_start..src_end]);

            // Write block back
            self.write_block(block_num as u64, &block_data)?;

            current_offset += bytes_to_block as u64;
            written += bytes_to_block;
        }

        // Update inode size if we wrote past the end
        let new_size = offset + data.len() as u64;
        if new_size > inode.size {
            inode.size = new_size;
            inode.blocks = new_size.div_ceil(512);
        }

        // Update modification time
        inode.mtime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.write_inode(inode_num, &inode)?;

        Ok(written)
    }

    /// Gets a data block number from an inode (handling indirect blocks)
    fn get_data_block(&self, inode: &Inode, block_index: usize) -> Result<u32> {
        if block_index < DIRECT_BLOCKS {
            return Ok(inode.direct[block_index]);
        }

        let indirect_index = block_index - DIRECT_BLOCKS;
        let ptrs_per_block = FS_BLOCK_SIZE as usize / 4;

        if indirect_index < ptrs_per_block {
            // Single indirect
            if inode.indirect == 0 {
                return Ok(0);
            }
            let indirect_block = self.read_block(inode.indirect as u64)?;
            let ptr_offset = indirect_index * 4;
            let block_num = u32::from_le_bytes([
                indirect_block[ptr_offset],
                indirect_block[ptr_offset + 1],
                indirect_block[ptr_offset + 2],
                indirect_block[ptr_offset + 3],
            ]);
            return Ok(block_num);
        }

        let double_index = indirect_index - ptrs_per_block;
        if double_index < ptrs_per_block * ptrs_per_block {
            // Double indirect
            if inode.double_indirect == 0 {
                return Ok(0);
            }

            let first_level = double_index / ptrs_per_block;
            let second_level = double_index % ptrs_per_block;

            let double_block = self.read_block(inode.double_indirect as u64)?;
            let first_ptr_offset = first_level * 4;
            let first_block = u32::from_le_bytes([
                double_block[first_ptr_offset],
                double_block[first_ptr_offset + 1],
                double_block[first_ptr_offset + 2],
                double_block[first_ptr_offset + 3],
            ]);

            if first_block == 0 {
                return Ok(0);
            }

            let second_block_data = self.read_block(first_block as u64)?;
            let second_ptr_offset = second_level * 4;
            let block_num = u32::from_le_bytes([
                second_block_data[second_ptr_offset],
                second_block_data[second_ptr_offset + 1],
                second_block_data[second_ptr_offset + 2],
                second_block_data[second_ptr_offset + 3],
            ]);
            return Ok(block_num);
        }

        Err(VolumeIOFsError::InvalidOperation("File too large".to_string()))
    }

    /// Gets or allocates a data block (handling indirect blocks)
    fn get_or_alloc_data_block(&self, inode: &mut Inode, block_index: usize) -> Result<u32> {
        if block_index < DIRECT_BLOCKS {
            if inode.direct[block_index] == 0 {
                inode.direct[block_index] = self.alloc_block()?;
            }
            return Ok(inode.direct[block_index]);
        }

        let indirect_index = block_index - DIRECT_BLOCKS;
        let ptrs_per_block = FS_BLOCK_SIZE as usize / 4;

        if indirect_index < ptrs_per_block {
            // Single indirect
            if inode.indirect == 0 {
                inode.indirect = self.alloc_block()?;
                // Zero the indirect block
                self.write_block(inode.indirect as u64, &vec![0u8; FS_BLOCK_SIZE as usize])?;
            }

            let mut indirect_block = self.read_block(inode.indirect as u64)?;
            let ptr_offset = indirect_index * 4;
            let mut block_num = u32::from_le_bytes([
                indirect_block[ptr_offset],
                indirect_block[ptr_offset + 1],
                indirect_block[ptr_offset + 2],
                indirect_block[ptr_offset + 3],
            ]);

            if block_num == 0 {
                block_num = self.alloc_block()?;
                let bytes = block_num.to_le_bytes();
                indirect_block[ptr_offset..ptr_offset + 4].copy_from_slice(&bytes);
                self.write_block(inode.indirect as u64, &indirect_block)?;
            }

            return Ok(block_num);
        }

        // TODO: Implement double indirect allocation
        Err(VolumeIOFsError::InvalidOperation(
            "Double indirect blocks not yet implemented".to_string(),
        ))
    }

    // ========================================================================
    // State management
    // ========================================================================

    /// Marks the filesystem as dirty (mounted)
    fn mark_dirty(&self) -> Result<()> {
        self.update_superblock(|sb| {
            sb.state = FsState::Dirty as u16;
            sb.mount_count += 1;
            sb.last_mount_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
        })
    }

    /// Marks the filesystem as clean (unmounted)
    fn mark_clean(&self) -> Result<()> {
        self.update_superblock(|sb| {
            sb.state = FsState::Clean as u16;
            sb.last_write_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
        })
    }

    /// Flushes all cached data to disk
    pub fn sync(&self) -> Result<()> {
        // Flush inode cache - collect entries first to avoid holding lock during writes
        let entries: Vec<(u32, Inode)> = {
            let cache = self.inode_cache.read().map_err(|_| VolumeIOFsError::LockPoisoned)?;
            cache.iter().map(|(&k, v)| (k, v.clone())).collect()
        };

        for (inode_num, inode) in entries {
            self.write_inode_no_cache(inode_num, &inode)?;
        }

        // Flush block bitmap
        if let Some(bitmap) = self.block_bitmap.read().map_err(|_| VolumeIOFsError::LockPoisoned)?.as_ref() {
            self.write_block_bitmap(bitmap)?;
        }

        // Flush inode bitmap
        if let Some(bitmap) = self.inode_bitmap.read().map_err(|_| VolumeIOFsError::LockPoisoned)?.as_ref() {
            self.write_inode_bitmap(bitmap)?;
        }

        // Flush superblock
        if let Some(sb) = self.superblock.read().map_err(|_| VolumeIOFsError::LockPoisoned)?.as_ref() {
            self.write_superblock(sb)?;
        }

        // Flush VolumeIO
        let io_guard = self.io.read().map_err(|_| VolumeIOFsError::LockPoisoned)?;
        if let Some(io) = io_guard.as_ref() {
            io.flush()?;
        }

        *self.dirty.write().map_err(|_| VolumeIOFsError::LockPoisoned)? = false;
        Ok(())
    }

    /// Converts an Inode to FileAttr
    fn inode_to_file_attr(&self, inode: &Inode) -> FileAttr {
        let file_type = match inode.file_type() {
            InodeType::File => FileType::RegularFile,
            InodeType::Directory => FileType::Directory,
            InodeType::Symlink => FileType::Symlink,
        };

        FileAttr {
            size: inode.size,
            nlink: inode.nlink as u32,
            file_type,
            perm: inode.permissions(),
            uid: inode.uid,
            gid: inode.gid,
            atime: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(inode.atime),
            mtime: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(inode.mtime),
            ctime: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(inode.ctime),
        }
    }

    /// Gets filesystem statistics
    pub fn get_statfs(&self) -> Result<(u64, u64, u64)> {
        let sb = self.get_superblock()?;
        let total_bytes = sb.total_blocks * sb.block_size as u64;
        let free_bytes = sb.free_blocks * sb.block_size as u64;
        Ok((total_bytes, free_bytes, free_bytes))
    }

    // ========================================================================
    // Public inode-based API for FUSE/WinFsp integration
    // ========================================================================

    /// Gets an inode by number (public API for FUSE)
    pub fn get_inode(&self, inode_num: u32) -> Result<Inode> {
        self.read_inode(inode_num)
    }

    /// Updates an inode (public API for FUSE)
    pub fn set_inode(&self, inode_num: u32, inode: &Inode) -> Result<()> {
        self.write_inode(inode_num, inode)
    }

    /// Looks up a name in a directory, returning the inode number if found
    pub fn lookup(&self, dir_inode: u32, name: &str) -> Result<Option<u32>> {
        self.dir_lookup(dir_inode, name)
    }

    /// Reads directory entries for an inode
    pub fn readdir_by_inode(&self, inode_num: u32) -> Result<Vec<DirEntry>> {
        self.read_dir_entries(inode_num)
    }

    /// Reads file data by inode number
    pub fn read_by_inode(&self, inode_num: u32, offset: u64, size: u32) -> Result<Vec<u8>> {
        self.read_file_data(inode_num, offset, size)
    }

    /// Writes file data by inode number
    pub fn write_by_inode(&self, inode_num: u32, offset: u64, data: &[u8]) -> Result<u32> {
        self.write_file_data(inode_num, offset, data)
    }

    /// Creates a new file in a directory, returning the new inode number
    pub fn create_file(&self, parent_inode: u32, name: &str, mode: u16) -> Result<u32> {
        // Check if already exists
        if self.dir_lookup(parent_inode, name)?.is_some() {
            return Err(VolumeIOFsError::Filesystem(FilesystemError::AlreadyExists(
                PathBuf::from(name),
            )));
        }

        // Allocate inode
        let inode_num = self.alloc_inode()?;

        // Create inode
        let inode = Inode::new_file(mode);
        self.write_inode(inode_num, &inode)?;

        // Add to parent directory
        self.dir_add_entry(parent_inode, name, inode_num, InodeType::File)?;

        Ok(inode_num)
    }

    /// Creates a new directory, returning the new inode number
    pub fn create_directory(&self, parent_inode: u32, name: &str, mode: u16) -> Result<u32> {
        // Check if already exists
        if self.dir_lookup(parent_inode, name)?.is_some() {
            return Err(VolumeIOFsError::Filesystem(FilesystemError::AlreadyExists(
                PathBuf::from(name),
            )));
        }

        // Allocate inode
        let inode_num = self.alloc_inode()?;

        // Create directory inode
        let mut inode = Inode::new_directory(mode);

        // Allocate a data block for the directory
        let data_block = self.alloc_block()?;
        inode.direct[0] = data_block;
        inode.size = FS_BLOCK_SIZE as u64;
        inode.blocks = (FS_BLOCK_SIZE / 512) as u64;

        self.write_inode(inode_num, &inode)?;

        // Initialize directory with . and .. entries
        let entries = vec![
            DirEntry::new(inode_num, ".", InodeType::Directory),
            DirEntry::new(parent_inode, "..", InodeType::Directory),
        ];
        self.write_dir_entries(inode_num, &entries)?;

        // Add to parent directory
        self.dir_add_entry(parent_inode, name, inode_num, InodeType::Directory)?;

        // Update parent nlink (for ..)
        let mut parent = self.read_inode(parent_inode)?;
        parent.nlink += 1;
        self.write_inode(parent_inode, &parent)?;

        Ok(inode_num)
    }

    /// Removes a file from a directory
    pub fn remove_file(&self, parent_inode: u32, name: &str) -> Result<()> {
        // Look up the inode
        let inode_num = self.dir_lookup(parent_inode, name)?
            .ok_or_else(|| VolumeIOFsError::Filesystem(FilesystemError::NotFound(
                PathBuf::from(name),
            )))?;

        let inode = self.read_inode(inode_num)?;

        if inode.is_dir() {
            return Err(VolumeIOFsError::Filesystem(FilesystemError::IsADirectory(
                PathBuf::from(name),
            )));
        }

        // Remove from parent directory
        self.dir_remove_entry(parent_inode, name)?;

        // Free data blocks
        for &block in &inode.direct {
            if block != 0 {
                self.free_block(block)?;
            }
        }
        // TODO: Free indirect blocks

        // Free inode
        self.free_inode(inode_num)?;

        Ok(())
    }

    /// Removes a directory
    pub fn remove_directory(&self, parent_inode: u32, name: &str) -> Result<()> {
        // Look up the inode
        let inode_num = self.dir_lookup(parent_inode, name)?
            .ok_or_else(|| VolumeIOFsError::Filesystem(FilesystemError::NotFound(
                PathBuf::from(name),
            )))?;

        let inode = self.read_inode(inode_num)?;

        if !inode.is_dir() {
            return Err(VolumeIOFsError::Filesystem(FilesystemError::NotADirectory(
                PathBuf::from(name),
            )));
        }

        // Check if directory is empty (only . and ..)
        let entries = self.read_dir_entries(inode_num)?;
        let non_dot_entries: Vec<_> = entries
            .iter()
            .filter(|e| {
                e.name_str()
                    .map(|n| n != "." && n != "..")
                    .unwrap_or(false)
            })
            .collect();

        if !non_dot_entries.is_empty() {
            return Err(VolumeIOFsError::Filesystem(FilesystemError::DirectoryNotEmpty(
                PathBuf::from(name),
            )));
        }

        // Remove from parent directory
        self.dir_remove_entry(parent_inode, name)?;

        // Free data blocks
        for &block in &inode.direct {
            if block != 0 {
                self.free_block(block)?;
            }
        }

        // Free inode
        self.free_inode(inode_num)?;

        // Update parent nlink
        let mut parent = self.read_inode(parent_inode)?;
        parent.nlink = parent.nlink.saturating_sub(1);
        self.write_inode(parent_inode, &parent)?;

        Ok(())
    }

    /// Renames a file or directory
    pub fn rename_entry(
        &self,
        old_parent: u32,
        old_name: &str,
        new_parent: u32,
        new_name: &str,
    ) -> Result<()> {
        // Look up the source inode
        let inode_num = self.dir_lookup(old_parent, old_name)?
            .ok_or_else(|| VolumeIOFsError::Filesystem(FilesystemError::NotFound(
                PathBuf::from(old_name),
            )))?;

        let inode = self.read_inode(inode_num)?;
        let file_type = if inode.is_dir() {
            InodeType::Directory
        } else if inode.is_symlink() {
            InodeType::Symlink
        } else {
            InodeType::File
        };

        // Check if destination exists
        if let Some(existing) = self.dir_lookup(new_parent, new_name)? {
            // Remove existing entry
            let existing_inode = self.read_inode(existing)?;
            if existing_inode.is_dir() {
                // For directories, check if empty
                let entries = self.read_dir_entries(existing)?;
                let non_dot_entries: Vec<_> = entries
                    .iter()
                    .filter(|e| {
                        e.name_str()
                            .map(|n| n != "." && n != "..")
                            .unwrap_or(false)
                    })
                    .collect();

                if !non_dot_entries.is_empty() {
                    return Err(VolumeIOFsError::Filesystem(FilesystemError::DirectoryNotEmpty(
                        PathBuf::from(new_name),
                    )));
                }
            }

            // Remove the existing entry
            self.dir_remove_entry(new_parent, new_name)?;

            // Free the old inode and its data
            for &block in &existing_inode.direct {
                if block != 0 {
                    self.free_block(block)?;
                }
            }
            self.free_inode(existing)?;
        }

        // Remove from old parent
        self.dir_remove_entry(old_parent, old_name)?;

        // Add to new parent
        self.dir_add_entry(new_parent, new_name, inode_num, file_type)?;

        // If it's a directory and parents changed, update .. entry
        if inode.is_dir() && old_parent != new_parent {
            let mut entries = self.read_dir_entries(inode_num)?;
            for entry in &mut entries {
                if entry.name_str().map(|n| n == "..").unwrap_or(false) {
                    *entry = DirEntry::new(new_parent, "..", InodeType::Directory);
                    break;
                }
            }
            self.write_dir_entries(inode_num, &entries)?;

            // Update link counts
            let mut old_parent_inode = self.read_inode(old_parent)?;
            old_parent_inode.nlink = old_parent_inode.nlink.saturating_sub(1);
            self.write_inode(old_parent, &old_parent_inode)?;

            let mut new_parent_inode = self.read_inode(new_parent)?;
            new_parent_inode.nlink += 1;
            self.write_inode(new_parent, &new_parent_inode)?;
        }

        Ok(())
    }

    /// Truncates a file to the specified size
    pub fn truncate_file(&self, inode_num: u32, size: u64) -> Result<()> {
        let mut inode = self.read_inode(inode_num)?;

        if inode.is_dir() {
            return Err(VolumeIOFsError::Filesystem(FilesystemError::IsADirectory(
                PathBuf::from(format!("inode {}", inode_num)),
            )));
        }

        let old_size = inode.size;
        let block_size = FS_BLOCK_SIZE as u64;

        if size < old_size {
            // Shrinking - free unused blocks
            let old_blocks = old_size.div_ceil(block_size);
            let new_blocks = size.div_ceil(block_size);

            for block_idx in new_blocks..old_blocks {
                if block_idx < DIRECT_BLOCKS as u64 {
                    let block_num = inode.direct[block_idx as usize];
                    if block_num != 0 {
                        self.free_block(block_num)?;
                        inode.direct[block_idx as usize] = 0;
                    }
                }
                // TODO: Handle indirect blocks
            }
        }
        // When growing, blocks are allocated on write

        inode.size = size;
        inode.blocks = size.div_ceil(block_size) * (block_size / 512);
        inode.mtime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.write_inode(inode_num, &inode)?;

        Ok(())
    }

    /// Converts an Inode to FileAttr (public for FUSE)
    pub fn inode_to_attr(&self, inode: &Inode) -> FileAttr {
        self.inode_to_file_attr(inode)
    }

    /// Returns the root inode number
    pub fn root_inode(&self) -> u32 {
        ROOT_INODE
    }

    // ========================================================================
    // Filesystem check and recovery (fsck)
    // ========================================================================

    /// Checks filesystem consistency without making repairs
    pub fn fsck(&self) -> Result<FsckResult> {
        self.fsck_internal(false)
    }

    /// Checks filesystem consistency and attempts repairs
    pub fn fsck_repair(&self) -> Result<FsckResult> {
        self.fsck_internal(true)
    }

    fn fsck_internal(&self, repair: bool) -> Result<FsckResult> {
        let mut result = FsckResult::default();

        // Get superblock
        let sb = self.get_superblock()?;

        // Phase 1: Check all inodes for corruption
        result.messages.push("Phase 1: Checking inodes...".to_string());
        let valid_inodes = self.fsck_check_inodes(&sb, &mut result)?;

        // Phase 2: Build block usage map from valid inodes
        result.messages.push("Phase 2: Building block usage map...".to_string());
        let (used_blocks, used_inodes) = self.fsck_build_usage_maps(&valid_inodes, &mut result)?;

        // Phase 3: Check block bitmap consistency
        result.messages.push("Phase 3: Checking block bitmap...".to_string());
        let _block_errors = self.fsck_check_block_bitmap(&sb, &used_blocks, &mut result)?;

        // Phase 4: Check inode bitmap consistency
        result.messages.push("Phase 4: Checking inode bitmap...".to_string());
        let _inode_errors = self.fsck_check_inode_bitmap(&sb, &used_inodes, &mut result)?;

        // Phase 5: Check directory tree connectivity
        result.messages.push("Phase 5: Checking directory tree...".to_string());
        self.fsck_check_directory_tree(&valid_inodes, &mut result)?;

        // Phase 6: Repair if requested
        if repair && !result.is_clean() {
            result.messages.push("Phase 6: Repairing filesystem...".to_string());
            self.fsck_repair_filesystem(&used_blocks, &used_inodes, &mut result)?;
        }

        result.messages.push(format!(
            "Filesystem check complete: {} inodes scanned, {} errors found",
            result.inodes_scanned,
            result.corrupted_inodes + result.orphaned_blocks + result.lost_inodes + result.bitmap_errors
        ));

        Ok(result)
    }

    fn fsck_check_inodes(&self, sb: &Superblock, result: &mut FsckResult) -> Result<HashMap<u32, Inode>> {
        let mut valid_inodes = HashMap::new();

        for inode_num in 1..=sb.total_inodes {
            result.inodes_scanned += 1;

            match self.read_inode(inode_num) {
                Ok(inode) => {
                    // Validate inode
                    if self.fsck_validate_inode(inode_num, &inode, sb) {
                        valid_inodes.insert(inode_num, inode);
                    } else {
                        result.corrupted_inodes += 1;
                        result.messages.push(format!(
                            "Corrupted inode {}: invalid structure",
                            inode_num
                        ));
                    }
                }
                Err(e) => {
                    result.corrupted_inodes += 1;
                    result.messages.push(format!(
                        "Cannot read inode {}: {}",
                        inode_num, e
                    ));
                }
            }
        }

        Ok(valid_inodes)
    }

    fn fsck_validate_inode(&self, inode_num: u32, inode: &Inode, sb: &Superblock) -> bool {
        // Check if inode looks valid
        // An unallocated inode should have nlink=0
        if inode.nlink == 0 && inode.size == 0 && inode.mode == 0 {
            return true; // Empty/unallocated inode is valid
        }

        // Check mode - should be a valid type
        let mode_type = inode.mode & 0o170000;
        if mode_type != 0o100000 && mode_type != 0o040000 && mode_type != 0o120000 && mode_type != 0 {
            return false;
        }

        // Check that direct block pointers are within valid range
        for &block in &inode.direct {
            if block != 0 && block >= sb.total_blocks as u32 {
                return false;
            }
        }

        // Root inode should always be a directory
        if inode_num == ROOT_INODE && inode.nlink > 0
            && !inode.is_dir() {
                return false;
            }

        true
    }

    fn fsck_build_usage_maps(
        &self,
        valid_inodes: &HashMap<u32, Inode>,
        result: &mut FsckResult,
    ) -> Result<(Bitmap, Bitmap)> {
        let sb = self.get_superblock()?;

        // Create bitmaps for tracking actual usage
        let mut used_blocks = Bitmap::new(sb.total_blocks as usize);
        let mut used_inodes = Bitmap::new(sb.total_inodes as usize);

        // Mark metadata blocks as used
        for block in 0..DATA_BLOCKS_START {
            used_blocks.set(block as usize);
        }

        // Process each valid inode
        for (&inode_num, inode) in valid_inodes {
            if inode.nlink > 0 {
                // Mark inode as used
                used_inodes.set(inode_num as usize);

                // Mark data blocks as used
                for &block in &inode.direct {
                    if block != 0 {
                        if used_blocks.is_set(block as usize) {
                            result.messages.push(format!(
                                "Block {} referenced by multiple inodes (found in inode {})",
                                block, inode_num
                            ));
                        }
                        used_blocks.set(block as usize);
                    }
                }

                // TODO: Handle indirect blocks
            }
        }

        Ok((used_blocks, used_inodes))
    }

    fn fsck_check_block_bitmap(
        &self,
        sb: &Superblock,
        used_blocks: &Bitmap,
        result: &mut FsckResult,
    ) -> Result<u32> {
        let mut errors = 0;

        let stored_bitmap = self.block_bitmap.read()
            .map_err(|_| VolumeIOFsError::LockPoisoned)?;

        if let Some(stored) = stored_bitmap.as_ref() {
            for i in 0..sb.total_blocks as usize {
                let actual_used = used_blocks.is_set(i);
                let bitmap_says_used = stored.is_set(i);

                if actual_used && !bitmap_says_used {
                    // Block is used but not marked in bitmap
                    result.messages.push(format!(
                        "Block {} is used but not marked in bitmap",
                        i
                    ));
                    errors += 1;
                    result.bitmap_errors += 1;
                } else if !actual_used && bitmap_says_used && i >= DATA_BLOCKS_START as usize {
                    // Block is marked used but not referenced (orphaned)
                    result.orphaned_blocks += 1;
                    result.messages.push(format!(
                        "Block {} is marked used but not referenced (orphaned)",
                        i
                    ));
                }
            }
        }

        Ok(errors)
    }

    fn fsck_check_inode_bitmap(
        &self,
        sb: &Superblock,
        used_inodes: &Bitmap,
        result: &mut FsckResult,
    ) -> Result<u32> {
        let mut errors = 0;

        let stored_bitmap = self.inode_bitmap.read()
            .map_err(|_| VolumeIOFsError::LockPoisoned)?;

        if let Some(stored) = stored_bitmap.as_ref() {
            for i in 1..=sb.total_inodes as usize {
                let actual_used = used_inodes.is_set(i);
                let bitmap_says_used = stored.is_set(i);

                if actual_used && !bitmap_says_used {
                    result.messages.push(format!(
                        "Inode {} is used but not marked in bitmap",
                        i
                    ));
                    errors += 1;
                    result.bitmap_errors += 1;
                } else if !actual_used && bitmap_says_used {
                    result.lost_inodes += 1;
                    result.messages.push(format!(
                        "Inode {} is marked used but not referenced (lost)",
                        i
                    ));
                }
            }
        }

        Ok(errors)
    }

    fn fsck_check_directory_tree(
        &self,
        valid_inodes: &HashMap<u32, Inode>,
        result: &mut FsckResult,
    ) -> Result<()> {
        // Check that root directory exists and is valid
        if let Some(root) = valid_inodes.get(&ROOT_INODE) {
            if !root.is_dir() {
                result.messages.push("Root inode is not a directory".to_string());
                result.corrupted_inodes += 1;
            } else {
                // Check directory entries
                match self.read_dir_entries(ROOT_INODE) {
                    Ok(entries) => {
                        // Root should have . and .. entries
                        let has_dot = entries.iter().any(|e| e.name_str().map(|n| n == ".").unwrap_or(false));
                        let has_dotdot = entries.iter().any(|e| e.name_str().map(|n| n == "..").unwrap_or(false));

                        if !has_dot {
                            result.messages.push("Root directory missing '.' entry".to_string());
                            result.corrupted_inodes += 1;
                        }
                        if !has_dotdot {
                            result.messages.push("Root directory missing '..' entry".to_string());
                            result.corrupted_inodes += 1;
                        }

                        // Check that directory entries point to valid inodes
                        for entry in entries {
                            if !valid_inodes.contains_key(&entry.inode) {
                                if let Ok(name) = entry.name_str() {
                                    result.messages.push(format!(
                                        "Directory entry '{}' points to invalid inode {}",
                                        name, entry.inode
                                    ));
                                    result.corrupted_inodes += 1;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        result.messages.push(format!(
                            "Cannot read root directory: {}",
                            e
                        ));
                        result.corrupted_inodes += 1;
                    }
                }
            }
        } else {
            result.messages.push("Root inode not found".to_string());
            result.corrupted_inodes += 1;
        }

        Ok(())
    }

    fn fsck_repair_filesystem(
        &self,
        used_blocks: &Bitmap,
        used_inodes: &Bitmap,
        result: &mut FsckResult,
    ) -> Result<()> {
        // Repair block bitmap
        {
            let mut bitmap = self.block_bitmap.write()
                .map_err(|_| VolumeIOFsError::LockPoisoned)?;

            if let Some(bm) = bitmap.as_mut() {
                let sb = self.get_superblock()?;
                let mut repaired = 0;

                for i in 0..sb.total_blocks as usize {
                    let should_be_used = used_blocks.is_set(i);
                    let is_used = bm.is_set(i);

                    if should_be_used != is_used {
                        if should_be_used {
                            bm.set(i);
                        } else {
                            bm.clear(i);
                        }
                        repaired += 1;
                    }
                }

                if repaired > 0 {
                    drop(bitmap);
                    let bitmap = self.block_bitmap.read()
                        .map_err(|_| VolumeIOFsError::LockPoisoned)?;
                    if let Some(bm) = bitmap.as_ref() {
                        self.write_block_bitmap(bm)?;
                    }
                    result.errors_repaired += repaired;
                    result.messages.push(format!("Repaired {} block bitmap entries", repaired));
                }
            }
        }

        // Repair inode bitmap
        {
            let mut bitmap = self.inode_bitmap.write()
                .map_err(|_| VolumeIOFsError::LockPoisoned)?;

            if let Some(bm) = bitmap.as_mut() {
                let sb = self.get_superblock()?;
                let mut repaired = 0;

                for i in 1..=sb.total_inodes as usize {
                    let should_be_used = used_inodes.is_set(i);
                    let is_used = bm.is_set(i);

                    if should_be_used != is_used {
                        if should_be_used {
                            bm.set(i);
                        } else {
                            bm.clear(i);
                        }
                        repaired += 1;
                    }
                }

                if repaired > 0 {
                    drop(bitmap);
                    let bitmap = self.inode_bitmap.read()
                        .map_err(|_| VolumeIOFsError::LockPoisoned)?;
                    if let Some(bm) = bitmap.as_ref() {
                        self.write_inode_bitmap(bm)?;
                    }
                    result.errors_repaired += repaired;
                    result.messages.push(format!("Repaired {} inode bitmap entries", repaired));
                }
            }
        }

        // Update superblock free counts
        {
            let mut sb_lock = self.superblock.write()
                .map_err(|_| VolumeIOFsError::LockPoisoned)?;

            if let Some(sb) = sb_lock.as_mut() {
                let block_bitmap = self.block_bitmap.read()
                    .map_err(|_| VolumeIOFsError::LockPoisoned)?;

                if let Some(bm) = block_bitmap.as_ref() {
                    let free_blocks = (0..sb.total_blocks as usize)
                        .filter(|&i| !bm.is_set(i))
                        .count() as u64;

                    if sb.free_blocks != free_blocks {
                        result.messages.push(format!(
                            "Fixed free_blocks: {} -> {}",
                            sb.free_blocks, free_blocks
                        ));
                        sb.free_blocks = free_blocks;
                        result.errors_repaired += 1;
                    }
                }

                drop(sb_lock);
                self.sync()?;
            }
        }

        Ok(())
    }

    /// Rebuilds the free block bitmap from scratch by scanning all inodes
    pub fn rebuild_block_bitmap(&self) -> Result<u32> {
        let sb = self.get_superblock()?;

        // Create a new bitmap
        let mut new_bitmap = Bitmap::new(sb.total_blocks as usize);

        // Mark metadata blocks as used
        for block in 0..DATA_BLOCKS_START {
            new_bitmap.set(block as usize);
        }

        let mut blocks_recovered = 0;

        // Scan all inodes
        for inode_num in 1..=sb.total_inodes {
            if let Ok(inode) = self.read_inode(inode_num) {
                if inode.nlink > 0 {
                    // Mark data blocks as used
                    for &block in &inode.direct {
                        if block != 0 && block < sb.total_blocks as u32 {
                            if !new_bitmap.is_set(block as usize) {
                                blocks_recovered += 1;
                            }
                            new_bitmap.set(block as usize);
                        }
                    }
                    // TODO: Handle indirect blocks
                }
            }
        }

        // Update the bitmap
        self.write_block_bitmap(&new_bitmap)?;

        // Update in-memory copy
        {
            let mut bitmap = self.block_bitmap.write()
                .map_err(|_| VolumeIOFsError::LockPoisoned)?;
            *bitmap = Some(new_bitmap);
        }

        // Update superblock free count
        {
            let mut sb_lock = self.superblock.write()
                .map_err(|_| VolumeIOFsError::LockPoisoned)?;

            if let Some(sb) = sb_lock.as_mut() {
                let block_bitmap = self.block_bitmap.read()
                    .map_err(|_| VolumeIOFsError::LockPoisoned)?;

                if let Some(bm) = block_bitmap.as_ref() {
                    sb.free_blocks = (0..sb.total_blocks as usize)
                        .filter(|&i| !bm.is_set(i))
                        .count() as u64;
                }
            }
        }

        self.sync()?;

        Ok(blocks_recovered)
    }
}

// ============================================================================
// EncryptedFilesystem trait implementation
// ============================================================================

impl EncryptedFilesystem for VolumeIOFilesystem {
    fn init(&mut self, master_key: &MasterKey, backing_file: &Path) -> FsResult<()> {
        // Open existing filesystem or create new one
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(backing_file)?;

        let metadata = file.metadata()?;
        let volume_size = metadata.len();

        // Use file backend
        let backend = Box::new(super::io::FileBackend::new(file, 0));

        // Try to open existing filesystem
        let result = VolumeIOFilesystem::open(master_key, volume_size, backend);

        match result {
            Ok(fs) => {
                // Copy state from opened filesystem
                *self.io.write().map_err(|_| FilesystemError::Other("Lock poisoned".to_string()))? =
                    fs.io.write().map_err(|_| FilesystemError::Other("Lock poisoned".to_string()))?.take();
                *self.superblock.write().map_err(|_| FilesystemError::Other("Lock poisoned".to_string()))? =
                    fs.superblock.write().map_err(|_| FilesystemError::Other("Lock poisoned".to_string()))?.take();
                *self.block_bitmap.write().map_err(|_| FilesystemError::Other("Lock poisoned".to_string()))? =
                    fs.block_bitmap.write().map_err(|_| FilesystemError::Other("Lock poisoned".to_string()))?.take();
                *self.inode_bitmap.write().map_err(|_| FilesystemError::Other("Lock poisoned".to_string()))? =
                    fs.inode_bitmap.write().map_err(|_| FilesystemError::Other("Lock poisoned".to_string()))?.take();
                Ok(())
            }
            Err(e) => Err(FilesystemError::Other(format!("Failed to open filesystem: {}", e))),
        }
    }

    fn getattr(&self, path: &Path) -> FsResult<FileAttr> {
        let inode_num = self.resolve_path(path).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        let inode = self.read_inode(inode_num).map_err(|e| FilesystemError::Other(e.to_string()))?;
        Ok(self.inode_to_file_attr(&inode))
    }

    fn readdir(&self, path: &Path) -> FsResult<Vec<FsDirEntry>> {
        let inode_num = self.resolve_path(path).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        let entries = self.read_dir_entries(inode_num).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        let result = entries
            .into_iter()
            .filter_map(|e| {
                let file_type = match InodeType::from(e.file_type) {
                    InodeType::File => FileType::RegularFile,
                    InodeType::Directory => FileType::Directory,
                    InodeType::Symlink => FileType::Symlink,
                };
                e.name_str().ok().map(|name| FsDirEntry {
                    name: name.to_string(),
                    file_type,
                })
            })
            .collect();

        Ok(result)
    }

    fn read(&self, path: &Path, offset: u64, size: u32) -> FsResult<Vec<u8>> {
        let inode_num = self.resolve_path(path).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        self.read_file_data(inode_num, offset, size)
            .map_err(|e| FilesystemError::Other(e.to_string()))
    }

    fn write(&mut self, path: &Path, offset: u64, data: &[u8]) -> FsResult<u32> {
        let inode_num = self.resolve_path(path).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        self.write_file_data(inode_num, offset, data)
            .map_err(|e| FilesystemError::Other(e.to_string()))
    }

    fn create(&mut self, path: &Path, mode: u16) -> FsResult<FileAttr> {
        let (parent_inode, name) = self.resolve_parent(path).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        // Check if already exists
        if self.dir_lookup(parent_inode, &name).map_err(|e| FilesystemError::Other(e.to_string()))?.is_some() {
            return Err(FilesystemError::AlreadyExists(path.to_path_buf()));
        }

        // Allocate inode
        let inode_num = self.alloc_inode().map_err(|e| FilesystemError::Other(e.to_string()))?;

        // Create inode
        let inode = Inode::new_file(mode);
        self.write_inode(inode_num, &inode).map_err(|e| FilesystemError::Other(e.to_string()))?;

        // Add to parent directory
        self.dir_add_entry(parent_inode, &name, inode_num, InodeType::File)
            .map_err(|e| FilesystemError::Other(e.to_string()))?;

        Ok(self.inode_to_file_attr(&inode))
    }

    fn mkdir(&mut self, path: &Path, mode: u16) -> FsResult<()> {
        let (parent_inode, name) = self.resolve_parent(path).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        // Check if already exists
        if self.dir_lookup(parent_inode, &name).map_err(|e| FilesystemError::Other(e.to_string()))?.is_some() {
            return Err(FilesystemError::AlreadyExists(path.to_path_buf()));
        }

        // Allocate inode
        let inode_num = self.alloc_inode().map_err(|e| FilesystemError::Other(e.to_string()))?;

        // Create directory inode
        let mut inode = Inode::new_directory(mode);

        // Allocate a data block for the directory
        let data_block = self.alloc_block().map_err(|e| FilesystemError::Other(e.to_string()))?;
        inode.direct[0] = data_block;
        inode.size = FS_BLOCK_SIZE as u64;
        inode.blocks = (FS_BLOCK_SIZE / 512) as u64;

        self.write_inode(inode_num, &inode).map_err(|e| FilesystemError::Other(e.to_string()))?;

        // Initialize directory with . and .. entries
        let entries = vec![
            DirEntry::new(inode_num, ".", InodeType::Directory),
            DirEntry::new(parent_inode, "..", InodeType::Directory),
        ];
        self.write_dir_entries(inode_num, &entries).map_err(|e| FilesystemError::Other(e.to_string()))?;

        // Add to parent directory
        self.dir_add_entry(parent_inode, &name, inode_num, InodeType::Directory)
            .map_err(|e| FilesystemError::Other(e.to_string()))?;

        // Update parent nlink (for ..)
        let mut parent = self.read_inode(parent_inode).map_err(|e| FilesystemError::Other(e.to_string()))?;
        parent.nlink += 1;
        self.write_inode(parent_inode, &parent).map_err(|e| FilesystemError::Other(e.to_string()))?;

        Ok(())
    }

    fn unlink(&mut self, path: &Path) -> FsResult<()> {
        let (parent_inode, name) = self.resolve_parent(path).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        // Look up the inode
        let inode_num = self.dir_lookup(parent_inode, &name)
            .map_err(|e| FilesystemError::Other(e.to_string()))?
            .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;

        let inode = self.read_inode(inode_num).map_err(|e| FilesystemError::Other(e.to_string()))?;

        if inode.is_dir() {
            return Err(FilesystemError::IsADirectory(path.to_path_buf()));
        }

        // Remove from parent directory
        self.dir_remove_entry(parent_inode, &name).map_err(|e| FilesystemError::Other(e.to_string()))?;

        // Free data blocks
        for &block in &inode.direct {
            if block != 0 {
                self.free_block(block).map_err(|e| FilesystemError::Other(e.to_string()))?;
            }
        }
        // TODO: Free indirect blocks

        // Free inode
        self.free_inode(inode_num).map_err(|e| FilesystemError::Other(e.to_string()))?;

        Ok(())
    }

    fn rmdir(&mut self, path: &Path) -> FsResult<()> {
        let (parent_inode, name) = self.resolve_parent(path).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        // Look up the inode
        let inode_num = self.dir_lookup(parent_inode, &name)
            .map_err(|e| FilesystemError::Other(e.to_string()))?
            .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;

        let inode = self.read_inode(inode_num).map_err(|e| FilesystemError::Other(e.to_string()))?;

        if !inode.is_dir() {
            return Err(FilesystemError::NotADirectory(path.to_path_buf()));
        }

        // Check if directory is empty (only . and ..)
        let entries = self.read_dir_entries(inode_num).map_err(|e| FilesystemError::Other(e.to_string()))?;
        let non_dot_entries: Vec<_> = entries
            .iter()
            .filter(|e| {
                e.name_str()
                    .map(|n| n != "." && n != "..")
                    .unwrap_or(false)
            })
            .collect();

        if !non_dot_entries.is_empty() {
            return Err(FilesystemError::DirectoryNotEmpty(path.to_path_buf()));
        }

        // Remove from parent directory
        self.dir_remove_entry(parent_inode, &name).map_err(|e| FilesystemError::Other(e.to_string()))?;

        // Update parent nlink
        let mut parent = self.read_inode(parent_inode).map_err(|e| FilesystemError::Other(e.to_string()))?;
        parent.nlink = parent.nlink.saturating_sub(1);
        self.write_inode(parent_inode, &parent).map_err(|e| FilesystemError::Other(e.to_string()))?;

        // Free data blocks
        for &block in &inode.direct {
            if block != 0 {
                self.free_block(block).map_err(|e| FilesystemError::Other(e.to_string()))?;
            }
        }

        // Free inode
        self.free_inode(inode_num).map_err(|e| FilesystemError::Other(e.to_string()))?;

        Ok(())
    }

    fn rename(&mut self, from: &Path, to: &Path) -> FsResult<()> {
        let (from_parent, from_name) = self.resolve_parent(from).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        let (to_parent, to_name) = self.resolve_parent(to).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        // Look up source
        let inode_num = self.dir_lookup(from_parent, &from_name)
            .map_err(|e| FilesystemError::Other(e.to_string()))?
            .ok_or_else(|| FilesystemError::NotFound(from.to_path_buf()))?;

        let inode = self.read_inode(inode_num).map_err(|e| FilesystemError::Other(e.to_string()))?;
        let file_type = inode.file_type();

        // Check if destination exists
        if let Some(existing) = self.dir_lookup(to_parent, &to_name).map_err(|e| FilesystemError::Other(e.to_string()))? {
            // Remove existing
            let existing_inode = self.read_inode(existing).map_err(|e| FilesystemError::Other(e.to_string()))?;
            if existing_inode.is_dir() {
                // Check if empty
                let entries = self.read_dir_entries(existing).map_err(|e| FilesystemError::Other(e.to_string()))?;
                let non_dot = entries.iter().filter(|e| {
                    e.name_str().map(|n| n != "." && n != "..").unwrap_or(false)
                }).count();
                if non_dot > 0 {
                    return Err(FilesystemError::DirectoryNotEmpty(to.to_path_buf()));
                }
            }
            self.dir_remove_entry(to_parent, &to_name).map_err(|e| FilesystemError::Other(e.to_string()))?;
            self.free_inode(existing).map_err(|e| FilesystemError::Other(e.to_string()))?;
        }

        // Remove from source directory
        self.dir_remove_entry(from_parent, &from_name).map_err(|e| FilesystemError::Other(e.to_string()))?;

        // Add to destination directory
        self.dir_add_entry(to_parent, &to_name, inode_num, file_type)
            .map_err(|e| FilesystemError::Other(e.to_string()))?;

        // Update .. entry if it's a directory and parent changed
        if inode.is_dir() && from_parent != to_parent {
            let mut entries = self.read_dir_entries(inode_num).map_err(|e| FilesystemError::Other(e.to_string()))?;
            for entry in &mut entries {
                if entry.name_str().map(|n| n == "..").unwrap_or(false) {
                    entry.inode = to_parent;
                }
            }
            self.write_dir_entries(inode_num, &entries).map_err(|e| FilesystemError::Other(e.to_string()))?;

            // Update nlink counts
            let mut old_parent = self.read_inode(from_parent).map_err(|e| FilesystemError::Other(e.to_string()))?;
            old_parent.nlink = old_parent.nlink.saturating_sub(1);
            self.write_inode(from_parent, &old_parent).map_err(|e| FilesystemError::Other(e.to_string()))?;

            let mut new_parent = self.read_inode(to_parent).map_err(|e| FilesystemError::Other(e.to_string()))?;
            new_parent.nlink += 1;
            self.write_inode(to_parent, &new_parent).map_err(|e| FilesystemError::Other(e.to_string()))?;
        }

        Ok(())
    }

    fn chmod(&mut self, path: &Path, mode: u16) -> FsResult<()> {
        let inode_num = self.resolve_path(path).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        let mut inode = self.read_inode(inode_num).map_err(|e| FilesystemError::Other(e.to_string()))?;

        // Preserve file type, update permissions
        let file_type = (inode.mode >> 12) & 0xF;
        inode.mode = (file_type << 12) | (mode & 0o7777);
        inode.ctime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.write_inode(inode_num, &inode).map_err(|e| FilesystemError::Other(e.to_string()))?;
        Ok(())
    }

    fn chown(&mut self, path: &Path, uid: u32, gid: u32) -> FsResult<()> {
        let inode_num = self.resolve_path(path).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        let mut inode = self.read_inode(inode_num).map_err(|e| FilesystemError::Other(e.to_string()))?;
        inode.uid = uid;
        inode.gid = gid;
        inode.ctime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.write_inode(inode_num, &inode).map_err(|e| FilesystemError::Other(e.to_string()))?;
        Ok(())
    }

    fn truncate(&mut self, path: &Path, size: u64) -> FsResult<()> {
        let inode_num = self.resolve_path(path).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        let mut inode = self.read_inode(inode_num).map_err(|e| FilesystemError::Other(e.to_string()))?;

        if inode.is_dir() {
            return Err(FilesystemError::IsADirectory(path.to_path_buf()));
        }

        let old_blocks = inode.size.div_ceil(FS_BLOCK_SIZE as u64);
        let new_blocks = size.div_ceil(FS_BLOCK_SIZE as u64);

        if size < inode.size {
            // Shrinking - free excess blocks
            for i in new_blocks..old_blocks {
                if (i as usize) < DIRECT_BLOCKS {
                    let block = inode.direct[i as usize];
                    if block != 0 {
                        self.free_block(block).map_err(|e| FilesystemError::Other(e.to_string()))?;
                        inode.direct[i as usize] = 0;
                    }
                }
                // TODO: Handle indirect blocks
            }
        }

        inode.size = size;
        inode.blocks = size.div_ceil(512);
        inode.mtime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        inode.ctime = inode.mtime;

        self.write_inode(inode_num, &inode).map_err(|e| FilesystemError::Other(e.to_string()))?;
        Ok(())
    }

    fn utimens(&mut self, path: &Path, atime: Option<SystemTime>, mtime: Option<SystemTime>) -> FsResult<()> {
        let inode_num = self.resolve_path(path).map_err(|e| match e {
            VolumeIOFsError::Filesystem(fe) => fe,
            other => FilesystemError::Other(other.to_string()),
        })?;

        let mut inode = self.read_inode(inode_num).map_err(|e| FilesystemError::Other(e.to_string()))?;

        if let Some(atime) = atime {
            inode.atime = atime
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
        }

        if let Some(mtime) = mtime {
            inode.mtime = mtime
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
        }

        inode.ctime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.write_inode(inode_num, &inode).map_err(|e| FilesystemError::Other(e.to_string()))?;
        Ok(())
    }

    fn flush(&mut self) -> FsResult<()> {
        self.sync().map_err(|e| FilesystemError::Other(e.to_string()))
    }

    fn statfs(&self) -> FsResult<(u64, u64, u64)> {
        self.get_statfs().map_err(|e| FilesystemError::Other(e.to_string()))
    }
}

impl Drop for VolumeIOFilesystem {
    fn drop(&mut self) {
        // Try to mark filesystem as clean on drop
        let _ = self.mark_clean();
        let _ = self.sync();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::io::MemoryBackend;
    use super::super::format::FS_MAGIC;

    fn create_test_fs(size_mb: u64) -> VolumeIOFilesystem {
        let volume_size = size_mb * 1024 * 1024;
        let master_key = MasterKey::generate();
        let backend = Box::new(MemoryBackend::new(volume_size as usize));
        VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume").unwrap()
    }

    #[test]
    fn test_mkfs() {
        let fs = create_test_fs(1);
        let sb = fs.get_superblock().unwrap();
        assert_eq!(sb.magic, FS_MAGIC);
        assert!(sb.verify_checksum());
    }

    #[test]
    fn test_root_directory() {
        let fs = create_test_fs(1);
        let entries = fs.read_dir_entries(ROOT_INODE).unwrap();

        // Should have . and ..
        assert!(entries.len() >= 2);
        let names: Vec<_> = entries.iter().filter_map(|e| e.name_str().ok()).collect();
        assert!(names.contains(&"."));
        assert!(names.contains(&".."));
    }

    #[test]
    fn test_create_file() {
        let mut fs = create_test_fs(1);

        let attr = fs.create(Path::new("/test.txt"), 0o644).unwrap();
        assert_eq!(attr.file_type, FileType::RegularFile);
        assert_eq!(attr.perm, 0o644);
        assert_eq!(attr.size, 0);
    }

    #[test]
    fn test_write_read_file() {
        let mut fs = create_test_fs(1);

        fs.create(Path::new("/test.txt"), 0o644).unwrap();

        let data = b"Hello, encrypted filesystem!";
        let written = fs.write(Path::new("/test.txt"), 0, data).unwrap();
        assert_eq!(written, data.len() as u32);

        let read_data = fs.read(Path::new("/test.txt"), 0, data.len() as u32).unwrap();
        assert_eq!(&read_data, data);
    }

    #[test]
    fn test_create_directory() {
        let mut fs = create_test_fs(1);

        fs.mkdir(Path::new("/testdir"), 0o755).unwrap();

        let attr = fs.getattr(Path::new("/testdir")).unwrap();
        assert_eq!(attr.file_type, FileType::Directory);
        assert_eq!(attr.perm, 0o755);
    }

    #[test]
    fn test_nested_directories() {
        let mut fs = create_test_fs(1);

        fs.mkdir(Path::new("/a"), 0o755).unwrap();
        fs.mkdir(Path::new("/a/b"), 0o755).unwrap();
        fs.mkdir(Path::new("/a/b/c"), 0o755).unwrap();

        let attr = fs.getattr(Path::new("/a/b/c")).unwrap();
        assert_eq!(attr.file_type, FileType::Directory);
    }

    #[test]
    fn test_readdir() {
        let mut fs = create_test_fs(1);

        fs.create(Path::new("/file1.txt"), 0o644).unwrap();
        fs.create(Path::new("/file2.txt"), 0o644).unwrap();
        fs.mkdir(Path::new("/subdir"), 0o755).unwrap();

        let entries = fs.readdir(Path::new("/")).unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();

        assert!(names.contains(&"."));
        assert!(names.contains(&".."));
        assert!(names.contains(&"file1.txt"));
        assert!(names.contains(&"file2.txt"));
        assert!(names.contains(&"subdir"));
    }

    #[test]
    fn test_unlink() {
        let mut fs = create_test_fs(1);

        fs.create(Path::new("/to_delete.txt"), 0o644).unwrap();
        fs.unlink(Path::new("/to_delete.txt")).unwrap();

        let result = fs.getattr(Path::new("/to_delete.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_rmdir() {
        let mut fs = create_test_fs(1);

        fs.mkdir(Path::new("/to_delete"), 0o755).unwrap();
        fs.rmdir(Path::new("/to_delete")).unwrap();

        let result = fs.getattr(Path::new("/to_delete"));
        assert!(result.is_err());
    }

    #[test]
    fn test_rmdir_not_empty() {
        let mut fs = create_test_fs(1);

        fs.mkdir(Path::new("/notempty"), 0o755).unwrap();
        fs.create(Path::new("/notempty/file.txt"), 0o644).unwrap();

        let result = fs.rmdir(Path::new("/notempty"));
        assert!(result.is_err());
    }

    #[test]
    fn test_rename_file() {
        let mut fs = create_test_fs(1);

        fs.create(Path::new("/old.txt"), 0o644).unwrap();
        let data = b"test data";
        fs.write(Path::new("/old.txt"), 0, data).unwrap();

        fs.rename(Path::new("/old.txt"), Path::new("/new.txt")).unwrap();

        // Old path should not exist
        assert!(fs.getattr(Path::new("/old.txt")).is_err());

        // New path should exist with same data
        let read_data = fs.read(Path::new("/new.txt"), 0, data.len() as u32).unwrap();
        assert_eq!(&read_data, data);
    }

    #[test]
    fn test_truncate() {
        let mut fs = create_test_fs(1);

        fs.create(Path::new("/truncate.txt"), 0o644).unwrap();
        let data = b"This is a longer string that will be truncated";
        fs.write(Path::new("/truncate.txt"), 0, data).unwrap();

        fs.truncate(Path::new("/truncate.txt"), 10).unwrap();

        let attr = fs.getattr(Path::new("/truncate.txt")).unwrap();
        assert_eq!(attr.size, 10);

        let read_data = fs.read(Path::new("/truncate.txt"), 0, 10).unwrap();
        assert_eq!(&read_data, &data[..10]);
    }

    #[test]
    fn test_chmod() {
        let mut fs = create_test_fs(1);

        fs.create(Path::new("/chmod.txt"), 0o644).unwrap();
        fs.chmod(Path::new("/chmod.txt"), 0o755).unwrap();

        let attr = fs.getattr(Path::new("/chmod.txt")).unwrap();
        assert_eq!(attr.perm, 0o755);
    }

    #[test]
    fn test_chown() {
        let mut fs = create_test_fs(1);

        fs.create(Path::new("/chown.txt"), 0o644).unwrap();
        fs.chown(Path::new("/chown.txt"), 1000, 1000).unwrap();

        let attr = fs.getattr(Path::new("/chown.txt")).unwrap();
        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.gid, 1000);
    }

    #[test]
    fn test_statfs() {
        let fs = create_test_fs(1);
        let (total, free, avail) = fs.statfs().unwrap();

        assert!(total > 0);
        assert!(free > 0);
        assert!(avail > 0);
        assert!(free <= total);
    }

    #[test]
    fn test_large_file() {
        let mut fs = create_test_fs(2); // 2MB volume

        fs.create(Path::new("/large.bin"), 0o644).unwrap();

        // Write 100KB of data
        let data = vec![0x42u8; 100 * 1024];
        let written = fs.write(Path::new("/large.bin"), 0, &data).unwrap();
        assert_eq!(written, data.len() as u32);

        // Read it back
        let read_data = fs.read(Path::new("/large.bin"), 0, data.len() as u32).unwrap();
        assert_eq!(read_data.len(), data.len());
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_append_write() {
        let mut fs = create_test_fs(1);

        fs.create(Path::new("/append.txt"), 0o644).unwrap();

        let data1 = b"First part. ";
        fs.write(Path::new("/append.txt"), 0, data1).unwrap();

        let data2 = b"Second part.";
        fs.write(Path::new("/append.txt"), data1.len() as u64, data2).unwrap();

        let full_data = fs.read(Path::new("/append.txt"), 0, 100).unwrap();
        assert_eq!(&full_data, b"First part. Second part.");
    }

    #[test]
    fn test_sync() {
        let fs = create_test_fs(1);
        // Should not panic
        fs.sync().unwrap();
    }
}

//! On-disk filesystem format for persistent encrypted volumes
//!
//! This module defines the binary layout for storing filesystem metadata
//! persistently within a Tesseract encrypted volume. The format is designed
//! for simplicity, crash recovery, and forward compatibility.
//!
//! ## Volume Layout
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │ Block 0: Superblock (4 KB)                                          │
//! │ - Magic, version, feature flags                                     │
//! │ - Block/inode counts, free counts                                   │
//! │ - Pointers to key structures                                        │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │ Block 1: Backup Superblock (4 KB)                                   │
//! │ - Duplicate for crash recovery                                      │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │ Blocks 2-3: Block Bitmap (8 KB = 65536 blocks trackable)            │
//! │ - 1 bit per block (0=free, 1=used)                                  │
//! │ - Supports up to 256 MB with 4KB blocks                             │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │ Blocks 4-5: Inode Bitmap (8 KB = 65536 inodes trackable)            │
//! │ - 1 bit per inode (0=free, 1=used)                                  │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │ Blocks 6-37: Inode Table (128 KB = 1024 inodes)                     │
//! │ - 128 bytes per inode                                               │
//! │ - Inode 0 reserved, Inode 1 = root directory                        │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │ Blocks 38-41: Journal (16 KB)                                       │
//! │ - Write-ahead log for crash recovery                                │
//! │ - Circular buffer of transactions                                   │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │ Blocks 42+: Data Blocks                                             │
//! │ - File contents and directory entries                               │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Design Principles
//!
//! 1. **Simplicity**: Similar to ext2/minix but simpler - no block groups
//! 2. **Crash Safety**: Journal ensures atomic metadata updates
//! 3. **Forward Compatibility**: Version field and feature flags
//! 4. **Small Footprint**: Optimized for encrypted volumes (typ. < 1GB)
//!
//! ## Block Size
//!
//! The filesystem uses 4KB blocks, matching the container's sector size.
//! This simplifies alignment with the underlying encryption layer.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::time::SystemTime;

/// Filesystem block size in bytes (matches encryption sector size)
pub const FS_BLOCK_SIZE: u32 = 4096;

/// Magic number for filesystem identification: "TSFS" + version
pub const FS_MAGIC: [u8; 8] = *b"TSFS0001";

/// Current filesystem format version
pub const FS_VERSION: u32 = 1;

/// Root directory inode number (always 1, inode 0 is reserved)
pub const ROOT_INODE: u32 = 1;

/// Reserved inode 0 (never allocated)
pub const RESERVED_INODE: u32 = 0;

/// Maximum filename length in bytes
pub const MAX_FILENAME_LEN: usize = 255;

/// Number of direct block pointers in an inode
pub const DIRECT_BLOCKS: usize = 12;

/// Block numbers for filesystem structures
pub const SUPERBLOCK_BLOCK: u64 = 0;
pub const BACKUP_SUPERBLOCK_BLOCK: u64 = 1;
pub const BLOCK_BITMAP_START: u64 = 2;
pub const BLOCK_BITMAP_BLOCKS: u64 = 2; // 8KB = 64K blocks
pub const INODE_BITMAP_START: u64 = 4;
pub const INODE_BITMAP_BLOCKS: u64 = 2; // 8KB = 64K inodes
pub const INODE_TABLE_START: u64 = 6;
pub const INODE_TABLE_BLOCKS: u64 = 32; // 128KB = 1024 inodes at 128 bytes each
pub const JOURNAL_START: u64 = 38;
pub const JOURNAL_BLOCKS: u64 = 4; // 16KB journal
pub const DATA_BLOCKS_START: u64 = 42;

/// Maximum number of inodes (limited by inode bitmap size)
pub const MAX_INODES: u32 = (INODE_BITMAP_BLOCKS * FS_BLOCK_SIZE as u64 * 8) as u32;

/// Maximum number of blocks (limited by block bitmap size)
pub const MAX_BLOCKS: u64 = BLOCK_BITMAP_BLOCKS * FS_BLOCK_SIZE as u64 * 8;

/// Inode size in bytes (power of 2 for easy indexing)
pub const INODE_SIZE: u32 = 128;

/// Inodes per block
pub const INODES_PER_BLOCK: u32 = FS_BLOCK_SIZE / INODE_SIZE;

// ============================================================================
// Superblock
// ============================================================================

/// Filesystem superblock - stored at block 0 and backed up at block 1
///
/// Contains global filesystem metadata and pointers to key structures.
/// The backup superblock allows recovery if the primary is corrupted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Superblock {
    /// Magic number for identification ("TSFS0001")
    pub magic: [u8; 8],

    /// Filesystem format version
    pub version: u32,

    /// Feature flags (for forward compatibility)
    pub features: u32,

    /// Total number of blocks in the filesystem
    pub total_blocks: u64,

    /// Number of free blocks
    pub free_blocks: u64,

    /// Total number of inodes
    pub total_inodes: u32,

    /// Number of free inodes
    pub free_inodes: u32,

    /// Block size in bytes (always 4096 for now)
    pub block_size: u32,

    /// First data block number
    pub first_data_block: u64,

    /// Block number of block bitmap
    pub block_bitmap_block: u64,

    /// Block number of inode bitmap
    pub inode_bitmap_block: u64,

    /// Block number of inode table start
    pub inode_table_block: u64,

    /// Block number of journal start
    pub journal_block: u64,

    /// Number of journal blocks
    pub journal_size: u32,

    /// Filesystem state (clean=0, dirty=1, error=2)
    pub state: u16,

    /// Number of mounts since last fsck
    pub mount_count: u16,

    /// Maximum mounts before fsck recommended
    pub max_mount_count: u16,

    /// Last mount time (Unix timestamp)
    pub last_mount_time: u64,

    /// Last write time (Unix timestamp)
    pub last_write_time: u64,

    /// UUID for this filesystem (random, for identification)
    pub uuid: [u8; 16],

    /// Volume label (UTF-8, null-terminated)
    #[serde(with = "BigArray")]
    pub label: [u8; 64],

    /// Reserved for future use
    #[serde(with = "BigArray")]
    pub reserved: [u8; 256],

    /// CRC32 checksum of this superblock (excluding this field)
    pub checksum: u32,
}

impl Superblock {
    /// Creates a new superblock for a fresh filesystem
    pub fn new(total_blocks: u64, label: &str) -> Self {
        let mut uuid = [0u8; 16];
        // Generate random UUID
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut uuid);

        let mut label_bytes = [0u8; 64];
        let label_slice = label.as_bytes();
        let copy_len = label_slice.len().min(63); // Leave room for null terminator
        label_bytes[..copy_len].copy_from_slice(&label_slice[..copy_len]);

        // Calculate usable data blocks (total - metadata)
        let metadata_blocks = DATA_BLOCKS_START;
        let data_blocks = total_blocks.saturating_sub(metadata_blocks);

        // Calculate available inodes
        let available_inodes = (INODE_TABLE_BLOCKS * INODES_PER_BLOCK as u64) as u32;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            magic: FS_MAGIC,
            version: FS_VERSION,
            features: 0,
            total_blocks,
            free_blocks: data_blocks.saturating_sub(1), // Root dir uses 1 block
            total_inodes: available_inodes,
            free_inodes: available_inodes.saturating_sub(2), // 0=reserved, 1=root
            block_size: FS_BLOCK_SIZE,
            first_data_block: DATA_BLOCKS_START,
            block_bitmap_block: BLOCK_BITMAP_START,
            inode_bitmap_block: INODE_BITMAP_START,
            inode_table_block: INODE_TABLE_START,
            journal_block: JOURNAL_START,
            journal_size: JOURNAL_BLOCKS as u32,
            state: FsState::Clean as u16,
            mount_count: 0,
            max_mount_count: 20,
            last_mount_time: now,
            last_write_time: now,
            uuid,
            label: label_bytes,
            reserved: [0u8; 256],
            checksum: 0, // Will be computed on serialization
        }
    }

    /// Validates the superblock
    pub fn validate(&self) -> Result<(), FormatError> {
        if self.magic != FS_MAGIC {
            return Err(FormatError::InvalidMagic);
        }
        if self.version > FS_VERSION {
            return Err(FormatError::UnsupportedVersion(self.version));
        }
        if self.block_size != FS_BLOCK_SIZE {
            return Err(FormatError::InvalidBlockSize(self.block_size));
        }
        Ok(())
    }

    /// Computes CRC32 checksum of the superblock (excluding checksum field)
    pub fn compute_checksum(&self) -> u32 {
        // Simple CRC32 implementation using the same algorithm as BLAKE3's truncated output
        // For a real implementation, use a proper CRC32 crate
        let mut hasher = blake3::Hasher::new();

        // Hash all fields except checksum
        hasher.update(&self.magic);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.features.to_le_bytes());
        hasher.update(&self.total_blocks.to_le_bytes());
        hasher.update(&self.free_blocks.to_le_bytes());
        hasher.update(&self.total_inodes.to_le_bytes());
        hasher.update(&self.free_inodes.to_le_bytes());
        hasher.update(&self.block_size.to_le_bytes());
        hasher.update(&self.first_data_block.to_le_bytes());
        hasher.update(&self.block_bitmap_block.to_le_bytes());
        hasher.update(&self.inode_bitmap_block.to_le_bytes());
        hasher.update(&self.inode_table_block.to_le_bytes());
        hasher.update(&self.journal_block.to_le_bytes());
        hasher.update(&self.journal_size.to_le_bytes());
        hasher.update(&self.state.to_le_bytes());
        hasher.update(&self.mount_count.to_le_bytes());
        hasher.update(&self.max_mount_count.to_le_bytes());
        hasher.update(&self.last_mount_time.to_le_bytes());
        hasher.update(&self.last_write_time.to_le_bytes());
        hasher.update(&self.uuid);
        hasher.update(&self.label);
        hasher.update(&self.reserved);

        // Take first 4 bytes of hash as checksum
        let hash = hasher.finalize();
        u32::from_le_bytes([hash.as_bytes()[0], hash.as_bytes()[1], hash.as_bytes()[2], hash.as_bytes()[3]])
    }

    /// Updates the checksum field
    pub fn update_checksum(&mut self) {
        self.checksum = self.compute_checksum();
    }

    /// Verifies the checksum
    pub fn verify_checksum(&self) -> bool {
        self.checksum == self.compute_checksum()
    }
}

/// Filesystem state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FsState {
    /// Filesystem was cleanly unmounted
    Clean = 0,
    /// Filesystem is currently mounted or was not cleanly unmounted
    Dirty = 1,
    /// Filesystem has errors (needs fsck)
    Error = 2,
}

// ============================================================================
// Inode
// ============================================================================

/// File type stored in inode mode field (upper 4 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum InodeType {
    /// Regular file
    File = 0,
    /// Directory
    Directory = 1,
    /// Symbolic link
    Symlink = 2,
}

impl From<u8> for InodeType {
    fn from(v: u8) -> Self {
        match v {
            0 => InodeType::File,
            1 => InodeType::Directory,
            2 => InodeType::Symlink,
            _ => InodeType::File, // Default to file for unknown types
        }
    }
}

/// On-disk inode structure (128 bytes)
///
/// Stores metadata for a file, directory, or symlink.
/// Block pointers support files up to ~50KB with direct blocks,
/// larger files use indirect blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inode {
    /// File type (4 bits) + permissions (12 bits)
    /// Bits 15-12: type (0=file, 1=dir, 2=symlink)
    /// Bits 11-0: Unix permissions (rwxrwxrwx)
    pub mode: u16,

    /// Number of hard links
    pub nlink: u16,

    /// Owner user ID
    pub uid: u32,

    /// Owner group ID
    pub gid: u32,

    /// File size in bytes
    pub size: u64,

    /// Number of 512-byte blocks allocated (for sparse files)
    pub blocks: u64,

    /// Last access time (Unix timestamp)
    pub atime: u64,

    /// Last modification time (Unix timestamp)
    pub mtime: u64,

    /// Last status change time (Unix timestamp)
    pub ctime: u64,

    /// Creation time (Unix timestamp)
    pub crtime: u64,

    /// Flags (immutable, append-only, etc.)
    pub flags: u32,

    /// Generation number (for NFS)
    pub generation: u32,

    /// Direct block pointers (12 * 4 bytes = 48 bytes)
    /// Each points to a data block, 0 = not allocated
    pub direct: [u32; DIRECT_BLOCKS],

    /// Single indirect block pointer
    /// Points to a block containing up to 1024 block pointers
    pub indirect: u32,

    /// Double indirect block pointer
    /// Points to a block containing pointers to indirect blocks
    pub double_indirect: u32,

    /// Reserved for future use (e.g., triple indirect, extended attributes)
    pub reserved: [u8; 4],
}

impl Inode {
    /// Creates a new empty inode
    pub fn new() -> Self {
        Self {
            mode: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            size: 0,
            blocks: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            crtime: 0,
            flags: 0,
            generation: 0,
            direct: [0; DIRECT_BLOCKS],
            indirect: 0,
            double_indirect: 0,
            reserved: [0; 4],
        }
    }

    /// Creates a new file inode with given permissions
    pub fn new_file(perm: u16) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            mode: ((InodeType::File as u16) << 12) | (perm & 0o7777),
            nlink: 1,
            uid: 0,
            gid: 0,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            flags: 0,
            generation: 0,
            direct: [0; DIRECT_BLOCKS],
            indirect: 0,
            double_indirect: 0,
            reserved: [0; 4],
        }
    }

    /// Creates a new directory inode with given permissions
    pub fn new_directory(perm: u16) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            mode: ((InodeType::Directory as u16) << 12) | (perm & 0o7777),
            nlink: 2, // . and parent link
            uid: 0,
            gid: 0,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            flags: 0,
            generation: 0,
            direct: [0; DIRECT_BLOCKS],
            indirect: 0,
            double_indirect: 0,
            reserved: [0; 4],
        }
    }

    /// Returns the file type
    pub fn file_type(&self) -> InodeType {
        InodeType::from((self.mode >> 12) as u8 & 0x0F)
    }

    /// Returns the permission bits (lower 12 bits)
    pub fn permissions(&self) -> u16 {
        self.mode & 0o7777
    }

    /// Returns true if this is a directory
    pub fn is_dir(&self) -> bool {
        self.file_type() == InodeType::Directory
    }

    /// Returns true if this is a regular file
    pub fn is_file(&self) -> bool {
        self.file_type() == InodeType::File
    }

    /// Returns true if this is a symlink
    pub fn is_symlink(&self) -> bool {
        self.file_type() == InodeType::Symlink
    }

    /// Calculates block index for a given file offset
    pub fn block_index_for_offset(&self, offset: u64) -> u64 {
        offset / FS_BLOCK_SIZE as u64
    }

    /// Returns the maximum file size this inode structure can support
    ///
    /// With 4KB blocks:
    /// - Direct: 12 * 4KB = 48KB
    /// - Indirect: 1024 * 4KB = 4MB
    /// - Double indirect: 1024 * 1024 * 4KB = 4GB
    pub fn max_file_size() -> u64 {
        let direct_size = DIRECT_BLOCKS as u64 * FS_BLOCK_SIZE as u64;
        let ptrs_per_block = FS_BLOCK_SIZE as u64 / 4;
        let indirect_size = ptrs_per_block * FS_BLOCK_SIZE as u64;
        let double_indirect_size = ptrs_per_block * ptrs_per_block * FS_BLOCK_SIZE as u64;
        direct_size + indirect_size + double_indirect_size
    }
}

impl Default for Inode {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Directory Entry
// ============================================================================

/// On-disk directory entry
///
/// Variable-length structure stored in directory data blocks.
/// Entries are packed sequentially; deleted entries are marked
/// with inode=0 and can be reclaimed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    /// Inode number (0 = deleted entry)
    pub inode: u32,

    /// Total size of this entry (for skipping to next)
    pub rec_len: u16,

    /// Length of the name (1-255)
    pub name_len: u8,

    /// File type (cached from inode for readdir performance)
    pub file_type: u8,

    /// Filename (not null-terminated, length given by name_len)
    /// Stored inline after this struct
    pub name: Vec<u8>,
}

impl DirEntry {
    /// Creates a new directory entry
    pub fn new(inode: u32, name: &str, file_type: InodeType) -> Self {
        let name_bytes = name.as_bytes().to_vec();
        let name_len = name_bytes.len().min(MAX_FILENAME_LEN) as u8;

        // Record length must be 4-byte aligned
        let base_size = 8; // inode(4) + rec_len(2) + name_len(1) + file_type(1)
        let rec_len = (base_size + name_len as u16).div_ceil(4) * 4;

        Self {
            inode,
            rec_len,
            name_len,
            file_type: file_type as u8,
            name: name_bytes,
        }
    }

    /// Returns the filename as a string
    pub fn name_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.name[..self.name_len as usize])
    }

    /// Returns true if this entry is deleted
    pub fn is_deleted(&self) -> bool {
        self.inode == 0
    }

    /// Serialized size of this entry
    pub fn size(&self) -> usize {
        self.rec_len as usize
    }
}

// ============================================================================
// Journal
// ============================================================================

/// Journal transaction types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum JournalOpType {
    /// No operation (padding)
    Nop = 0,
    /// Write block to disk
    WriteBlock = 1,
    /// Update inode
    UpdateInode = 2,
    /// Allocate block
    AllocBlock = 3,
    /// Free block
    FreeBlock = 4,
    /// Allocate inode
    AllocInode = 5,
    /// Free inode
    FreeInode = 6,
    /// Transaction commit marker
    Commit = 7,
}

/// Journal entry header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Transaction sequence number
    pub sequence: u64,

    /// Operation type
    pub op_type: u8,

    /// Flags (reserved)
    pub flags: u8,

    /// Data length following this header
    pub data_len: u16,

    /// Block or inode number this operation affects
    pub target: u64,

    /// CRC32 of this entry + data
    pub checksum: u32,
}

impl JournalEntry {
    /// Size of the journal entry header
    pub const HEADER_SIZE: usize = 24;

    /// Creates a new journal entry
    pub fn new(sequence: u64, op_type: JournalOpType, target: u64, data_len: u16) -> Self {
        Self {
            sequence,
            op_type: op_type as u8,
            flags: 0,
            data_len,
            target,
            checksum: 0,
        }
    }
}

/// Journal header (at start of journal area)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalHeader {
    /// Magic number
    pub magic: [u8; 4],

    /// Journal format version
    pub version: u32,

    /// Size of journal in blocks
    pub size_blocks: u32,

    /// Current head position (oldest valid entry)
    pub head: u32,

    /// Current tail position (next write position)
    pub tail: u32,

    /// Current sequence number
    pub sequence: u64,

    /// Reserved
    #[serde(with = "BigArray")]
    pub reserved: [u8; 32],
}

impl JournalHeader {
    /// Journal magic number
    pub const MAGIC: [u8; 4] = *b"JRNL";

    /// Creates a new journal header
    pub fn new(size_blocks: u32) -> Self {
        Self {
            magic: Self::MAGIC,
            version: 1,
            size_blocks,
            head: 0,
            tail: 0,
            sequence: 1,
            reserved: [0; 32],
        }
    }
}

// ============================================================================
// Bitmap Operations
// ============================================================================

/// Bitmap helper for block/inode allocation
#[derive(Debug, Clone)]
pub struct Bitmap {
    /// Raw bitmap data
    data: Vec<u8>,
}

impl Bitmap {
    /// Creates a new bitmap with given size in bits
    pub fn new(bits: usize) -> Self {
        let bytes = bits.div_ceil(8);
        Self {
            data: vec![0u8; bytes],
        }
    }

    /// Creates a bitmap from existing data
    pub fn from_data(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Returns the raw data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns mutable raw data
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Checks if a bit is set
    pub fn is_set(&self, index: usize) -> bool {
        let byte_idx = index / 8;
        let bit_idx = index % 8;
        if byte_idx >= self.data.len() {
            return false;
        }
        (self.data[byte_idx] & (1 << bit_idx)) != 0
    }

    /// Sets a bit
    pub fn set(&mut self, index: usize) {
        let byte_idx = index / 8;
        let bit_idx = index % 8;
        if byte_idx < self.data.len() {
            self.data[byte_idx] |= 1 << bit_idx;
        }
    }

    /// Clears a bit
    pub fn clear(&mut self, index: usize) {
        let byte_idx = index / 8;
        let bit_idx = index % 8;
        if byte_idx < self.data.len() {
            self.data[byte_idx] &= !(1 << bit_idx);
        }
    }

    /// Finds the first clear bit starting from `start`
    pub fn find_first_clear(&self, start: usize) -> Option<usize> {
        let total_bits = self.data.len() * 8;
        (start..total_bits).find(|&i| !self.is_set(i))
    }

    /// Counts set bits
    pub fn count_set(&self) -> usize {
        self.data.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Counts clear bits (up to total_bits)
    pub fn count_clear(&self, total_bits: usize) -> usize {
        total_bits - self.count_set().min(total_bits)
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur with the on-disk format
#[derive(Debug, Clone, thiserror::Error)]
pub enum FormatError {
    /// Invalid magic number
    #[error("Invalid filesystem magic number")]
    InvalidMagic,

    /// Unsupported version
    #[error("Unsupported filesystem version: {0}")]
    UnsupportedVersion(u32),

    /// Invalid block size
    #[error("Invalid block size: {0}")]
    InvalidBlockSize(u32),

    /// Checksum mismatch
    #[error("Checksum verification failed")]
    ChecksumMismatch,

    /// Filesystem is full (no free blocks)
    #[error("Filesystem is full: no free blocks")]
    NoFreeBlocks,

    /// No free inodes
    #[error("No free inodes")]
    NoFreeInodes,

    /// Invalid inode number
    #[error("Invalid inode number: {0}")]
    InvalidInode(u32),

    /// Invalid block number
    #[error("Invalid block number: {0}")]
    InvalidBlock(u64),

    /// Name too long
    #[error("Filename too long: {0} bytes (max {MAX_FILENAME_LEN})")]
    NameTooLong(usize),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_superblock_new() {
        let sb = Superblock::new(1000, "TestVolume");
        assert_eq!(sb.magic, FS_MAGIC);
        assert_eq!(sb.version, FS_VERSION);
        assert_eq!(sb.block_size, FS_BLOCK_SIZE);
        assert_eq!(sb.total_blocks, 1000);
        assert!(sb.validate().is_ok());
    }

    #[test]
    fn test_superblock_checksum() {
        let mut sb = Superblock::new(1000, "Test");
        sb.update_checksum();
        assert!(sb.verify_checksum());

        // Modify and verify checksum fails
        sb.free_blocks = 999;
        assert!(!sb.verify_checksum());
    }

    #[test]
    fn test_inode_types() {
        let file = Inode::new_file(0o644);
        assert!(file.is_file());
        assert!(!file.is_dir());
        assert_eq!(file.permissions(), 0o644);

        let dir = Inode::new_directory(0o755);
        assert!(dir.is_dir());
        assert!(!dir.is_file());
        assert_eq!(dir.permissions(), 0o755);
    }

    #[test]
    fn test_inode_size() {
        // Verify inode fits in INODE_SIZE bytes
        let inode = Inode::new();
        let serialized = bincode::serialize(&inode).unwrap();
        assert!(
            serialized.len() <= INODE_SIZE as usize,
            "Inode too large: {} > {}",
            serialized.len(),
            INODE_SIZE
        );
    }

    #[test]
    fn test_max_file_size() {
        let max_size = Inode::max_file_size();
        // Should be > 4GB with double indirect
        assert!(max_size > 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_dir_entry() {
        let entry = DirEntry::new(42, "test.txt", InodeType::File);
        assert_eq!(entry.inode, 42);
        assert_eq!(entry.name_str().unwrap(), "test.txt");
        assert_eq!(entry.file_type, InodeType::File as u8);
        assert!(!entry.is_deleted());

        // Verify 4-byte alignment
        assert_eq!(entry.rec_len % 4, 0);
    }

    #[test]
    fn test_bitmap() {
        let mut bitmap = Bitmap::new(100);

        assert!(!bitmap.is_set(0));
        assert!(!bitmap.is_set(50));

        bitmap.set(42);
        assert!(bitmap.is_set(42));
        assert!(!bitmap.is_set(41));
        assert!(!bitmap.is_set(43));

        bitmap.clear(42);
        assert!(!bitmap.is_set(42));

        // Test find_first_clear
        bitmap.set(0);
        bitmap.set(1);
        assert_eq!(bitmap.find_first_clear(0), Some(2));
    }

    #[test]
    fn test_layout_constants() {
        // Verify non-overlapping layout
        assert!(BACKUP_SUPERBLOCK_BLOCK > SUPERBLOCK_BLOCK);
        assert!(BLOCK_BITMAP_START > BACKUP_SUPERBLOCK_BLOCK);
        assert!(INODE_BITMAP_START >= BLOCK_BITMAP_START + BLOCK_BITMAP_BLOCKS);
        assert!(INODE_TABLE_START >= INODE_BITMAP_START + INODE_BITMAP_BLOCKS);
        assert!(JOURNAL_START >= INODE_TABLE_START + INODE_TABLE_BLOCKS);
        assert!(DATA_BLOCKS_START >= JOURNAL_START + JOURNAL_BLOCKS);
    }

    #[test]
    fn test_journal_entry() {
        let entry = JournalEntry::new(1, JournalOpType::WriteBlock, 100, 4096);
        assert_eq!(entry.sequence, 1);
        assert_eq!(entry.op_type, JournalOpType::WriteBlock as u8);
        assert_eq!(entry.target, 100);
    }
}

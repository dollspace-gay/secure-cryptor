/// Cross-platform filesystem abstraction for encrypted volumes
///
/// This module provides a common interface for implementing encrypted filesystems
/// that works across FUSE (Linux/macOS) and WinFsp (Windows).

use std::path::{Path, PathBuf};
use std::time::SystemTime;
use thiserror::Error;

use super::MasterKey;

/// File type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Regular file
    RegularFile,
    /// Directory
    Directory,
    /// Symbolic link
    Symlink,
}

/// File attributes (metadata)
#[derive(Debug, Clone)]
pub struct FileAttr {
    /// Size in bytes
    pub size: u64,

    /// Number of hard links
    pub nlink: u32,

    /// File type
    pub file_type: FileType,

    /// Permissions (Unix-style, e.g., 0o755)
    pub perm: u16,

    /// User ID
    pub uid: u32,

    /// Group ID
    pub gid: u32,

    /// Last access time
    pub atime: SystemTime,

    /// Last modification time
    pub mtime: SystemTime,

    /// Last status change time
    pub ctime: SystemTime,
}

/// Directory entry
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// File name
    pub name: String,

    /// File type
    pub file_type: FileType,
}

/// Filesystem operation errors
#[derive(Debug, Error)]
pub enum FilesystemError {
    /// File or directory not found
    #[error("No such file or directory: {0}")]
    NotFound(PathBuf),

    /// File or directory already exists
    #[error("File already exists: {0}")]
    AlreadyExists(PathBuf),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(PathBuf),

    /// Not a directory
    #[error("Not a directory: {0}")]
    NotADirectory(PathBuf),

    /// Is a directory (when file expected)
    #[error("Is a directory: {0}")]
    IsADirectory(PathBuf),

    /// Directory not empty
    #[error("Directory not empty: {0}")]
    DirectoryNotEmpty(PathBuf),

    /// Invalid file name
    #[error("Invalid file name: {0}")]
    InvalidFileName(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Encryption/decryption error
    #[error("Encryption error: {0}")]
    CryptoError(String),

    /// Not supported operation
    #[error("Operation not supported: {0}")]
    NotSupported(String),

    /// Other error
    #[error("Filesystem error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, FilesystemError>;

/// Trait for encrypted filesystem implementations
///
/// This trait provides a common interface for filesystem operations
/// that can be implemented for different platforms (FUSE, WinFsp).
pub trait EncryptedFilesystem {
    /// Initialize the filesystem with a master key
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master encryption key
    /// * `backing_file` - Path to the volume file
    fn init(&mut self, master_key: &MasterKey, backing_file: &Path) -> Result<()>;

    /// Get file attributes
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    ///
    /// # Returns
    ///
    /// File attributes
    fn getattr(&self, path: &Path) -> Result<FileAttr>;

    /// Read directory contents
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the directory
    ///
    /// # Returns
    ///
    /// Vector of directory entries
    fn readdir(&self, path: &Path) -> Result<Vec<DirEntry>>;

    /// Read file data
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    /// * `offset` - Byte offset to start reading from
    /// * `size` - Number of bytes to read
    ///
    /// # Returns
    ///
    /// Decrypted file data
    fn read(&self, path: &Path, offset: u64, size: u32) -> Result<Vec<u8>>;

    /// Write file data
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    /// * `offset` - Byte offset to start writing at
    /// * `data` - Data to write (will be encrypted)
    ///
    /// # Returns
    ///
    /// Number of bytes written
    fn write(&mut self, path: &Path, offset: u64, data: &[u8]) -> Result<u32>;

    /// Create a new file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the new file
    /// * `mode` - Permission mode
    ///
    /// # Returns
    ///
    /// File attributes of the created file
    fn create(&mut self, path: &Path, mode: u16) -> Result<FileAttr>;

    /// Create a new directory
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the new directory
    /// * `mode` - Permission mode
    fn mkdir(&mut self, path: &Path, mode: u16) -> Result<()>;

    /// Remove a file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to remove
    fn unlink(&mut self, path: &Path) -> Result<()>;

    /// Remove a directory
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the directory to remove (must be empty)
    fn rmdir(&mut self, path: &Path) -> Result<()>;

    /// Rename a file or directory
    ///
    /// # Arguments
    ///
    /// * `from` - Current path
    /// * `to` - New path
    fn rename(&mut self, from: &Path, to: &Path) -> Result<()>;

    /// Change file permissions
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    /// * `mode` - New permission mode
    fn chmod(&mut self, path: &Path, mode: u16) -> Result<()>;

    /// Change file ownership
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    /// * `uid` - New user ID
    /// * `gid` - New group ID
    fn chown(&mut self, path: &Path, uid: u32, gid: u32) -> Result<()>;

    /// Truncate a file to a specified size
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    /// * `size` - New size in bytes
    fn truncate(&mut self, path: &Path, size: u64) -> Result<()>;

    /// Update file timestamps
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    /// * `atime` - New access time (None to keep current)
    /// * `mtime` - New modification time (None to keep current)
    fn utimens(&mut self, path: &Path, atime: Option<SystemTime>, mtime: Option<SystemTime>) -> Result<()>;

    /// Flush any cached data to disk
    fn flush(&mut self) -> Result<()>;

    /// Get filesystem statistics
    ///
    /// # Returns
    ///
    /// (total_bytes, free_bytes, available_bytes)
    fn statfs(&self) -> Result<(u64, u64, u64)>;
}

impl Default for FileAttr {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            size: 0,
            nlink: 1,
            file_type: FileType::RegularFile,
            perm: 0o644,
            uid: 0,
            gid: 0,
            atime: now,
            mtime: now,
            ctime: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_attr_default() {
        let attr = FileAttr::default();
        assert_eq!(attr.size, 0);
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.file_type, FileType::RegularFile);
        assert_eq!(attr.perm, 0o644);
    }

    #[test]
    fn test_file_type() {
        assert_eq!(FileType::RegularFile, FileType::RegularFile);
        assert_ne!(FileType::RegularFile, FileType::Directory);
    }

    #[test]
    fn test_dir_entry() {
        let entry = DirEntry {
            name: "test.txt".to_string(),
            file_type: FileType::RegularFile,
        };
        assert_eq!(entry.name, "test.txt");
        assert_eq!(entry.file_type, FileType::RegularFile);
    }
}

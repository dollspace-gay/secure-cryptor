//! In-memory encrypted filesystem implementation
//!
//! This module provides a concrete implementation of the EncryptedFilesystem trait
//! that stores file data and metadata in memory with transparent encryption.

use super::filesystem::{
    DirEntry, EncryptedFilesystem, FileAttr, FileType, FilesystemError, Result,
};
use super::MasterKey;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Inode number type
type InodeId = u64;

/// Root inode ID
const ROOT_INODE: InodeId = 1;

/// Inode representing a file or directory
#[derive(Debug, Clone)]
struct Inode {
    /// Inode ID
    #[allow(dead_code)]
    id: InodeId,

    /// File type
    file_type: FileType,

    /// File size in bytes
    size: u64,

    /// Permissions
    perm: u16,

    /// User ID
    uid: u32,

    /// Group ID
    gid: u32,

    /// Number of hard links
    nlink: u32,

    /// Access time
    atime: SystemTime,

    /// Modification time
    mtime: SystemTime,

    /// Change time
    ctime: SystemTime,

    /// File data (encrypted)
    data: Vec<u8>,

    /// Directory entries (if directory)
    children: HashMap<String, InodeId>,
}

/// In-memory encrypted filesystem
pub struct InMemoryFilesystem {
    /// Master encryption key
    master_key: Option<MasterKey>,

    /// Inode table
    inodes: HashMap<InodeId, Inode>,

    /// Next inode ID
    next_inode: InodeId,

    /// Path to inode mapping for fast lookup
    path_cache: HashMap<PathBuf, InodeId>,
}

impl Inode {
    /// Creates a new file inode
    fn new_file(id: InodeId, perm: u16) -> Self {
        let now = SystemTime::now();
        Self {
            id,
            file_type: FileType::RegularFile,
            size: 0,
            perm,
            uid: 1000,
            gid: 1000,
            nlink: 1,
            atime: now,
            mtime: now,
            ctime: now,
            data: Vec::new(),
            children: HashMap::new(),
        }
    }

    /// Creates a new directory inode
    fn new_dir(id: InodeId, perm: u16) -> Self {
        let now = SystemTime::now();
        Self {
            id,
            file_type: FileType::Directory,
            size: 0,
            perm,
            uid: 1000,
            gid: 1000,
            nlink: 2, // . and ..
            atime: now,
            mtime: now,
            ctime: now,
            data: Vec::new(),
            children: HashMap::new(),
        }
    }

    /// Converts to FileAttr
    fn to_attr(&self) -> FileAttr {
        FileAttr {
            size: self.size,
            nlink: self.nlink,
            file_type: self.file_type,
            perm: self.perm,
            uid: self.uid,
            gid: self.gid,
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
        }
    }
}

impl InMemoryFilesystem {
    /// Creates a new empty filesystem
    pub fn new() -> Self {
        let mut inodes = HashMap::new();
        let mut path_cache = HashMap::new();

        // Create root directory
        let root = Inode::new_dir(ROOT_INODE, 0o755);
        inodes.insert(ROOT_INODE, root);
        path_cache.insert(PathBuf::from("/"), ROOT_INODE);

        Self {
            master_key: None,
            inodes,
            next_inode: ROOT_INODE + 1,
            path_cache,
        }
    }

    /// Encrypts data using the master key
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.master_key.as_ref()
            .ok_or_else(|| FilesystemError::Other("Filesystem not initialized".to_string()))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| FilesystemError::CryptoError(e.to_string()))?;

        let nonce = Nonce::try_from(nonce_bytes).expect("Invalid nonce length");
        let ciphertext = cipher.encrypt(&nonce, data)
            .map_err(|e| FilesystemError::CryptoError(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypts data using the master key
    fn decrypt_data(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < 12 {
            return Err(FilesystemError::CryptoError("Invalid encrypted data".to_string()));
        }

        let key = self.master_key.as_ref()
            .ok_or_else(|| FilesystemError::Other("Filesystem not initialized".to_string()))?;

        // Extract nonce and ciphertext
        let nonce_bytes: [u8; 12] = encrypted[0..12].try_into().unwrap();
        let ciphertext = &encrypted[12..];

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| FilesystemError::CryptoError(e.to_string()))?;

        let nonce = Nonce::try_from(nonce_bytes).expect("Invalid nonce length");
        let plaintext = cipher.decrypt(&nonce, ciphertext)
            .map_err(|_| FilesystemError::CryptoError("Decryption failed".to_string()))?;

        Ok(plaintext)
    }

    /// Resolves a path to an inode ID
    fn resolve_path(&self, path: &Path) -> Result<InodeId> {
        // Check cache first
        if let Some(&inode_id) = self.path_cache.get(path) {
            return Ok(inode_id);
        }

        // Root case
        if path == Path::new("/") {
            return Ok(ROOT_INODE);
        }

        // Walk the path
        let mut current = ROOT_INODE;
        let components: Vec<_> = path.components()
            .filter_map(|c| c.as_os_str().to_str())
            .filter(|s| *s != "/")
            .collect();

        for component in components {
            let inode = self.inodes.get(&current)
                .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;

            if inode.file_type != FileType::Directory {
                return Err(FilesystemError::NotADirectory(path.to_path_buf()));
            }

            current = *inode.children.get(component)
                .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;
        }

        Ok(current)
    }

    /// Allocates a new inode ID
    fn alloc_inode(&mut self) -> InodeId {
        let id = self.next_inode;
        self.next_inode += 1;
        id
    }
}

impl Default for InMemoryFilesystem {
    fn default() -> Self {
        Self::new()
    }
}

impl EncryptedFilesystem for InMemoryFilesystem {
    fn init(&mut self, master_key: &MasterKey, _backing_file: &Path) -> Result<()> {
        self.master_key = Some(master_key.clone());
        Ok(())
    }

    fn getattr(&self, path: &Path) -> Result<FileAttr> {
        let inode_id = self.resolve_path(path)?;
        let inode = self.inodes.get(&inode_id)
            .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;
        Ok(inode.to_attr())
    }

    fn readdir(&self, path: &Path) -> Result<Vec<DirEntry>> {
        let inode_id = self.resolve_path(path)?;
        let inode = self.inodes.get(&inode_id)
            .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;

        if inode.file_type != FileType::Directory {
            return Err(FilesystemError::NotADirectory(path.to_path_buf()));
        }

        let mut entries = vec![
            DirEntry {
                name: ".".to_string(),
                file_type: FileType::Directory,
            },
            DirEntry {
                name: "..".to_string(),
                file_type: FileType::Directory,
            },
        ];

        for (name, &child_id) in &inode.children {
            if let Some(child) = self.inodes.get(&child_id) {
                entries.push(DirEntry {
                    name: name.clone(),
                    file_type: child.file_type,
                });
            }
        }

        Ok(entries)
    }

    fn read(&self, path: &Path, offset: u64, size: u32) -> Result<Vec<u8>> {
        let inode_id = self.resolve_path(path)?;
        let inode = self.inodes.get(&inode_id)
            .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;

        if inode.file_type != FileType::RegularFile {
            return Err(FilesystemError::IsADirectory(path.to_path_buf()));
        }

        // Decrypt data
        let data = if !inode.data.is_empty() {
            self.decrypt_data(&inode.data)?
        } else {
            Vec::new()
        };

        // Read requested range
        let start = offset.min(data.len() as u64) as usize;
        let end = (offset + size as u64).min(data.len() as u64) as usize;

        Ok(data[start..end].to_vec())
    }

    fn write(&mut self, path: &Path, offset: u64, data: &[u8]) -> Result<u32> {
        let inode_id = self.resolve_path(path)?;

        // Get existing encrypted data and file type
        let (encrypted_data, file_type) = {
            let inode = self.inodes.get(&inode_id)
                .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;
            (inode.data.clone(), inode.file_type)
        };

        if file_type != FileType::RegularFile {
            return Err(FilesystemError::IsADirectory(path.to_path_buf()));
        }

        // Decrypt existing data
        let mut file_data = if !encrypted_data.is_empty() {
            self.decrypt_data(&encrypted_data)?
        } else {
            Vec::new()
        };

        // Extend if necessary
        let end = offset as usize + data.len();
        if end > file_data.len() {
            file_data.resize(end, 0);
        }

        // Write data
        file_data[offset as usize..end].copy_from_slice(data);

        // Encrypt
        let new_encrypted_data = self.encrypt_data(&file_data)?;
        let new_size = file_data.len() as u64;

        // Update inode
        let inode = self.inodes.get_mut(&inode_id).unwrap();
        inode.data = new_encrypted_data;
        inode.size = new_size;
        inode.mtime = SystemTime::now();

        Ok(data.len() as u32)
    }

    fn create(&mut self, path: &Path, mode: u16) -> Result<FileAttr> {
        let parent = path.parent()
            .ok_or_else(|| FilesystemError::InvalidFileName("No parent directory".to_string()))?;
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| FilesystemError::InvalidFileName("Invalid filename".to_string()))?;

        let parent_id = self.resolve_path(parent)?;

        // Check if parent is a directory and child doesn't exist
        {
            let parent_inode = self.inodes.get(&parent_id)
                .ok_or_else(|| FilesystemError::NotFound(parent.to_path_buf()))?;

            if parent_inode.children.contains_key(filename) {
                return Err(FilesystemError::AlreadyExists(path.to_path_buf()));
            }
        }

        // Create new inode
        let inode_id = self.alloc_inode();
        let inode = Inode::new_file(inode_id, mode);
        let attr = inode.to_attr();

        // Add to parent
        let parent_inode = self.inodes.get_mut(&parent_id).unwrap();
        parent_inode.children.insert(filename.to_string(), inode_id);
        parent_inode.mtime = SystemTime::now();

        // Store inode
        self.inodes.insert(inode_id, inode);
        self.path_cache.insert(path.to_path_buf(), inode_id);

        Ok(attr)
    }

    fn mkdir(&mut self, path: &Path, mode: u16) -> Result<()> {
        let parent = path.parent()
            .ok_or_else(|| FilesystemError::InvalidFileName("No parent directory".to_string()))?;
        let dirname = path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| FilesystemError::InvalidFileName("Invalid directory name".to_string()))?;

        let parent_id = self.resolve_path(parent)?;

        // Check if parent exists and child doesn't exist
        {
            let parent_inode = self.inodes.get(&parent_id)
                .ok_or_else(|| FilesystemError::NotFound(parent.to_path_buf()))?;

            if parent_inode.children.contains_key(dirname) {
                return Err(FilesystemError::AlreadyExists(path.to_path_buf()));
            }
        }

        // Create new directory inode
        let inode_id = self.alloc_inode();
        let inode = Inode::new_dir(inode_id, mode);

        // Add to parent
        let parent_inode = self.inodes.get_mut(&parent_id).unwrap();
        parent_inode.children.insert(dirname.to_string(), inode_id);
        parent_inode.nlink += 1;
        parent_inode.mtime = SystemTime::now();

        // Store inode
        self.inodes.insert(inode_id, inode);
        self.path_cache.insert(path.to_path_buf(), inode_id);

        Ok(())
    }

    fn unlink(&mut self, path: &Path) -> Result<()> {
        let parent = path.parent()
            .ok_or_else(|| FilesystemError::InvalidFileName("No parent directory".to_string()))?;
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| FilesystemError::InvalidFileName("Invalid filename".to_string()))?;

        let parent_id = self.resolve_path(parent)?;
        let inode_id = self.resolve_path(path)?;

        let inode = self.inodes.get(&inode_id)
            .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;

        if inode.file_type != FileType::RegularFile {
            return Err(FilesystemError::IsADirectory(path.to_path_buf()));
        }

        // Remove from parent
        let parent_inode = self.inodes.get_mut(&parent_id).unwrap();
        parent_inode.children.remove(filename);
        parent_inode.mtime = SystemTime::now();

        // Remove inode
        self.inodes.remove(&inode_id);
        self.path_cache.remove(path);

        Ok(())
    }

    fn rmdir(&mut self, path: &Path) -> Result<()> {
        let inode_id = self.resolve_path(path)?;
        let inode = self.inodes.get(&inode_id)
            .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;

        if inode.file_type != FileType::Directory {
            return Err(FilesystemError::NotADirectory(path.to_path_buf()));
        }

        if !inode.children.is_empty() {
            return Err(FilesystemError::DirectoryNotEmpty(path.to_path_buf()));
        }

        let parent = path.parent()
            .ok_or_else(|| FilesystemError::InvalidFileName("Cannot remove root".to_string()))?;
        let dirname = path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| FilesystemError::InvalidFileName("Invalid directory name".to_string()))?;

        let parent_id = self.resolve_path(parent)?;

        // Remove from parent
        let parent_inode = self.inodes.get_mut(&parent_id).unwrap();
        parent_inode.children.remove(dirname);
        parent_inode.nlink -= 1;
        parent_inode.mtime = SystemTime::now();

        // Remove inode
        self.inodes.remove(&inode_id);
        self.path_cache.remove(path);

        Ok(())
    }

    fn rename(&mut self, from: &Path, to: &Path) -> Result<()> {
        // Simplified implementation - doesn't handle all edge cases
        let from_parent = from.parent()
            .ok_or_else(|| FilesystemError::InvalidFileName("No parent directory".to_string()))?;
        let from_name = from.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| FilesystemError::InvalidFileName("Invalid filename".to_string()))?;

        let to_parent = to.parent()
            .ok_or_else(|| FilesystemError::InvalidFileName("No parent directory".to_string()))?;
        let to_name = to.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| FilesystemError::InvalidFileName("Invalid filename".to_string()))?;

        let inode_id = self.resolve_path(from)?;
        let from_parent_id = self.resolve_path(from_parent)?;
        let to_parent_id = self.resolve_path(to_parent)?;

        // Remove from old parent
        let from_parent_inode = self.inodes.get_mut(&from_parent_id).unwrap();
        from_parent_inode.children.remove(from_name);

        // Add to new parent
        let to_parent_inode = self.inodes.get_mut(&to_parent_id).unwrap();
        to_parent_inode.children.insert(to_name.to_string(), inode_id);

        // Update cache
        self.path_cache.remove(from);
        self.path_cache.insert(to.to_path_buf(), inode_id);

        Ok(())
    }

    fn chmod(&mut self, path: &Path, mode: u16) -> Result<()> {
        let inode_id = self.resolve_path(path)?;
        let inode = self.inodes.get_mut(&inode_id)
            .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;
        inode.perm = mode;
        inode.ctime = SystemTime::now();
        Ok(())
    }

    fn chown(&mut self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        let inode_id = self.resolve_path(path)?;
        let inode = self.inodes.get_mut(&inode_id)
            .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;
        inode.uid = uid;
        inode.gid = gid;
        inode.ctime = SystemTime::now();
        Ok(())
    }

    fn truncate(&mut self, path: &Path, size: u64) -> Result<()> {
        let inode_id = self.resolve_path(path)?;

        // Get existing encrypted data and file type (clone to avoid borrow issues)
        let (encrypted_data, file_type) = {
            let inode = self.inodes.get(&inode_id)
                .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;
            (inode.data.clone(), inode.file_type)
        };

        if file_type != FileType::RegularFile {
            return Err(FilesystemError::IsADirectory(path.to_path_buf()));
        }

        // Decrypt, resize, encrypt
        let mut data = if !encrypted_data.is_empty() {
            self.decrypt_data(&encrypted_data)?
        } else {
            Vec::new()
        };

        data.resize(size as usize, 0);
        let new_encrypted_data = self.encrypt_data(&data)?;

        // Update inode
        let inode = self.inodes.get_mut(&inode_id).unwrap();
        inode.data = new_encrypted_data;
        inode.size = size;
        inode.mtime = SystemTime::now();

        Ok(())
    }

    fn utimens(&mut self, path: &Path, atime: Option<SystemTime>, mtime: Option<SystemTime>) -> Result<()> {
        let inode_id = self.resolve_path(path)?;
        let inode = self.inodes.get_mut(&inode_id)
            .ok_or_else(|| FilesystemError::NotFound(path.to_path_buf()))?;

        if let Some(atime) = atime {
            inode.atime = atime;
        }
        if let Some(mtime) = mtime {
            inode.mtime = mtime;
        }
        inode.ctime = SystemTime::now();

        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        // In-memory implementation - nothing to flush
        Ok(())
    }

    fn statfs(&self) -> Result<(u64, u64, u64)> {
        // Return dummy values for in-memory filesystem
        let total: u64 = 1024 * 1024 * 1024; // 1GB
        let used: u64 = self.inodes.values().map(|i| i.size).sum();
        let free = total.saturating_sub(used);
        Ok((total, free, free))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> MasterKey {
        MasterKey::generate()
    }

    #[test]
    fn test_filesystem_init() {
        let mut fs = InMemoryFilesystem::new();
        let key = test_key();
        assert!(fs.init(&key, Path::new("/tmp/test.vol")).is_ok());
    }

    #[test]
    fn test_root_exists() {
        let mut fs = InMemoryFilesystem::new();
        let key = test_key();
        fs.init(&key, Path::new("/tmp/test.vol")).unwrap();

        let attr = fs.getattr(Path::new("/")).unwrap();
        assert_eq!(attr.file_type, FileType::Directory);
    }

    #[test]
    fn test_create_and_read_file() {
        let mut fs = InMemoryFilesystem::new();
        let key = test_key();
        fs.init(&key, Path::new("/tmp/test.vol")).unwrap();

        // Create file
        let path = Path::new("/test.txt");
        fs.create(path, 0o644).unwrap();

        // Write data
        let data = b"Hello, World!";
        let written = fs.write(path, 0, data).unwrap();
        assert_eq!(written, data.len() as u32);

        // Read data
        let read_data = fs.read(path, 0, data.len() as u32).unwrap();
        assert_eq!(&read_data, data);
    }

    #[test]
    fn test_mkdir_and_readdir() {
        let mut fs = InMemoryFilesystem::new();
        let key = test_key();
        fs.init(&key, Path::new("/tmp/test.vol")).unwrap();

        // Create directory
        let dir = Path::new("/testdir");
        fs.mkdir(dir, 0o755).unwrap();

        // Create file in directory
        let file = Path::new("/testdir/file.txt");
        fs.create(file, 0o644).unwrap();

        // Read directory
        let entries = fs.readdir(dir).unwrap();
        assert!(entries.iter().any(|e| e.name == "file.txt"));
    }

    #[test]
    fn test_unlink() {
        let mut fs = InMemoryFilesystem::new();
        let key = test_key();
        fs.init(&key, Path::new("/tmp/test.vol")).unwrap();

        let path = Path::new("/test.txt");
        fs.create(path, 0o644).unwrap();
        fs.unlink(path).unwrap();

        assert!(fs.getattr(path).is_err());
    }

    #[test]
    fn test_rename() {
        let mut fs = InMemoryFilesystem::new();
        let key = test_key();
        fs.init(&key, Path::new("/tmp/test.vol")).unwrap();

        let from = Path::new("/old.txt");
        let to = Path::new("/new.txt");

        fs.create(from, 0o644).unwrap();
        fs.rename(from, to).unwrap();

        assert!(fs.getattr(from).is_err());
        assert!(fs.getattr(to).is_ok());
    }

    #[test]
    fn test_encryption_decryption() {
        let mut fs = InMemoryFilesystem::new();
        let key = test_key();
        fs.init(&key, Path::new("/tmp/test.vol")).unwrap();

        let path = Path::new("/test.txt");
        fs.create(path, 0o644).unwrap();

        let data = b"Secret message that should be encrypted";
        fs.write(path, 0, data).unwrap();

        // Verify data is encrypted in storage
        let inode_id = fs.resolve_path(path).unwrap();
        let inode = fs.inodes.get(&inode_id).unwrap();
        assert_ne!(&inode.data[12..], data); // Skip nonce

        // Verify decryption works
        let read_data = fs.read(path, 0, data.len() as u32).unwrap();
        assert_eq!(&read_data, data);
    }
}

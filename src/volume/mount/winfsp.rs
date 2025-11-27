/// WinFsp filesystem implementation for Windows
///
/// This module implements a WinFsp adapter that allows mounting encrypted
/// containers as drive letters or directories on Windows.
///
/// Uses VolumeIOFilesystem for persistent, encrypted storage.

use std::collections::HashMap;
use std::ffi::{OsString, c_void};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use windows::Win32::Foundation::*;

use winfsp::{
    U16CStr, U16CString,
    filesystem::{
        FileInfo, FileSecurity, FileSystemContext, DirInfo, DirMarker,
        OpenFileInfo, VolumeInfo,
    },
    host::{FileSystemHost, VolumeParams},
    FspError, Result as FspResult,
};

use super::super::container::Container;
use super::super::filesystem::FilesystemError;
use super::super::format::{InodeType, FS_BLOCK_SIZE, ROOT_INODE};
use super::super::io::{FileBackend, StorageBackend};
use super::super::volumeio_fs::{VolumeIOFilesystem, VolumeIOFsError};
use super::{MountError, MountOptions, Result};

/// Windows file attribute constants
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_READONLY: u32 = 0x01;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFF;

/// Convert Windows FILETIME (100-nanosecond intervals since 1601) to Unix timestamp
fn filetime_to_unix(filetime: u64) -> u64 {
    const WINDOWS_TICK: u64 = 10_000_000; // 100ns intervals per second
    const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000; // 1970-01-01 in FILETIME

    if filetime < UNIX_EPOCH_FILETIME {
        0
    } else {
        (filetime - UNIX_EPOCH_FILETIME) / WINDOWS_TICK
    }
}

/// Convert Unix timestamp to Windows FILETIME
fn unix_to_filetime(unix_time: u64) -> u64 {
    const WINDOWS_TICK: u64 = 10_000_000;
    const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;

    UNIX_EPOCH_FILETIME + (unix_time * WINDOWS_TICK)
}

/// Convert SystemTime to Windows FILETIME
fn systemtime_to_filetime(time: SystemTime) -> u64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => unix_to_filetime(duration.as_secs()),
        Err(_) => unix_to_filetime(0),
    }
}

/// File context - holds the inode number for the opened file/directory
#[derive(Clone)]
pub struct WinFspFileContext {
    inode: u32,
    path: PathBuf, // Keep path for name lookups in rename
}

/// Path to inode cache entry
struct PathCacheEntry {
    inode: u32,
    parent_inode: u32,
    name: String,
}

/// WinFsp filesystem adapter using VolumeIOFilesystem
pub struct WinFspAdapter {
    fs: VolumeIOFilesystem,
    /// Cache mapping paths to inodes for efficient lookup
    path_cache: RwLock<HashMap<PathBuf, PathCacheEntry>>,
}

impl WinFspAdapter {
    fn new(fs: VolumeIOFilesystem) -> Self {
        // Initialize with root path
        let mut cache = HashMap::new();
        cache.insert(PathBuf::from("/"), PathCacheEntry {
            inode: ROOT_INODE,
            parent_inode: ROOT_INODE,
            name: String::new(),
        });

        Self {
            fs,
            path_cache: RwLock::new(cache),
        }
    }

    /// Converts InodeType to Windows file attributes
    fn inode_type_to_attributes(it: InodeType) -> u32 {
        match it {
            InodeType::Directory => FILE_ATTRIBUTE_DIRECTORY,
            InodeType::File => FILE_ATTRIBUTE_NORMAL,
            InodeType::Symlink => FILE_ATTRIBUTE_REPARSE_POINT,
        }
    }

    /// Converts VolumeIOFsError to FspError
    fn error_to_fsp(err: VolumeIOFsError) -> FspError {
        match err {
            VolumeIOFsError::Filesystem(fe) => Self::fs_error_to_fsp(fe),
            VolumeIOFsError::VolumeIO(_) => STATUS_IO_DEVICE_ERROR.into(),
            VolumeIOFsError::Format(_) => STATUS_IO_DEVICE_ERROR.into(),
            VolumeIOFsError::Serialization(_) => STATUS_IO_DEVICE_ERROR.into(),
            VolumeIOFsError::InvalidOperation(_) => STATUS_INVALID_PARAMETER.into(),
            VolumeIOFsError::LockPoisoned => STATUS_IO_DEVICE_ERROR.into(),
            VolumeIOFsError::NotInitialized => STATUS_IO_DEVICE_ERROR.into(),
        }
    }

    /// Converts FilesystemError to FspError
    fn fs_error_to_fsp(err: FilesystemError) -> FspError {
        match err {
            FilesystemError::NotFound(_) => STATUS_OBJECT_NAME_NOT_FOUND.into(),
            FilesystemError::AlreadyExists(_) => STATUS_OBJECT_NAME_COLLISION.into(),
            FilesystemError::PermissionDenied(_) => STATUS_ACCESS_DENIED.into(),
            FilesystemError::NotADirectory(_) => STATUS_NOT_A_DIRECTORY.into(),
            FilesystemError::IsADirectory(_) => STATUS_FILE_IS_A_DIRECTORY.into(),
            FilesystemError::DirectoryNotEmpty(_) => STATUS_DIRECTORY_NOT_EMPTY.into(),
            FilesystemError::InvalidFileName(_) => STATUS_OBJECT_NAME_INVALID.into(),
            FilesystemError::Io(_) => STATUS_IO_DEVICE_ERROR.into(),
            FilesystemError::CryptoError(_) => STATUS_DECRYPTION_FAILED.into(),
            FilesystemError::NotSupported(_) => STATUS_NOT_SUPPORTED.into(),
            FilesystemError::Other(_) => STATUS_UNSUCCESSFUL.into(),
        }
    }

    /// Convert Windows path (UTF-16) to PathBuf
    fn u16_to_path(u16_path: &U16CStr) -> PathBuf {
        let wide_slice: &[u16] = u16_path.as_slice();
        let os_str = OsString::from_wide(wide_slice);
        PathBuf::from(os_str)
    }

    /// Normalize path for internal use (remove leading backslash, convert to forward slashes)
    fn normalize_path(path: &Path) -> PathBuf {
        let path_str = path.to_string_lossy();
        let normalized = path_str
            .trim_start_matches('\\')
            .replace('\\', "/");

        if normalized.is_empty() {
            PathBuf::from("/")
        } else {
            PathBuf::from(format!("/{}", normalized))
        }
    }

    /// Resolve a path to an inode number
    fn resolve_path(&self, path: &Path) -> FspResult<u32> {
        // Check cache first
        {
            let cache = self.path_cache.read().unwrap();
            if let Some(entry) = cache.get(path) {
                return Ok(entry.inode);
            }
        }

        // Walk the path from root
        let mut current_inode = ROOT_INODE;

        for component in path.components() {
            match component {
                std::path::Component::RootDir => {
                    current_inode = ROOT_INODE;
                }
                std::path::Component::Normal(name) => {
                    let name_str = name.to_string_lossy();
                    match self.fs.lookup(current_inode, &name_str) {
                        Ok(Some(inode)) => {
                            current_inode = inode;
                        }
                        Ok(None) => {
                            return Err(STATUS_OBJECT_NAME_NOT_FOUND.into());
                        }
                        Err(e) => {
                            return Err(Self::error_to_fsp(e));
                        }
                    }
                }
                _ => {}
            }
        }

        // Cache the result
        if let Some(parent) = path.parent() {
            if let Some(name) = path.file_name() {
                let parent_inode = if parent == Path::new("/") || parent == Path::new("") {
                    ROOT_INODE
                } else {
                    self.resolve_path(parent)?
                };

                let mut cache = self.path_cache.write().unwrap();
                cache.insert(path.to_path_buf(), PathCacheEntry {
                    inode: current_inode,
                    parent_inode,
                    name: name.to_string_lossy().to_string(),
                });
            }
        }

        Ok(current_inode)
    }

    /// Get parent inode and filename from a path
    fn get_parent_and_name(&self, path: &Path) -> FspResult<(u32, String)> {
        let parent = path.parent().unwrap_or(Path::new("/"));
        let name = path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let parent_inode = if parent == Path::new("/") || parent == Path::new("") {
            ROOT_INODE
        } else {
            self.resolve_path(parent)?
        };

        Ok((parent_inode, name))
    }

    /// Fill FileInfo structure from an inode
    fn fill_file_info_from_inode(&self, inode_num: u32, file_info: &mut FileInfo) -> FspResult<()> {
        let inode = self.fs.get_inode(inode_num).map_err(Self::error_to_fsp)?;

        let file_type = if inode.is_dir() {
            InodeType::Directory
        } else if inode.is_symlink() {
            InodeType::Symlink
        } else {
            InodeType::File
        };

        file_info.file_attributes = Self::inode_type_to_attributes(file_type);
        file_info.reparse_tag = 0;
        file_info.file_size = inode.size;
        file_info.allocation_size = ((inode.size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64) * FS_BLOCK_SIZE as u64;
        file_info.creation_time = unix_to_filetime(inode.ctime);
        file_info.last_access_time = unix_to_filetime(inode.atime);
        file_info.last_write_time = unix_to_filetime(inode.mtime);
        file_info.change_time = unix_to_filetime(inode.ctime);
        file_info.index_number = inode_num as u64;
        file_info.hard_links = 0;
        file_info.ea_size = 0;

        Ok(())
    }

    /// Invalidate path cache entries for a path and its children
    fn invalidate_cache(&self, path: &Path) {
        let mut cache = self.path_cache.write().unwrap();
        let path_str = path.to_string_lossy().to_string();

        // Remove the path itself
        cache.remove(path);

        // Remove any children (paths that start with this path)
        let keys_to_remove: Vec<PathBuf> = cache.keys()
            .filter(|k| k.starts_with(path) && *k != path)
            .cloned()
            .collect();

        for key in keys_to_remove {
            cache.remove(&key);
        }
    }
}

impl FileSystemContext for WinFspAdapter {
    type FileContext = WinFspFileContext;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> FspResult<FileSecurity> {
        let path = Self::u16_to_path(file_name);
        let normalized_path = Self::normalize_path(&path);

        let inode_num = self.resolve_path(&normalized_path)?;
        let inode = self.fs.get_inode(inode_num).map_err(Self::error_to_fsp)?;

        let file_type = if inode.is_dir() {
            InodeType::Directory
        } else if inode.is_symlink() {
            InodeType::Symlink
        } else {
            InodeType::File
        };

        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes: Self::inode_type_to_attributes(file_type),
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> FspResult<Self::FileContext> {
        let path = Self::u16_to_path(file_name);
        let normalized_path = Self::normalize_path(&path);

        let inode_num = self.resolve_path(&normalized_path)?;
        self.fill_file_info_from_inode(inode_num, file_info.as_mut())?;

        Ok(WinFspFileContext {
            inode: inode_num,
            path: normalized_path,
        })
    }

    fn close(&self, _context: Self::FileContext) {
        // Sync on close for safety
        let _ = self.fs.sync();
    }

    fn create(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> FspResult<Self::FileContext> {
        let path = Self::u16_to_path(file_name);
        let normalized_path = Self::normalize_path(&path);

        let (parent_inode, name) = self.get_parent_and_name(&normalized_path)?;

        // Determine if this is a directory or file
        let is_directory = file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0;

        let inode_num = if is_directory {
            self.fs.create_directory(parent_inode, &name, 0o755)
                .map_err(Self::error_to_fsp)?
        } else {
            self.fs.create_file(parent_inode, &name, 0o644)
                .map_err(Self::error_to_fsp)?
        };

        self.fill_file_info_from_inode(inode_num, file_info.as_mut())?;

        // Cache the new entry
        {
            let mut cache = self.path_cache.write().unwrap();
            cache.insert(normalized_path.clone(), PathCacheEntry {
                inode: inode_num,
                parent_inode,
                name,
            });
        }

        Ok(WinFspFileContext {
            inode: inode_num,
            path: normalized_path,
        })
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> FspResult<u32> {
        let data = self.fs.read_by_inode(context.inode, offset, buffer.len() as u32)
            .map_err(Self::error_to_fsp)?;

        let bytes_read = data.len();
        buffer[..bytes_read].copy_from_slice(&data);

        Ok(bytes_read as u32)
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        _write_to_end_of_file: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> FspResult<u32> {
        let bytes_written = self.fs.write_by_inode(context.inode, offset, buffer)
            .map_err(Self::error_to_fsp)?;

        // Update file info
        self.fill_file_info_from_inode(context.inode, file_info)?;

        Ok(bytes_written)
    }

    fn flush(
        &self,
        _context: Option<&Self::FileContext>,
        _file_info: &mut FileInfo,
    ) -> FspResult<()> {
        self.fs.sync().map_err(Self::error_to_fsp)?;
        Ok(())
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        self.fill_file_info_from_inode(context.inode, file_info)
    }

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        _creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        _last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        let mut inode = self.fs.get_inode(context.inode).map_err(Self::error_to_fsp)?;

        // Update timestamps if specified (0 means don't change)
        if last_access_time != 0 {
            inode.atime = filetime_to_unix(last_access_time);
        }

        if last_write_time != 0 {
            inode.mtime = filetime_to_unix(last_write_time);
        }

        // Update file attributes (permissions)
        if file_attributes != 0 && file_attributes != INVALID_FILE_ATTRIBUTES {
            inode.mode = if file_attributes & FILE_ATTRIBUTE_READONLY != 0 {
                0o444 // Read-only
            } else {
                0o644 // Read-write
            };
        }

        self.fs.set_inode(context.inode, &inode).map_err(Self::error_to_fsp)?;

        // Return updated file info
        self.fill_file_info_from_inode(context.inode, file_info)
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        self.fs.truncate_file(context.inode, new_size)
            .map_err(Self::error_to_fsp)?;

        self.fill_file_info_from_inode(context.inode, file_info)
    }

    fn rename(
        &self,
        _context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        _replace_if_exists: bool,
    ) -> FspResult<()> {
        let old_path = Self::u16_to_path(file_name);
        let new_path = Self::u16_to_path(new_file_name);
        let old_normalized = Self::normalize_path(&old_path);
        let new_normalized = Self::normalize_path(&new_path);

        let (old_parent, old_name) = self.get_parent_and_name(&old_normalized)?;
        let (new_parent, new_name) = self.get_parent_and_name(&new_normalized)?;

        self.fs.rename_entry(old_parent, &old_name, new_parent, &new_name)
            .map_err(Self::error_to_fsp)?;

        // Invalidate cache for both old and new paths
        self.invalidate_cache(&old_normalized);
        self.invalidate_cache(&new_normalized);

        Ok(())
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        _delete_file: bool,
    ) -> FspResult<()> {
        let inode = self.fs.get_inode(context.inode).map_err(Self::error_to_fsp)?;

        // Get parent and name from cached path
        let (parent_inode, name) = self.get_parent_and_name(&context.path)?;

        if inode.is_dir() {
            self.fs.remove_directory(parent_inode, &name)
                .map_err(Self::error_to_fsp)?;
        } else {
            self.fs.remove_file(parent_inode, &name)
                .map_err(Self::error_to_fsp)?;
        }

        // Invalidate cache
        self.invalidate_cache(&context.path);

        Ok(())
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> FspResult<u32> {
        let entries = self.fs.readdir_by_inode(context.inode)
            .map_err(Self::error_to_fsp)?;

        let mut cursor = 0u32;

        // Determine where to start based on marker
        let start_index = if marker.is_none() {
            0
        } else if marker.is_current() {
            1 // Skip '.'
        } else if marker.is_parent() {
            2 // Skip '.' and '..'
        } else {
            // Find the entry matching the marker and start after it
            let marker_name = marker.inner_as_cstr();
            let mut found_index = 0;

            if let Some(marker_str) = marker_name {
                for (i, entry) in entries.iter().enumerate() {
                    if let Ok(entry_name) = entry.name_str() {
                        let entry_name_u16 = U16CString::from_str(entry_name).ok();
                        if let Some(name) = entry_name_u16 {
                            let name_ref: &U16CStr = name.as_ref();
                            if name_ref == marker_str {
                                found_index = i + 1; // Start after this entry
                                break;
                            }
                        }
                    }
                }
            }
            found_index
        };

        // Process entries starting from start_index
        for (i, entry) in entries.iter().enumerate().skip(start_index) {
            let name = match entry.name_str() {
                Ok(n) => n,
                Err(_) => continue,
            };

            let mut dir_info = DirInfo::<255>::new();

            if dir_info.set_name(name).is_err() {
                continue; // Skip entries with names that are too long
            }

            // Get inode info for this entry
            if let Ok(entry_inode) = self.fs.get_inode(entry.inode) {
                let file_info = dir_info.file_info_mut();

                let file_type = if entry_inode.is_dir() {
                    InodeType::Directory
                } else if entry_inode.is_symlink() {
                    InodeType::Symlink
                } else {
                    InodeType::File
                };

                file_info.file_attributes = Self::inode_type_to_attributes(file_type);
                file_info.file_size = entry_inode.size;
                file_info.allocation_size = ((entry_inode.size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64) * FS_BLOCK_SIZE as u64;
                file_info.creation_time = unix_to_filetime(entry_inode.ctime);
                file_info.last_access_time = unix_to_filetime(entry_inode.atime);
                file_info.last_write_time = unix_to_filetime(entry_inode.mtime);
                file_info.change_time = unix_to_filetime(entry_inode.ctime);
                file_info.index_number = entry.inode as u64;
            }

            if !dir_info.append_to_buffer(buffer, &mut cursor) {
                break;
            }
        }

        // Finalize the buffer
        DirInfo::<255>::finalize_buffer(buffer, &mut cursor);

        Ok(cursor)
    }

    fn get_dir_info_by_name(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        dir_info: &mut DirInfo,
    ) -> FspResult<()> {
        let name_path = Self::u16_to_path(file_name);
        let name = name_path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // Look up the entry in the parent directory
        let inode_num = self.fs.lookup(context.inode, &name)
            .map_err(Self::error_to_fsp)?
            .ok_or_else(|| -> FspError { STATUS_OBJECT_NAME_NOT_FOUND.into() })?;

        let inode = self.fs.get_inode(inode_num).map_err(Self::error_to_fsp)?;

        let file_info = dir_info.file_info_mut();

        let file_type = if inode.is_dir() {
            InodeType::Directory
        } else if inode.is_symlink() {
            InodeType::Symlink
        } else {
            InodeType::File
        };

        file_info.file_attributes = Self::inode_type_to_attributes(file_type);
        file_info.file_size = inode.size;
        file_info.allocation_size = ((inode.size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64) * FS_BLOCK_SIZE as u64;
        file_info.creation_time = unix_to_filetime(inode.ctime);
        file_info.last_access_time = unix_to_filetime(inode.atime);
        file_info.last_write_time = unix_to_filetime(inode.mtime);
        file_info.change_time = unix_to_filetime(inode.ctime);
        file_info.index_number = inode_num as u64;

        let _ = dir_info.set_name(&name);

        Ok(())
    }

    fn get_volume_info(&self, volume_info: &mut VolumeInfo) -> FspResult<()> {
        match self.fs.get_statfs() {
            Ok((total_bytes, free_bytes, _)) => {
                volume_info.total_size = total_bytes;
                volume_info.free_size = free_bytes;
            }
            Err(_) => {
                // Fallback values
                volume_info.total_size = 1024 * 1024 * 1024 * 10; // 10 GB
                volume_info.free_size = 1024 * 1024 * 1024 * 5;   // 5 GB free
            }
        }
        volume_info.set_volume_label("Tesseract");

        Ok(())
    }
}

/// WinFsp mount handle
pub struct WinFspMountHandle {
    mount_point: PathBuf,
    filesystem: Option<FileSystemHost<WinFspAdapter>>,
}

impl WinFspMountHandle {
    pub fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    pub fn unmount(mut self) -> Result<()> {
        if let Some(_fs) = self.filesystem.take() {
            // FileSystemHost Drop will handle cleanup
        }
        Ok(())
    }
}

impl Drop for WinFspMountHandle {
    fn drop(&mut self) {
        if let Some(_fs) = self.filesystem.take() {
            // FileSystemHost Drop will handle cleanup
        }
    }
}

/// Mounts a container using WinFsp with persistent VolumeIOFilesystem
pub fn mount(
    container_path: impl AsRef<Path>,
    password: &str,
    options: MountOptions,
) -> Result<WinFspMountHandle> {
    use std::fs::OpenOptions;

    let container_path = container_path.as_ref();

    // Open container to get the master key
    let container = if let Some(hidden_offset) = options.hidden_offset {
        let hidden_pwd = options.hidden_password
            .as_deref()
            .ok_or_else(|| MountError::Other("Hidden password required for hidden volume mount".to_string()))?;

        let outer = Container::open(container_path, password)?;
        outer.open_hidden_volume(hidden_pwd, hidden_offset)?
    } else {
        Container::open(container_path, password)?
    };

    // Get master key from container
    let master_key = container.master_key()
        .ok_or_else(|| MountError::Other("Container is locked".to_string()))?
        .clone();

    // Get data offset and size from container header
    let data_offset = container.data_offset();
    let data_size = container.data_size();

    // Open file for filesystem backend
    let file = OpenOptions::new()
        .read(true)
        .write(!options.read_only)
        .open(container_path)
        .map_err(MountError::Io)?;

    // Create backend with proper offset
    let backend: Box<dyn StorageBackend> = Box::new(FileBackend::new(file, data_offset));

    // Try to open existing filesystem or create new one
    let fs = match VolumeIOFilesystem::open(&master_key, data_size, backend) {
        Ok(fs) => fs,
        Err(_) => {
            // Filesystem doesn't exist, create a new one
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(container_path)
                .map_err(MountError::Io)?;

            let backend: Box<dyn StorageBackend> = Box::new(FileBackend::new(file, data_offset));

            let volume_name = options.fs_name.as_deref().unwrap_or("Tesseract");
            VolumeIOFilesystem::mkfs(&master_key, data_size, backend, volume_name)
                .map_err(|e| MountError::Other(format!("Failed to create filesystem: {}", e)))?
        }
    };

    // Create WinFsp adapter
    let adapter = WinFspAdapter::new(fs);

    // Create volume parameters
    let mut volume_params = VolumeParams::new();
    volume_params.sector_size(FS_BLOCK_SIZE as u16);
    volume_params.sectors_per_allocation_unit(1);
    volume_params.volume_creation_time(systemtime_to_filetime(SystemTime::now()));
    volume_params.volume_serial_number(0x12345678);

    // Set volume prefix (drive letter or mount point)
    let mount_point_str = options.mount_point.to_string_lossy().to_string();
    volume_params.prefix(&mount_point_str);

    // Set filesystem name
    let fs_name = options.fs_name.unwrap_or_else(|| "Tesseract".to_string());
    volume_params.filesystem_name(&fs_name);

    // Set read-only if requested
    if options.read_only {
        volume_params.read_only_volume(true);
    }

    // Create filesystem host
    let mut filesystem = FileSystemHost::new(volume_params, adapter)
        .map_err(|e| MountError::Other(format!("Failed to create WinFsp filesystem: {:?}", e)))?;

    // Start the filesystem
    filesystem.start()
        .map_err(|e| MountError::Other(format!("Failed to start WinFsp filesystem: {:?}", e)))?;

    Ok(WinFspMountHandle {
        mount_point: options.mount_point,
        filesystem: Some(filesystem),
    })
}

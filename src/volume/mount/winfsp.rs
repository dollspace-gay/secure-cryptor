/// WinFsp filesystem implementation for Windows
///
/// This module implements a WinFsp adapter that allows mounting encrypted
/// containers as drive letters or directories on Windows.

use std::ffi::{OsString, c_void};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use windows::Win32::Foundation::*;

use winfsp::{
    U16CStr, U16CString,
    filesystem::{
        FileInfo, FileSecurity, FileSystemContext, DirInfo, DirMarker,
        OpenFileInfo, VolumeInfo, WideNameInfo,
    },
    host::{FileSystemHost, VolumeParams},
    FspError, Result as FspResult,
};
// Note: winfsp re-exports winfsp_sys types through its modules
// We don't need to import winfsp_sys directly

use super::super::container::Container;
use super::super::filesystem::{EncryptedFilesystem, FileType, FilesystemError};
use super::super::operations::InMemoryFilesystem;
use super::{MountError, MountOptions, Result};

/// Windows file attribute constants
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_READONLY: u32 = 0x01;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFF;

/// Convert Windows FILETIME (100-nanosecond intervals since 1601) to SystemTime
fn filetime_to_systemtime(filetime: u64) -> SystemTime {
    const WINDOWS_TICK: u64 = 10_000_000; // 100ns intervals per second
    const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000; // 1970-01-01 in FILETIME

    if filetime < UNIX_EPOCH_FILETIME {
        SystemTime::UNIX_EPOCH
    } else {
        let duration_since_epoch = (filetime - UNIX_EPOCH_FILETIME) / WINDOWS_TICK;
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(duration_since_epoch)
    }
}

/// Convert SystemTime to Windows FILETIME
fn systemtime_to_filetime(time: SystemTime) -> u64 {
    const WINDOWS_TICK: u64 = 10_000_000;
    const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;

    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            UNIX_EPOCH_FILETIME + (secs * WINDOWS_TICK)
        }
        Err(_) => UNIX_EPOCH_FILETIME, // Before Unix epoch
    }
}

/// File context - holds path to the opened file
#[derive(Clone)]
pub struct WinFspFileContext {
    path: PathBuf,
}

/// WinFsp filesystem adapter
pub struct WinFspAdapter {
    fs: Arc<Mutex<InMemoryFilesystem>>,
}

impl WinFspAdapter {
    fn new(fs: InMemoryFilesystem) -> Self {
        Self {
            fs: Arc::new(Mutex::new(fs)),
        }
    }

    /// Converts our FileType to Windows file attributes
    fn file_type_to_attributes(ft: FileType) -> u32 {
        match ft {
            FileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
            FileType::RegularFile => FILE_ATTRIBUTE_NORMAL,
            FileType::Symlink => FILE_ATTRIBUTE_REPARSE_POINT,
        }
    }

    /// Converts filesystem error to NTSTATUS/FspError
    fn error_to_fsp(err: FilesystemError) -> FspError {
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

    /// Fill FileInfo structure from our FileAttr
    fn fill_file_info(attr: &super::super::filesystem::FileAttr, file_info: &mut FileInfo) {
        file_info.file_attributes = Self::file_type_to_attributes(attr.file_type);
        file_info.reparse_tag = 0;
        file_info.file_size = attr.size;
        file_info.allocation_size = ((attr.size + 4095) / 4096) * 4096; // Round up to 4KB
        file_info.creation_time = systemtime_to_filetime(attr.ctime);
        file_info.last_access_time = systemtime_to_filetime(attr.atime);
        file_info.last_write_time = systemtime_to_filetime(attr.mtime);
        file_info.change_time = systemtime_to_filetime(attr.ctime);
        file_info.index_number = 0; // Could hash the path
        file_info.hard_links = 0; // Always 0 per WinFSP docs
        file_info.ea_size = 0; // Extended attributes size
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

        let fs = self.fs.lock().unwrap();
        let attr = fs.getattr(&normalized_path).map_err(Self::error_to_fsp)?;

        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes: Self::file_type_to_attributes(attr.file_type),
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

        let fs = self.fs.lock().unwrap();
        let attr = fs.getattr(&normalized_path).map_err(Self::error_to_fsp)?;

        Self::fill_file_info(&attr, file_info.as_mut());

        Ok(WinFspFileContext {
            path: normalized_path,
        })
    }

    fn close(&self, _context: Self::FileContext) {
        // No cleanup needed for our simple implementation
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

        let mut fs = self.fs.lock().unwrap();

        // Determine if this is a directory or file
        let is_directory = file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0;

        if is_directory {
            fs.mkdir(&normalized_path, 0o755).map_err(Self::error_to_fsp)?;
            let attr = fs.getattr(&normalized_path).map_err(Self::error_to_fsp)?;
            Self::fill_file_info(&attr, file_info.as_mut());
        } else {
            let attr = fs.create(&normalized_path, 0o644).map_err(Self::error_to_fsp)?;
            Self::fill_file_info(&attr, file_info.as_mut());
        }

        Ok(WinFspFileContext {
            path: normalized_path,
        })
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> FspResult<u32> {
        let fs = self.fs.lock().unwrap();
        let data = fs.read(&context.path, offset, buffer.len() as u32)
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
        let mut fs = self.fs.lock().unwrap();

        let bytes_written = fs.write(&context.path, offset, buffer)
            .map_err(Self::error_to_fsp)?;

        // Update file info
        let attr = fs.getattr(&context.path).map_err(Self::error_to_fsp)?;
        Self::fill_file_info(&attr, file_info);

        Ok(bytes_written)
    }

    fn flush(
        &self,
        _context: Option<&Self::FileContext>,
        _file_info: &mut FileInfo,
    ) -> FspResult<()> {
        // All writes are synchronous
        Ok(())
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        let fs = self.fs.lock().unwrap();
        let attr = fs.getattr(&context.path).map_err(Self::error_to_fsp)?;
        Self::fill_file_info(&attr, file_info);
        Ok(())
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
        let mut fs = self.fs.lock().unwrap();

        // Update timestamps if specified (0 means don't change)
        if last_access_time != 0 || last_write_time != 0 {
            let atime = if last_access_time != 0 {
                Some(filetime_to_systemtime(last_access_time))
            } else {
                None
            };

            let mtime = if last_write_time != 0 {
                Some(filetime_to_systemtime(last_write_time))
            } else {
                None
            };

            fs.utimens(&context.path, atime, mtime)
                .map_err(Self::error_to_fsp)?;
        }

        // Update file attributes (permissions)
        if file_attributes != 0 && file_attributes != INVALID_FILE_ATTRIBUTES {
            let mode = if file_attributes & FILE_ATTRIBUTE_READONLY != 0 {
                0o444 // Read-only
            } else {
                0o644 // Read-write
            };

            fs.chmod(&context.path, mode).map_err(Self::error_to_fsp)?;
        }

        // Return updated file info
        let attr = fs.getattr(&context.path).map_err(Self::error_to_fsp)?;
        Self::fill_file_info(&attr, file_info);

        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        let mut fs = self.fs.lock().unwrap();

        fs.truncate(&context.path, new_size)
            .map_err(Self::error_to_fsp)?;

        let attr = fs.getattr(&context.path).map_err(Self::error_to_fsp)?;
        Self::fill_file_info(&attr, file_info);

        Ok(())
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

        let mut fs = self.fs.lock().unwrap();
        fs.rename(&old_normalized, &new_normalized)
            .map_err(Self::error_to_fsp)?;

        Ok(())
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        _delete_file: bool,
    ) -> FspResult<()> {
        let mut fs = self.fs.lock().unwrap();

        // Check if it's a directory
        let attr = fs.getattr(&context.path).map_err(Self::error_to_fsp)?;

        if attr.file_type == FileType::Directory {
            fs.rmdir(&context.path).map_err(Self::error_to_fsp)?;
        } else {
            fs.unlink(&context.path).map_err(Self::error_to_fsp)?;
        }

        Ok(())
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> FspResult<u32> {
        let fs = self.fs.lock().unwrap();
        let entries = fs.readdir(&context.path).map_err(Self::error_to_fsp)?;

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
            let mut found_index = 2; // Start after . and ..

            if let Some(marker_str) = marker_name {
                for (i, entry) in entries.iter().enumerate() {
                    let entry_name_u16 = U16CString::from_os_str(&entry.name).ok();
                    if let Some(name) = entry_name_u16 {
                        let name_ref: &U16CStr = name.as_ref();
                        if name_ref == marker_str {
                            found_index = i + 3; // +2 for . and .., +1 to start after this entry
                            break;
                        }
                    }
                }
            }
            found_index
        };

        // Add . entry
        if start_index == 0 {
            let mut dir_info = DirInfo::<255>::new();
            let _ = dir_info.set_name(".");
            let file_info = dir_info.file_info_mut();
            file_info.file_attributes = FILE_ATTRIBUTE_DIRECTORY;

            if !dir_info.append_to_buffer(buffer, &mut cursor) {
                return Ok(cursor);
            }
        }

        // Add .. entry
        if start_index <= 1 {
            let mut dir_info = DirInfo::<255>::new();
            let _ = dir_info.set_name("..");
            let file_info = dir_info.file_info_mut();
            file_info.file_attributes = FILE_ATTRIBUTE_DIRECTORY;

            if !dir_info.append_to_buffer(buffer, &mut cursor) {
                return Ok(cursor);
            }
        }

        // Add actual entries
        let entry_start = if start_index >= 2 { start_index - 2 } else { 0 };

        for entry in entries.iter().skip(entry_start) {
            let mut dir_info = DirInfo::<255>::new();

            if let Err(_) = dir_info.set_name(&entry.name) {
                continue; // Skip entries with names that are too long
            }

            let file_info = dir_info.file_info_mut();
            file_info.file_attributes = Self::file_type_to_attributes(entry.file_type);
            file_info.file_size = 0; // DirEntry doesn't have size field
            file_info.allocation_size = 0;

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
        _context: &Self::FileContext,
        file_name: &U16CStr,
        dir_info: &mut DirInfo,
    ) -> FspResult<()> {
        let path = Self::u16_to_path(file_name);
        let normalized_path = Self::normalize_path(&path);

        let fs = self.fs.lock().unwrap();
        let attr = fs.getattr(&normalized_path).map_err(Self::error_to_fsp)?;

        let file_info = dir_info.file_info_mut();
        Self::fill_file_info(&attr, file_info);

        if let Some(file_name_part) = path.file_name() {
            let _ = dir_info.set_name(file_name_part);
        }

        Ok(())
    }

    fn get_volume_info(&self, volume_info: &mut VolumeInfo) -> FspResult<()> {
        volume_info.total_size = 1024 * 1024 * 1024 * 10; // 10 GB
        volume_info.free_size = 1024 * 1024 * 1024 * 5;   // 5 GB free
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

/// Mounts a container using WinFsp
pub fn mount(
    container_path: impl AsRef<Path>,
    password: &str,
    options: MountOptions,
) -> Result<WinFspMountHandle> {
    // Open container (normal or hidden)
    let container = if let Some(hidden_offset) = options.hidden_offset {
        // For hidden volumes, password is the outer password
        // and hidden_password is the hidden volume password
        let hidden_pwd = options.hidden_password
            .as_deref()
            .ok_or_else(|| MountError::Other("Hidden password required for hidden volume mount".to_string()))?;

        let outer = Container::open(&container_path, password)?;
        outer.open_hidden_volume(hidden_pwd, hidden_offset)?
    } else {
        Container::open(container_path, password)?
    };

    // Get filesystem
    let fs = container.mount_filesystem()?;

    // Create WinFsp adapter
    let adapter = WinFspAdapter::new(fs);

    // Create volume parameters
    let mut volume_params = VolumeParams::new();
    volume_params.sector_size(4096); // 4KB sectors
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

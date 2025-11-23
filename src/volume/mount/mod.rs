/// Platform-specific volume mounting implementations
///
/// This module provides cross-platform support for mounting encrypted volumes
/// as filesystems using FUSE (Linux/macOS) or WinFsp (Windows).

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[cfg(feature = "encrypted-volumes")]
pub mod fuse;

#[cfg(target_os = "windows")]
#[cfg(feature = "encrypted-volumes")]
pub mod winfsp;

use std::path::Path;
use thiserror::Error;

/// Errors that can occur during volume mounting
#[derive(Debug, Error)]
pub enum MountError {
    /// Container error
    #[error("Container error: {0}")]
    Container(#[from] super::container::ContainerError),

    /// Filesystem error
    #[error("Filesystem error: {0}")]
    Filesystem(String),

    /// Mount point error
    #[error("Mount point error: {0}")]
    MountPoint(String),

    /// Platform not supported
    #[error("Platform not supported for mounting")]
    PlatformNotSupported,

    /// Feature not enabled
    #[error("Encrypted volumes feature not enabled")]
    FeatureNotEnabled,

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Other error
    #[error("Mount error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, MountError>;

/// Options for mounting a volume
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Mount point path
    pub mount_point: std::path::PathBuf,

    /// Read-only mode
    pub read_only: bool,

    /// Allow other users to access the mount
    pub allow_other: bool,

    /// Auto-unmount on process exit
    pub auto_unmount: bool,

    /// Filesystem name/label
    pub fs_name: Option<String>,

    /// Hidden volume offset (for mounting hidden volumes)
    /// If set, the container will be opened at this offset as a hidden volume
    pub hidden_offset: Option<u64>,

    /// Hidden volume password (when mounting hidden volumes)
    /// This is the password for the hidden volume itself
    /// The main password parameter to mount() should be the outer volume password
    pub hidden_password: Option<String>,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            mount_point: std::path::PathBuf::new(),
            read_only: false,
            allow_other: false,
            auto_unmount: true,
            fs_name: Some("Tesseract".to_string()),
            hidden_offset: None,
            hidden_password: None,
        }
    }
}

/// Mount an encrypted container
///
/// # Arguments
///
/// * `container_path` - Path to the container file
/// * `password` - Password to unlock the container
/// * `options` - Mount options
///
/// # Returns
///
/// A handle that keeps the mount alive (unmounts on drop)
///
/// # Errors
///
/// Returns an error if:
/// - The container cannot be opened
/// - The password is incorrect
/// - The mount point is invalid
/// - The platform is not supported
#[cfg(feature = "encrypted-volumes")]
pub fn mount(
    container_path: impl AsRef<Path>,
    password: &str,
    options: MountOptions,
) -> Result<MountHandle> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        fuse::mount(container_path, password, options).map(|inner| MountHandle { inner })
    }

    #[cfg(target_os = "windows")]
    {
        winfsp::mount(container_path, password, options).map(|inner| MountHandle { inner })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(MountError::PlatformNotSupported)
    }
}

/// Handle to a mounted volume
///
/// The volume is automatically unmounted when this handle is dropped.
#[cfg(feature = "encrypted-volumes")]
pub struct MountHandle {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    inner: fuse::FuseMountHandle,

    #[cfg(target_os = "windows")]
    inner: winfsp::WinFspMountHandle,
}

#[cfg(feature = "encrypted-volumes")]
impl MountHandle {
    /// Returns the mount point path
    pub fn mount_point(&self) -> &Path {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.mount_point()
        }

        #[cfg(target_os = "windows")]
        {
            self.inner.mount_point()
        }
    }

    /// Unmounts the volume
    pub fn unmount(self) -> Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.unmount()
        }

        #[cfg(target_os = "windows")]
        {
            self.inner.unmount()
        }
    }
}

#[cfg(not(feature = "encrypted-volumes"))]
pub fn mount(
    _container_path: impl AsRef<Path>,
    _password: &str,
    _options: MountOptions,
) -> Result<()> {
    Err(MountError::FeatureNotEnabled)
}

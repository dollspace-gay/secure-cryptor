/// FUSE filesystem implementation for Linux and macOS
///
/// This module implements a FUSE (Filesystem in Userspace) adapter that
/// allows mounting encrypted containers as regular filesystems.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use fuser::{
    FileAttr as FuseFileAttr, FileType as FuseFileType, Filesystem,
    ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyWrite, Request,
    MountOption, TimeOrNow,
};
use libc::{EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY};

use super::super::container::Container;
use super::super::filesystem::{EncryptedFilesystem, FileType, FilesystemError};
use super::super::operations::InMemoryFilesystem;
use super::{MountError, MountOptions, Result};

/// FUSE filesystem adapter
struct FuseAdapter {
    fs: InMemoryFilesystem,
}

impl FuseAdapter {
    fn new(fs: InMemoryFilesystem) -> Self {
        Self { fs }
    }

    /// Converts our FileType to FUSE FileType
    fn file_type_to_fuse(ft: FileType) -> FuseFileType {
        match ft {
            FileType::RegularFile => FuseFileType::RegularFile,
            FileType::Directory => FuseFileType::Directory,
            FileType::Symlink => FuseFileType::Symlink,
        }
    }

    /// Converts our FileAttr to FUSE FileAttr
    fn attr_to_fuse(&self, attr: &super::super::filesystem::FileAttr, ino: u64) -> FuseFileAttr {
        FuseFileAttr {
            ino,
            size: attr.size,
            blocks: (attr.size + 511) / 512, // Round up to 512-byte blocks
            atime: attr.atime,
            mtime: attr.mtime,
            ctime: attr.ctime,
            crtime: attr.ctime, // Use ctime as creation time
            kind: Self::file_type_to_fuse(attr.file_type),
            perm: attr.perm,
            nlink: attr.nlink,
            uid: attr.uid,
            gid: attr.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// Converts filesystem error to errno
    fn error_to_errno(err: FilesystemError) -> libc::c_int {
        match err {
            FilesystemError::NotFound(_) => ENOENT,
            FilesystemError::AlreadyExists(_) => EEXIST,
            FilesystemError::PermissionDenied(_) => libc::EACCES,
            FilesystemError::NotADirectory(_) => ENOTDIR,
            FilesystemError::IsADirectory(_) => EISDIR,
            FilesystemError::DirectoryNotEmpty(_) => ENOTEMPTY,
            FilesystemError::InvalidFileName(_) => EINVAL,
            FilesystemError::Io(_) => EIO,
            FilesystemError::CryptoError(_) => EIO,
            FilesystemError::NotSupported(_) => libc::ENOTSUP,
            FilesystemError::Other(_) => EIO,
        }
    }

    /// Gets inode number from path (simplified - just hash the path)
    fn path_to_ino(&self, path: &Path) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        if path == Path::new("/") {
            return 1;
        }

        let mut hasher = DefaultHasher::new();
        path.hash(&mut hasher);
        let hash = hasher.finish();
        // Ensure we don't collide with root inode
        if hash == 1 { 2 } else { hash }
    }

    /// Converts inode to path (simplified - we'll need to track this properly)
    fn ino_to_path(&self, ino: u64) -> PathBuf {
        if ino == 1 {
            PathBuf::from("/")
        } else {
            // This is a limitation - in a real implementation we'd maintain
            // an inode-to-path mapping
            PathBuf::from("/")
        }
    }
}

impl Filesystem for FuseAdapter {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let parent_path = self.ino_to_path(parent);
        let path = parent_path.join(name);

        match self.fs.getattr(&path) {
            Ok(attr) => {
                let ino = self.path_to_ino(&path);
                let fuse_attr = self.attr_to_fuse(&attr, ino);
                let ttl = Duration::from_secs(1);
                reply.entry(&ttl, &fuse_attr, 0);
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        let path = self.ino_to_path(ino);

        match self.fs.getattr(&path) {
            Ok(attr) => {
                let fuse_attr = self.attr_to_fuse(&attr, ino);
                let ttl = Duration::from_secs(1);
                reply.attr(&ttl, &fuse_attr);
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let path = self.ino_to_path(ino);

        match self.fs.read(&path, offset as u64, size) {
            Ok(data) => {
                reply.data(&data);
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let path = self.ino_to_path(ino);

        match self.fs.write(&path, offset as u64, data) {
            Ok(written) => {
                reply.written(written);
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path = self.ino_to_path(ino);

        match self.fs.readdir(&path) {
            Ok(entries) => {
                let mut index = offset as usize;

                // Add . and .. entries
                if index == 0 {
                    if reply.add(ino, 1, FuseFileType::Directory, ".") {
                        reply.ok();
                        return;
                    }
                    index += 1;
                }

                if index == 1 {
                    let parent_ino = if ino == 1 { 1 } else { 1 }; // Simplified
                    if reply.add(parent_ino, 2, FuseFileType::Directory, "..") {
                        reply.ok();
                        return;
                    }
                    index += 1;
                }

                // Add actual entries
                for (i, entry) in entries.iter().enumerate().skip(index.saturating_sub(2)) {
                    let entry_path = path.join(&entry.name);
                    let entry_ino = self.path_to_ino(&entry_path);
                    let entry_type = Self::file_type_to_fuse(entry.file_type);

                    if reply.add(entry_ino, (i + 3) as i64, entry_type, &entry.name) {
                        break;
                    }
                }

                reply.ok();
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent_path = self.ino_to_path(parent);
        let path = parent_path.join(name);

        match self.fs.mkdir(&path, mode as u16) {
            Ok(()) => {
                match self.fs.getattr(&path) {
                    Ok(attr) => {
                        let ino = self.path_to_ino(&path);
                        let fuse_attr = self.attr_to_fuse(&attr, ino);
                        let ttl = Duration::from_secs(1);
                        reply.entry(&ttl, &fuse_attr, 0);
                    }
                    Err(e) => {
                        reply.error(Self::error_to_errno(e));
                    }
                }
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        let parent_path = self.ino_to_path(parent);
        let path = parent_path.join(name);

        match self.fs.unlink(&path) {
            Ok(()) => {
                reply.ok();
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        let parent_path = self.ino_to_path(parent);
        let path = parent_path.join(name);

        match self.fs.rmdir(&path) {
            Ok(()) => {
                reply.ok();
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        let old_parent = self.ino_to_path(parent);
        let new_parent = self.ino_to_path(newparent);
        let old_path = old_parent.join(name);
        let new_path = new_parent.join(newname);

        match self.fs.rename(&old_path, &new_path) {
            Ok(()) => {
                reply.ok();
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        let parent_path = self.ino_to_path(parent);
        let path = parent_path.join(name);

        match self.fs.create(&path, mode as u16) {
            Ok(attr) => {
                let ino = self.path_to_ino(&path);
                let fuse_attr = self.attr_to_fuse(&attr, ino);
                let ttl = Duration::from_secs(1);
                let fh = 0; // File handle (we don't track these)
                let flags = 0;
                reply.created(&ttl, &fuse_attr, 0, fh, flags);
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let path = self.ino_to_path(ino);

        // Apply changes
        if let Some(mode) = mode {
            if let Err(e) = self.fs.chmod(&path, mode as u16) {
                reply.error(Self::error_to_errno(e));
                return;
            }
        }

        if uid.is_some() || gid.is_some() {
            let uid = uid.unwrap_or(0);
            let gid = gid.unwrap_or(0);
            if let Err(e) = self.fs.chown(&path, uid, gid) {
                reply.error(Self::error_to_errno(e));
                return;
            }
        }

        if let Some(size) = size {
            if let Err(e) = self.fs.truncate(&path, size) {
                reply.error(Self::error_to_errno(e));
                return;
            }
        }

        if atime.is_some() || mtime.is_some() {
            let atime_val = match atime {
                Some(TimeOrNow::SpecificTime(t)) => Some(t),
                Some(TimeOrNow::Now) => Some(SystemTime::now()),
                None => None,
            };

            let mtime_val = match mtime {
                Some(TimeOrNow::SpecificTime(t)) => Some(t),
                Some(TimeOrNow::Now) => Some(SystemTime::now()),
                None => None,
            };

            if let Err(e) = self.fs.utimens(&path, atime_val, mtime_val) {
                reply.error(Self::error_to_errno(e));
                return;
            }
        }

        // Return updated attributes
        match self.fs.getattr(&path) {
            Ok(attr) => {
                let fuse_attr = self.attr_to_fuse(&attr, ino);
                let ttl = Duration::from_secs(1);
                reply.attr(&ttl, &fuse_attr);
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }
}

/// FUSE mount handle
pub struct FuseMountHandle {
    mount_point: PathBuf,
    session: Option<fuser::BackgroundSession>,
}

impl FuseMountHandle {
    pub fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    pub fn unmount(mut self) -> Result<()> {
        if let Some(session) = self.session.take() {
            drop(session);
        }
        Ok(())
    }
}

impl Drop for FuseMountHandle {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            drop(session);
        }
    }
}

/// Mounts a container using FUSE
pub fn mount(
    container_path: impl AsRef<Path>,
    password: &str,
    options: MountOptions,
) -> Result<FuseMountHandle> {
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

    // Create FUSE adapter
    let adapter = FuseAdapter::new(fs);

    // Build mount options
    let mut mount_opts = vec![
        MountOption::FSName(options.fs_name.unwrap_or_else(|| "Tesseract".to_string())),
        MountOption::NoAtime,
    ];

    if options.read_only {
        mount_opts.push(MountOption::RO);
    }

    if options.allow_other {
        mount_opts.push(MountOption::AllowOther);
    }

    if options.auto_unmount {
        mount_opts.push(MountOption::AutoUnmount);
    }

    // Mount the filesystem
    let session = fuser::spawn_mount2(adapter, &options.mount_point, &mount_opts)
        .map_err(|e| MountError::Other(format!("FUSE mount failed: {}", e)))?;

    Ok(FuseMountHandle {
        mount_point: options.mount_point,
        session: Some(session),
    })
}

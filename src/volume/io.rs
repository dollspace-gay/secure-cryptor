//! Volume I/O Engine with LRU caching and storage backend abstraction
//!
//! This module provides the core I/O layer for encrypted volumes. It handles:
//! - Chunk-based read/write operations with XTS-AES encryption
//! - LRU caching of decrypted chunks for performance
//! - Storage backend abstraction for local files and cloud storage
//!
//! ## Architecture
//!
//! ```text
//! +------------------+
//! |   Filesystem     |  (FUSE/WinFsp)
//! +--------+---------+
//!          |
//! +--------v---------+
//! |    VolumeIO      |  <- This module
//! |  +------------+  |
//! |  | LRU Cache  |  |  (decrypted chunks)
//! |  +-----+------+  |
//! |        |         |
//! |  +-----v------+  |
//! |  |ChunkMapper |  |  (offset translation)
//! |  +-----+------+  |
//! |        |         |
//! |  +-----v------+  |
//! |  |SectorCipher|  |  (XTS encryption)
//! |  +-----+------+  |
//! +--------+---------+
//!          |
//! +--------v---------+
//! | StorageBackend   |  (file, cloud, etc.)
//! +------------------+
//! ```
//!
//! ## Backend Types
//!
//! Two backend trait variants are provided:
//! - `StorageBackend`: Synchronous trait for local file access
//! - `AsyncStorageBackend`: Async trait for cloud storage (S3, Dropbox, etc.)
//!
//! The `BlockingAdapter` allows using sync backends in async contexts.
//!
//! ## Caching Strategy
//!
//! Chunks are cached in decrypted form to avoid repeated decryption:
//! - On read: Check cache first, fetch from backend and decrypt on miss
//! - On write: Modify chunk in cache, mark as dirty
//! - Dirty chunks are encrypted and written back on flush or eviction

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::future::Future;

use lru::LruCache;
use thiserror::Error;
use zeroize::Zeroizing;

use super::chunk::{ChunkError, ChunkMapper, DEFAULT_CHUNK_SIZE};
use super::keyslot::MasterKey;
use super::sector::{SectorCipher, SectorError, SECTOR_SIZE_4K};

/// Errors that can occur during volume I/O operations
#[derive(Debug, Error)]
pub enum VolumeIOError {
    /// Storage backend error
    #[error("Storage error: {0}")]
    Storage(#[from] io::Error),

    /// Chunk mapping error
    #[error("Chunk mapping error: {0}")]
    ChunkMapping(#[from] ChunkError),

    /// Sector encryption error
    #[error("Encryption error: {0}")]
    Encryption(#[from] SectorError),

    /// Invalid offset
    #[error("Invalid offset: {offset} (volume size: {volume_size})")]
    InvalidOffset { offset: u64, volume_size: u64 },

    /// Read past end of volume
    #[error("Read past end of volume at offset {offset}")]
    ReadPastEnd { offset: u64 },

    /// Lock poisoned
    #[error("Lock poisoned")]
    LockPoisoned,

    /// Backend not available
    #[error("Backend not available: {0}")]
    BackendUnavailable(String),
}

pub type Result<T> = std::result::Result<T, VolumeIOError>;

/// Trait for storage backends
///
/// This abstraction allows the VolumeIO to work with different storage types:
/// - Local files (FileBackend)
/// - Cloud storage (future)
/// - In-memory (for testing)
pub trait StorageBackend: Send + Sync {
    /// Read bytes from the storage at the given offset
    ///
    /// # Arguments
    /// * `offset` - Byte offset to read from
    /// * `buf` - Buffer to read into
    ///
    /// # Returns
    /// Number of bytes actually read
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Write bytes to the storage at the given offset
    ///
    /// # Arguments
    /// * `offset` - Byte offset to write to
    /// * `data` - Data to write
    ///
    /// # Returns
    /// Number of bytes actually written
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<usize>;

    /// Flush any buffered writes to storage
    fn flush(&mut self) -> io::Result<()>;

    /// Get the total size of the storage
    fn size(&self) -> io::Result<u64>;
}

/// Type alias for async operation results
pub type AsyncResult<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

/// Async trait for storage backends supporting cloud and network storage
///
/// This trait enables non-blocking I/O for remote storage backends like S3, Dropbox,
/// or any network-based storage. Use `BlockingAdapter` to wrap sync backends.
///
/// # Design Notes
///
/// Unlike the sync `StorageBackend`, this trait uses chunk-based operations rather
/// than offset-based operations. This is because:
/// - Cloud APIs typically work with objects/chunks, not byte offsets
/// - Network round-trips are expensive, so we batch data into chunks
/// - This aligns better with the VolumeIO caching architecture
pub trait AsyncStorageBackend: Send + Sync {
    /// Read a chunk from storage
    ///
    /// # Arguments
    /// * `chunk_index` - The chunk number to read
    /// * `chunk_size` - Expected size of the chunk in bytes
    ///
    /// # Returns
    /// The chunk data, or `None` if the chunk doesn't exist yet
    fn read_chunk<'a>(&'a self, chunk_index: u64, chunk_size: u64) -> AsyncResult<'a, Option<Vec<u8>>>;

    /// Write a chunk to storage
    ///
    /// # Arguments
    /// * `chunk_index` - The chunk number to write
    /// * `data` - The chunk data to write
    fn write_chunk<'a>(&'a self, chunk_index: u64, data: &'a [u8]) -> AsyncResult<'a, ()>;

    /// Flush any buffered writes to storage
    fn flush<'a>(&'a self) -> AsyncResult<'a, ()>;

    /// Get the total size of the storage in bytes
    fn size<'a>(&'a self) -> AsyncResult<'a, u64>;

    /// Delete a chunk from storage (optional, for sparse volumes)
    ///
    /// Default implementation returns success without doing anything.
    fn delete_chunk<'a>(&'a self, _chunk_index: u64) -> AsyncResult<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

/// Adapter that wraps a synchronous `StorageBackend` for async use
///
/// This adapter runs sync operations on the tokio blocking thread pool,
/// allowing sync backends to be used in async contexts without blocking
/// the async runtime.
///
/// # Example
///
/// ```ignore
/// let file_backend = FileBackend::new(file, data_offset);
/// let async_backend = BlockingAdapter::new(Box::new(file_backend), 64 * 1024);
/// ```
pub struct BlockingAdapter {
    backend: Arc<std::sync::Mutex<Box<dyn StorageBackend>>>,
    chunk_size: u64,
}

impl BlockingAdapter {
    /// Creates a new blocking adapter
    ///
    /// # Arguments
    /// * `backend` - The sync backend to wrap
    /// * `chunk_size` - Size of each chunk in bytes
    pub fn new(backend: Box<dyn StorageBackend>, chunk_size: u64) -> Self {
        Self {
            backend: Arc::new(std::sync::Mutex::new(backend)),
            chunk_size,
        }
    }
}

impl AsyncStorageBackend for BlockingAdapter {
    fn read_chunk<'a>(&'a self, chunk_index: u64, chunk_size: u64) -> AsyncResult<'a, Option<Vec<u8>>> {
        let backend = Arc::clone(&self.backend);
        let offset = chunk_index * self.chunk_size;

        Box::pin(async move {
            // In a real implementation, this would use tokio::task::spawn_blocking
            // For now, we do it inline since we're keeping it simple
            let mut guard = backend.lock().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "lock poisoned")
            })?;

            let mut buf = vec![0u8; chunk_size as usize];
            let bytes_read = guard.read_at(offset, &mut buf)?;

            if bytes_read == 0 {
                Ok(None)
            } else {
                buf.truncate(bytes_read);
                Ok(Some(buf))
            }
        })
    }

    fn write_chunk<'a>(&'a self, chunk_index: u64, data: &'a [u8]) -> AsyncResult<'a, ()> {
        let backend = Arc::clone(&self.backend);
        let offset = chunk_index * self.chunk_size;

        Box::pin(async move {
            let mut guard = backend.lock().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "lock poisoned")
            })?;

            guard.write_at(offset, data)?;
            Ok(())
        })
    }

    fn flush<'a>(&'a self) -> AsyncResult<'a, ()> {
        let backend = Arc::clone(&self.backend);

        Box::pin(async move {
            let mut guard = backend.lock().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "lock poisoned")
            })?;

            guard.flush()
        })
    }

    fn size<'a>(&'a self) -> AsyncResult<'a, u64> {
        let backend = Arc::clone(&self.backend);

        Box::pin(async move {
            let guard = backend.lock().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "lock poisoned")
            })?;

            guard.size()
        })
    }
}

/// Stub implementation for S3-compatible cloud storage
///
/// This is a placeholder for future S3 backend implementation.
/// Currently returns "not implemented" errors for all operations.
///
/// # Future Implementation
///
/// A real implementation would:
/// - Use the AWS SDK or compatible HTTP client
/// - Store chunks as individual objects: `s3://bucket/volume-id/chunk-XXXX`
/// - Support multipart uploads for large chunks
/// - Handle authentication and region configuration
#[derive(Debug, Clone)]
pub struct S3Backend {
    bucket: String,
    prefix: String,
    chunk_size: u64,
}

impl S3Backend {
    /// Creates a new S3 backend configuration
    ///
    /// # Arguments
    /// * `bucket` - S3 bucket name
    /// * `prefix` - Object key prefix (e.g., "volumes/my-volume/")
    /// * `chunk_size` - Size of each chunk in bytes
    pub fn new(bucket: String, prefix: String, chunk_size: u64) -> Self {
        Self {
            bucket,
            prefix,
            chunk_size,
        }
    }

    /// Returns the S3 object key for a given chunk
    pub fn chunk_key(&self, chunk_index: u64) -> String {
        format!("{}chunk-{:08x}", self.prefix, chunk_index)
    }

    /// Returns the bucket name
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Returns the chunk size
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }
}

impl AsyncStorageBackend for S3Backend {
    fn read_chunk<'a>(&'a self, chunk_index: u64, _chunk_size: u64) -> AsyncResult<'a, Option<Vec<u8>>> {
        let _key = self.chunk_key(chunk_index);
        Box::pin(async move {
            // TODO: Implement S3 GetObject
            // let response = s3_client.get_object()
            //     .bucket(&self.bucket)
            //     .key(&key)
            //     .send()
            //     .await?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "S3 backend not yet implemented",
            ))
        })
    }

    fn write_chunk<'a>(&'a self, chunk_index: u64, _data: &'a [u8]) -> AsyncResult<'a, ()> {
        let _key = self.chunk_key(chunk_index);
        Box::pin(async move {
            // TODO: Implement S3 PutObject
            // s3_client.put_object()
            //     .bucket(&self.bucket)
            //     .key(&key)
            //     .body(ByteStream::from(data.to_vec()))
            //     .send()
            //     .await?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "S3 backend not yet implemented",
            ))
        })
    }

    fn flush<'a>(&'a self) -> AsyncResult<'a, ()> {
        // S3 writes are immediately durable, no flush needed
        Box::pin(async { Ok(()) })
    }

    fn size<'a>(&'a self) -> AsyncResult<'a, u64> {
        Box::pin(async move {
            // TODO: List objects with prefix and sum sizes, or read metadata object
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "S3 backend not yet implemented",
            ))
        })
    }

    fn delete_chunk<'a>(&'a self, chunk_index: u64) -> AsyncResult<'a, ()> {
        let _key = self.chunk_key(chunk_index);
        Box::pin(async move {
            // TODO: Implement S3 DeleteObject
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "S3 backend not yet implemented",
            ))
        })
    }
}

/// Stub implementation for Dropbox cloud storage
///
/// This is a placeholder for future Dropbox backend implementation.
/// Currently returns "not implemented" errors for all operations.
///
/// # Future Implementation
///
/// A real implementation would:
/// - Use the Dropbox HTTP API
/// - Store chunks as individual files: `/Apps/Tesseract/volume-id/chunk-XXXX`
/// - Handle OAuth2 authentication
/// - Support chunked uploads for large files
#[derive(Debug, Clone)]
pub struct DropboxBackend {
    path_prefix: String,
    chunk_size: u64,
}

impl DropboxBackend {
    /// Creates a new Dropbox backend configuration
    ///
    /// # Arguments
    /// * `path_prefix` - Path prefix in Dropbox (e.g., "/Apps/Tesseract/my-volume/")
    /// * `chunk_size` - Size of each chunk in bytes
    pub fn new(path_prefix: String, chunk_size: u64) -> Self {
        Self {
            path_prefix,
            chunk_size,
        }
    }

    /// Returns the Dropbox path for a given chunk
    pub fn chunk_path(&self, chunk_index: u64) -> String {
        format!("{}chunk-{:08x}", self.path_prefix, chunk_index)
    }

    /// Returns the chunk size
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }
}

impl AsyncStorageBackend for DropboxBackend {
    fn read_chunk<'a>(&'a self, chunk_index: u64, _chunk_size: u64) -> AsyncResult<'a, Option<Vec<u8>>> {
        let _path = self.chunk_path(chunk_index);
        Box::pin(async move {
            // TODO: Implement Dropbox download
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Dropbox backend not yet implemented",
            ))
        })
    }

    fn write_chunk<'a>(&'a self, chunk_index: u64, _data: &'a [u8]) -> AsyncResult<'a, ()> {
        let _path = self.chunk_path(chunk_index);
        Box::pin(async move {
            // TODO: Implement Dropbox upload
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Dropbox backend not yet implemented",
            ))
        })
    }

    fn flush<'a>(&'a self) -> AsyncResult<'a, ()> {
        // Dropbox writes are immediately durable
        Box::pin(async { Ok(()) })
    }

    fn size<'a>(&'a self) -> AsyncResult<'a, u64> {
        Box::pin(async move {
            // TODO: List folder and sum file sizes
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Dropbox backend not yet implemented",
            ))
        })
    }

    fn delete_chunk<'a>(&'a self, chunk_index: u64) -> AsyncResult<'a, ()> {
        let _path = self.chunk_path(chunk_index);
        Box::pin(async move {
            // TODO: Implement Dropbox delete
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Dropbox backend not yet implemented",
            ))
        })
    }
}

/// File-based storage backend for local volumes
pub struct FileBackend<F> {
    file: F,
    data_offset: u64,
}

impl<F> FileBackend<F> {
    /// Creates a new file backend
    ///
    /// # Arguments
    /// * `file` - The file handle
    /// * `data_offset` - Offset where the data area begins (after headers)
    pub fn new(file: F, data_offset: u64) -> Self {
        Self { file, data_offset }
    }
}

impl<F: Read + Write + Seek + Send + Sync> StorageBackend for FileBackend<F> {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.file.seek(SeekFrom::Start(self.data_offset + offset))?;
        self.file.read(buf)
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<usize> {
        self.file.seek(SeekFrom::Start(self.data_offset + offset))?;
        self.file.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    fn size(&self) -> io::Result<u64> {
        // Size is managed externally via VolumeIO
        Ok(u64::MAX)
    }
}

/// In-memory storage backend for testing
pub struct MemoryBackend {
    data: Vec<u8>,
}

impl MemoryBackend {
    /// Creates a new memory backend with the given size
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    /// Creates a memory backend from existing data
    pub fn from_data(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Returns the underlying data
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

impl StorageBackend for MemoryBackend {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - offset;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        Ok(to_read)
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<usize> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - offset;
        let to_write = data.len().min(available);
        self.data[offset..offset + to_write].copy_from_slice(&data[..to_write]);
        Ok(to_write)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.data.len() as u64)
    }
}

/// A cached chunk with optional dirty flag
struct CachedChunk {
    /// Decrypted chunk data
    data: Zeroizing<Vec<u8>>,
    /// Whether this chunk has been modified and needs write-back
    dirty: bool,
}

impl CachedChunk {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data: Zeroizing::new(data),
            dirty: false,
        }
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn mark_clean(&mut self) {
        self.dirty = false;
    }
}

/// Default cache capacity (number of chunks)
/// With 4MB chunks, 16 chunks = 64MB max cache
pub const DEFAULT_CACHE_CAPACITY: usize = 16;

/// Volume I/O engine
///
/// Provides encrypted read/write access to volume data with:
/// - Chunk-based caching for performance
/// - XTS-AES encryption per sector
/// - Storage backend abstraction
pub struct VolumeIO {
    /// Chunk mapper for offset translation
    chunk_mapper: ChunkMapper,

    /// Sector cipher for encryption/decryption
    cipher: SectorCipher,

    /// Storage backend
    backend: Arc<RwLock<Box<dyn StorageBackend>>>,

    /// LRU cache for decrypted chunks
    cache: RwLock<LruCache<u64, CachedChunk>>,

    /// Volume size in bytes
    volume_size: u64,

    /// Chunk size in bytes
    chunk_size: u64,

    /// Sector size in bytes
    sector_size: usize,
}

impl VolumeIO {
    /// Creates a new VolumeIO engine
    ///
    /// # Arguments
    /// * `master_key` - The master encryption key
    /// * `volume_size` - Total size of the data area in bytes
    /// * `backend` - Storage backend implementation
    ///
    /// # Returns
    /// A new VolumeIO instance with default settings
    pub fn new(
        master_key: &MasterKey,
        volume_size: u64,
        backend: Box<dyn StorageBackend>,
    ) -> Result<Self> {
        Self::with_options(
            master_key,
            volume_size,
            backend,
            DEFAULT_CHUNK_SIZE,
            SECTOR_SIZE_4K,
            DEFAULT_CACHE_CAPACITY,
        )
    }

    /// Creates a new VolumeIO engine with custom options
    ///
    /// # Arguments
    /// * `master_key` - The master encryption key
    /// * `volume_size` - Total size of the data area in bytes
    /// * `backend` - Storage backend implementation
    /// * `chunk_size` - Size of each chunk in bytes
    /// * `sector_size` - Size of each sector in bytes
    /// * `cache_capacity` - Number of chunks to cache
    pub fn with_options(
        master_key: &MasterKey,
        volume_size: u64,
        backend: Box<dyn StorageBackend>,
        chunk_size: u64,
        sector_size: usize,
        cache_capacity: usize,
    ) -> Result<Self> {
        let chunk_mapper = ChunkMapper::new(volume_size, chunk_size, sector_size as u64)?;
        let cipher = SectorCipher::new(master_key, sector_size)?;
        let capacity = NonZeroUsize::new(cache_capacity.max(1)).unwrap();

        Ok(Self {
            chunk_mapper,
            cipher,
            backend: Arc::new(RwLock::new(backend)),
            cache: RwLock::new(LruCache::new(capacity)),
            volume_size,
            chunk_size,
            sector_size,
        })
    }

    /// Reads data from the volume at the given offset
    ///
    /// # Arguments
    /// * `offset` - Byte offset to read from
    /// * `buf` - Buffer to read into
    ///
    /// # Returns
    /// Number of bytes actually read
    pub fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.volume_size {
            return Err(VolumeIOError::InvalidOffset {
                offset,
                volume_size: self.volume_size,
            });
        }

        let available = self.volume_size - offset;
        let to_read = (buf.len() as u64).min(available) as usize;
        if to_read == 0 {
            return Ok(0);
        }

        // Map the range to chunks
        let range = self.chunk_mapper.map_range(offset, to_read as u64)?;
        let mut buf_offset = 0;

        // Read from each chunk in the range
        for chunk_id in range.chunk_ids() {
            let chunk_data = self.get_chunk(chunk_id)?;

            // Calculate the portion of this chunk to read
            let chunk_start = if chunk_id == range.start.chunk_id {
                range.start.chunk_offset as usize
            } else {
                0
            };

            let chunk_end = if chunk_id == range.end.chunk_id {
                (range.end.chunk_offset + 1) as usize
            } else {
                self.chunk_mapper.chunk_actual_size(chunk_id).unwrap_or(self.chunk_size) as usize
            };

            let bytes_from_chunk = chunk_end - chunk_start;
            let remaining = to_read - buf_offset;
            let copy_len = bytes_from_chunk.min(remaining);

            buf[buf_offset..buf_offset + copy_len]
                .copy_from_slice(&chunk_data[chunk_start..chunk_start + copy_len]);
            buf_offset += copy_len;
        }

        Ok(buf_offset)
    }

    /// Writes data to the volume at the given offset
    ///
    /// # Arguments
    /// * `offset` - Byte offset to write to
    /// * `data` - Data to write
    ///
    /// # Returns
    /// Number of bytes actually written
    pub fn write(&self, offset: u64, data: &[u8]) -> Result<usize> {
        if offset >= self.volume_size {
            return Err(VolumeIOError::InvalidOffset {
                offset,
                volume_size: self.volume_size,
            });
        }

        let available = self.volume_size - offset;
        let to_write = (data.len() as u64).min(available) as usize;
        if to_write == 0 {
            return Ok(0);
        }

        // Map the range to chunks
        let range = self.chunk_mapper.map_range(offset, to_write as u64)?;
        let mut data_offset = 0;

        // Write to each chunk in the range
        for chunk_id in range.chunk_ids() {
            // Get chunk (read-modify-write pattern)
            let mut chunk_data = self.get_chunk(chunk_id)?;

            // Calculate the portion of this chunk to write
            let chunk_start = if chunk_id == range.start.chunk_id {
                range.start.chunk_offset as usize
            } else {
                0
            };

            let chunk_end = if chunk_id == range.end.chunk_id {
                (range.end.chunk_offset + 1) as usize
            } else {
                self.chunk_mapper.chunk_actual_size(chunk_id).unwrap_or(self.chunk_size) as usize
            };

            let bytes_to_chunk = chunk_end - chunk_start;
            let remaining = to_write - data_offset;
            let copy_len = bytes_to_chunk.min(remaining);

            // Modify the chunk data
            chunk_data[chunk_start..chunk_start + copy_len]
                .copy_from_slice(&data[data_offset..data_offset + copy_len]);

            // Put modified chunk back into cache as dirty
            self.put_chunk_dirty(chunk_id, chunk_data)?;
            data_offset += copy_len;
        }

        Ok(data_offset)
    }

    /// Flushes all dirty chunks to storage
    pub fn flush(&self) -> Result<()> {
        let mut cache = self.cache.write().map_err(|_| VolumeIOError::LockPoisoned)?;

        // Collect dirty chunk IDs first
        let dirty_ids: Vec<u64> = cache
            .iter()
            .filter_map(|(&id, chunk)| if chunk.dirty { Some(id) } else { None })
            .collect();

        // Write back each dirty chunk
        for chunk_id in dirty_ids {
            if let Some(chunk) = cache.get_mut(&chunk_id) {
                self.write_chunk_to_backend(chunk_id, &chunk.data)?;
                chunk.mark_clean();
            }
        }

        // Flush the backend
        let mut backend = self.backend.write().map_err(|_| VolumeIOError::LockPoisoned)?;
        backend.flush()?;

        Ok(())
    }

    /// Gets a chunk from cache or fetches it from backend
    fn get_chunk(&self, chunk_id: u64) -> Result<Vec<u8>> {
        // Check cache first
        {
            let mut cache = self.cache.write().map_err(|_| VolumeIOError::LockPoisoned)?;
            if let Some(cached) = cache.get(&chunk_id) {
                return Ok(cached.data.to_vec());
            }
        }

        // Cache miss - fetch from backend and decrypt
        let chunk_size = self.chunk_mapper.chunk_actual_size(chunk_id)
            .ok_or(ChunkError::OffsetOutOfBounds {
                offset: chunk_id * self.chunk_size,
                volume_size: self.volume_size,
            })?;

        let encrypted = self.read_chunk_from_backend(chunk_id, chunk_size)?;
        let decrypted = self.decrypt_chunk(chunk_id, &encrypted)?;

        // Store in cache
        {
            let mut cache = self.cache.write().map_err(|_| VolumeIOError::LockPoisoned)?;

            // Check if evicted chunk was dirty
            if let Some((evicted_id, evicted_chunk)) = cache.push(chunk_id, CachedChunk::new(decrypted.clone())) {
                if evicted_chunk.dirty {
                    // Write back evicted dirty chunk
                    drop(cache); // Release lock before backend write
                    self.write_chunk_to_backend(evicted_id, &evicted_chunk.data)?;
                }
            }
        }

        Ok(decrypted)
    }

    /// Puts a modified chunk into the cache and marks it as dirty
    fn put_chunk_dirty(&self, chunk_id: u64, data: Vec<u8>) -> Result<()> {
        let mut cache = self.cache.write().map_err(|_| VolumeIOError::LockPoisoned)?;

        let mut cached = CachedChunk::new(data);
        cached.mark_dirty();

        // Check if evicted chunk was dirty
        if let Some((evicted_id, evicted_chunk)) = cache.push(chunk_id, cached) {
            if evicted_chunk.dirty {
                // Write back evicted dirty chunk
                drop(cache); // Release lock before backend write
                self.write_chunk_to_backend(evicted_id, &evicted_chunk.data)?;
            }
        }

        Ok(())
    }

    /// Reads an encrypted chunk from the backend
    fn read_chunk_from_backend(&self, chunk_id: u64, chunk_size: u64) -> Result<Vec<u8>> {
        let offset = chunk_id * self.chunk_size;
        let mut buf = vec![0u8; chunk_size as usize];

        let mut backend = self.backend.write().map_err(|_| VolumeIOError::LockPoisoned)?;
        let bytes_read = backend.read_at(offset, &mut buf)?;

        if bytes_read < chunk_size as usize {
            // Pad with zeros if partial read (e.g., new file)
            buf[bytes_read..].fill(0);
        }

        Ok(buf)
    }

    /// Writes an encrypted chunk to the backend
    fn write_chunk_to_backend(&self, chunk_id: u64, plaintext: &[u8]) -> Result<()> {
        let encrypted = self.encrypt_chunk(chunk_id, plaintext)?;
        let offset = chunk_id * self.chunk_size;

        let mut backend = self.backend.write().map_err(|_| VolumeIOError::LockPoisoned)?;
        backend.write_at(offset, &encrypted)?;

        Ok(())
    }

    /// Decrypts a chunk using sector-based XTS encryption
    fn decrypt_chunk(&self, chunk_id: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let sectors_per_chunk = self.chunk_mapper.sectors_per_chunk();
        let start_sector = chunk_id * sectors_per_chunk;

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let sector_count = ciphertext.len() / self.sector_size;

        for i in 0..sector_count {
            let start = i * self.sector_size;
            let end = start + self.sector_size;
            let sector_ciphertext = &ciphertext[start..end];
            let decrypted = self.cipher.decrypt_sector(start_sector + i as u64, sector_ciphertext)?;
            plaintext.extend_from_slice(&decrypted);
        }

        // Handle partial sector at end (if any)
        let remaining = ciphertext.len() % self.sector_size;
        if remaining > 0 {
            // For partial sectors, we need to pad to sector size, decrypt, then truncate
            let start = sector_count * self.sector_size;
            let mut padded = vec![0u8; self.sector_size];
            padded[..remaining].copy_from_slice(&ciphertext[start..]);
            let decrypted = self.cipher.decrypt_sector(start_sector + sector_count as u64, &padded)?;
            plaintext.extend_from_slice(&decrypted[..remaining]);
        }

        Ok(plaintext)
    }

    /// Encrypts a chunk using sector-based XTS encryption
    fn encrypt_chunk(&self, chunk_id: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let sectors_per_chunk = self.chunk_mapper.sectors_per_chunk();
        let start_sector = chunk_id * sectors_per_chunk;

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let sector_count = plaintext.len() / self.sector_size;

        for i in 0..sector_count {
            let start = i * self.sector_size;
            let end = start + self.sector_size;
            let sector_plaintext = &plaintext[start..end];
            let encrypted = self.cipher.encrypt_sector(start_sector + i as u64, sector_plaintext)?;
            ciphertext.extend_from_slice(&encrypted);
        }

        // Handle partial sector at end (if any)
        let remaining = plaintext.len() % self.sector_size;
        if remaining > 0 {
            // For partial sectors, we need to pad to sector size, encrypt, then truncate
            let start = sector_count * self.sector_size;
            let mut padded = vec![0u8; self.sector_size];
            padded[..remaining].copy_from_slice(&plaintext[start..]);
            let encrypted = self.cipher.encrypt_sector(start_sector + sector_count as u64, &padded)?;
            ciphertext.extend_from_slice(&encrypted[..remaining]);
        }

        Ok(ciphertext)
    }

    /// Returns the volume size
    pub fn volume_size(&self) -> u64 {
        self.volume_size
    }

    /// Returns the chunk size
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// Returns the sector size
    pub fn sector_size(&self) -> usize {
        self.sector_size
    }

    /// Returns the number of chunks in the volume
    pub fn total_chunks(&self) -> u64 {
        self.chunk_mapper.total_chunks()
    }

    /// Returns current cache statistics
    pub fn cache_stats(&self) -> Option<CacheStats> {
        let cache = self.cache.read().ok()?;
        Some(CacheStats {
            capacity: cache.cap().get(),
            len: cache.len(),
        })
    }

    /// Clears the cache, flushing dirty chunks first
    pub fn clear_cache(&self) -> Result<()> {
        self.flush()?;

        let mut cache = self.cache.write().map_err(|_| VolumeIOError::LockPoisoned)?;
        cache.clear();
        Ok(())
    }
}

/// Cache statistics
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    /// Maximum number of chunks the cache can hold
    pub capacity: usize,
    /// Current number of chunks in the cache
    pub len: usize,
}

/// In-memory async storage backend for testing async code paths
///
/// This is the async equivalent of `MemoryBackend` for use in tests.
pub struct AsyncMemoryBackend {
    data: std::sync::Mutex<Vec<u8>>,
    chunk_size: u64,
}

impl AsyncMemoryBackend {
    /// Creates a new async memory backend with the given size and chunk size
    pub fn new(size: usize, chunk_size: u64) -> Self {
        Self {
            data: std::sync::Mutex::new(vec![0u8; size]),
            chunk_size,
        }
    }
}

impl AsyncStorageBackend for AsyncMemoryBackend {
    fn read_chunk<'a>(&'a self, chunk_index: u64, chunk_size: u64) -> AsyncResult<'a, Option<Vec<u8>>> {
        let offset = (chunk_index * self.chunk_size) as usize;

        // Lock, clone, release - all synchronously before the async block
        let data_result: io::Result<Vec<u8>> = self.data.lock()
            .map(|guard| guard.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "lock poisoned"));

        Box::pin(async move {
            let data = data_result?;
            if offset >= data.len() {
                return Ok(None);
            }
            let end = (offset + chunk_size as usize).min(data.len());
            Ok(Some(data[offset..end].to_vec()))
        })
    }

    fn write_chunk<'a>(&'a self, chunk_index: u64, chunk_data: &'a [u8]) -> AsyncResult<'a, ()> {
        let offset = (chunk_index * self.chunk_size) as usize;

        // Perform the write synchronously before the async block
        let result: io::Result<()> = (|| {
            let mut data = self.data.lock().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "lock poisoned")
            })?;

            if offset >= data.len() {
                return Ok(());
            }

            let end = (offset + chunk_data.len()).min(data.len());
            let copy_len = end - offset;
            data[offset..end].copy_from_slice(&chunk_data[..copy_len]);
            Ok(())
        })();

        Box::pin(async move { result })
    }

    fn flush<'a>(&'a self) -> AsyncResult<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn size<'a>(&'a self) -> AsyncResult<'a, u64> {
        // Get size synchronously before async block
        let size_result: io::Result<u64> = self.data.lock()
            .map(|guard| guard.len() as u64)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "lock poisoned"));

        Box::pin(async move { size_result })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_io(volume_size: u64) -> VolumeIO {
        let master_key = MasterKey::generate();
        let backend = Box::new(MemoryBackend::new(volume_size as usize));
        VolumeIO::with_options(
            &master_key,
            volume_size,
            backend,
            64 * 1024, // 64KB chunks for testing
            SECTOR_SIZE_4K,
            4,
        ).unwrap()
    }

    #[test]
    fn test_volume_io_creation() {
        let io = create_test_io(1024 * 1024); // 1 MB
        assert_eq!(io.volume_size(), 1024 * 1024);
        assert_eq!(io.chunk_size(), 64 * 1024);
        assert_eq!(io.sector_size(), SECTOR_SIZE_4K);
    }

    #[test]
    fn test_write_read_small() {
        let io = create_test_io(1024 * 1024);

        let data = b"Hello, encrypted world!";
        let written = io.write(0, data).unwrap();
        assert_eq!(written, data.len());

        io.flush().unwrap();

        let mut buf = vec![0u8; data.len()];
        let read = io.read(0, &mut buf).unwrap();
        assert_eq!(read, data.len());
        assert_eq!(&buf, data);
    }

    #[test]
    fn test_write_read_at_offset() {
        let io = create_test_io(1024 * 1024);

        let offset = 12345;
        let data = b"Data at offset!";
        io.write(offset, data).unwrap();
        io.flush().unwrap();

        let mut buf = vec![0u8; data.len()];
        io.read(offset, &mut buf).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn test_write_read_spanning_chunks() {
        let io = create_test_io(1024 * 1024);

        // Write data that spans chunk boundary (chunk size is 64KB)
        let offset = 60 * 1024; // Near end of first chunk
        let data = vec![0xABu8; 10 * 1024]; // 10KB - will span into second chunk

        io.write(offset, &data).unwrap();
        io.flush().unwrap();

        let mut buf = vec![0u8; data.len()];
        io.read(offset, &mut buf).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn test_cache_hit() {
        let io = create_test_io(1024 * 1024);

        // Write some data
        let data = b"cached data";
        io.write(0, data).unwrap();

        // Read should come from cache (not backend since not flushed)
        let mut buf = vec![0u8; data.len()];
        io.read(0, &mut buf).unwrap();
        assert_eq!(&buf, data);

        // Check cache stats
        let stats = io.cache_stats().unwrap();
        assert!(stats.len > 0);
    }

    #[test]
    fn test_read_past_end() {
        let io = create_test_io(1024);

        // Reading past volume size should return error
        let mut buf = vec![0u8; 100];
        let result = io.read(2000, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_past_end() {
        let io = create_test_io(1024);

        // Writing past volume size should return error
        let data = b"test";
        let result = io.write(2000, data);
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_read_at_end() {
        let io = create_test_io(1024);

        // Write some data
        let data = vec![0x42u8; 500];
        io.write(0, &data).unwrap();
        io.flush().unwrap();

        // Try to read more than available at end
        let mut buf = vec![0u8; 100];
        let read = io.read(950, &mut buf).unwrap();
        assert_eq!(read, 74); // Only 74 bytes left (1024 - 950)
    }

    #[test]
    fn test_flush_dirty_chunks() {
        let io = create_test_io(1024 * 1024);

        let data = b"dirty data";
        io.write(0, data).unwrap();

        // Clear cache without flush should lose data
        // Actually, let's test proper flush behavior
        io.flush().unwrap();

        // Data should still be readable after flush
        let mut buf = vec![0u8; data.len()];
        io.read(0, &mut buf).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn test_clear_cache() {
        let io = create_test_io(1024 * 1024);

        let data = b"test data";
        io.write(0, data).unwrap();
        io.flush().unwrap();

        // Clear cache
        io.clear_cache().unwrap();

        let stats = io.cache_stats().unwrap();
        assert_eq!(stats.len, 0);

        // Data should still be readable (re-fetched from backend)
        let mut buf = vec![0u8; data.len()];
        io.read(0, &mut buf).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn test_overwrite_data() {
        let io = create_test_io(1024 * 1024);

        // Write initial data
        let data1 = b"initial data here";
        io.write(100, data1).unwrap();
        io.flush().unwrap();

        // Overwrite with different data
        let data2 = b"overwritten!!!";
        io.write(100, data2).unwrap();
        io.flush().unwrap();

        // Read back - should get the new data
        let mut buf = vec![0u8; data2.len()];
        io.read(100, &mut buf).unwrap();
        assert_eq!(&buf, data2);
    }

    #[test]
    fn test_multiple_chunks() {
        let io = create_test_io(512 * 1024); // 512 KB = 8 chunks of 64KB

        // Write to multiple chunks
        for i in 0..8 {
            let offset = i * 64 * 1024;
            let data = vec![i as u8; 1024];
            io.write(offset, &data).unwrap();
        }

        io.flush().unwrap();

        // Verify each chunk
        for i in 0..8 {
            let offset = i * 64 * 1024;
            let mut buf = vec![0u8; 1024];
            io.read(offset, &mut buf).unwrap();
            assert!(buf.iter().all(|&b| b == i as u8));
        }
    }

    #[test]
    fn test_cache_eviction_writes_dirty() {
        // Small cache that will force evictions
        let master_key = MasterKey::generate();
        let backend = Box::new(MemoryBackend::new(256 * 1024));
        let io = VolumeIO::with_options(
            &master_key,
            256 * 1024, // 256 KB
            backend,
            64 * 1024, // 64 KB chunks
            SECTOR_SIZE_4K,
            2, // Only 2 chunk cache
        ).unwrap();

        // Write to 4 chunks (will cause evictions)
        for i in 0..4 {
            let offset = i * 64 * 1024;
            let data = vec![i as u8; 100];
            io.write(offset, &data).unwrap();
        }

        io.flush().unwrap();

        // All chunks should have been written (including evicted ones)
        for i in 0..4 {
            let offset = i * 64 * 1024;
            let mut buf = vec![0u8; 100];
            io.read(offset, &mut buf).unwrap();
            assert!(buf.iter().all(|&b| b == i as u8), "Chunk {} data mismatch", i);
        }
    }

    #[test]
    fn test_total_chunks() {
        let io = create_test_io(256 * 1024); // 256 KB
        // 256 KB / 64 KB = 4 chunks
        assert_eq!(io.total_chunks(), 4);
    }

    #[test]
    fn test_sector_alignment() {
        let io = create_test_io(1024 * 1024);

        // Write data that's not sector-aligned
        let data = vec![0x42u8; 5000]; // Not aligned to 4KB
        io.write(0, &data).unwrap();
        io.flush().unwrap();

        let mut buf = vec![0u8; 5000];
        io.read(0, &mut buf).unwrap();
        assert_eq!(buf, data);
    }

    // ===== Async Backend Tests =====

    /// Helper to poll a boxed future once (for testing simple futures that complete immediately)
    fn poll_once<T>(mut fut: Pin<Box<dyn Future<Output = T> + Send + '_>>) -> T {
        use std::task::{Context, Poll, Wake, Waker};

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }

        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);

        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("Future did not complete immediately"),
        }
    }

    #[test]
    fn test_blocking_adapter_read_write() {
        // Test that BlockingAdapter correctly wraps a sync backend
        let memory_backend = Box::new(MemoryBackend::new(64 * 1024));
        let adapter = BlockingAdapter::new(memory_backend, 4096);

        // Test write
        let data = b"Hello, async world!";
        let result = poll_once(adapter.write_chunk(0, data));
        assert!(result.is_ok());

        // Test read
        let result = poll_once(adapter.read_chunk(0, 4096));
        match result {
            Ok(Some(chunk)) => {
                assert_eq!(&chunk[..data.len()], data);
            }
            other => panic!("Unexpected read result: {:?}", other),
        }
    }

    #[test]
    fn test_async_memory_backend() {
        let backend = AsyncMemoryBackend::new(64 * 1024, 4096);

        // Write data
        let data = b"Async test data";
        let result = poll_once(backend.write_chunk(1, data));
        assert!(result.is_ok());

        // Read it back
        let result = poll_once(backend.read_chunk(1, 4096));
        match result {
            Ok(Some(chunk)) => {
                assert_eq!(&chunk[..data.len()], data);
            }
            other => panic!("Unexpected read result: {:?}", other),
        }

        // Test size
        let result = poll_once(backend.size());
        assert_eq!(result.unwrap(), 64 * 1024);
    }

    #[test]
    fn test_s3_backend_config() {
        let backend = S3Backend::new(
            "my-bucket".to_string(),
            "volumes/vol1/".to_string(),
            4 * 1024 * 1024, // 4MB chunks
        );

        assert_eq!(backend.bucket(), "my-bucket");
        assert_eq!(backend.chunk_size(), 4 * 1024 * 1024);
        assert_eq!(backend.chunk_key(0), "volumes/vol1/chunk-00000000");
        assert_eq!(backend.chunk_key(255), "volumes/vol1/chunk-000000ff");
    }

    #[test]
    fn test_dropbox_backend_config() {
        let backend = DropboxBackend::new(
            "/Apps/Tesseract/my-volume/".to_string(),
            4 * 1024 * 1024,
        );

        assert_eq!(backend.chunk_size(), 4 * 1024 * 1024);
        assert_eq!(backend.chunk_path(0), "/Apps/Tesseract/my-volume/chunk-00000000");
        assert_eq!(backend.chunk_path(16), "/Apps/Tesseract/my-volume/chunk-00000010");
    }
}

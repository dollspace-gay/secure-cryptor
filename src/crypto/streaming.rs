//! Streaming encryption for large files.
//!
//! This module provides chunk-based encryption that allows processing files
//! of any size without loading the entire file into memory.
//!
//! # Security Design
//!
//! - Each chunk is encrypted independently with a unique nonce
//! - Nonces are derived deterministically from a base nonce + chunk counter
//! - Each chunk maintains AEAD properties (authentication + encryption)
//! - Chunk size is configurable (default: 1 MB)
//! - Maximum file size: 2^64 bytes (nonce counter is u64)
//!
//! # File Format V2
//!
//! ```text
//! [Header]
//!   - Magic bytes: "SCRYPTv2" (8 bytes)
//!   - Version: 0x02 (1 byte)
//!   - Header size: u32 (4 bytes)
//!   - Flags: u8 (1 byte) - bit 0: compression enabled
//!   - Salt length: u16 (2 bytes)
//!   - Salt: variable
//!   - Base nonce: 12 bytes
//!   - Chunk size: u32 (4 bytes)
//!   - Total chunks: u64 (8 bytes)
//!   - Original file size: u64 (8 bytes)
//!   - Metadata size: u16 (2 bytes)
//!   - Metadata: JSON (optional)
//!
//! [Chunk 0]
//!   - Chunk index: u64 (8 bytes)
//!   - Data size: u32 (4 bytes)
//!   - Encrypted data + auth tag
//!
//! [Chunk 1]
//!   - Chunk index: u64 (8 bytes)
//!   - Data size: u32 (4 bytes)
//!   - Encrypted data + auth tag
//!
//! ...
//! ```

use crate::config::NONCE_LEN;
use crate::error::{CryptorError, Result};
use flate2::read::{DeflateDecoder, DeflateEncoder};
use flate2::Compression;
use rayon::prelude::*;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Default chunk size: 1 MB
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Minimum chunk size: 4 KB
pub const MIN_CHUNK_SIZE: usize = 4 * 1024;

/// Maximum chunk size: 16 MB
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Magic bytes for streaming file format v2
pub const MAGIC_BYTES_V2: &[u8] = b"SCRYPTv2";

/// File format version
pub const FORMAT_VERSION: u8 = 0x02;

/// Configuration for streaming encryption/decryption.
#[derive(Debug, Clone, Copy)]
pub struct StreamConfig {
    /// Size of each chunk in bytes
    pub chunk_size: usize,
    /// Whether to enable compression before encryption
    pub compress: bool,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            compress: false,
        }
    }
}

impl StreamConfig {
    /// Creates a new stream configuration with custom chunk size.
    ///
    /// # Arguments
    ///
    /// * `chunk_size` - Size of each chunk in bytes (must be between MIN and MAX)
    ///
    /// # Errors
    ///
    /// Returns an error if chunk size is out of valid range.
    pub fn new(chunk_size: usize) -> Result<Self> {
        if chunk_size < MIN_CHUNK_SIZE || chunk_size > MAX_CHUNK_SIZE {
            return Err(CryptorError::Cryptography(format!(
                "Chunk size {} is out of range [{}, {}]",
                chunk_size, MIN_CHUNK_SIZE, MAX_CHUNK_SIZE
            )));
        }

        Ok(Self {
            chunk_size,
            compress: false,
        })
    }

    /// Enables or disables compression.
    pub fn with_compression(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }

    /// Creates a configuration optimized for fast processing.
    pub fn fast() -> Self {
        Self {
            chunk_size: 4 * 1024 * 1024, // 4 MB chunks
            compress: false,
        }
    }

    /// Creates a configuration optimized for small memory footprint.
    pub fn low_memory() -> Self {
        Self {
            chunk_size: 64 * 1024, // 64 KB chunks
            compress: true,
        }
    }
}

/// Derives a unique nonce for a specific chunk.
///
/// # Security
///
/// This function generates a unique nonce for each chunk by combining:
/// - A base nonce (12 bytes, randomly generated once per file)
/// - A chunk counter (u64, incremented for each chunk)
///
/// The nonce is constructed as: base_nonce[0..8] || (base_nonce[8..12] XOR chunk_counter_bytes)
///
/// This ensures:
/// - Each chunk gets a unique nonce
/// - Nonces are deterministic (same chunk = same nonce)
/// - No nonce reuse within a single file
/// - Maximum file size: 2^64 chunks
///
/// # Arguments
///
/// * `base_nonce` - 12-byte base nonce (randomly generated per file)
/// * `chunk_index` - Index of the chunk (0-based)
///
/// # Returns
///
/// A 12-byte nonce unique to this chunk.
pub fn derive_chunk_nonce(base_nonce: &[u8; NONCE_LEN], chunk_index: u64) -> [u8; NONCE_LEN] {
    let mut nonce = *base_nonce;

    // XOR the last 8 bytes with the chunk counter
    // This ensures each chunk has a unique nonce
    let counter_bytes = chunk_index.to_le_bytes();
    for i in 0..8 {
        nonce[i + 4] ^= counter_bytes[i];
    }

    nonce
}

/// Checkpoint for resumable encryption/decryption operations.
///
/// Stores the state of an in-progress operation to allow resuming later.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Path to the input file
    pub input_path: PathBuf,
    /// Path to the output file
    pub output_path: PathBuf,
    /// Current chunk being processed
    pub current_chunk: u64,
    /// Total chunks in the operation
    pub total_chunks: u64,
    /// Bytes written so far
    pub bytes_written: u64,
    /// Original file size
    pub original_size: u64,
    /// Operation type (encrypt or decrypt)
    pub operation: CheckpointOperation,
    /// Timestamp when checkpoint was created
    pub timestamp: u64,
}

/// Type of operation being checkpointed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointOperation {
    /// Encryption operation
    Encrypt,
    /// Decryption operation
    Decrypt,
}

impl Checkpoint {
    /// Creates a new checkpoint.
    pub fn new(
        input_path: PathBuf,
        output_path: PathBuf,
        current_chunk: u64,
        total_chunks: u64,
        bytes_written: u64,
        original_size: u64,
        operation: CheckpointOperation,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            input_path,
            output_path,
            current_chunk,
            total_chunks,
            bytes_written,
            original_size,
            operation,
            timestamp,
        }
    }

    /// Calculates progress as a percentage (0.0 to 1.0).
    pub fn progress(&self) -> f64 {
        if self.total_chunks == 0 {
            1.0
        } else {
            (self.current_chunk as f64 / self.total_chunks as f64).min(1.0)
        }
    }

    /// Saves the checkpoint to a file.
    ///
    /// The checkpoint file is saved with a `.checkpoint` extension.
    pub fn save(&self, checkpoint_path: &Path) -> Result<()> {
        use std::io::Write;

        let mut file = File::create(checkpoint_path)?;

        // Write checkpoint format version
        file.write_all(&[0x01])?;

        // Write operation type
        let op_byte = match self.operation {
            CheckpointOperation::Encrypt => 0x01,
            CheckpointOperation::Decrypt => 0x02,
        };
        file.write_all(&[op_byte])?;

        // Write input path
        let input_str = self.input_path.to_string_lossy();
        let input_bytes = input_str.as_bytes();
        file.write_all(&(input_bytes.len() as u32).to_le_bytes())?;
        file.write_all(input_bytes)?;

        // Write output path
        let output_str = self.output_path.to_string_lossy();
        let output_bytes = output_str.as_bytes();
        file.write_all(&(output_bytes.len() as u32).to_le_bytes())?;
        file.write_all(output_bytes)?;

        // Write progress data
        file.write_all(&self.current_chunk.to_le_bytes())?;
        file.write_all(&self.total_chunks.to_le_bytes())?;
        file.write_all(&self.bytes_written.to_le_bytes())?;
        file.write_all(&self.original_size.to_le_bytes())?;
        file.write_all(&self.timestamp.to_le_bytes())?;

        file.flush()?;
        Ok(())
    }

    /// Loads a checkpoint from a file.
    pub fn load(checkpoint_path: &Path) -> Result<Self> {
        let mut file = File::open(checkpoint_path)?;

        // Read checkpoint format version
        let mut version = [0u8; 1];
        file.read_exact(&mut version)?;
        if version[0] != 0x01 {
            return Err(CryptorError::InvalidFormat);
        }

        // Read operation type
        let mut op_byte = [0u8; 1];
        file.read_exact(&mut op_byte)?;
        let operation = match op_byte[0] {
            0x01 => CheckpointOperation::Encrypt,
            0x02 => CheckpointOperation::Decrypt,
            _ => return Err(CryptorError::InvalidFormat),
        };

        // Read input path
        let mut path_len_bytes = [0u8; 4];
        file.read_exact(&mut path_len_bytes)?;
        let input_len = u32::from_le_bytes(path_len_bytes) as usize;
        let mut input_bytes = vec![0u8; input_len];
        file.read_exact(&mut input_bytes)?;
        let input_path = PathBuf::from(String::from_utf8(input_bytes)
            .map_err(|_| CryptorError::InvalidFormat)?);

        // Read output path
        let mut output_len_bytes = [0u8; 4];
        file.read_exact(&mut output_len_bytes)?;
        let output_len = u32::from_le_bytes(output_len_bytes) as usize;
        let mut output_bytes = vec![0u8; output_len];
        file.read_exact(&mut output_bytes)?;
        let output_path = PathBuf::from(String::from_utf8(output_bytes)
            .map_err(|_| CryptorError::InvalidFormat)?);

        // Read progress data
        let mut current_chunk_bytes = [0u8; 8];
        file.read_exact(&mut current_chunk_bytes)?;
        let current_chunk = u64::from_le_bytes(current_chunk_bytes);

        let mut total_chunks_bytes = [0u8; 8];
        file.read_exact(&mut total_chunks_bytes)?;
        let total_chunks = u64::from_le_bytes(total_chunks_bytes);

        let mut bytes_written_bytes = [0u8; 8];
        file.read_exact(&mut bytes_written_bytes)?;
        let bytes_written = u64::from_le_bytes(bytes_written_bytes);

        let mut original_size_bytes = [0u8; 8];
        file.read_exact(&mut original_size_bytes)?;
        let original_size = u64::from_le_bytes(original_size_bytes);

        let mut timestamp_bytes = [0u8; 8];
        file.read_exact(&mut timestamp_bytes)?;
        let timestamp = u64::from_le_bytes(timestamp_bytes);

        Ok(Self {
            input_path,
            output_path,
            current_chunk,
            total_chunks,
            bytes_written,
            original_size,
            operation,
            timestamp,
        })
    }

    /// Deletes the checkpoint file.
    pub fn delete(checkpoint_path: &Path) -> Result<()> {
        std::fs::remove_file(checkpoint_path)?;
        Ok(())
    }
}

/// Header information for a streaming encrypted file.
#[derive(Debug, Clone)]
pub struct StreamHeader {
    /// Salt string for key derivation
    pub salt: String,
    /// Base nonce for deriving chunk nonces
    pub base_nonce: [u8; NONCE_LEN],
    /// Size of each chunk in bytes
    pub chunk_size: u32,
    /// Total number of chunks in the file
    pub total_chunks: u64,
    /// Original file size in bytes
    pub original_size: u64,
    /// Whether compression is enabled
    pub compressed: bool,
    /// Optional metadata (JSON)
    pub metadata: Option<String>,
}

impl StreamHeader {
    /// Calculates the number of chunks needed for a given file size.
    pub fn calculate_chunks(file_size: u64, chunk_size: u32) -> u64 {
        let chunk_size = chunk_size as u64;
        (file_size + chunk_size - 1) / chunk_size
    }

    /// Writes the header to a writer.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Magic bytes
        writer.write_all(MAGIC_BYTES_V2)?;

        // Version
        writer.write_all(&[FORMAT_VERSION])?;

        // Calculate and write header size (placeholder for now)
        let header_size_pos = 0u32; // We'll calculate this
        writer.write_all(&header_size_pos.to_le_bytes())?;

        // Flags (bit 0: compression)
        let flags = if self.compressed { 0x01 } else { 0x00 };
        writer.write_all(&[flags])?;

        // Salt
        let salt_bytes = self.salt.as_bytes();
        let salt_len = salt_bytes.len() as u16;
        writer.write_all(&salt_len.to_le_bytes())?;
        writer.write_all(salt_bytes)?;

        // Base nonce
        writer.write_all(&self.base_nonce)?;

        // Chunk size
        writer.write_all(&self.chunk_size.to_le_bytes())?;

        // Total chunks
        writer.write_all(&self.total_chunks.to_le_bytes())?;

        // Original file size
        writer.write_all(&self.original_size.to_le_bytes())?;

        // Metadata
        let metadata_bytes = self.metadata.as_ref().map(|s| s.as_bytes()).unwrap_or(&[]);
        let metadata_len = metadata_bytes.len() as u16;
        writer.write_all(&metadata_len.to_le_bytes())?;
        writer.write_all(metadata_bytes)?;

        Ok(())
    }

    /// Reads the header from a reader.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        // Magic bytes
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;
        if magic != MAGIC_BYTES_V2 {
            return Err(CryptorError::InvalidFormat);
        }

        // Version
        let mut version = [0u8; 1];
        reader.read_exact(&mut version)?;
        if version[0] != FORMAT_VERSION {
            return Err(CryptorError::InvalidFormat);
        }

        // Header size (skip for now)
        let mut header_size_bytes = [0u8; 4];
        reader.read_exact(&mut header_size_bytes)?;

        // Flags
        let mut flags = [0u8; 1];
        reader.read_exact(&mut flags)?;
        let compressed = (flags[0] & 0x01) != 0;

        // Salt length and salt
        let mut salt_len_bytes = [0u8; 2];
        reader.read_exact(&mut salt_len_bytes)?;
        let salt_len = u16::from_le_bytes(salt_len_bytes) as usize;

        let mut salt_bytes = vec![0u8; salt_len];
        reader.read_exact(&mut salt_bytes)?;
        let salt = String::from_utf8(salt_bytes)
            .map_err(|_| CryptorError::InvalidFormat)?;

        // Base nonce
        let mut base_nonce = [0u8; NONCE_LEN];
        reader.read_exact(&mut base_nonce)?;

        // Chunk size
        let mut chunk_size_bytes = [0u8; 4];
        reader.read_exact(&mut chunk_size_bytes)?;
        let chunk_size = u32::from_le_bytes(chunk_size_bytes);

        // Total chunks
        let mut total_chunks_bytes = [0u8; 8];
        reader.read_exact(&mut total_chunks_bytes)?;
        let total_chunks = u64::from_le_bytes(total_chunks_bytes);

        // Original size
        let mut original_size_bytes = [0u8; 8];
        reader.read_exact(&mut original_size_bytes)?;
        let original_size = u64::from_le_bytes(original_size_bytes);

        // Metadata length and metadata
        let mut metadata_len_bytes = [0u8; 2];
        reader.read_exact(&mut metadata_len_bytes)?;
        let metadata_len = u16::from_le_bytes(metadata_len_bytes) as usize;

        let metadata = if metadata_len > 0 {
            let mut metadata_bytes = vec![0u8; metadata_len];
            reader.read_exact(&mut metadata_bytes)?;
            Some(String::from_utf8(metadata_bytes)
                .map_err(|_| CryptorError::InvalidFormat)?)
        } else {
            None
        };

        Ok(Self {
            salt,
            base_nonce,
            chunk_size,
            total_chunks,
            original_size,
            compressed,
            metadata,
        })
    }
}

/// A chunk of data read from a file.
#[derive(Debug, Clone)]
pub struct Chunk {
    /// Index of this chunk (0-based)
    pub index: u64,
    /// Data contained in this chunk
    pub data: Vec<u8>,
    /// Whether this is the last chunk
    pub is_last: bool,
}

/// Streaming file reader that reads files in configurable chunks.
///
/// This reader efficiently processes large files by reading them in
/// fixed-size chunks, reducing memory usage.
///
/// # Examples
///
/// ```no_run
/// # use secure_cryptor::crypto::streaming::{ChunkedReader, StreamConfig};
/// # use std::path::Path;
/// let config = StreamConfig::default();
/// let mut reader = ChunkedReader::open(Path::new("large_file.dat"), config).unwrap();
///
/// while let Some(chunk) = reader.next_chunk().unwrap() {
///     println!("Read chunk {} with {} bytes", chunk.index, chunk.data.len());
/// }
/// ```
pub struct ChunkedReader {
    file: File,
    config: StreamConfig,
    current_chunk: u64,
    total_size: u64,
    bytes_read: u64,
}

impl ChunkedReader {
    /// Opens a file for chunked reading.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to read
    /// * `config` - Configuration specifying chunk size
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or metadata cannot be read.
    pub fn open(path: &Path, config: StreamConfig) -> Result<Self> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let total_size = metadata.len();

        Ok(Self {
            file,
            config,
            current_chunk: 0,
            total_size,
            bytes_read: 0,
        })
    }

    /// Creates a chunked reader from an existing file handle.
    ///
    /// # Arguments
    ///
    /// * `file` - Open file handle
    /// * `config` - Configuration specifying chunk size
    ///
    /// # Errors
    ///
    /// Returns an error if file metadata cannot be read.
    pub fn from_file(file: File, config: StreamConfig) -> Result<Self> {
        let metadata = file.metadata()?;
        let total_size = metadata.len();

        Ok(Self {
            file,
            config,
            current_chunk: 0,
            total_size,
            bytes_read: 0,
        })
    }

    /// Returns the total size of the file in bytes.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Returns the number of bytes read so far.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Returns the current chunk index.
    pub fn current_chunk(&self) -> u64 {
        self.current_chunk
    }

    /// Calculates the total number of chunks.
    pub fn total_chunks(&self) -> u64 {
        StreamHeader::calculate_chunks(self.total_size, self.config.chunk_size as u32)
    }

    /// Returns the progress as a percentage (0.0 to 1.0).
    pub fn progress(&self) -> f64 {
        if self.total_size == 0 {
            1.0
        } else {
            self.bytes_read as f64 / self.total_size as f64
        }
    }

    /// Reads the next chunk from the file.
    ///
    /// Returns `None` when the end of the file is reached.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the file fails.
    pub fn next_chunk(&mut self) -> Result<Option<Chunk>> {
        if self.bytes_read >= self.total_size {
            return Ok(None);
        }

        let remaining = self.total_size - self.bytes_read;
        let chunk_size = std::cmp::min(self.config.chunk_size, remaining as usize);

        let mut buffer = vec![0u8; chunk_size];
        self.file.read_exact(&mut buffer)?;

        let chunk = Chunk {
            index: self.current_chunk,
            data: buffer,
            is_last: self.bytes_read + chunk_size as u64 >= self.total_size,
        };

        self.current_chunk += 1;
        self.bytes_read += chunk_size as u64;

        Ok(Some(chunk))
    }

    /// Seeks to a specific chunk index.
    ///
    /// This allows random access to chunks in the file.
    ///
    /// # Arguments
    ///
    /// * `chunk_index` - Index of the chunk to seek to (0-based)
    ///
    /// # Errors
    ///
    /// Returns an error if the chunk index is out of bounds or seeking fails.
    pub fn seek_to_chunk(&mut self, chunk_index: u64) -> Result<()> {
        let total_chunks = self.total_chunks();
        if chunk_index >= total_chunks {
            return Err(CryptorError::Cryptography(format!(
                "Chunk index {} is out of bounds (total chunks: {})",
                chunk_index, total_chunks
            )));
        }

        let offset = chunk_index * self.config.chunk_size as u64;
        self.file.seek(SeekFrom::Start(offset))?;
        self.current_chunk = chunk_index;
        self.bytes_read = offset;

        Ok(())
    }

    /// Resets the reader to the beginning of the file.
    ///
    /// # Errors
    ///
    /// Returns an error if seeking fails.
    pub fn reset(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.current_chunk = 0;
        self.bytes_read = 0;
        Ok(())
    }
}

/// Iterator implementation for chunked reading.
impl Iterator for ChunkedReader {
    type Item = Result<Chunk>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_chunk().transpose()
    }
}

/// Streaming file encryptor that encrypts files chunk-by-chunk.
///
/// This encryptor efficiently processes large files by encrypting them in
/// fixed-size chunks, reducing memory usage. Each chunk is encrypted with
/// a unique nonce derived from a base nonce and chunk index.
///
/// # Security
///
/// - Each chunk is encrypted with AES-256-GCM (authenticated encryption)
/// - Unique nonce per chunk prevents nonce reuse
/// - Each chunk is independently authenticated
///
/// # Examples
///
/// ```no_run
/// # use secure_cryptor::crypto::streaming::{ChunkedEncryptor, ChunkedReader, StreamConfig};
/// # use secure_cryptor::crypto::aes_gcm::AesGcmEncryptor;
/// # use secure_cryptor::crypto::kdf::Argon2Kdf;
/// # use secure_cryptor::crypto::KeyDerivation;
/// # use std::path::Path;
/// # use std::fs::File;
/// # use zeroize::Zeroizing;
/// # use argon2::password_hash::rand_core::{OsRng, RngCore};
/// # use secure_cryptor::config::NONCE_LEN;
/// let config = StreamConfig::default();
/// let reader = ChunkedReader::open(Path::new("large_file.dat"), config).unwrap();
///
/// let kdf = Argon2Kdf::default();
/// let salt = kdf.generate_salt();
/// let key = kdf.derive_key(b"password", &salt).unwrap();
///
/// let mut base_nonce = [0u8; NONCE_LEN];
/// OsRng.fill_bytes(&mut base_nonce);
///
/// let mut encryptor = ChunkedEncryptor::new(
///     reader,
///     Box::new(AesGcmEncryptor::new()),
///     key,
///     base_nonce,
///     String::from_utf8(salt).unwrap(),
/// );
///
/// let mut output = File::create("large_file.enc").unwrap();
/// encryptor.encrypt_to(&mut output).unwrap();
/// ```
pub struct ChunkedEncryptor {
    reader: ChunkedReader,
    encryptor: Box<dyn crate::crypto::Encryptor>,
    key: zeroize::Zeroizing<[u8; 32]>,
    base_nonce: [u8; NONCE_LEN],
    header: StreamHeader,
    compress: bool,
}

impl ChunkedEncryptor {
    /// Creates a new chunked encryptor.
    ///
    /// # Arguments
    ///
    /// * `reader` - ChunkedReader for reading the input file
    /// * `encryptor` - Encryption algorithm (e.g., AES-256-GCM)
    /// * `key` - 32-byte encryption key
    /// * `base_nonce` - Base nonce for deriving chunk nonces
    /// * `salt` - Salt string used for key derivation
    pub fn new(
        reader: ChunkedReader,
        encryptor: Box<dyn crate::crypto::Encryptor>,
        key: zeroize::Zeroizing<[u8; 32]>,
        base_nonce: [u8; NONCE_LEN],
        salt: String,
    ) -> Self {
        let total_size = reader.total_size();
        let chunk_size = reader.config.chunk_size as u32;
        let total_chunks = reader.total_chunks();
        let compress = reader.config.compress;

        let header = StreamHeader {
            salt,
            base_nonce,
            chunk_size,
            total_chunks,
            original_size: total_size,
            compressed: compress,
            metadata: None,
        };

        Self {
            reader,
            encryptor,
            key,
            base_nonce,
            header,
            compress,
        }
    }

    /// Sets optional metadata for the encrypted file.
    ///
    /// Metadata is stored in the file header and can contain arbitrary
    /// JSON-encoded information about the file.
    pub fn with_metadata(mut self, metadata: String) -> Self {
        self.header.metadata = Some(metadata);
        self
    }

    /// Returns the current progress as a percentage (0.0 to 1.0).
    pub fn progress(&self) -> f64 {
        self.reader.progress()
    }

    /// Compresses data using DEFLATE compression.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to compress
    ///
    /// # Returns
    ///
    /// Compressed data.
    fn compress_data(data: &[u8]) -> Result<Vec<u8>> {
        use std::io::Read as _;

        let mut encoder = DeflateEncoder::new(data, Compression::default());
        let mut compressed = Vec::new();
        encoder.read_to_end(&mut compressed)?;

        Ok(compressed)
    }

    /// Encrypts the file and writes it to the provided writer.
    ///
    /// This method:
    /// 1. Writes the file header (magic bytes, salt, nonce, metadata)
    /// 2. Reads chunks from the input file
    /// 3. Encrypts each chunk with a unique nonce
    /// 4. Writes each encrypted chunk with its index and size
    ///
    /// # Arguments
    ///
    /// * `writer` - Output writer for the encrypted file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Reading from input fails
    /// - Encryption fails
    /// - Writing to output fails
    pub fn encrypt_to<W: Write>(mut self, writer: &mut W) -> Result<()> {
        // Write header
        self.header.write_to(writer)?;

        // Encrypt and write each chunk
        while let Some(chunk) = self.reader.next_chunk()? {
            // Optionally compress chunk data
            let data = if self.compress {
                Self::compress_data(&chunk.data)?
            } else {
                chunk.data.clone()
            };

            // Derive unique nonce for this chunk
            let chunk_nonce = derive_chunk_nonce(&self.base_nonce, chunk.index);

            // Encrypt chunk data
            let ciphertext = self.encryptor.encrypt(&self.key, &chunk_nonce, &data)?;

            // Write chunk header: index (u64) + size (u32)
            writer.write_all(&chunk.index.to_le_bytes())?;
            writer.write_all(&(ciphertext.len() as u32).to_le_bytes())?;

            // Write encrypted data
            writer.write_all(&ciphertext)?;
        }

        Ok(())
    }

    /// Encrypts the file using parallel processing for better performance.
    ///
    /// This method processes multiple chunks concurrently using a thread pool,
    /// which can significantly improve performance on multi-core systems.
    ///
    /// # Arguments
    ///
    /// * `writer` - Output writer for the encrypted file
    /// * `batch_size` - Number of chunks to process in parallel (default: number of CPU cores)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Reading from input fails
    /// - Encryption fails
    /// - Writing to output fails
    ///
    /// # Performance
    ///
    /// Parallel encryption can achieve 2-4x speedup on modern multi-core CPUs,
    /// depending on file size, chunk size, and available cores.
    pub fn encrypt_to_parallel<W: Write>(
        mut self,
        writer: &mut W,
        batch_size: Option<usize>,
    ) -> Result<()> {
        // Write header
        self.header.write_to(writer)?;

        let batch_size = batch_size.unwrap_or_else(|| rayon::current_num_threads());
        let compress = self.compress;

        // Process chunks in batches
        let mut batch = Vec::with_capacity(batch_size);

        loop {
            // Collect a batch of chunks
            batch.clear();
            for _ in 0..batch_size {
                match self.reader.next_chunk()? {
                    Some(chunk) => batch.push(chunk),
                    None => break,
                }
            }

            if batch.is_empty() {
                break;
            }

            // Process batch in parallel
            let results: Vec<_> = batch
                .par_iter()
                .map(|chunk| {
                    // Optionally compress chunk data
                    let data = if compress {
                        Self::compress_data(&chunk.data)?
                    } else {
                        chunk.data.clone()
                    };

                    // Derive unique nonce for this chunk
                    let chunk_nonce = derive_chunk_nonce(&self.base_nonce, chunk.index);

                    // Encrypt chunk data
                    let ciphertext = self.encryptor.encrypt(&self.key, &chunk_nonce, &data)?;

                    Ok::<_, CryptorError>((chunk.index, ciphertext))
                })
                .collect();

            // Write results in order
            for result in results {
                let (index, ciphertext) = result?;

                // Write chunk header: index (u64) + size (u32)
                writer.write_all(&index.to_le_bytes())?;
                writer.write_all(&(ciphertext.len() as u32).to_le_bytes())?;

                // Write encrypted data
                writer.write_all(&ciphertext)?;
            }
        }

        Ok(())
    }
}

/// Streaming file decryptor that decrypts files chunk-by-chunk.
///
/// This decryptor efficiently processes large encrypted files by decrypting them in
/// chunks, reducing memory usage. It reads the file header to determine chunk size
/// and derives unique nonces for each chunk.
///
/// # Security
///
/// - Each chunk is decrypted with AES-256-GCM (authenticated decryption)
/// - Unique nonce per chunk matches encryption nonces
/// - Each chunk is independently authenticated
/// - Authentication failures will return an error
///
/// # Examples
///
/// ```no_run
/// # use secure_cryptor::crypto::streaming::ChunkedDecryptor;
/// # use secure_cryptor::crypto::aes_gcm::AesGcmEncryptor;
/// # use secure_cryptor::crypto::kdf::Argon2Kdf;
/// # use secure_cryptor::crypto::KeyDerivation;
/// # use std::fs::File;
/// # use zeroize::Zeroizing;
/// let encrypted_file = File::open("large_file.enc").unwrap();
///
/// let kdf = Argon2Kdf::default();
/// // Salt is read from file header
/// // Key derived from password
/// # let key = Zeroizing::new([0u8; 32]);
///
/// let mut decryptor = ChunkedDecryptor::new(
///     encrypted_file,
///     Box::new(AesGcmEncryptor::new()),
///     key,
/// ).unwrap();
///
/// let mut output = File::create("large_file.dat").unwrap();
/// decryptor.decrypt_to(&mut output).unwrap();
/// ```
pub struct ChunkedDecryptor<R: Read> {
    reader: R,
    encryptor: Box<dyn crate::crypto::Encryptor>,
    key: zeroize::Zeroizing<[u8; 32]>,
    header: StreamHeader,
    current_chunk: u64,
    bytes_written: u64,
}

impl<R: Read> ChunkedDecryptor<R> {
    /// Creates a new chunked decryptor.
    ///
    /// Reads and parses the file header to extract encryption metadata.
    ///
    /// # Arguments
    ///
    /// * `reader` - Reader for the encrypted file
    /// * `encryptor` - Decryption algorithm (same as used for encryption)
    /// * `key` - 32-byte decryption key (must match encryption key)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File header cannot be read
    /// - File format is invalid
    /// - Magic bytes don't match
    pub fn new(
        mut reader: R,
        encryptor: Box<dyn crate::crypto::Encryptor>,
        key: zeroize::Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        let header = StreamHeader::read_from(&mut reader)?;

        Ok(Self {
            reader,
            encryptor,
            key,
            header,
            current_chunk: 0,
            bytes_written: 0,
        })
    }

    /// Returns a reference to the file header.
    pub fn header(&self) -> &StreamHeader {
        &self.header
    }

    /// Returns the current progress as a percentage (0.0 to 1.0).
    pub fn progress(&self) -> f64 {
        if self.header.original_size == 0 {
            1.0
        } else {
            self.bytes_written as f64 / self.header.original_size as f64
        }
    }

    /// Returns the number of bytes written so far.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Returns the current chunk index.
    pub fn current_chunk(&self) -> u64 {
        self.current_chunk
    }

    /// Decompresses data using DEFLATE decompression.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to decompress
    ///
    /// # Returns
    ///
    /// Decompressed data.
    fn decompress_data(data: &[u8]) -> Result<Vec<u8>> {
        use std::io::Read as _;

        let mut decoder = DeflateDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;

        Ok(decompressed)
    }

    /// Decrypts the entire file and writes it to the provided writer.
    ///
    /// This method:
    /// 1. Reads each encrypted chunk with its header (index + size)
    /// 2. Derives the unique nonce for each chunk
    /// 3. Decrypts and authenticates each chunk
    /// 4. Writes decrypted data to the output
    ///
    /// # Arguments
    ///
    /// * `writer` - Output writer for the decrypted file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Reading from input fails
    /// - Chunk format is invalid
    /// - Decryption or authentication fails (wrong key/password or corrupted data)
    /// - Writing to output fails
    pub fn decrypt_to<W: Write>(&mut self, writer: &mut W) -> Result<()> {
        // Process each chunk
        while self.current_chunk < self.header.total_chunks {
            // Read chunk header: index (u64) + size (u32)
            let mut chunk_index_bytes = [0u8; 8];
            self.reader.read_exact(&mut chunk_index_bytes)?;
            let chunk_index = u64::from_le_bytes(chunk_index_bytes);

            let mut chunk_size_bytes = [0u8; 4];
            self.reader.read_exact(&mut chunk_size_bytes)?;
            let chunk_size = u32::from_le_bytes(chunk_size_bytes);

            // Verify chunk index matches expected
            if chunk_index != self.current_chunk {
                return Err(CryptorError::InvalidFormat);
            }

            // Read encrypted chunk data
            let mut ciphertext = vec![0u8; chunk_size as usize];
            self.reader.read_exact(&mut ciphertext)?;

            // Derive chunk nonce
            let chunk_nonce = derive_chunk_nonce(&self.header.base_nonce, chunk_index);

            // Decrypt chunk
            let decrypted = self.encryptor.decrypt(&self.key, &chunk_nonce, &ciphertext)?;

            // Optionally decompress chunk data
            let plaintext = if self.header.compressed {
                Self::decompress_data(&decrypted)?
            } else {
                decrypted
            };

            // Write decrypted data
            writer.write_all(&plaintext)?;

            self.bytes_written += plaintext.len() as u64;
            self.current_chunk += 1;
        }

        // Verify we've written the expected amount
        if self.bytes_written != self.header.original_size {
            return Err(CryptorError::InvalidFormat);
        }

        Ok(())
    }

    /// Decrypts the file using parallel processing for better performance.
    ///
    /// This method processes multiple chunks concurrently using a thread pool,
    /// which can significantly improve performance on multi-core systems.
    ///
    /// # Arguments
    ///
    /// * `writer` - Output writer for the decrypted file
    /// * `batch_size` - Number of chunks to process in parallel (default: number of CPU cores)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Reading from input fails
    /// - Chunk format is invalid
    /// - Decryption or authentication fails
    /// - Writing to output fails
    ///
    /// # Performance
    ///
    /// Parallel decryption can achieve 2-4x speedup on modern multi-core CPUs.
    pub fn decrypt_to_parallel<W: Write>(
        &mut self,
        writer: &mut W,
        batch_size: Option<usize>,
    ) -> Result<()> {
        let batch_size = batch_size.unwrap_or_else(|| rayon::current_num_threads());
        let compressed = self.header.compressed;

        // Process chunks in batches
        while self.current_chunk < self.header.total_chunks {
            let chunks_remaining = self.header.total_chunks - self.current_chunk;
            let current_batch_size = std::cmp::min(batch_size as u64, chunks_remaining) as usize;

            // Read batch of encrypted chunks
            let mut encrypted_chunks = Vec::with_capacity(current_batch_size);

            for _ in 0..current_batch_size {
                // Read chunk header: index (u64) + size (u32)
                let mut chunk_index_bytes = [0u8; 8];
                self.reader.read_exact(&mut chunk_index_bytes)?;
                let chunk_index = u64::from_le_bytes(chunk_index_bytes);

                let mut chunk_size_bytes = [0u8; 4];
                self.reader.read_exact(&mut chunk_size_bytes)?;
                let chunk_size = u32::from_le_bytes(chunk_size_bytes);

                // Verify chunk index matches expected
                if chunk_index != self.current_chunk {
                    return Err(CryptorError::InvalidFormat);
                }

                // Read encrypted chunk data
                let mut ciphertext = vec![0u8; chunk_size as usize];
                self.reader.read_exact(&mut ciphertext)?;

                encrypted_chunks.push((chunk_index, ciphertext));
                self.current_chunk += 1;
            }

            // Decrypt batch in parallel
            let results: Vec<_> = encrypted_chunks
                .par_iter()
                .map(|(chunk_index, ciphertext)| {
                    // Derive chunk nonce
                    let chunk_nonce = derive_chunk_nonce(&self.header.base_nonce, *chunk_index);

                    // Decrypt chunk
                    let decrypted = self.encryptor.decrypt(&self.key, &chunk_nonce, ciphertext)?;

                    // Optionally decompress chunk data
                    let plaintext = if compressed {
                        Self::decompress_data(&decrypted)?
                    } else {
                        decrypted
                    };

                    Ok::<_, CryptorError>(plaintext)
                })
                .collect();

            // Write results in order
            for result in results {
                let plaintext = result?;
                writer.write_all(&plaintext)?;
                self.bytes_written += plaintext.len() as u64;
            }
        }

        // Verify we've written the expected amount
        if self.bytes_written != self.header.original_size {
            return Err(CryptorError::InvalidFormat);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_config_validation() {
        assert!(StreamConfig::new(1024).is_err()); // Too small
        assert!(StreamConfig::new(MIN_CHUNK_SIZE).is_ok());
        assert!(StreamConfig::new(DEFAULT_CHUNK_SIZE).is_ok());
        assert!(StreamConfig::new(MAX_CHUNK_SIZE).is_ok());
        assert!(StreamConfig::new(20 * 1024 * 1024).is_err()); // Too large
    }

    #[test]
    fn test_derive_chunk_nonce_uniqueness() {
        let base_nonce = [1u8; NONCE_LEN];

        let nonce0 = derive_chunk_nonce(&base_nonce, 0);
        let nonce1 = derive_chunk_nonce(&base_nonce, 1);
        let nonce2 = derive_chunk_nonce(&base_nonce, 2);

        assert_ne!(nonce0, nonce1);
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce0, nonce2);
    }

    #[test]
    fn test_derive_chunk_nonce_deterministic() {
        let base_nonce = [42u8; NONCE_LEN];

        let nonce1_a = derive_chunk_nonce(&base_nonce, 100);
        let nonce1_b = derive_chunk_nonce(&base_nonce, 100);

        assert_eq!(nonce1_a, nonce1_b);
    }

    #[test]
    fn test_calculate_chunks() {
        assert_eq!(StreamHeader::calculate_chunks(0, 1024), 0);
        assert_eq!(StreamHeader::calculate_chunks(1024, 1024), 1);
        assert_eq!(StreamHeader::calculate_chunks(1025, 1024), 2);
        assert_eq!(StreamHeader::calculate_chunks(2048, 1024), 2);
        assert_eq!(StreamHeader::calculate_chunks(2049, 1024), 3);
    }

    #[test]
    fn test_stream_header_roundtrip() {
        let header = StreamHeader {
            salt: "test_salt_string".to_string(),
            base_nonce: [42u8; NONCE_LEN],
            chunk_size: 1024 * 1024,
            total_chunks: 100,
            original_size: 100 * 1024 * 1024,
            compressed: true,
            metadata: Some("{\"compressed\":true}".to_string()),
        };

        let mut buffer = Vec::new();
        header.write_to(&mut buffer).unwrap();

        let mut cursor = std::io::Cursor::new(buffer);
        let decoded = StreamHeader::read_from(&mut cursor).unwrap();

        assert_eq!(header.salt, decoded.salt);
        assert_eq!(header.base_nonce, decoded.base_nonce);
        assert_eq!(header.chunk_size, decoded.chunk_size);
        assert_eq!(header.total_chunks, decoded.total_chunks);
        assert_eq!(header.original_size, decoded.original_size);
        assert_eq!(header.compressed, decoded.compressed);
        assert_eq!(header.metadata, decoded.metadata);
    }

    #[test]
    fn test_config_presets() {
        let fast = StreamConfig::fast();
        assert_eq!(fast.chunk_size, 4 * 1024 * 1024);
        assert!(!fast.compress);

        let low_mem = StreamConfig::low_memory();
        assert_eq!(low_mem.chunk_size, 64 * 1024);
        assert!(low_mem.compress);
    }

    #[test]
    fn test_chunked_reader_basic() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a test file with known content
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = vec![42u8; 40960]; // 40KB of data
        temp_file.write_all(&test_data).unwrap();
        temp_file.flush().unwrap();

        // Read it in chunks
        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap(); // 4KB chunks
        let mut reader = ChunkedReader::open(temp_file.path(), config).unwrap();

        assert_eq!(reader.total_size(), 40960);
        assert_eq!(reader.total_chunks(), 10); // 40KB / 4KB = 10 chunks
        assert_eq!(reader.bytes_read(), 0);
        assert_eq!(reader.current_chunk(), 0);

        // Read all chunks
        let mut chunks_read = 0;
        while let Some(chunk) = reader.next_chunk().unwrap() {
            chunks_read += 1;
            assert_eq!(chunk.index as usize, chunks_read - 1);
            assert_eq!(chunk.data.len(), MIN_CHUNK_SIZE);
            assert!(chunk.data.iter().all(|&b| b == 42));
        }

        assert_eq!(chunks_read, 10);
        assert_eq!(reader.bytes_read(), 40960);
        assert_eq!(reader.progress(), 1.0);
    }

    #[test]
    fn test_chunked_reader_partial_last_chunk() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a file that doesn't divide evenly (10KB)
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = vec![1u8; 10240]; // 10KB
        temp_file.write_all(&test_data).unwrap();
        temp_file.flush().unwrap();

        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap(); // 4KB chunks
        let mut reader = ChunkedReader::open(temp_file.path(), config).unwrap();

        assert_eq!(reader.total_chunks(), 3); // ceil(10240 / 4096) = 3

        // First chunk: 4096 bytes
        let chunk1 = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk1.data.len(), MIN_CHUNK_SIZE);
        assert!(!chunk1.is_last);

        // Second chunk: 4096 bytes
        let chunk2 = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk2.data.len(), MIN_CHUNK_SIZE);
        assert!(!chunk2.is_last);

        // Last chunk: 2048 bytes (10240 - 8192)
        let chunk3 = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk3.data.len(), 2048);
        assert!(chunk3.is_last);

        // No more chunks
        assert!(reader.next_chunk().unwrap().is_none());
    }

    #[test]
    fn test_chunked_reader_seek() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = vec![99u8; 20480]; // 20KB
        temp_file.write_all(&test_data).unwrap();
        temp_file.flush().unwrap();

        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap(); // 4KB chunks
        let mut reader = ChunkedReader::open(temp_file.path(), config).unwrap();

        // Seek to chunk 2
        reader.seek_to_chunk(2).unwrap();
        assert_eq!(reader.current_chunk(), 2);
        assert_eq!(reader.bytes_read(), 2 * MIN_CHUNK_SIZE as u64);

        let chunk = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk.index, 2);

        // Reset to beginning
        reader.reset().unwrap();
        assert_eq!(reader.current_chunk(), 0);
        assert_eq!(reader.bytes_read(), 0);

        let chunk = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk.index, 0);
    }

    #[test]
    fn test_chunked_reader_iterator() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = vec![5u8; 12288]; // 12KB
        temp_file.write_all(&test_data).unwrap();
        temp_file.flush().unwrap();

        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap(); // 4KB chunks
        let reader = ChunkedReader::open(temp_file.path(), config).unwrap();

        let chunks: Vec<_> = reader.collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].index, 0);
        assert_eq!(chunks[1].index, 1);
        assert_eq!(chunks[2].index, 2);
    }

    #[test]
    fn test_chunked_reader_progress() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = vec![0u8; 20480]; // 20KB
        temp_file.write_all(&test_data).unwrap();
        temp_file.flush().unwrap();

        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap(); // 4KB chunks
        let mut reader = ChunkedReader::open(temp_file.path(), config).unwrap();

        assert_eq!(reader.progress(), 0.0);

        reader.next_chunk().unwrap(); // Read 4096 bytes
        assert!((reader.progress() - 0.2).abs() < 0.01);

        reader.next_chunk().unwrap(); // Read another 4096 bytes
        assert!((reader.progress() - 0.4).abs() < 0.01);
    }

    #[test]
    fn test_chunked_encryptor_basic() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Create test file
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![42u8; 20480]; // 20KB
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        // Set up encryption
        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([1u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);
        let salt = "test_salt_string".to_string();

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key,
            base_nonce,
            salt.clone(),
        );

        // Encrypt to buffer
        let mut output = Vec::new();
        encryptor.encrypt_to(&mut output).unwrap();

        // Verify header is present
        assert!(output.starts_with(MAGIC_BYTES_V2));
        assert!(output.len() > test_data.len()); // Encrypted data should be larger
    }

    #[test]
    fn test_chunked_encryptor_with_metadata() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![1u8; 8192]; // 8KB
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let config = StreamConfig::default();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([5u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let metadata = r#"{"filename":"test.dat","timestamp":1234567890}"#.to_string();

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key,
            base_nonce,
            "salt123".to_string(),
        )
        .with_metadata(metadata.clone());

        let mut output = Vec::new();
        encryptor.encrypt_to(&mut output).unwrap();

        // Read header back and verify metadata
        let mut cursor = std::io::Cursor::new(output);
        let header = StreamHeader::read_from(&mut cursor).unwrap();
        assert_eq!(header.metadata, Some(metadata));
    }

    #[test]
    fn test_chunked_encryptor_multiple_chunks() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Create file with exactly 3 chunks worth of data
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![7u8; MIN_CHUNK_SIZE * 3]; // 3 full chunks
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([9u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key,
            base_nonce,
            "salt_abc".to_string(),
        );

        let mut output = Vec::new();
        encryptor.encrypt_to(&mut output).unwrap();

        // Read and verify header
        let mut cursor = std::io::Cursor::new(&output);
        let header = StreamHeader::read_from(&mut cursor).unwrap();
        assert_eq!(header.total_chunks, 3);
        assert_eq!(header.original_size, (MIN_CHUNK_SIZE * 3) as u64);
        assert_eq!(header.chunk_size, MIN_CHUNK_SIZE as u32);
    }

    #[test]
    fn test_chunked_encryptor_partial_last_chunk() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Create file that doesn't divide evenly
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![3u8; MIN_CHUNK_SIZE * 2 + 1024]; // 2.25 chunks
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([11u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key,
            base_nonce,
            "salt_xyz".to_string(),
        );

        let mut output = Vec::new();
        encryptor.encrypt_to(&mut output).unwrap();

        // Verify header shows correct total chunks (should be 3)
        let mut cursor = std::io::Cursor::new(&output);
        let header = StreamHeader::read_from(&mut cursor).unwrap();
        assert_eq!(header.total_chunks, 3);
        assert_eq!(header.original_size, (MIN_CHUNK_SIZE * 2 + 1024) as u64);
    }

    #[test]
    fn test_chunked_encryptor_empty_file() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Create empty file
        let input_file = NamedTempFile::new().unwrap();

        let config = StreamConfig::default();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([13u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key,
            base_nonce,
            "salt_empty".to_string(),
        );

        let mut output = Vec::new();
        encryptor.encrypt_to(&mut output).unwrap();

        // Verify header
        let mut cursor = std::io::Cursor::new(&output);
        let header = StreamHeader::read_from(&mut cursor).unwrap();
        assert_eq!(header.total_chunks, 0);
        assert_eq!(header.original_size, 0);
    }

    #[test]
    fn test_chunked_encryptor_single_chunk() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Create file smaller than one chunk
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![99u8; 1024]; // 1KB (less than MIN_CHUNK_SIZE)
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([17u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key,
            base_nonce,
            "salt_single".to_string(),
        );

        let mut output = Vec::new();
        encryptor.encrypt_to(&mut output).unwrap();

        // Verify header
        let mut cursor = std::io::Cursor::new(&output);
        let header = StreamHeader::read_from(&mut cursor).unwrap();
        assert_eq!(header.total_chunks, 1);
        assert_eq!(header.original_size, 1024);
    }

    #[test]
    fn test_chunked_decryptor_basic() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Create and encrypt test file
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![42u8; 20480]; // 20KB
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([1u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);
        let salt = "test_salt".to_string();

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            salt,
        );

        let mut encrypted = Vec::new();
        encryptor.encrypt_to(&mut encrypted).unwrap();

        // Decrypt
        let cursor = std::io::Cursor::new(encrypted);
        let mut decryptor = ChunkedDecryptor::new(
            cursor,
            Box::new(AesGcmEncryptor::new()),
            key,
        ).unwrap();

        let mut decrypted = Vec::new();
        decryptor.decrypt_to(&mut decrypted).unwrap();

        // Verify
        assert_eq!(decrypted, test_data);
        assert_eq!(decryptor.bytes_written(), 20480);
        assert_eq!(decryptor.progress(), 1.0);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Test with multiple chunks
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![7u8; MIN_CHUNK_SIZE * 5 + 2048]; // 5.5 chunks
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([99u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "salt_roundtrip".to_string(),
        );

        let mut encrypted = Vec::new();
        encryptor.encrypt_to(&mut encrypted).unwrap();

        // Decrypt
        let cursor = std::io::Cursor::new(encrypted);
        let mut decryptor = ChunkedDecryptor::new(
            cursor,
            Box::new(AesGcmEncryptor::new()),
            key,
        ).unwrap();

        assert_eq!(decryptor.header().total_chunks, 6);
        assert_eq!(decryptor.header().original_size, test_data.len() as u64);

        let mut decrypted = Vec::new();
        decryptor.decrypt_to(&mut decrypted).unwrap();

        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_decrypt_with_metadata() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![3u8; 8192];
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let config = StreamConfig::default();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([55u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let metadata = r#"{"filename":"test.bin","timestamp":9876543210}"#.to_string();

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "salt_meta".to_string(),
        ).with_metadata(metadata.clone());

        let mut encrypted = Vec::new();
        encryptor.encrypt_to(&mut encrypted).unwrap();

        // Decrypt and verify metadata
        let cursor = std::io::Cursor::new(encrypted);
        let mut decryptor = ChunkedDecryptor::new(
            cursor,
            Box::new(AesGcmEncryptor::new()),
            key,
        ).unwrap();

        assert_eq!(decryptor.header().metadata, Some(metadata));

        let mut decrypted = Vec::new();
        decryptor.decrypt_to(&mut decrypted).unwrap();
        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![11u8; 8192];
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let config = StreamConfig::default();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([22u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key,
            base_nonce,
            "salt_wrong".to_string(),
        );

        let mut encrypted = Vec::new();
        encryptor.encrypt_to(&mut encrypted).unwrap();

        // Try to decrypt with wrong key
        let wrong_key = Zeroizing::new([33u8; 32]);
        let cursor = std::io::Cursor::new(encrypted);
        let mut decryptor = ChunkedDecryptor::new(
            cursor,
            Box::new(AesGcmEncryptor::new()),
            wrong_key,
        ).unwrap();

        let mut decrypted = Vec::new();
        let result = decryptor.decrypt_to(&mut decrypted);

        // Should fail due to authentication error
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_empty_file() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        let input_file = NamedTempFile::new().unwrap();

        let config = StreamConfig::default();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([44u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "salt_empty".to_string(),
        );

        let mut encrypted = Vec::new();
        encryptor.encrypt_to(&mut encrypted).unwrap();

        // Decrypt
        let cursor = std::io::Cursor::new(encrypted);
        let mut decryptor = ChunkedDecryptor::new(
            cursor,
            Box::new(AesGcmEncryptor::new()),
            key,
        ).unwrap();

        assert_eq!(decryptor.header().total_chunks, 0);
        assert_eq!(decryptor.header().original_size, 0);

        let mut decrypted = Vec::new();
        decryptor.decrypt_to(&mut decrypted).unwrap();

        assert_eq!(decrypted.len(), 0);
        assert_eq!(decryptor.progress(), 1.0);
    }

    #[test]
    fn test_decrypt_progress_tracking() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![88u8; MIN_CHUNK_SIZE * 4]; // Exactly 4 chunks
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([66u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "salt_progress".to_string(),
        );

        let mut encrypted = Vec::new();
        encryptor.encrypt_to(&mut encrypted).unwrap();

        // Decrypt
        let cursor = std::io::Cursor::new(encrypted);
        let mut decryptor = ChunkedDecryptor::new(
            cursor,
            Box::new(AesGcmEncryptor::new()),
            key,
        ).unwrap();

        assert_eq!(decryptor.progress(), 0.0);
        assert_eq!(decryptor.current_chunk(), 0);

        let mut decrypted = Vec::new();
        decryptor.decrypt_to(&mut decrypted).unwrap();

        assert_eq!(decrypted, test_data);
        assert_eq!(decryptor.progress(), 1.0);
        assert_eq!(decryptor.current_chunk(), 4);
        assert_eq!(decryptor.bytes_written(), test_data.len() as u64);
    }

    #[test]
    fn test_parallel_encryption() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Create test file with multiple chunks
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![55u8; MIN_CHUNK_SIZE * 8]; // 8 chunks
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([77u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key,
            base_nonce,
            "salt_parallel".to_string(),
        );

        let mut output = Vec::new();
        encryptor.encrypt_to_parallel(&mut output, Some(4)).unwrap();

        // Verify header is present
        assert!(output.starts_with(MAGIC_BYTES_V2));
        assert!(output.len() > test_data.len());
    }

    #[test]
    fn test_parallel_decryption() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Encrypt data first
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![88u8; MIN_CHUNK_SIZE * 8]; // 8 chunks
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([99u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "salt_par_dec".to_string(),
        );

        let mut encrypted = Vec::new();
        encryptor.encrypt_to(&mut encrypted).unwrap();

        // Decrypt in parallel
        let cursor = std::io::Cursor::new(encrypted);
        let mut decryptor = ChunkedDecryptor::new(
            cursor,
            Box::new(AesGcmEncryptor::new()),
            key,
        ).unwrap();

        let mut decrypted = Vec::new();
        decryptor.decrypt_to_parallel(&mut decrypted, Some(4)).unwrap();

        // Verify
        assert_eq!(decrypted, test_data);
        assert_eq!(decryptor.bytes_written(), test_data.len() as u64);
    }

    #[test]
    fn test_parallel_roundtrip() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Create large file for parallel processing
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![123u8; MIN_CHUNK_SIZE * 16]; // 16 chunks
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([200u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        // Parallel encryption
        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "salt_par_round".to_string(),
        );

        let mut encrypted = Vec::new();
        encryptor.encrypt_to_parallel(&mut encrypted, None).unwrap();

        // Parallel decryption
        let cursor = std::io::Cursor::new(encrypted);
        let mut decryptor = ChunkedDecryptor::new(
            cursor,
            Box::new(AesGcmEncryptor::new()),
            key,
        ).unwrap();

        let mut decrypted = Vec::new();
        decryptor.decrypt_to_parallel(&mut decrypted, None).unwrap();

        // Verify roundtrip
        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_parallel_vs_sequential_same_output() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Create test file
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![42u8; MIN_CHUNK_SIZE * 6]; // 6 chunks
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let key = Zeroizing::new([111u8; 32]);
        let base_nonce = [222u8; NONCE_LEN];

        // Sequential encryption
        let config1 = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let reader1 = ChunkedReader::open(input_file.path(), config1).unwrap();
        let encryptor1 = ChunkedEncryptor::new(
            reader1,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "salt_compare".to_string(),
        );

        let mut encrypted_sequential = Vec::new();
        encryptor1.encrypt_to(&mut encrypted_sequential).unwrap();

        // Parallel encryption
        let config2 = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let reader2 = ChunkedReader::open(input_file.path(), config2).unwrap();
        let encryptor2 = ChunkedEncryptor::new(
            reader2,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "salt_compare".to_string(),
        );

        let mut encrypted_parallel = Vec::new();
        encryptor2.encrypt_to_parallel(&mut encrypted_parallel, Some(3)).unwrap();

        // Both should produce identical output
        assert_eq!(encrypted_sequential, encrypted_parallel);
    }

    #[test]
    fn test_compression_roundtrip() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Create test file with highly compressible data
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![0u8; MIN_CHUNK_SIZE * 3]; // 3 chunks of zeros
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        // Encrypt with compression
        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap().with_compression(true);
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([123u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "salt_compress".to_string(),
        );

        let mut encrypted = Vec::new();
        encryptor.encrypt_to(&mut encrypted).unwrap();

        // Decrypt
        let cursor = std::io::Cursor::new(encrypted);
        let mut decryptor = ChunkedDecryptor::new(
            cursor,
            Box::new(AesGcmEncryptor::new()),
            key,
        ).unwrap();

        assert!(decryptor.header().compressed);

        let mut decrypted = Vec::new();
        decryptor.decrypt_to(&mut decrypted).unwrap();

        // Verify data matches
        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_compression_reduces_size() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Create test file with highly compressible data
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![0u8; MIN_CHUNK_SIZE * 2]; // 2 chunks of zeros
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        let key = Zeroizing::new([99u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        // Encrypt WITHOUT compression
        let config1 = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let reader1 = ChunkedReader::open(input_file.path(), config1).unwrap();
        let encryptor1 = ChunkedEncryptor::new(
            reader1,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "salt_no_compress".to_string(),
        );

        let mut encrypted_without_compression = Vec::new();
        encryptor1.encrypt_to(&mut encrypted_without_compression).unwrap();

        // Encrypt WITH compression
        let config2 = StreamConfig::new(MIN_CHUNK_SIZE).unwrap().with_compression(true);
        let reader2 = ChunkedReader::open(input_file.path(), config2).unwrap();
        let encryptor2 = ChunkedEncryptor::new(
            reader2,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "salt_compress".to_string(),
        );

        let mut encrypted_with_compression = Vec::new();
        encryptor2.encrypt_to(&mut encrypted_with_compression).unwrap();

        // Compressed version should be significantly smaller for zeros
        println!(
            "Without compression: {} bytes, With compression: {} bytes",
            encrypted_without_compression.len(),
            encrypted_with_compression.len()
        );
        assert!(encrypted_with_compression.len() < encrypted_without_compression.len());
    }

    #[test]
    fn test_compression_with_incompressible_data() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Create test file with random (incompressible) data
        let mut input_file = NamedTempFile::new().unwrap();
        let mut test_data = vec![0u8; MIN_CHUNK_SIZE * 2];
        OsRng.fill_bytes(&mut test_data);
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        // Encrypt with compression (should still work, even if not beneficial)
        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap().with_compression(true);
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([55u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "salt_random".to_string(),
        );

        let mut encrypted = Vec::new();
        encryptor.encrypt_to(&mut encrypted).unwrap();

        // Decrypt
        let cursor = std::io::Cursor::new(encrypted);
        let mut decryptor = ChunkedDecryptor::new(
            cursor,
            Box::new(AesGcmEncryptor::new()),
            key,
        ).unwrap();

        let mut decrypted = Vec::new();
        decryptor.decrypt_to(&mut decrypted).unwrap();

        // Verify data matches even with random data
        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_compression_parallel_roundtrip() {
        use crate::crypto::aes_gcm::AesGcmEncryptor;
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::io::Write;
        use tempfile::NamedTempFile;
        use zeroize::Zeroizing;

        // Create test file with compressible data
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = vec![42u8; MIN_CHUNK_SIZE * 8]; // 8 chunks of repeated data
        input_file.write_all(&test_data).unwrap();
        input_file.flush().unwrap();

        // Encrypt with compression (parallel)
        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap().with_compression(true);
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([200u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "salt_par_compress".to_string(),
        );

        let mut encrypted = Vec::new();
        encryptor.encrypt_to_parallel(&mut encrypted, None).unwrap();

        // Decrypt (parallel)
        let cursor = std::io::Cursor::new(encrypted);
        let mut decryptor = ChunkedDecryptor::new(
            cursor,
            Box::new(AesGcmEncryptor::new()),
            key,
        ).unwrap();

        assert!(decryptor.header().compressed);

        let mut decrypted = Vec::new();
        decryptor.decrypt_to_parallel(&mut decrypted, None).unwrap();

        // Verify data matches
        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_checkpoint_save_load() {
        use tempfile::NamedTempFile;
        use std::path::PathBuf;

        // Create a checkpoint
        let checkpoint = Checkpoint::new(
            PathBuf::from("/input/file.txt"),
            PathBuf::from("/output/file.enc"),
            50,
            100,
            5000000,
            10000000,
            CheckpointOperation::Encrypt,
        );

        assert_eq!(checkpoint.progress(), 0.5);

        // Save checkpoint
        let checkpoint_file = NamedTempFile::new().unwrap();
        checkpoint.save(checkpoint_file.path()).unwrap();

        // Load checkpoint
        let loaded = Checkpoint::load(checkpoint_file.path()).unwrap();

        assert_eq!(checkpoint.input_path, loaded.input_path);
        assert_eq!(checkpoint.output_path, loaded.output_path);
        assert_eq!(checkpoint.current_chunk, loaded.current_chunk);
        assert_eq!(checkpoint.total_chunks, loaded.total_chunks);
        assert_eq!(checkpoint.bytes_written, loaded.bytes_written);
        assert_eq!(checkpoint.original_size, loaded.original_size);
        assert_eq!(checkpoint.operation, loaded.operation);
        assert_eq!(checkpoint.timestamp, loaded.timestamp);
    }

    #[test]
    fn test_checkpoint_delete() {
        use tempfile::NamedTempFile;
        use std::path::PathBuf;

        let checkpoint = Checkpoint::new(
            PathBuf::from("/input/file.txt"),
            PathBuf::from("/output/file.enc"),
            0,
            10,
            0,
            1000,
            CheckpointOperation::Decrypt,
        );

        let checkpoint_file = NamedTempFile::new().unwrap();
        let checkpoint_path = checkpoint_file.path().to_path_buf();
        checkpoint.save(&checkpoint_path).unwrap();

        // Verify file exists
        assert!(checkpoint_path.exists());

        // Delete checkpoint
        Checkpoint::delete(&checkpoint_path).unwrap();

        // Verify file is deleted
        assert!(!checkpoint_path.exists());
    }

    #[test]
    fn test_checkpoint_operation_types() {
        use tempfile::NamedTempFile;
        use std::path::PathBuf;

        // Test encrypt operation
        let checkpoint_encrypt = Checkpoint::new(
            PathBuf::from("/input/file.txt"),
            PathBuf::from("/output/file.enc"),
            10,
            50,
            1000,
            5000,
            CheckpointOperation::Encrypt,
        );

        let file1 = NamedTempFile::new().unwrap();
        checkpoint_encrypt.save(file1.path()).unwrap();
        let loaded1 = Checkpoint::load(file1.path()).unwrap();
        assert_eq!(loaded1.operation, CheckpointOperation::Encrypt);

        // Test decrypt operation
        let checkpoint_decrypt = Checkpoint::new(
            PathBuf::from("/input/file.enc"),
            PathBuf::from("/output/file.txt"),
            20,
            50,
            2000,
            5000,
            CheckpointOperation::Decrypt,
        );

        let file2 = NamedTempFile::new().unwrap();
        checkpoint_decrypt.save(file2.path()).unwrap();
        let loaded2 = Checkpoint::load(file2.path()).unwrap();
        assert_eq!(loaded2.operation, CheckpointOperation::Decrypt);
    }

    #[test]
    fn test_chunked_reader_resume_from_checkpoint() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create test file
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = vec![42u8; MIN_CHUNK_SIZE * 5]; // 5 chunks
        temp_file.write_all(&test_data).unwrap();
        temp_file.flush().unwrap();

        // Read first 2 chunks
        let config = StreamConfig::new(MIN_CHUNK_SIZE).unwrap();
        let mut reader = ChunkedReader::open(temp_file.path(), config).unwrap();

        reader.next_chunk().unwrap(); // Chunk 0
        reader.next_chunk().unwrap(); // Chunk 1

        assert_eq!(reader.current_chunk(), 2);
        assert_eq!(reader.bytes_read(), (MIN_CHUNK_SIZE * 2) as u64);

        // Simulate resuming: seek to chunk 2
        reader.seek_to_chunk(2).unwrap();
        assert_eq!(reader.current_chunk(), 2);

        // Continue reading from chunk 2
        let chunk2 = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk2.index, 2);

        let chunk3 = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk3.index, 3);

        let chunk4 = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk4.index, 4);
        assert!(chunk4.is_last);

        // No more chunks
        assert!(reader.next_chunk().unwrap().is_none());
    }
}

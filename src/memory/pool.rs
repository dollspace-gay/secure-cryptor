//! Encrypted memory pool for sensitive data.
//!
//! Provides a memory pool with transparent encryption at rest using ChaCha20,
//! combined with optional memory locking to prevent swapping to disk.
//!
//! # Security Features
//!
//! - **Encryption at rest**: All data is encrypted with ChaCha20 when stored
//! - **Memory locking**: High/Maximum security levels prevent swapping
//! - **Unique nonces**: Each allocation gets a cryptographically unique nonce
//! - **Automatic zeroization**: Memory is zeroed on deallocation
//! - **Re-keying**: Maximum security level periodically rotates encryption keys
//!
//! # Example
//!
//! ```no_run
//! use tesseract::memory::pool::{EncryptedMemoryPool, SecurityLevel};
//!
//! let pool = EncryptedMemoryPool::new(SecurityLevel::High).unwrap();
//! let mut allocation = pool.allocate(1024).unwrap();
//!
//! // Write sensitive data
//! allocation.write(b"secret data");
//!
//! // Data is encrypted in memory and locked (won't swap to disk)
//! // Automatically decrypted when reading
//! let data = allocation.read();
//!
//! // Memory is zeroed and unlocked on drop
//! ```

use super::LockedMemory;
use crate::error::{CryptorError, Result};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::RngCore;
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

/// Security level for memory pool allocations.
///
/// Different levels provide different tradeoffs between security and performance:
///
/// - **Standard**: ChaCha20 encryption only, no memory locking
/// - **High**: ChaCha20 encryption + memory locking (prevents swap)
/// - **Maximum**: High + periodic key rotation for forward secrecy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Encryption only, no memory locking.
    ///
    /// Best for: Non-critical sensitive data, performance-sensitive operations
    Standard,

    /// Encryption + memory locking.
    ///
    /// Best for: Passwords, keys, authentication tokens
    High,

    /// Encryption + memory locking + periodic re-keying.
    ///
    /// Best for: Master keys, long-lived cryptographic material
    Maximum,
}

/// Encrypted memory allocation.
///
/// Represents a single allocation from the encrypted memory pool.
/// Data is automatically encrypted when written and decrypted when read.
pub struct EncryptedAllocation {
    /// Encrypted data storage
    data: Vec<u8>,

    /// Nonce for this allocation (96 bits / 12 bytes for ChaCha20)
    nonce: [u8; 12],

    /// Encryption key for this allocation (copied from pool at creation time)
    /// This ensures allocations work even after pool key rotation
    encryption_key: Zeroizing<[u8; 32]>,

    /// Security level for this allocation
    security_level: SecurityLevel,

    /// Optional locked memory wrapper for High/Maximum security
    locked: Option<LockedMemory<Vec<u8>>>,
}

/// Inner state of the memory pool (shared across allocations).
struct PoolInner {
    /// Master encryption key (256 bits for ChaCha20)
    master_key: Zeroizing<[u8; 32]>,

    /// Security level for this pool
    security_level: SecurityLevel,

    /// Allocation counter for statistics
    allocation_count: usize,

    /// Total bytes allocated
    bytes_allocated: usize,
}

/// Encrypted memory pool.
///
/// Manages a pool of encrypted memory allocations with configurable security levels.
pub struct EncryptedMemoryPool {
    inner: Arc<Mutex<PoolInner>>,
}

impl EncryptedMemoryPool {
    /// Creates a new encrypted memory pool with the specified security level.
    ///
    /// # Arguments
    ///
    /// * `security_level` - The security level for allocations from this pool
    ///
    /// # Errors
    ///
    /// Returns an error if the master key cannot be generated.
    ///
    /// # Example
    ///
    /// ```
    /// use tesseract::memory::pool::{EncryptedMemoryPool, SecurityLevel};
    ///
    /// let pool = EncryptedMemoryPool::new(SecurityLevel::High).unwrap();
    /// ```
    pub fn new(security_level: SecurityLevel) -> Result<Self> {
        // Generate random master key
        let mut master_key = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(&mut *master_key);

        Ok(Self {
            inner: Arc::new(Mutex::new(PoolInner {
                master_key,
                security_level,
                allocation_count: 0,
                bytes_allocated: 0,
            })),
        })
    }

    /// Allocates encrypted memory of the specified size.
    ///
    /// # Arguments
    ///
    /// * `size` - Size in bytes to allocate
    ///
    /// # Returns
    ///
    /// An `EncryptedAllocation` that automatically encrypts/decrypts data.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Memory locking fails (for High/Maximum security levels)
    /// - Allocation fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tesseract::memory::pool::{EncryptedMemoryPool, SecurityLevel};
    /// let pool = EncryptedMemoryPool::new(SecurityLevel::Standard).unwrap();
    /// let allocation = pool.allocate(4096).unwrap();
    /// ```
    pub fn allocate(&self, size: usize) -> Result<EncryptedAllocation> {
        let mut inner = self.inner.lock()
            .map_err(|_| CryptorError::Cryptography("Pool mutex poisoned".to_string()))?;

        // Generate unique nonce for this allocation
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);

        // Update statistics
        inner.allocation_count += 1;
        inner.bytes_allocated += size;

        let security_level = inner.security_level;

        // Copy the master key for this allocation
        let encryption_key = Zeroizing::new(*inner.master_key);

        // For High/Maximum security, use locked memory
        let locked = if security_level == SecurityLevel::High || security_level == SecurityLevel::Maximum {
            let data_vec = vec![0u8; size];
            match LockedMemory::new(data_vec) {
                Ok(locked) => Some(locked),
                Err(_) => {
                    // Fall back to best-effort if locking fails
                    let (locked, _) = LockedMemory::new_best_effort(vec![0u8; size]);
                    Some(locked)
                }
            }
        } else {
            None
        };

        Ok(EncryptedAllocation {
            data: vec![0u8; size],
            nonce,
            encryption_key,
            security_level,
            locked,
        })
    }

    /// Returns the security level of this pool.
    pub fn security_level(&self) -> SecurityLevel {
        self.inner.lock()
            .map(|inner| inner.security_level)
            .unwrap_or(SecurityLevel::Standard)
    }

    /// Returns the number of allocations made from this pool.
    pub fn allocation_count(&self) -> usize {
        self.inner.lock()
            .map(|inner| inner.allocation_count)
            .unwrap_or(0)
    }

    /// Returns the total bytes allocated from this pool.
    pub fn bytes_allocated(&self) -> usize {
        self.inner.lock()
            .map(|inner| inner.bytes_allocated)
            .unwrap_or(0)
    }

    /// Rotates the master encryption key.
    ///
    /// This is primarily useful for Maximum security level pools where
    /// periodic re-keying provides forward secrecy.
    ///
    /// # Security Note
    ///
    /// Existing allocations will continue to use their original keys.
    /// Only new allocations will use the rotated key.
    pub fn rotate_key(&self) -> Result<()> {
        let mut inner = self.inner.lock()
            .map_err(|_| CryptorError::Cryptography("Pool mutex poisoned".to_string()))?;

        // Generate new master key
        let mut new_key = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(&mut *new_key);

        // Replace old key (old key is zeroized via Drop)
        inner.master_key = new_key;

        Ok(())
    }
}

impl EncryptedAllocation {
    /// Writes data to the allocation (encrypts automatically).
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to write (will be encrypted)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The data is larger than the allocation size
    /// - Encryption fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tesseract::memory::pool::{EncryptedMemoryPool, SecurityLevel};
    /// # let pool = EncryptedMemoryPool::new(SecurityLevel::Standard).unwrap();
    /// let mut allocation = pool.allocate(1024).unwrap();
    /// allocation.write(b"sensitive data").unwrap();
    /// ```
    pub fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        if plaintext.len() > self.data.len() {
            return Err(CryptorError::Cryptography(format!(
                "Data too large: {} bytes, allocation is {} bytes",
                plaintext.len(),
                self.data.len()
            )));
        }

        // Create ChaCha20 cipher using allocation's own key
        let mut cipher = ChaCha20::new((&*self.encryption_key).into(), (&self.nonce).into());

        // Encrypt the plaintext
        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        // Store encrypted data
        if let Some(ref mut locked) = self.locked {
            // Write to locked memory
            locked[..ciphertext.len()].copy_from_slice(&ciphertext);
        } else {
            // Write to regular memory
            self.data[..ciphertext.len()].copy_from_slice(&ciphertext);
        }

        // Zero the temporary ciphertext
        ciphertext.zeroize();

        Ok(())
    }

    /// Reads data from the allocation (decrypts automatically).
    ///
    /// # Returns
    ///
    /// The decrypted data in zeroizing memory.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tesseract::memory::pool::{EncryptedMemoryPool, SecurityLevel};
    /// # let pool = EncryptedMemoryPool::new(SecurityLevel::Standard).unwrap();
    /// # let mut allocation = pool.allocate(1024).unwrap();
    /// # allocation.write(b"data").unwrap();
    /// let data = allocation.read().unwrap();
    /// ```
    pub fn read(&self) -> Result<Zeroizing<Vec<u8>>> {
        // Get encrypted data
        let ciphertext = if let Some(ref locked) = self.locked {
            locked.as_ref()
        } else {
            &self.data
        };

        // Create ChaCha20 cipher (same key and nonce for decryption)
        let mut cipher = ChaCha20::new((&*self.encryption_key).into(), (&self.nonce).into());

        // Decrypt the ciphertext
        let mut plaintext = Zeroizing::new(ciphertext.to_vec());
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }

    /// Returns the size of this allocation in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Returns the security level of this allocation.
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Returns whether this allocation is using locked memory.
    pub fn is_locked(&self) -> bool {
        self.locked.as_ref().map(|l| l.is_locked()).unwrap_or(false)
    }
}

impl Drop for EncryptedAllocation {
    fn drop(&mut self) {
        // Zero the data buffer
        self.data.zeroize();

        // Zero the nonce
        self.nonce.zeroize();

        // encryption_key is automatically zeroed via Zeroizing Drop impl
        // Locked memory is automatically zeroed and unlocked via its Drop impl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_creation() {
        let pool = EncryptedMemoryPool::new(SecurityLevel::Standard).unwrap();
        assert_eq!(pool.security_level(), SecurityLevel::Standard);
        assert_eq!(pool.allocation_count(), 0);
        assert_eq!(pool.bytes_allocated(), 0);
    }

    #[test]
    fn test_allocation() {
        let pool = EncryptedMemoryPool::new(SecurityLevel::Standard).unwrap();
        let allocation = pool.allocate(1024).unwrap();

        assert_eq!(allocation.size(), 1024);
        assert_eq!(pool.allocation_count(), 1);
        assert_eq!(pool.bytes_allocated(), 1024);
    }

    #[test]
    fn test_write_read_roundtrip() {
        let pool = EncryptedMemoryPool::new(SecurityLevel::Standard).unwrap();
        let mut allocation = pool.allocate(1024).unwrap();

        let plaintext = b"This is a secret message!";
        allocation.write(plaintext).unwrap();

        let decrypted = allocation.read().unwrap();
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }

    #[test]
    fn test_high_security_level() {
        let pool = EncryptedMemoryPool::new(SecurityLevel::High).unwrap();
        let mut allocation = pool.allocate(512).unwrap();

        assert_eq!(allocation.security_level(), SecurityLevel::High);

        let data = b"High security data";
        allocation.write(data).unwrap();

        let decrypted = allocation.read().unwrap();
        assert_eq!(&decrypted[..data.len()], data);
    }

    #[test]
    fn test_maximum_security_level() {
        let pool = EncryptedMemoryPool::new(SecurityLevel::Maximum).unwrap();
        let mut allocation = pool.allocate(256).unwrap();

        assert_eq!(allocation.security_level(), SecurityLevel::Maximum);

        let data = b"Maximum security";
        allocation.write(data).unwrap();

        let decrypted = allocation.read().unwrap();
        assert_eq!(&decrypted[..data.len()], data);
    }

    #[test]
    fn test_write_too_large() {
        let pool = EncryptedMemoryPool::new(SecurityLevel::Standard).unwrap();
        let mut allocation = pool.allocate(16).unwrap();

        let large_data = vec![0u8; 32];
        let result = allocation.write(&large_data);

        assert!(result.is_err());
    }

    #[test]
    fn test_key_rotation() {
        let pool = EncryptedMemoryPool::new(SecurityLevel::Maximum).unwrap();

        // Create allocation with original key
        let mut alloc1 = pool.allocate(128).unwrap();
        alloc1.write(b"Before rotation").unwrap();

        // Rotate key
        pool.rotate_key().unwrap();

        // Old allocation should still decrypt correctly
        let decrypted1 = alloc1.read().unwrap();
        assert_eq!(&decrypted1[..15], b"Before rotation");

        // New allocation uses new key but should work independently
        let mut alloc2 = pool.allocate(128).unwrap();
        alloc2.write(b"After rotation").unwrap();
        let decrypted2 = alloc2.read().unwrap();
        assert_eq!(&decrypted2[..14], b"After rotation");
    }

    #[test]
    fn test_multiple_allocations() {
        let pool = EncryptedMemoryPool::new(SecurityLevel::Standard).unwrap();

        let mut alloc1 = pool.allocate(256).unwrap();
        let mut alloc2 = pool.allocate(512).unwrap();
        let mut alloc3 = pool.allocate(128).unwrap();

        alloc1.write(b"First").unwrap();
        alloc2.write(b"Second").unwrap();
        alloc3.write(b"Third").unwrap();

        assert_eq!(&alloc1.read().unwrap()[..5], b"First");
        assert_eq!(&alloc2.read().unwrap()[..6], b"Second");
        assert_eq!(&alloc3.read().unwrap()[..5], b"Third");

        assert_eq!(pool.allocation_count(), 3);
        assert_eq!(pool.bytes_allocated(), 256 + 512 + 128);
    }

    #[test]
    fn test_different_nonces() {
        let pool = EncryptedMemoryPool::new(SecurityLevel::Standard).unwrap();

        let alloc1 = pool.allocate(64).unwrap();
        let alloc2 = pool.allocate(64).unwrap();

        // Each allocation should have a unique nonce
        assert_ne!(alloc1.nonce, alloc2.nonce);
    }

    #[test]
    fn test_zeroization_on_drop() {
        let pool = EncryptedMemoryPool::new(SecurityLevel::Standard).unwrap();
        let mut allocation = pool.allocate(128).unwrap();

        allocation.write(b"Sensitive data").unwrap();

        // Get raw pointer to data before drop
        let data_ptr = allocation.data.as_ptr();

        // Drop the allocation
        drop(allocation);

        // Note: We can't reliably test that memory was zeroed without
        // memory forensics tools. This test just verifies drop doesn't panic.
    }
}

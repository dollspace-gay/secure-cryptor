//! Memory protection utilities for preventing sensitive data from being swapped to disk.
//!
//! This module provides cross-platform memory locking using:
//! - Linux/macOS: `mlock(2)` / `munlock(2)`
//! - Windows: `VirtualLock()` / `VirtualUnlock()`
//!
//! Memory locking prevents the OS from swapping sensitive data (keys, passwords, plaintext)
//! to disk, which could leave traces in swap files or hibernation images.
//!
//! Additionally, this module provides an encrypted memory pool for defense-in-depth
//! and advanced memory scrubbing utilities with multi-pass overwrite capabilities.

pub mod pool;
pub mod scrub;

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::ptr;
use zeroize::Zeroize;

#[cfg(unix)]
use libc::{mlock, munlock};

#[cfg(windows)]
use winapi::um::memoryapi::{VirtualLock, VirtualUnlock};

/// Errors that can occur during memory locking operations.
#[derive(Debug)]
pub enum MemLockError {
    /// The system does not allow locking this memory (permissions, limits, etc.)
    PermissionDenied,
    /// Insufficient resources to lock memory (hit ulimit)
    ResourceLimitExceeded,
    /// Other system error
    SystemError(String),
}

impl fmt::Display for MemLockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied => write!(f, "Permission denied to lock memory"),
            Self::ResourceLimitExceeded => write!(f, "Memory lock resource limit exceeded"),
            Self::SystemError(msg) => write!(f, "System error: {}", msg),
        }
    }
}

impl std::error::Error for MemLockError {}

/// A wrapper that locks memory pages to prevent swapping to disk.
///
/// This type ensures sensitive data remains in RAM and is never written to swap
/// or hibernation files. The memory is automatically unlocked and zeroed when dropped.
///
/// # Platform Support
///
/// - **Linux/macOS**: Uses `mlock(2)` to lock pages in RAM
/// - **Windows**: Uses `VirtualLock()` to lock pages in RAM
///
/// # Resource Limits
///
/// On Unix systems, `mlock()` may fail if:
/// - The process has insufficient privileges
/// - The `RLIMIT_MEMLOCK` resource limit is exceeded
/// - The system has insufficient lockable memory
///
/// # Example
///
/// ```
/// use secure_cryptor::memory::LockedMemory;
///
/// let secret = LockedMemory::new([0u8; 32])?;
/// // Memory is locked in RAM
/// // Automatically unlocked and zeroed on drop
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct LockedMemory<T: Zeroize> {
    data: T,
    locked: bool,
}

impl<T: Zeroize> LockedMemory<T> {
    /// Creates a new locked memory region containing the given data.
    ///
    /// # Errors
    ///
    /// Returns an error if the memory cannot be locked due to permissions,
    /// resource limits, or other system constraints.
    ///
    /// # Security Note
    ///
    /// If locking fails, this function returns an error rather than silently
    /// proceeding with unlocked memory. Callers should handle failures appropriately,
    /// either by aborting sensitive operations or warning the user.
    pub fn new(data: T) -> Result<Self, MemLockError> {
        let mut locked_mem = Self {
            data,
            locked: false,
        };

        locked_mem.lock()?;
        Ok(locked_mem)
    }

    /// Attempts to create locked memory, but doesn't fail if locking is unavailable.
    ///
    /// This is useful for systems where memory locking may not be available or
    /// when degraded security is acceptable.
    ///
    /// # Returns
    ///
    /// Returns a tuple of (LockedMemory, bool) where the bool indicates whether
    /// locking was successful.
    ///
    /// # Security Warning
    ///
    /// Using this function may result in unlocked memory if the system doesn't
    /// support or allow memory locking. Prefer `new()` when security is critical.
    pub fn new_best_effort(data: T) -> (Self, bool) {
        let mut locked_mem = Self {
            data,
            locked: false,
        };

        match locked_mem.lock() {
            Ok(()) => (locked_mem, true),
            Err(_) => (locked_mem, false),
        }
    }

    /// Locks the memory pages containing this data.
    fn lock(&mut self) -> Result<(), MemLockError> {
        let ptr = &self.data as *const T as *const u8;
        let len = std::mem::size_of::<T>();

        #[cfg(unix)]
        {
            // SAFETY: We're locking memory we own, and ptr/len are valid
            let result = unsafe { mlock(ptr as *const libc::c_void, len) };

            if result != 0 {
                let errno = std::io::Error::last_os_error();
                return Err(match errno.raw_os_error() {
                    Some(libc::EPERM) | Some(libc::EACCES) => MemLockError::PermissionDenied,
                    Some(libc::ENOMEM) | Some(libc::EAGAIN) => {
                        MemLockError::ResourceLimitExceeded
                    }
                    _ => MemLockError::SystemError(errno.to_string()),
                });
            }
        }

        #[cfg(windows)]
        {
            // SAFETY: We're locking memory we own, and ptr/len are valid
            let result = unsafe { VirtualLock(ptr as *mut winapi::ctypes::c_void, len) };

            if result == 0 {
                let error = std::io::Error::last_os_error();
                return Err(MemLockError::SystemError(error.to_string()));
            }
        }

        self.locked = true;
        Ok(())
    }

    /// Unlocks the memory pages.
    fn unlock(&mut self) {
        if !self.locked {
            return;
        }

        let ptr = &self.data as *const T as *const u8;
        let len = std::mem::size_of::<T>();

        #[cfg(unix)]
        {
            // SAFETY: We're unlocking memory we previously locked
            unsafe {
                munlock(ptr as *const libc::c_void, len);
            }
        }

        #[cfg(windows)]
        {
            // SAFETY: We're unlocking memory we previously locked
            unsafe {
                VirtualUnlock(ptr as *mut winapi::ctypes::c_void, len);
            }
        }

        self.locked = false;
    }

    /// Returns whether the memory is currently locked.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Consumes the locked memory and returns the inner value.
    ///
    /// The memory will be unlocked before returning.
    pub fn into_inner(mut self) -> T {
        self.unlock();
        let data = unsafe { ptr::read(&self.data) };
        std::mem::forget(self); // Don't run Drop
        data
    }
}

impl<T: Zeroize> Deref for LockedMemory<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: Zeroize> DerefMut for LockedMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: Zeroize> Drop for LockedMemory<T> {
    fn drop(&mut self) {
        // First zero the data
        self.data.zeroize();

        // Then unlock the memory
        self.unlock();
    }
}

// LockedMemory is automatically !Copy because T: Zeroize doesn't imply Copy,
// and we store T directly without wrapping it in a Copy-able container.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locked_memory_creation() {
        let data = [42u8; 32];
        let locked = LockedMemory::new(data);

        // May fail on systems with restrictive mlock limits
        match locked {
            Ok(mem) => {
                assert!(mem.is_locked());
                assert_eq!(*mem, [42u8; 32]);
            }
            Err(MemLockError::ResourceLimitExceeded) | Err(MemLockError::PermissionDenied) => {
                // Expected on systems with limited mlock permissions
                eprintln!("Warning: mlock not available, skipping test");
            }
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn test_best_effort_creation() {
        let data = [42u8; 32];
        let (locked, was_locked) = LockedMemory::new_best_effort(data);

        assert_eq!(*locked, [42u8; 32]);

        if was_locked {
            assert!(locked.is_locked());
        } else {
            assert!(!locked.is_locked());
        }
    }

    #[test]
    fn test_deref() {
        let data = [42u8; 32];
        let (locked, _) = LockedMemory::new_best_effort(data);

        // Test Deref
        assert_eq!(locked[0], 42);
        assert_eq!(locked.len(), 32);
    }

    #[test]
    fn test_deref_mut() {
        let data = [42u8; 32];
        let (mut locked, _) = LockedMemory::new_best_effort(data);

        // Test DerefMut
        locked[0] = 100;
        assert_eq!(locked[0], 100);
    }

    #[test]
    fn test_into_inner() {
        let data = [42u8; 32];
        let (locked, _) = LockedMemory::new_best_effort(data);

        let inner = locked.into_inner();
        assert_eq!(inner, [42u8; 32]);
    }

    #[test]
    fn test_drop_zeros_memory() {
        let data = [42u8; 32];
        let (locked, _) = LockedMemory::new_best_effort(data);

        // Drop the locked memory - this should zero the data and unlock
        drop(locked);

        // NOTE: In a real scenario, we can't reliably test zeroization without
        // memory forensics tools. This test just verifies that Drop completes
        // without panicking.
    }

    #[test]
    fn test_small_types() {
        // Test with various sizes
        let (mem_u32, _) = LockedMemory::new_best_effort(42u32);
        assert_eq!(*mem_u32, 42u32);

        let (mem_arr, _) = LockedMemory::new_best_effort([1u8, 2, 3, 4]);
        assert_eq!(*mem_arr, [1u8, 2, 3, 4]);
    }
}

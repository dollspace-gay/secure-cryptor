//! Guard pages for buffer overflow detection
//!
//! This module provides guard pages that surround allocated memory to detect
//! buffer overflows and underflows immediately via segmentation faults.
//!
//! # Architecture
//!
//! Guard pages work by allocating extra memory pages before and after the
//! actual data allocation, then marking those pages as inaccessible using
//! `mprotect` (Unix) or `VirtualProtect` (Windows). Any access to guard
//! pages triggers a segmentation fault.
//!
//! Layout:
//! ```text
//! ┌─────────────────┐
//! │  Guard Page     │ ← No access (PROT_NONE / PAGE_NOACCESS)
//! ├─────────────────┤
//! │  Canary (8B)    │ ← Random value for overflow detection
//! ├─────────────────┤
//! │  User Data      │ ← Actual allocation
//! ├─────────────────┤
//! │  Canary (8B)    │ ← Random value for overflow detection
//! ├─────────────────┤
//! │  Guard Page     │ ← No access (PROT_NONE / PAGE_NOACCESS)
//! └─────────────────┘
//! ```
//!
//! # Usage
//!
//! ```no_run
//! use tesseract::memory::guard::GuardedAllocation;
//!
//! // Allocate 1024 bytes with guard pages
//! let mut alloc = GuardedAllocation::new(1024).unwrap();
//!
//! // Write to the allocation
//! alloc.as_mut_slice()[0] = 42;
//!
//! // Verify canaries are intact
//! assert!(alloc.verify_canaries());
//!
//! // Any overflow will:
//! // 1. First corrupt a canary (detected on verify)
//! // 2. Then hit guard page (immediate segfault)
//! ```
//!
//! # Security
//!
//! - **Immediate Detection**: Overflows hitting guard pages cause instant segfault
//! - **Canary Protection**: Detects overflows that don't reach guard pages
//! - **Both Directions**: Protects against both overflow and underflow
//! - **Page Aligned**: Uses OS-level page protection for maximum security

use std::ptr::NonNull;
use thiserror::Error;
use zeroize::Zeroize;
use rand::Rng;

#[cfg(unix)]
use libc::{mprotect, mmap, munmap, PROT_NONE, PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS};

#[cfg(windows)]
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect};
#[cfg(windows)]
use winapi::um::winnt::{PAGE_NOACCESS, PAGE_READWRITE, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE};

/// Errors that can occur with guarded allocations
#[derive(Debug, Error)]
pub enum GuardError {
    /// Failed to allocate memory
    #[error("Allocation failed")]
    AllocationFailed,

    /// Failed to protect guard pages
    #[error("Failed to protect guard pages: {0}")]
    ProtectionFailed(String),

    /// Canary value was corrupted (buffer overflow detected)
    #[error("Buffer overflow detected: canary corrupted at {0}")]
    CanaryCorrupted(String),

    /// Invalid size (too small or not aligned)
    #[error("Invalid allocation size: {0}")]
    InvalidSize(String),
}

/// Result type for guard operations
pub type Result<T> = std::result::Result<T, GuardError>;

/// Size of a memory page (typically 4096 bytes)
const PAGE_SIZE: usize = 4096;

/// Size of canary values in bytes
const CANARY_SIZE: usize = 8;

/// A guarded memory allocation with overflow/underflow detection
///
/// This structure wraps a memory allocation with:
/// - Guard pages before and after (no-access)
/// - Canary values for additional protection
/// - Automatic cleanup on drop
pub struct GuardedAllocation {
    /// Pointer to the start of the entire allocation (including guard pages)
    base_ptr: NonNull<u8>,
    /// Total size of the allocation (including guard pages)
    total_size: usize,
    /// Pointer to the usable data region
    data_ptr: NonNull<u8>,
    /// Size of the usable data region
    data_size: usize,
    /// Front canary value
    front_canary: u64,
    /// Back canary value
    back_canary: u64,
}

impl GuardedAllocation {
    /// Create a new guarded allocation
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the data region in bytes
    ///
    /// # Returns
    ///
    /// A new guarded allocation with guard pages and canaries
    ///
    /// # Errors
    ///
    /// Returns error if allocation or protection fails
    pub fn new(size: usize) -> Result<Self> {
        if size == 0 {
            return Err(GuardError::InvalidSize("Size cannot be zero".to_string()));
        }

        // Calculate data region size (data + canaries), rounded up to page boundary
        let data_region_size = CANARY_SIZE + size + CANARY_SIZE;
        let data_region_pages = data_region_size.div_ceil(PAGE_SIZE);
        let data_region_aligned = data_region_pages * PAGE_SIZE;

        // Calculate total size: front guard page + data region (page-aligned) + back guard page
        let total_size = PAGE_SIZE + data_region_aligned + PAGE_SIZE;

        // Allocate memory using platform-specific APIs
        let base_ptr = Self::allocate_pages(total_size)?;

        // Generate random canary values
        let front_canary = rand::rng().random::<u64>();
        let back_canary = rand::rng().random::<u64>();

        // Calculate data pointer (after front guard page and canary)
        let data_ptr = unsafe {
            NonNull::new_unchecked(base_ptr.as_ptr().add(PAGE_SIZE + CANARY_SIZE))
        };

        // Write canaries
        unsafe {
            // Front canary (after front guard page)
            let front_canary_ptr = base_ptr.as_ptr().add(PAGE_SIZE) as *mut u64;
            *front_canary_ptr = front_canary;

            // Back canary (after data)
            let back_canary_ptr = data_ptr.as_ptr().add(size) as *mut u64;
            *back_canary_ptr = back_canary;
        }

        let mut allocation = Self {
            base_ptr,
            total_size,
            data_ptr,
            data_size: size,
            front_canary,
            back_canary,
        };

        // Protect guard pages
        allocation.protect_guard_pages()?;

        Ok(allocation)
    }

    /// Allocate memory pages using platform-specific APIs
    ///
    /// # Safety
    ///
    /// Returns page-aligned memory that can be used with mprotect/VirtualProtect
    fn allocate_pages(size: usize) -> Result<NonNull<u8>> {
        unsafe {
            #[cfg(unix)]
            {
                let ptr = mmap(
                    std::ptr::null_mut(),
                    size,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if ptr == libc::MAP_FAILED {
                    return Err(GuardError::AllocationFailed);
                }
                Ok(NonNull::new_unchecked(ptr as *mut u8))
            }

            #[cfg(windows)]
            {
                let ptr = VirtualAlloc(
                    std::ptr::null_mut(),
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );
                if ptr.is_null() {
                    return Err(GuardError::AllocationFailed);
                }
                Ok(NonNull::new_unchecked(ptr as *mut u8))
            }

            #[cfg(not(any(unix, windows)))]
            {
                Err(GuardError::AllocationFailed)
            }
        }
    }

    /// Deallocate memory pages using platform-specific APIs
    ///
    /// # Safety
    ///
    /// - `ptr` must have been allocated with `allocate_pages`
    /// - `size` must match the size used during allocation
    unsafe fn deallocate_pages(ptr: NonNull<u8>, _size: usize) {
        #[cfg(unix)]
        {
            munmap(ptr.as_ptr() as *mut _, _size);
        }

        #[cfg(windows)]
        {
            VirtualFree(ptr.as_ptr() as *mut _, 0, MEM_RELEASE);
        }

        #[cfg(not(any(unix, windows)))]
        {
            // No-op on unsupported platforms
            let _ = (ptr, _size);
        }
    }

    /// Protect the guard pages (mark as no-access)
    fn protect_guard_pages(&mut self) -> Result<()> {
        unsafe {
            // Front guard page
            Self::protect_page(self.base_ptr.as_ptr(), false)?;

            // Back guard page (at offset: total_size - PAGE_SIZE)
            let back_guard_ptr = self.base_ptr.as_ptr()
                .add(self.total_size - PAGE_SIZE);
            Self::protect_page(back_guard_ptr, false)?;
        }

        Ok(())
    }

    /// Protect or unprotect a single page
    ///
    /// # Safety
    ///
    /// - `ptr` must point to the start of an allocated page
    /// - `allow_access` determines whether to allow (true) or deny (false) access
    #[cfg(unix)]
    unsafe fn protect_page(ptr: *mut u8, allow_access: bool) -> Result<()> {
        let prot = if allow_access {
            PROT_READ | PROT_WRITE
        } else {
            PROT_NONE
        };

        if mprotect(ptr as *mut _, PAGE_SIZE, prot) != 0 {
            return Err(GuardError::ProtectionFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(windows)]
    unsafe fn protect_page(ptr: *mut u8, allow_access: bool) -> Result<()> {
        let protect = if allow_access {
            PAGE_READWRITE
        } else {
            PAGE_NOACCESS
        };

        let mut old_protect = 0;
        if VirtualProtect(ptr as *mut _, PAGE_SIZE, protect, &mut old_protect) == 0 {
            return Err(GuardError::ProtectionFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    unsafe fn protect_page(_ptr: *mut u8, _allow_access: bool) -> Result<()> {
        // No-op on unsupported platforms
        Ok(())
    }

    /// Get the data region as a slice
    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self.data_ptr.as_ptr(), self.data_size)
        }
    }

    /// Get the data region as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(self.data_ptr.as_ptr(), self.data_size)
        }
    }

    /// Verify that canaries are intact
    ///
    /// # Returns
    ///
    /// `true` if canaries are intact, `false` if corrupted
    pub fn verify_canaries(&self) -> bool {
        unsafe {
            // Check front canary
            let front_canary_ptr = self.base_ptr.as_ptr().add(PAGE_SIZE) as *const u64;
            if *front_canary_ptr != self.front_canary {
                return false;
            }

            // Check back canary
            let back_canary_ptr = self.data_ptr.as_ptr().add(self.data_size) as *const u64;
            if *back_canary_ptr != self.back_canary {
                return false;
            }

            true
        }
    }

    /// Verify canaries and return an error if corrupted
    pub fn verify_canaries_or_error(&self) -> Result<()> {
        unsafe {
            // Check front canary
            let front_canary_ptr = self.base_ptr.as_ptr().add(PAGE_SIZE) as *const u64;
            if *front_canary_ptr != self.front_canary {
                return Err(GuardError::CanaryCorrupted("front".to_string()));
            }

            // Check back canary
            let back_canary_ptr = self.data_ptr.as_ptr().add(self.data_size) as *const u64;
            if *back_canary_ptr != self.back_canary {
                return Err(GuardError::CanaryCorrupted("back".to_string()));
            }

            Ok(())
        }
    }

    /// Get the size of the data region
    pub fn len(&self) -> usize {
        self.data_size
    }

    /// Check if the allocation is empty
    pub fn is_empty(&self) -> bool {
        self.data_size == 0
    }
}

impl Drop for GuardedAllocation {
    fn drop(&mut self) {
        // Verify canaries before deallocation (panic if corrupted)
        if !self.verify_canaries() {
            eprintln!("WARNING: Buffer overflow detected during deallocation!");
            // Don't panic in drop, but log the issue
        }

        // Unprotect guard pages before deallocation
        unsafe {
            let _ = Self::protect_page(self.base_ptr.as_ptr(), true);
            let back_guard_ptr = self.base_ptr.as_ptr()
                .add(self.total_size - PAGE_SIZE);
            let _ = Self::protect_page(back_guard_ptr, true);
        }

        // Zero out data region
        let data_slice = unsafe {
            std::slice::from_raw_parts_mut(self.data_ptr.as_ptr(), self.data_size)
        };
        data_slice.zeroize();

        // Deallocate using platform-specific API
        unsafe {
            Self::deallocate_pages(self.base_ptr, self.total_size);
        }
    }
}

// GuardedAllocation is not Send/Sync by default due to raw pointers,
// but it's safe to implement them since we have exclusive ownership
unsafe impl Send for GuardedAllocation {}
unsafe impl Sync for GuardedAllocation {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guarded_allocation_basic() {
        let mut alloc = GuardedAllocation::new(1024).unwrap();
        assert_eq!(alloc.len(), 1024);
        assert!(!alloc.is_empty());

        // Write some data
        alloc.as_mut_slice()[0] = 42;
        alloc.as_mut_slice()[1023] = 99;

        // Verify data
        assert_eq!(alloc.as_slice()[0], 42);
        assert_eq!(alloc.as_slice()[1023], 99);

        // Verify canaries
        assert!(alloc.verify_canaries());
    }

    #[test]
    fn test_canary_verification() {
        let alloc = GuardedAllocation::new(256).unwrap();
        assert!(alloc.verify_canaries());
        assert!(alloc.verify_canaries_or_error().is_ok());
    }

    #[test]
    fn test_zero_size_rejected() {
        let result = GuardedAllocation::new(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_allocations() {
        let mut allocs = Vec::new();
        for i in 0..10 {
            let mut alloc = GuardedAllocation::new(128).unwrap();
            alloc.as_mut_slice()[0] = i as u8;
            allocs.push(alloc);
        }

        for (i, alloc) in allocs.iter().enumerate() {
            assert_eq!(alloc.as_slice()[0], i as u8);
            assert!(alloc.verify_canaries());
        }
    }

    #[test]
    fn test_data_isolation() {
        let mut alloc1 = GuardedAllocation::new(64).unwrap();
        let mut alloc2 = GuardedAllocation::new(64).unwrap();

        alloc1.as_mut_slice().fill(0xAA);
        alloc2.as_mut_slice().fill(0xBB);

        assert_eq!(alloc1.as_slice()[0], 0xAA);
        assert_eq!(alloc2.as_slice()[0], 0xBB);
    }
}

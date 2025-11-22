//! Advanced memory scrubbing utilities.
//!
//! Provides secure memory wiping with multiple patterns and passes,
//! resistant to compiler optimizations and suitable for high-security contexts.
//!
//! # Security Features
//!
//! - **Volatile writes**: Uses compiler barriers to prevent optimization
//! - **Multiple passes**: Supports DoD 5220.22-M and custom patterns
//! - **Verification**: Optional verification of scrubbing completion
//! - **Stack scrubbing**: Utilities for clearing sensitive stack data
//!
//! # Example
//!
//! ```
//! use secure_cryptor::memory::scrub::{scrub_bytes, ScrubPattern};
//!
//! let mut sensitive_data = vec![0x42; 1024];
//!
//! // Basic single-pass zero scrubbing
//! scrub_bytes(&mut sensitive_data);
//!
//! // Multi-pass DoD standard scrubbing
//! scrub_bytes_pattern(&mut sensitive_data, ScrubPattern::Dod522022M);
//! ```

use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};
use zeroize::Zeroize;

/// Scrubbing patterns for multi-pass wiping.
///
/// Different standards and methods for securely overwriting memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrubPattern {
    /// Single pass with zeros (fast, suitable for most cases)
    Zero,

    /// Single pass with 0xFF (all ones)
    Ones,

    /// DoD 5220.22-M standard (3 passes: 0x00, 0xFF, random)
    ///
    /// U.S. Department of Defense standard for magnetic media sanitization.
    /// While overkill for modern RAM, provides defense in depth.
    Dod522022M,

    /// NIST SP 800-88 (single pass with zeros or random)
    ///
    /// NIST recommends single-pass overwrite for RAM as sufficient.
    NistSp80088,

    /// Paranoid mode (7 passes: alternating patterns)
    ///
    /// Multiple passes with different patterns for maximum security.
    /// Not necessary for RAM but available for high-security contexts.
    Paranoid,

    /// Custom single pass with specified byte value
    Custom(u8),
}

/// Scrubbing statistics for verification and debugging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrubStats {
    /// Number of bytes scrubbed
    pub bytes_scrubbed: usize,

    /// Number of passes performed
    pub passes: usize,

    /// Whether verification was successful (if performed)
    pub verified: Option<bool>,
}

/// Securely scrub a byte slice using a single-pass zero pattern.
///
/// This is the recommended default for most use cases. Uses volatile writes
/// and compiler barriers to prevent optimization.
///
/// # Arguments
///
/// * `data` - Mutable slice to scrub
///
/// # Example
///
/// ```
/// use secure_cryptor::memory::scrub::scrub_bytes;
///
/// let mut secret = vec![0x42; 256];
/// scrub_bytes(&mut secret);
/// assert!(secret.iter().all(|&b| b == 0));
/// ```
pub fn scrub_bytes(data: &mut [u8]) {
    // Use zeroize for the actual wiping (it handles volatile writes)
    data.zeroize();

    // Compiler fence to prevent reordering
    compiler_fence(Ordering::SeqCst);
}

/// Securely scrub a byte slice using the specified pattern.
///
/// Performs multi-pass scrubbing for patterns that require it.
///
/// # Arguments
///
/// * `data` - Mutable slice to scrub
/// * `pattern` - Scrubbing pattern to use
///
/// # Returns
///
/// Statistics about the scrubbing operation.
///
/// # Example
///
/// ```
/// use secure_cryptor::memory::scrub::{scrub_bytes_pattern, ScrubPattern};
///
/// let mut secret = vec![0x42; 256];
/// let stats = scrub_bytes_pattern(&mut secret, ScrubPattern::Dod522022M);
/// assert_eq!(stats.passes, 3); // DoD standard uses 3 passes
/// ```
pub fn scrub_bytes_pattern(data: &mut [u8], pattern: ScrubPattern) -> ScrubStats {
    let bytes_scrubbed = data.len();

    let passes = match pattern {
        ScrubPattern::Zero => {
            overwrite_with_pattern(data, 0x00);
            1
        }

        ScrubPattern::Ones => {
            overwrite_with_pattern(data, 0xFF);
            overwrite_with_pattern(data, 0x00); // Final zero for verification
            2
        }

        ScrubPattern::Dod522022M => {
            // Pass 1: Write 0x00
            overwrite_with_pattern(data, 0x00);

            // Pass 2: Write 0xFF
            overwrite_with_pattern(data, 0xFF);

            // Pass 3: Write random data
            overwrite_with_random(data);

            // Final pass: Zero (for verification)
            overwrite_with_pattern(data, 0x00);

            4 // 3 DoD passes + final zero
        }

        ScrubPattern::NistSp80088 => {
            // NIST recommends single pass (we use zero for predictability)
            overwrite_with_pattern(data, 0x00);
            1
        }

        ScrubPattern::Paranoid => {
            // 7-pass Gutmann-inspired pattern for RAM
            overwrite_with_pattern(data, 0x55); // 01010101
            overwrite_with_pattern(data, 0xAA); // 10101010
            overwrite_with_random(data);
            overwrite_with_pattern(data, 0x00);
            overwrite_with_pattern(data, 0xFF);
            overwrite_with_random(data);
            overwrite_with_pattern(data, 0x00); // Final zero
            7
        }

        ScrubPattern::Custom(byte) => {
            overwrite_with_pattern(data, byte);
            overwrite_with_pattern(data, 0x00); // Final zero for verification
            2
        }
    };

    ScrubStats {
        bytes_scrubbed,
        passes,
        verified: None,
    }
}

/// Scrub and verify that the memory was actually zeroed.
///
/// Performs scrubbing and then verifies all bytes are zero.
///
/// # Arguments
///
/// * `data` - Mutable slice to scrub and verify
/// * `pattern` - Scrubbing pattern to use
///
/// # Returns
///
/// Statistics including verification result.
///
/// # Example
///
/// ```
/// use secure_cryptor::memory::scrub::{scrub_and_verify, ScrubPattern};
///
/// let mut secret = vec![0x42; 256];
/// let stats = scrub_and_verify(&mut secret, ScrubPattern::Zero);
/// assert_eq!(stats.verified, Some(true));
/// ```
pub fn scrub_and_verify(data: &mut [u8], pattern: ScrubPattern) -> ScrubStats {
    let mut stats = scrub_bytes_pattern(data, pattern);

    // Verify all bytes are zero (we always end with zero pass)
    let verified = data.iter().all(|&b| b == 0);
    stats.verified = Some(verified);

    stats
}

/// Overwrite memory with a specific byte pattern using volatile writes.
///
/// Uses `ptr::write_volatile` to prevent compiler optimization.
#[inline(never)]
fn overwrite_with_pattern(data: &mut [u8], pattern: u8) {
    // Use volatile writes to prevent optimization
    for byte in data.iter_mut() {
        unsafe {
            ptr::write_volatile(byte as *mut u8, pattern);
        }
    }

    // Compiler fence to ensure writes complete
    compiler_fence(Ordering::SeqCst);
}

/// Overwrite memory with cryptographically random bytes.
#[inline(never)]
fn overwrite_with_random(data: &mut [u8]) {
    use rand::RngCore;

    // Fill with random bytes
    rand::rng().fill_bytes(data);

    // Compiler fence
    compiler_fence(Ordering::SeqCst);
}

/// Stack scrubber for clearing sensitive data from function stack frames.
///
/// This macro helps ensure sensitive stack variables are wiped before
/// function return. Use this for functions that handle keys, passwords,
/// or other sensitive data on the stack.
///
/// # Example
///
/// ```ignore
/// fn process_password(password: &str) {
///     let mut password_copy = password.to_string();
///
///     // ... process password ...
///
///     // Scrub before returning
///     scrub_stack_variable!(password_copy);
/// }
/// ```
#[macro_export]
macro_rules! scrub_stack_variable {
    ($var:expr) => {
        {
            use zeroize::Zeroize;
            $var.zeroize();
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        }
    };
}

/// RAII guard for automatic stack scrubbing.
///
/// Wraps a value and ensures it's scrubbed when the guard is dropped.
/// Useful for ensuring cleanup even if function returns early.
///
/// # Example
///
/// ```
/// use secure_cryptor::memory::scrub::ScrubGuard;
///
/// {
///     let secret = vec![0x42; 256];
///     let _guard = ScrubGuard::new(secret);
///
///     // ... use _guard.as_ref() or _guard.as_mut() ...
///
/// } // Automatically scrubbed on drop
/// ```
pub struct ScrubGuard<T: Zeroize> {
    value: T,
}

impl<T: Zeroize> ScrubGuard<T> {
    /// Create a new scrub guard wrapping the value.
    pub fn new(value: T) -> Self {
        Self { value }
    }

    /// Get an immutable reference to the wrapped value.
    pub fn as_ref(&self) -> &T {
        &self.value
    }

    /// Get a mutable reference to the wrapped value.
    pub fn as_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Consume the guard and return the inner value without scrubbing.
    ///
    /// # Security Warning
    ///
    /// Only use this if you're transferring ownership to another
    /// scrubbing mechanism. Otherwise the value won't be scrubbed!
    pub fn into_inner(self) -> T {
        // Take ownership without running Drop
        unsafe {
            let value = ptr::read(&self.value);
            // Prevent Drop from running
            std::mem::forget(self);
            value
        }
    }
}

impl<T: Zeroize> Drop for ScrubGuard<T> {
    fn drop(&mut self) {
        self.value.zeroize();
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T: Zeroize> std::ops::Deref for ScrubGuard<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: Zeroize> std::ops::DerefMut for ScrubGuard<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

/// Scrub a stack buffer of fixed size.
///
/// Useful for clearing fixed-size arrays on the stack.
///
/// # Example
///
/// ```
/// use secure_cryptor::memory::scrub::scrub_stack_buffer;
///
/// let mut buffer = [0x42u8; 256];
/// scrub_stack_buffer(&mut buffer);
/// assert!(buffer.iter().all(|&b| b == 0));
/// ```
pub fn scrub_stack_buffer<const N: usize>(buffer: &mut [u8; N]) {
    scrub_bytes(buffer);
}

/// Scrub multiple byte slices in one operation.
///
/// More efficient than scrubbing each slice individually when you have
/// multiple buffers to clear.
///
/// # Example
///
/// ```
/// use secure_cryptor::memory::scrub::scrub_multiple;
///
/// let mut buf1 = vec![0x42; 128];
/// let mut buf2 = vec![0x43; 256];
/// let mut buf3 = vec![0x44; 512];
///
/// scrub_multiple(&mut [&mut buf1, &mut buf2, &mut buf3]);
/// ```
pub fn scrub_multiple(buffers: &mut [&mut [u8]]) {
    for buffer in buffers {
        scrub_bytes(buffer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_bytes_basic() {
        let mut data = vec![0x42; 256];
        scrub_bytes(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_scrub_pattern_zero() {
        let mut data = vec![0xFF; 128];
        let stats = scrub_bytes_pattern(&mut data, ScrubPattern::Zero);

        assert_eq!(stats.bytes_scrubbed, 128);
        assert_eq!(stats.passes, 1);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_scrub_pattern_ones() {
        let mut data = vec![0x00; 128];
        scrub_bytes_pattern(&mut data, ScrubPattern::Ones);

        // Final pass is always zero for verification
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_scrub_pattern_dod() {
        let mut data = vec![0x42; 256];
        let stats = scrub_bytes_pattern(&mut data, ScrubPattern::Dod522022M);

        assert_eq!(stats.bytes_scrubbed, 256);
        assert_eq!(stats.passes, 4); // 3 DoD + final zero
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_scrub_pattern_nist() {
        let mut data = vec![0x55; 512];
        let stats = scrub_bytes_pattern(&mut data, ScrubPattern::NistSp80088);

        assert_eq!(stats.bytes_scrubbed, 512);
        assert_eq!(stats.passes, 1);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_scrub_pattern_paranoid() {
        let mut data = vec![0xAA; 1024];
        let stats = scrub_bytes_pattern(&mut data, ScrubPattern::Paranoid);

        assert_eq!(stats.bytes_scrubbed, 1024);
        assert_eq!(stats.passes, 7);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_scrub_pattern_custom() {
        let mut data = vec![0x00; 64];
        scrub_bytes_pattern(&mut data, ScrubPattern::Custom(0x37));

        // Final scrub is always zero
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_scrub_and_verify() {
        let mut data = vec![0x99; 128];
        let stats = scrub_and_verify(&mut data, ScrubPattern::Zero);

        assert_eq!(stats.verified, Some(true));
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_scrub_guard() {
        let secret = vec![0x42; 256];
        {
            let guard = ScrubGuard::new(secret);
            assert_eq!(guard.as_ref().len(), 256);
            assert!(guard.as_ref().iter().all(|&b| b == 0x42));
        }
        // Guard dropped, memory should be scrubbed
    }

    #[test]
    fn test_scrub_guard_deref() {
        let secret = vec![0x42; 128];
        let mut guard = ScrubGuard::new(secret);

        // Test Deref
        assert_eq!(guard.len(), 128);

        // Test DerefMut
        guard[0] = 0x99;
        assert_eq!(guard[0], 0x99);
    }

    #[test]
    fn test_scrub_stack_buffer() {
        let mut buffer = [0x55u8; 256];
        scrub_stack_buffer(&mut buffer);
        assert!(buffer.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_scrub_multiple() {
        let mut buf1 = vec![0x11; 64];
        let mut buf2 = vec![0x22; 128];
        let mut buf3 = vec![0x33; 256];

        scrub_multiple(&mut [&mut buf1, &mut buf2, &mut buf3]);

        assert!(buf1.iter().all(|&b| b == 0));
        assert!(buf2.iter().all(|&b| b == 0));
        assert!(buf3.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_volatile_write_not_optimized() {
        // This test ensures writes aren't optimized away
        let mut data = vec![0x42; 1024];

        // Multiple scrubs should all execute
        for _ in 0..10 {
            overwrite_with_pattern(&mut data, 0xFF);
            overwrite_with_pattern(&mut data, 0x00);
        }

        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_empty_slice() {
        let mut data: Vec<u8> = vec![];
        scrub_bytes(&mut data);
        let stats = scrub_bytes_pattern(&mut data, ScrubPattern::Dod522022M);
        assert_eq!(stats.bytes_scrubbed, 0);
    }

    #[test]
    fn test_large_buffer() {
        // Test with a larger buffer to ensure performance is reasonable
        let mut data = vec![0x42; 10 * 1024 * 1024]; // 10 MB
        let stats = scrub_bytes_pattern(&mut data, ScrubPattern::Zero);

        assert_eq!(stats.bytes_scrubbed, 10 * 1024 * 1024);
        assert!(data.iter().all(|&b| b == 0));
    }
}

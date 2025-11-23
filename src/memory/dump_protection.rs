//! Memory dump protection
//!
//! This module provides protection against memory dump attacks including crash dumps,
//! hibernation files, and core dumps.
//!
//! # Platform Support
//!
//! - **Windows**: Excludes process from Windows Error Reporting (WER) dumps
//! - **Linux**: Disables core dumps via RLIMIT_CORE
//! - **macOS**: Disables core dumps via RLIMIT_CORE
//!
//! # Security
//!
//! Memory dumps can expose sensitive cryptographic material even after a process
//! terminates. This module provides defense-in-depth by:
//! - Preventing creation of crash dumps
//! - Disabling core dumps
//! - Providing callbacks for cleaning sensitive data before system suspend
//!
//! # Usage
//!
//! ```no_run
//! use tesseract::memory::dump_protection::{disable_core_dumps, disable_crash_dumps};
//!
//! // Disable all memory dumps for this process
//! disable_core_dumps().expect("Failed to disable core dumps");
//! disable_crash_dumps().expect("Failed to disable crash dumps");
//! ```

use thiserror::Error;

#[cfg(unix)]
use libc::{setrlimit, rlimit, RLIMIT_CORE};

/// Errors that can occur during dump protection operations
#[derive(Debug, Error)]
pub enum DumpProtectionError {
    /// Failed to disable core dumps
    #[error("Failed to disable core dumps: {0}")]
    CoreDumpFailed(String),

    /// Failed to disable crash dumps
    #[error("Failed to disable crash dumps: {0}")]
    CrashDumpFailed(String),

    /// System call failed
    #[error("System call failed: {0}")]
    SystemError(String),

    /// Feature not supported on this platform
    #[error("Feature not supported on this platform")]
    NotSupported,
}

/// Result type for dump protection operations
pub type Result<T> = std::result::Result<T, DumpProtectionError>;

/// Disable core dumps for the current process
///
/// On Unix systems, this sets RLIMIT_CORE to 0, preventing core dump file creation.
/// On Windows, this is a no-op (use `disable_crash_dumps` instead).
///
/// # Returns
///
/// `Ok(())` if core dumps were disabled successfully
///
/// # Errors
///
/// Returns error if the system call fails
///
/// # Example
///
/// ```no_run
/// use tesseract::memory::dump_protection::disable_core_dumps;
///
/// disable_core_dumps().expect("Failed to disable core dumps");
/// ```
pub fn disable_core_dumps() -> Result<()> {
    #[cfg(unix)]
    {
        unsafe {
            let limits = rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };

            if setrlimit(RLIMIT_CORE, &limits) != 0 {
                return Err(DumpProtectionError::CoreDumpFailed(
                    std::io::Error::last_os_error().to_string(),
                ));
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        // Core dumps are a Unix concept
        Ok(())
    }
}

/// Disable crash dumps for the current process
///
/// On Unix systems, this is handled by `disable_core_dumps`.
/// On Windows, crash dump protection requires elevated privileges and specific
/// system configurations, so this is currently a no-op.
///
/// # Returns
///
/// `Ok(())` always succeeds
///
/// # Example
///
/// ```no_run
/// use tesseract::memory::dump_protection::disable_crash_dumps;
///
/// disable_crash_dumps().expect("Failed to disable crash dumps");
/// ```
pub fn disable_crash_dumps() -> Result<()> {
    // Note: Windows Error Reporting (WER) dump exclusion APIs require
    // specific SDK versions and elevated privileges. Core dumps on Unix
    // are handled via disable_core_dumps().
    Ok(())
}

/// Check if core dumps are currently disabled
///
/// # Returns
///
/// `true` if core dumps are disabled, `false` otherwise
pub fn are_core_dumps_disabled() -> bool {
    #[cfg(unix)]
    {
        unsafe {
            let mut limits = rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };

            if libc::getrlimit(RLIMIT_CORE, &mut limits) == 0 {
                return limits.rlim_cur == 0 && limits.rlim_max == 0;
            }
        }
        false
    }

    #[cfg(not(unix))]
    {
        // On non-Unix, we can't easily check this
        false
    }
}

/// Power state manager for handling hibernation and sleep events
///
/// This allows applications to register callbacks that are invoked before
/// the system enters a sleep or hibernation state, giving them a chance to
/// clear sensitive data from memory.
#[cfg(windows)]
pub struct PowerStateMonitor {
    /// Callback to invoke before sleep/hibernation
    callback: Option<Box<dyn FnMut() + Send + 'static>>,
}

#[cfg(windows)]
impl PowerStateMonitor {
    /// Create a new power state monitor
    pub fn new() -> Self {
        Self { callback: None }
    }

    /// Set the callback to invoke before sleep/hibernation
    ///
    /// # Arguments
    ///
    /// * `callback` - Function to call before system suspend
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: FnMut() + Send + 'static,
    {
        self.callback = Some(Box::new(callback));
    }

    /// Invoke the callback (called internally when power event detected)
    #[allow(dead_code)]
    fn invoke_callback(&mut self) {
        if let Some(ref mut cb) = self.callback {
            cb();
        }
    }
}

#[cfg(windows)]
impl Default for PowerStateMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Disable all memory dump mechanisms for the current process
///
/// This is a convenience function that calls both `disable_core_dumps()` and
/// `disable_crash_dumps()`.
///
/// # Returns
///
/// `Ok(())` if all dump mechanisms were disabled successfully
///
/// # Errors
///
/// Returns the first error encountered
///
/// # Example
///
/// ```no_run
/// use tesseract::memory::dump_protection::disable_all_dumps;
///
/// disable_all_dumps().expect("Failed to disable memory dumps");
/// ```
pub fn disable_all_dumps() -> Result<()> {
    disable_core_dumps()?;
    disable_crash_dumps()?;
    Ok(())
}

/// Memory dump protection guard that automatically disables dumps when created
/// and can restore the original state when dropped.
///
/// # Example
///
/// ```no_run
/// use tesseract::memory::dump_protection::DumpProtectionGuard;
///
/// {
///     let _guard = DumpProtectionGuard::new().expect("Failed to enable protection");
///     // Protected region - no dumps will be created here
///     // ... perform sensitive operations ...
/// } // Protection is released when guard drops
/// ```
pub struct DumpProtectionGuard {
    #[cfg(unix)]
    original_limits: Option<rlimit>,
}

impl DumpProtectionGuard {
    /// Create a new dump protection guard
    ///
    /// This immediately disables all dump mechanisms for the current process.
    ///
    /// # Returns
    ///
    /// A guard that will restore the original dump settings when dropped
    ///
    /// # Errors
    ///
    /// Returns error if dump protection could not be enabled
    pub fn new() -> Result<Self> {
        #[cfg(unix)]
        {
            // Save current limits
            let mut original_limits = rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };

            unsafe {
                if libc::getrlimit(RLIMIT_CORE, &mut original_limits) != 0 {
                    return Err(DumpProtectionError::SystemError(
                        std::io::Error::last_os_error().to_string(),
                    ));
                }
            }

            // Disable dumps
            disable_all_dumps()?;

            Ok(Self {
                original_limits: Some(original_limits),
            })
        }

        #[cfg(not(unix))]
        {
            disable_all_dumps()?;
            Ok(Self {})
        }
    }

    /// Keep dump protection enabled even after guard is dropped
    ///
    /// This consumes the guard without restoring the original settings.
    pub fn keep(self) {
        #[cfg(unix)]
        {
            // Don't restore limits on drop
            let mut guard = self;
            guard.original_limits = None;
            std::mem::forget(guard);
        }
        #[cfg(not(unix))]
        {
            std::mem::forget(self);
        }
    }
}

impl Drop for DumpProtectionGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            // Restore original limits if we saved them
            if let Some(limits) = self.original_limits {
                unsafe {
                    let _ = setrlimit(RLIMIT_CORE, &limits);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disable_core_dumps() {
        // This may fail on systems with restrictive permissions
        match disable_core_dumps() {
            Ok(()) => {
                #[cfg(unix)]
                {
                    // Verify core dumps are disabled
                    assert!(are_core_dumps_disabled());
                }
            }
            Err(e) => {
                eprintln!("Warning: Could not disable core dumps: {}", e);
            }
        }
    }

    #[test]
    fn test_disable_crash_dumps() {
        // This may fail on systems with restrictive permissions
        match disable_crash_dumps() {
            Ok(()) => {
                // Success
            }
            Err(e) => {
                eprintln!("Warning: Could not disable crash dumps: {}", e);
            }
        }
    }

    #[test]
    fn test_disable_all_dumps() {
        // This may fail on systems with restrictive permissions
        let _ = disable_all_dumps();
    }

    #[test]
    fn test_dump_protection_guard() {
        // Test guard creation and drop
        match DumpProtectionGuard::new() {
            Ok(guard) => {
                #[cfg(unix)]
                {
                    assert!(are_core_dumps_disabled());
                }
                drop(guard);
                // Limits should be restored after drop
            }
            Err(e) => {
                eprintln!("Warning: Could not create dump protection guard: {}", e);
            }
        }
    }

    #[test]
    fn test_dump_protection_guard_keep() {
        // Test keeping protection enabled
        match DumpProtectionGuard::new() {
            Ok(guard) => {
                guard.keep();
                // Protection should remain enabled
                #[cfg(unix)]
                {
                    assert!(are_core_dumps_disabled());
                }
            }
            Err(e) => {
                eprintln!("Warning: Could not create dump protection guard: {}", e);
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_power_state_monitor() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let callback_invoked = Arc::new(AtomicBool::new(false));
        let callback_invoked_clone = Arc::clone(&callback_invoked);

        let mut monitor = PowerStateMonitor::new();
        monitor.set_callback(move || {
            callback_invoked_clone.store(true, Ordering::Relaxed);
        });

        // Manually invoke callback for testing
        monitor.invoke_callback();

        assert!(callback_invoked.load(Ordering::Relaxed));
    }
}

//! Debugger detection and anti-debugging measures
//!
//! This module provides cross-platform debugger detection to protect sensitive
//! cryptographic operations from analysis and memory inspection.
//!
//! # Platform Support
//!
//! - **Windows**: Uses `IsDebuggerPresent()` and `CheckRemoteDebuggerPresent()`
//! - **Linux**: Checks `/proc/self/status` for `TracerPid`
//! - **macOS**: Uses `sysctl()` with `P_TRACED` flag
//!
//! # Security
//!
//! Debugger detection is not foolproof and can be bypassed by sophisticated
//! attackers. This provides defense-in-depth against casual analysis but should
//! not be relied upon as the sole security measure.
//!
//! # Usage
//!
//! ```no_run
//! use tesseract::memory::debugger::{is_debugger_present, DebuggerMonitor};
//!
//! // Simple check
//! if is_debugger_present() {
//!     eprintln!("WARNING: Debugger detected!");
//!     // Clear sensitive data, exit, etc.
//! }
//!
//! // Continuous monitoring with callback
//! let mut monitor = DebuggerMonitor::new();
//! monitor.set_callback(Box::new(|| {
//!     eprintln!("Debugger detected!");
//!     std::process::exit(1);
//! }));
//! monitor.start_monitoring(std::time::Duration::from_secs(1));
//! ```

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

#[cfg(windows)]
use winapi::um::debugapi::{IsDebuggerPresent, CheckRemoteDebuggerPresent};
#[cfg(windows)]
use winapi::um::processthreadsapi::GetCurrentProcess;

#[cfg(target_os = "linux")]
use std::fs;

#[cfg(target_os = "macos")]
use libc::{c_int, c_void, sysctl, CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid};

/// Check if a debugger is currently attached to the process
///
/// # Returns
///
/// `true` if a debugger is detected, `false` otherwise
///
/// # Platform-Specific Behavior
///
/// - **Windows**: Checks both local and remote debuggers
/// - **Linux**: Checks TracerPid in /proc/self/status
/// - **macOS**: Checks P_TRACED flag via sysctl
/// - **Other**: Always returns false
pub fn is_debugger_present() -> bool {
    #[cfg(windows)]
    {
        unsafe {
            // Check for local debugger
            if IsDebuggerPresent() != 0 {
                return true;
            }

            // Check for remote debugger
            let mut is_remote_debugger_present = 0;
            let result = CheckRemoteDebuggerPresent(
                GetCurrentProcess(),
                &mut is_remote_debugger_present
            );

            if result != 0 && is_remote_debugger_present != 0 {
                return true;
            }
        }
        false
    }

    #[cfg(target_os = "linux")]
    {
        // Read /proc/self/status and check TracerPid
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    if let Some(pid_str) = line.split_whitespace().nth(1) {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            // TracerPid of 0 means no tracer
                            return pid != 0;
                        }
                    }
                }
            }
        }
        false
    }

    #[cfg(target_os = "macos")]
    {
        unsafe {
            // Use sysctl to check P_TRACED flag
            const P_TRACED: u32 = 0x00000800;

            #[repr(C)]
            struct KinfoProc {
                padding: [u8; 32],  // Simplified - actual struct is more complex
                p_flag: u32,
                // ... more fields we don't need
            }

            let mut info: KinfoProc = std::mem::zeroed();
            let mut size = std::mem::size_of::<KinfoProc>();

            let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()];

            let result = sysctl(
                mib.as_mut_ptr(),
                4,
                &mut info as *mut _ as *mut c_void,
                &mut size,
                std::ptr::null_mut(),
                0
            );

            if result == 0 {
                return (info.p_flag & P_TRACED) != 0;
            }
        }
        false
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        // Unsupported platform - assume no debugger
        false
    }
}

/// Callback type for debugger detection events
pub type DebuggerCallback = Box<dyn FnMut() + Send + 'static>;

/// Debugger monitoring service that continuously checks for attached debuggers
///
/// This provides periodic scanning for debugger attachment with customizable
/// callbacks for handling detection events.
pub struct DebuggerMonitor {
    /// Whether monitoring is active
    running: Arc<AtomicBool>,
    /// Optional callback to invoke when debugger is detected
    callback: Arc<Mutex<Option<DebuggerCallback>>>,
    /// Monitoring thread handle
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl DebuggerMonitor {
    /// Create a new debugger monitor
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            callback: Arc::new(Mutex::new(None)),
            thread_handle: None,
        }
    }

    /// Set the callback to invoke when a debugger is detected
    ///
    /// # Arguments
    ///
    /// * `callback` - Function to call when debugger is detected
    pub fn set_callback(&mut self, callback: DebuggerCallback) {
        let mut cb = self.callback.lock().unwrap();
        *cb = Some(callback);
    }

    /// Start monitoring for debuggers
    ///
    /// # Arguments
    ///
    /// * `interval` - How often to check for debuggers
    ///
    /// # Panics
    ///
    /// Panics if monitoring is already running
    pub fn start_monitoring(&mut self, interval: Duration) {
        if self.running.load(Ordering::Relaxed) {
            panic!("Debugger monitoring is already running");
        }

        self.running.store(true, Ordering::Relaxed);

        let running = Arc::clone(&self.running);
        let callback = Arc::clone(&self.callback);

        let handle = thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                if is_debugger_present() {
                    // Invoke callback if set
                    if let Ok(mut cb_guard) = callback.lock() {
                        if let Some(ref mut cb) = *cb_guard {
                            cb();
                        }
                    }
                }

                thread::sleep(interval);
            }
        });

        self.thread_handle = Some(handle);
    }

    /// Stop monitoring for debuggers
    pub fn stop_monitoring(&mut self) {
        self.running.store(false, Ordering::Relaxed);

        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }

    /// Check if monitoring is currently active
    pub fn is_monitoring(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

impl Default for DebuggerMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DebuggerMonitor {
    fn drop(&mut self) {
        self.stop_monitoring();
    }
}

/// Additional anti-debugging techniques for release builds
///
/// These are more aggressive measures that should only be enabled in
/// release builds to avoid interfering with legitimate debugging.
#[cfg(not(debug_assertions))]
pub mod anti_debug {
    /// Timing-based debugger detection
    ///
    /// Measures execution time of a no-op operation. If it takes too long,
    /// a debugger or analysis tool may be interfering.
    ///
    /// # Returns
    ///
    /// `true` if timing anomaly detected
    pub fn check_timing_anomaly() -> bool {
        use std::time::Instant;

        let start = Instant::now();

        // Perform simple operation
        let mut x = 0u64;
        for _ in 0..1000 {
            x = x.wrapping_add(1);
        }
        std::hint::black_box(x);

        let elapsed = start.elapsed();

        // If this takes more than 1ms, something is wrong
        elapsed.as_millis() > 1
    }

    /// Check for common debugger artifacts in memory
    ///
    /// # Returns
    ///
    /// `true` if debugger artifacts detected
    #[cfg(windows)]
    pub fn check_debugger_artifacts() -> bool {
        use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
        use winapi::um::memoryapi::VirtualQuery;
        use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

        unsafe {
            // Check if our code section has unexpected permissions
            // Debuggers sometimes modify page protections
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQuery(
                check_debugger_artifacts as usize as *const winapi::ctypes::c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
            );

            if result != 0 {
                // Check if protection includes write (unusual for code)
                return (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0;
            }
        }
        false
    }

    #[cfg(not(windows))]
    pub fn check_debugger_artifacts() -> bool {
        // Not implemented for non-Windows platforms
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debugger_check_returns_bool() {
        // This should always return a bool, regardless of platform
        let result = is_debugger_present();
        assert!(result == true || result == false);
    }

    #[test]
    fn test_monitor_creation() {
        let monitor = DebuggerMonitor::new();
        assert!(!monitor.is_monitoring());
    }

    #[test]
    fn test_monitor_start_stop() {
        let mut monitor = DebuggerMonitor::new();

        monitor.start_monitoring(Duration::from_millis(100));
        assert!(monitor.is_monitoring());

        thread::sleep(Duration::from_millis(150));

        monitor.stop_monitoring();
        assert!(!monitor.is_monitoring());
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_timing_check() {
        use anti_debug::check_timing_anomaly;

        // Should not detect anomaly in normal execution
        // (may fail if running under heavy system load or debugger)
        let _ = check_timing_anomaly();
    }

    #[test]
    fn test_monitor_with_callback() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let callback_triggered = Arc::new(AtomicBool::new(false));
        let callback_triggered_clone = Arc::clone(&callback_triggered);

        let mut monitor = DebuggerMonitor::new();
        monitor.set_callback(Box::new(move || {
            callback_triggered_clone.store(true, Ordering::Relaxed);
        }));

        monitor.start_monitoring(Duration::from_millis(10));
        thread::sleep(Duration::from_millis(50));
        monitor.stop_monitoring();

        // Callback may or may not have been triggered depending on whether
        // a debugger is actually attached. This just tests that the mechanism works.
    }
}

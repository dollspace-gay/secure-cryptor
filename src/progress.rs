//! Progress reporting for long-running operations.
//!
//! This module provides a trait-based interface for reporting progress during
//! encryption, decryption, and other streaming operations.
//!
//! # Examples
//!
//! ```rust
//! use tesseract_lib::progress::{ProgressReporter, ProgressCallback};
//!
//! fn process_with_progress<P: ProgressReporter>(mut op: P) {
//!     while !op.is_complete() {
//!         println!("Progress: {:.1}%", op.progress() * 100.0);
//!         // ... do work ...
//!     }
//! }
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

/// Callback function type for progress updates.
///
/// # Arguments
///
/// * `progress` - Completion percentage (0.0 to 1.0)
/// * `bytes_processed` - Number of bytes processed so far
/// * `total_bytes` - Total number of bytes to process
pub type ProgressCallback = Arc<dyn Fn(f64, u64, u64) + Send + Sync>;

/// Trait for operations that can report their progress.
///
/// Implementors provide progress information for long-running operations,
/// allowing UI and monitoring code to track completion status.
pub trait ProgressReporter {
    /// Returns the current progress as a percentage (0.0 to 1.0).
    ///
    /// # Returns
    ///
    /// A value between 0.0 (0% complete) and 1.0 (100% complete).
    fn progress(&self) -> f64;

    /// Returns the number of bytes processed so far.
    fn bytes_processed(&self) -> u64;

    /// Returns the total number of bytes to process.
    ///
    /// Returns 0 if the total size is unknown.
    fn total_bytes(&self) -> u64;

    /// Returns true if the operation is complete.
    fn is_complete(&self) -> bool {
        self.progress() >= 1.0
    }

    /// Returns the estimated time remaining.
    ///
    /// Returns `None` if estimation is not available or not enough data
    /// has been collected to make a reliable estimate.
    fn eta(&self) -> Option<Duration> {
        None
    }

    /// Returns the average processing speed in bytes per second.
    ///
    /// Returns `None` if not enough time has passed to calculate speed.
    fn bytes_per_second(&self) -> Option<f64> {
        None
    }

    /// Registers a callback to be invoked on progress updates.
    ///
    /// Not all implementations support callbacks. Default implementation
    /// does nothing.
    fn set_progress_callback(&mut self, _callback: ProgressCallback) {}
}

/// Progress tracker that measures elapsed time and estimates completion.
///
/// This tracker can be embedded in long-running operations to provide
/// progress reporting with ETA estimation.
pub struct ProgressTracker {
    start_time: Instant,
    bytes_processed: u64,
    total_bytes: u64,
    callback: Option<ProgressCallback>,
    last_callback_time: Option<Instant>,
    callback_throttle: Duration,
}

impl std::fmt::Debug for ProgressTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressTracker")
            .field("start_time", &self.start_time)
            .field("bytes_processed", &self.bytes_processed)
            .field("total_bytes", &self.total_bytes)
            .field("callback", &self.callback.as_ref().map(|_| "<callback>"))
            .field("last_callback_time", &self.last_callback_time)
            .field("callback_throttle", &self.callback_throttle)
            .finish()
    }
}

impl ProgressTracker {
    /// Creates a new progress tracker.
    ///
    /// # Arguments
    ///
    /// * `total_bytes` - Total number of bytes to process
    pub fn new(total_bytes: u64) -> Self {
        Self {
            start_time: Instant::now(),
            bytes_processed: 0,
            total_bytes,
            callback: None,
            last_callback_time: None,
            callback_throttle: Duration::from_millis(100), // 10 updates/sec max
        }
    }

    /// Updates the number of bytes processed.
    ///
    /// This will trigger the progress callback if one is registered
    /// and the throttle duration has elapsed.
    ///
    /// # Arguments
    ///
    /// * `bytes` - New total of bytes processed
    pub fn update(&mut self, bytes: u64) {
        self.bytes_processed = bytes;

        // Trigger callback if registered and throttle has elapsed
        if let Some(callback) = &self.callback {
            let should_call = self.last_callback_time
                .map(|last| last.elapsed() >= self.callback_throttle)
                .unwrap_or(true);

            if should_call {
                callback(self.progress(), self.bytes_processed, self.total_bytes);
                self.last_callback_time = Some(Instant::now());
            }
        }
    }

    /// Increments the bytes processed counter.
    ///
    /// # Arguments
    ///
    /// * `delta` - Number of bytes to add to the counter
    pub fn increment(&mut self, delta: u64) {
        self.update(self.bytes_processed + delta);
    }

    /// Sets the callback throttle duration.
    ///
    /// The callback will be invoked at most once per throttle duration,
    /// even if `update()` is called more frequently.
    ///
    /// # Arguments
    ///
    /// * `duration` - Minimum time between callback invocations
    pub fn set_throttle(&mut self, duration: Duration) {
        self.callback_throttle = duration;
    }

    /// Forces the callback to be invoked immediately, bypassing throttle.
    ///
    /// Useful for ensuring final progress is reported.
    pub fn force_callback(&mut self) {
        if let Some(callback) = &self.callback {
            callback(self.progress(), self.bytes_processed, self.total_bytes);
            self.last_callback_time = Some(Instant::now());
        }
    }
}

impl ProgressReporter for ProgressTracker {
    fn progress(&self) -> f64 {
        if self.total_bytes == 0 {
            1.0
        } else {
            (self.bytes_processed as f64 / self.total_bytes as f64).min(1.0)
        }
    }

    fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    fn eta(&self) -> Option<Duration> {
        if self.bytes_processed == 0 {
            return None;
        }

        let elapsed = self.start_time.elapsed();
        let elapsed_secs = elapsed.as_secs_f64();

        if elapsed_secs < 0.1 {
            // Not enough time to make a reliable estimate
            return None;
        }

        let bytes_per_sec = self.bytes_processed as f64 / elapsed_secs;
        let remaining_bytes = self.total_bytes.saturating_sub(self.bytes_processed);
        let remaining_secs = remaining_bytes as f64 / bytes_per_sec;

        Some(Duration::from_secs_f64(remaining_secs))
    }

    fn bytes_per_second(&self) -> Option<f64> {
        let elapsed = self.start_time.elapsed();
        let elapsed_secs = elapsed.as_secs_f64();

        if elapsed_secs < 0.1 {
            return None;
        }

        Some(self.bytes_processed as f64 / elapsed_secs)
    }

    fn set_progress_callback(&mut self, callback: ProgressCallback) {
        self.callback = Some(callback);
    }
}

/// Formats a byte count as a human-readable string.
///
/// # Examples
///
/// ```
/// use tesseract_lib::progress::format_bytes;
///
/// assert_eq!(format_bytes(1024), "1.0 KB");
/// assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
/// assert_eq!(format_bytes(1536 * 1024), "1.5 MB");
/// ```
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];

    if bytes == 0 {
        return "0 B".to_string();
    }

    let bytes_f64 = bytes as f64;
    let unit_index = (bytes_f64.log2() / 10.0).floor() as usize;
    let unit_index = unit_index.min(UNITS.len() - 1);

    let divisor = 1024_f64.powi(unit_index as i32);
    let value = bytes_f64 / divisor;

    format!("{:.1} {}", value, UNITS[unit_index])
}

/// Formats a duration as a human-readable string.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use tesseract_lib::progress::format_duration;
///
/// assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
/// assert_eq!(format_duration(Duration::from_secs(3665)), "1h 1m 5s");
/// ```
pub fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();

    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn test_progress_tracker_basic() {
        let mut tracker = ProgressTracker::new(1000);

        assert_eq!(tracker.progress(), 0.0);
        assert_eq!(tracker.bytes_processed(), 0);
        assert_eq!(tracker.total_bytes(), 1000);
        assert!(!tracker.is_complete());

        tracker.update(500);
        assert_eq!(tracker.progress(), 0.5);
        assert_eq!(tracker.bytes_processed(), 500);

        tracker.update(1000);
        assert_eq!(tracker.progress(), 1.0);
        assert!(tracker.is_complete());
    }

    #[test]
    fn test_progress_tracker_increment() {
        let mut tracker = ProgressTracker::new(1000);

        tracker.increment(250);
        assert_eq!(tracker.bytes_processed(), 250);

        tracker.increment(250);
        assert_eq!(tracker.bytes_processed(), 500);
        assert_eq!(tracker.progress(), 0.5);
    }

    #[test]
    fn test_progress_tracker_zero_total() {
        let tracker = ProgressTracker::new(0);
        assert_eq!(tracker.progress(), 1.0);
        assert!(tracker.is_complete());
    }

    #[test]
    fn test_progress_tracker_callback() {
        let mut tracker = ProgressTracker::new(1000);

        let call_count = Arc::new(AtomicU64::new(0));
        let call_count_clone = call_count.clone();

        tracker.set_progress_callback(Arc::new(move |progress, processed, total| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            assert!(progress >= 0.0 && progress <= 1.0);
            assert!(processed <= total);
        }));

        // Set throttle to zero for testing
        tracker.set_throttle(Duration::from_millis(0));

        tracker.update(250);
        tracker.update(500);
        tracker.update(750);
        tracker.update(1000);

        // Should have been called 4 times
        assert_eq!(call_count.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn test_progress_tracker_eta() {
        let mut tracker = ProgressTracker::new(1000);

        // Initially, ETA should be None (not enough data)
        assert!(tracker.eta().is_none());

        // After some progress and time, ETA should be available
        std::thread::sleep(Duration::from_millis(200));
        tracker.update(500);

        if let Some(eta) = tracker.eta() {
            // ETA should be roughly 200ms (same time for remaining 50%)
            assert!(eta.as_millis() > 50 && eta.as_millis() < 500);
        }
    }

    #[test]
    fn test_progress_tracker_bytes_per_second() {
        let mut tracker = ProgressTracker::new(1000);

        // Initially, bytes_per_second should be None
        assert!(tracker.bytes_per_second().is_none());

        std::thread::sleep(Duration::from_millis(200));
        tracker.update(200);

        if let Some(bps) = tracker.bytes_per_second() {
            // Should be roughly 1000 bytes/sec (200 bytes in 0.2 seconds)
            assert!(bps > 500.0 && bps < 2000.0);
        }
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512.0 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(format_bytes(1536 * 1024 * 1024), "1.5 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3665)), "1h 1m 5s");
        assert_eq!(format_duration(Duration::from_secs(7200)), "2h 0m 0s");
    }

    #[test]
    fn test_force_callback() {
        let mut tracker = ProgressTracker::new(1000);

        let call_count = Arc::new(AtomicU64::new(0));
        let call_count_clone = call_count.clone();

        tracker.set_progress_callback(Arc::new(move |_, _, _| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
        }));

        tracker.update(500);
        tracker.force_callback();

        // Should have been called twice (once from update, once from force)
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }
}

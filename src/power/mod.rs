/// Power state monitoring module
///
/// Monitors system power events (suspend, hibernate, shutdown) to ensure
/// encrypted volumes are safely unmounted before power state transitions.

use thiserror::Error;

#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

/// Power events that can trigger callbacks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerEvent {
    /// System is about to suspend
    Suspend,

    /// System is about to hibernate
    Hibernate,

    /// System is about to shut down
    Shutdown,

    /// System is resuming from suspend/hibernate
    Resume,
}

/// Errors that can occur in power monitoring
#[derive(Debug, Error)]
pub enum PowerMonitorError {
    /// Platform not supported
    #[error("Power monitoring not supported on this platform")]
    PlatformNotSupported,

    /// Failed to register for power events
    #[error("Failed to register for power events: {0}")]
    RegistrationFailed(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Other error
    #[error("Power monitor error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, PowerMonitorError>;

/// Callback function type for power events
pub type PowerCallback = Box<dyn Fn(PowerEvent) + Send + Sync>;

/// Power state monitor
///
/// Monitors system power events and triggers callbacks when power state changes.
/// This allows for graceful handling of suspend/hibernate/shutdown events.
///
/// # Example
///
/// ```no_run
/// use tesseract::power::{PowerMonitor, PowerEvent};
///
/// let mut monitor = PowerMonitor::new();
///
/// monitor.register_callback(Box::new(move |event| {
///     match event {
///         PowerEvent::Suspend | PowerEvent::Hibernate | PowerEvent::Shutdown => {
///             println!("System power event: {:?} - unmounting volumes", event);
///             // Unmount all volumes here
///         }
///         PowerEvent::Resume => {
///             println!("System resumed");
///         }
///     }
/// }));
///
/// monitor.start().expect("Failed to start power monitor");
/// ```
pub struct PowerMonitor {
    #[cfg(windows)]
    inner: windows::WindowsPowerMonitor,

    #[cfg(target_os = "linux")]
    inner: linux::LinuxPowerMonitor,

    #[cfg(target_os = "macos")]
    inner: macos::MacOSPowerMonitor,

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    _phantom: std::marker::PhantomData<()>,
}

impl PowerMonitor {
    /// Creates a new power monitor
    pub fn new() -> Self {
        #[cfg(windows)]
        {
            Self {
                inner: windows::WindowsPowerMonitor::new(),
            }
        }

        #[cfg(target_os = "linux")]
        {
            Self {
                inner: linux::LinuxPowerMonitor::new(),
            }
        }

        #[cfg(target_os = "macos")]
        {
            Self {
                inner: macos::MacOSPowerMonitor::new(),
            }
        }

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            Self {
                _phantom: std::marker::PhantomData,
            }
        }
    }

    /// Registers a callback to be called on power events
    pub fn register_callback(&mut self, callback: PowerCallback) {
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        {
            self.inner.register_callback(callback);
        }

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            let _ = callback;
        }
    }

    /// Starts monitoring power events
    pub fn start(&mut self) -> Result<()> {
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        {
            self.inner.start()
        }

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            Err(PowerMonitorError::PlatformNotSupported)
        }
    }

    /// Stops monitoring power events
    pub fn stop(&mut self) -> Result<()> {
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        {
            self.inner.stop()
        }

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            Err(PowerMonitorError::PlatformNotSupported)
        }
    }
}

impl Default for PowerMonitor {
    fn default() -> Self {
        Self::new()
    }
}

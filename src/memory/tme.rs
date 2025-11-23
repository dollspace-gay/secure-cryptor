//! Intel Total Memory Encryption (TME) support
//!
//! This module provides detection and information about Intel Total Memory Encryption (TME),
//! a hardware-based memory encryption technology that encrypts all system memory.
//!
//! # Background
//!
//! Intel TME is a hardware feature that provides transparent encryption of all system memory
//! using AES-XTS encryption. It operates at the hardware level and requires:
//! - Intel processors with TME support (Ice Lake or newer)
//! - BIOS/firmware support and configuration
//! - Operating system awareness (not strictly required for operation)
//!
//! # Important Notes
//!
//! TME is **not** configurable from user-space applications. It must be:
//! 1. Supported by the CPU
//! 2. Enabled in the BIOS/firmware
//! 3. Configured at boot time
//!
//! This module can only **detect** if TME is available and enabled. Applications cannot
//! enable, disable, or configure TME - that must be done in the BIOS.
//!
//! # Usage
//!
//! ```no_run
//! use tesseract::memory::tme::{is_tme_supported, is_tme_enabled, TmeInfo};
//!
//! // Check if TME is supported by CPU
//! if is_tme_supported() {
//!     println!("CPU supports Intel TME");
//!
//!     // Check if TME is actually enabled
//!     if is_tme_enabled() {
//!         println!("TME is enabled - all memory is encrypted!");
//!     } else {
//!         println!("TME is supported but not enabled. Enable in BIOS.");
//!     }
//! } else {
//!     println!("CPU does not support TME");
//! }
//!
//! // Get detailed TME information
//! if let Some(info) = TmeInfo::detect() {
//!     println!("TME Version: {}", info.version);
//!     println!("Encryption Algorithm: {}", info.algorithm);
//!     println!("Key Bits: {}", info.key_bits);
//! }
//! ```
//!
//! # Platform Support
//!
//! - **x86/x86_64**: Full TME detection via CPUID
//! - **Other platforms**: Always returns false (TME is Intel-specific)
//!
//! # Security Implications
//!
//! When TME is enabled:
//! - All data in RAM is encrypted with AES-XTS
//! - Protection against physical memory attacks (cold boot, DMA)
//! - Keys are generated per-boot and stored in hardware
//! - Transparent to applications - no performance impact on crypto operations
//!
//! When TME is **not** enabled:
//! - Memory is stored in plaintext
//! - Vulnerable to physical access attacks
//! - Application-level encryption (like this library provides) is still important

use thiserror::Error;

/// Errors that can occur during TME operations
#[derive(Debug, Error)]
pub enum TmeError {
    /// CPUID instruction failed or is not available
    #[error("CPUID not available or failed")]
    CpuidFailed,

    /// TME is not supported on this CPU
    #[error("Intel TME is not supported on this CPU")]
    NotSupported,

    /// TME is supported but not enabled
    #[error("Intel TME is supported but not enabled in BIOS")]
    NotEnabled,
}

/// Result type for TME operations
pub type Result<T> = std::result::Result<T, TmeError>;

/// Information about Intel TME capabilities
#[derive(Debug, Clone)]
pub struct TmeInfo {
    /// TME version
    pub version: u32,
    /// Encryption algorithm (typically "AES-XTS")
    pub algorithm: String,
    /// Number of key bits
    pub key_bits: u32,
    /// Whether TME is currently enabled
    pub enabled: bool,
}

impl TmeInfo {
    /// Detect TME capabilities and status
    ///
    /// # Returns
    ///
    /// `Some(TmeInfo)` if TME is supported, `None` otherwise
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tesseract::memory::tme::TmeInfo;
    ///
    /// if let Some(info) = TmeInfo::detect() {
    ///     println!("TME is supported!");
    ///     println!("Algorithm: {}", info.algorithm);
    ///     println!("Enabled: {}", info.enabled);
    /// }
    /// ```
    pub fn detect() -> Option<Self> {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            // Check CPUID for TME support
            // TME is indicated by CPUID.(EAX=07H, ECX=0):ECX[bit 13] = 1
            if let Some(cpuid_result) = cpuid(0x7, 0) {
                let tme_supported = (cpuid_result.ecx & (1 << 13)) != 0;

                if !tme_supported {
                    return None;
                }

                // Get TME capabilities from CPUID.(EAX=1DH, ECX=0)
                if let Some(tme_caps) = cpuid(0x1D, 0) {
                    let enabled = (tme_caps.eax & 0x1) != 0;
                    let key_bits = tme_caps.ebx & 0xFFFF;
                    let version = (tme_caps.eax >> 1) & 0x7F;

                    return Some(Self {
                        version,
                        algorithm: "AES-XTS".to_string(),
                        key_bits,
                        enabled,
                    });
                }
            }
        }

        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            // TME is Intel x86-specific
        }

        None
    }
}

/// Check if Intel TME is supported by the CPU
///
/// This checks the CPU capabilities via CPUID. Support means the CPU has the TME feature,
/// but it may not be enabled in the BIOS.
///
/// # Returns
///
/// `true` if TME is supported by the CPU, `false` otherwise
///
/// # Example
///
/// ```no_run
/// use tesseract::memory::tme::is_tme_supported;
///
/// if is_tme_supported() {
///     println!("This CPU supports Intel TME");
/// } else {
///     println!("This CPU does not support TME");
/// }
/// ```
pub fn is_tme_supported() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if let Some(cpuid_result) = cpuid(0x7, 0) {
            return (cpuid_result.ecx & (1 << 13)) != 0;
        }
    }

    false
}

/// Check if Intel TME is currently enabled
///
/// This checks if TME is not only supported, but also actively enabled and encrypting memory.
/// TME must be enabled in the BIOS/firmware for this to return `true`.
///
/// # Returns
///
/// `true` if TME is enabled and active, `false` otherwise
///
/// # Example
///
/// ```no_run
/// use tesseract::memory::tme::is_tme_enabled;
///
/// if is_tme_enabled() {
///     println!("All system memory is encrypted with TME");
/// } else {
///     println!("TME is not active");
/// }
/// ```
pub fn is_tme_enabled() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if !is_tme_supported() {
            return false;
        }

        if let Some(tme_caps) = cpuid(0x1D, 0) {
            return (tme_caps.eax & 0x1) != 0;
        }
    }

    false
}

/// CPUID result structure
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Debug, Clone, Copy)]
struct CpuidResult {
    eax: u32,
    ebx: u32,
    ecx: u32,
    #[allow(dead_code)]
    edx: u32,
}

/// Execute CPUID instruction
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpuid(leaf: u32, subleaf: u32) -> Option<CpuidResult> {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::__cpuid_count;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::__cpuid_count;

    // First check if CPUID is available
    if !is_cpuid_available() {
        return None;
    }

    unsafe {
        let result = __cpuid_count(leaf, subleaf);
        Some(CpuidResult {
            eax: result.eax,
            ebx: result.ebx,
            ecx: result.ecx,
            edx: result.edx,
        })
    }
}

/// Check if CPUID is available
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn is_cpuid_available() -> bool {
    // On x86_64, CPUID is always available
    // On x86, we could check, but for simplicity assume it's available
    // (any modern x86 CPU has CPUID)
    true
}

/// Get a recommendation message about TME configuration
///
/// This provides user-friendly guidance based on the current TME status.
///
/// # Returns
///
/// A string with recommendations about enabling/using TME
///
/// # Example
///
/// ```no_run
/// use tesseract::memory::tme::get_tme_recommendation;
///
/// println!("{}", get_tme_recommendation());
/// ```
pub fn get_tme_recommendation() -> String {
    if is_tme_enabled() {
        "Intel TME is enabled. All system memory is encrypted with AES-XTS. \
         This provides hardware-level protection against physical memory attacks."
            .to_string()
    } else if is_tme_supported() {
        "Intel TME is supported by your CPU but not currently enabled. \
         To enable TME, reboot your system and enable it in the BIOS/firmware settings. \
         This will provide hardware-level encryption of all system memory."
            .to_string()
    } else {
        "Intel TME is not supported by your CPU. Consider using application-level \
         memory encryption and protection features provided by this library."
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tme_support_check() {
        // This will return true/false depending on CPU
        let _ = is_tme_supported();
    }

    #[test]
    fn test_tme_enabled_check() {
        // This will return true/false depending on CPU and BIOS settings
        let _ = is_tme_enabled();
    }

    #[test]
    fn test_tme_info_detect() {
        // This may return Some or None depending on hardware
        let _ = TmeInfo::detect();
    }

    #[test]
    fn test_recommendation() {
        // Should always return a valid string
        let recommendation = get_tme_recommendation();
        assert!(!recommendation.is_empty());
    }

    #[test]
    fn test_tme_logic() {
        // If TME is enabled, it must also be supported
        if is_tme_enabled() {
            assert!(is_tme_supported());
        }

        // If we have TmeInfo, it should match is_tme_supported()
        if let Some(info) = TmeInfo::detect() {
            assert!(is_tme_supported());
            assert_eq!(info.enabled, is_tme_enabled());
        }
    }

    #[test]
    fn test_tme_info_fields() {
        if let Some(info) = TmeInfo::detect() {
            // Version should be reasonable
            assert!(info.version <= 100);
            // Algorithm should be AES-XTS for TME
            assert_eq!(info.algorithm, "AES-XTS");
            // Key bits should be 128 or 256
            assert!(info.key_bits == 128 || info.key_bits == 256 || info.key_bits == 0);
        }
    }
}

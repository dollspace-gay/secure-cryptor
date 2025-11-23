//! Configuration management for Secure Cryptor.
//!
//! This module defines all configuration parameters for encryption,
//! key derivation, and file format settings.

/// Magic bytes identifying encrypted files (version 1 format).
pub const MAGIC_BYTES: &[u8] = b"SCRYPTv1";

/// AES-GCM standard nonce size (96 bits / 12 bytes).
pub const NONCE_LEN: usize = 12;

/// Maximum salt length (aligned with u8 max value).
pub const MAX_SALT_LEN: usize = 255;

/// Argon2 memory cost in KiB (64 MB).
pub const ARGON2_MEM_COST_KIB: u32 = 64 * 1024;

/// Argon2 time cost (number of iterations).
pub const ARGON2_TIME_COST: u32 = 3;

/// Argon2 parallelism (number of threads/lanes).
pub const ARGON2_LANES: u32 = 4;

/// Configuration for encryption operations.
#[derive(Debug, Clone, Copy)]
pub struct CryptoConfig {
    /// Memory cost for Argon2 key derivation (in KiB).
    pub argon2_mem_cost_kib: u32,
    /// Time cost for Argon2 (number of iterations).
    pub argon2_time_cost: u32,
    /// Number of parallel threads for Argon2.
    pub argon2_lanes: u32,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            argon2_mem_cost_kib: ARGON2_MEM_COST_KIB,
            argon2_time_cost: ARGON2_TIME_COST,
            argon2_lanes: ARGON2_LANES,
        }
    }
}

impl CryptoConfig {
    /// Creates a new configuration with custom Argon2 parameters.
    ///
    /// # Arguments
    ///
    /// * `mem_cost_kib` - Memory cost in KiB
    /// * `time_cost` - Number of iterations
    /// * `lanes` - Number of parallel threads
    ///
    /// # Examples
    ///
    /// ```
    /// # use tesseract::config::CryptoConfig;
    /// let config = CryptoConfig::new(32 * 1024, 2, 2); // Lower security, faster
    /// ```
    pub fn new(mem_cost_kib: u32, time_cost: u32, lanes: u32) -> Self {
        Self {
            argon2_mem_cost_kib: mem_cost_kib,
            argon2_time_cost: time_cost,
            argon2_lanes: lanes,
        }
    }

    /// Creates a configuration optimized for fast operations (lower security).
    ///
    /// Suitable for testing or low-security scenarios.
    pub fn fast() -> Self {
        Self::new(16 * 1024, 1, 2) // 16 MB, 1 iteration, 2 threads
    }

    /// Creates a configuration optimized for maximum security (slower).
    ///
    /// Suitable for highly sensitive data.
    pub fn paranoid() -> Self {
        Self::new(128 * 1024, 5, 8) // 128 MB, 5 iterations, 8 threads
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CryptoConfig::default();
        assert_eq!(config.argon2_mem_cost_kib, 64 * 1024);
        assert_eq!(config.argon2_time_cost, 3);
        assert_eq!(config.argon2_lanes, 4);
    }

    #[test]
    fn test_custom_config() {
        let config = CryptoConfig::new(32 * 1024, 2, 2);
        assert_eq!(config.argon2_mem_cost_kib, 32 * 1024);
        assert_eq!(config.argon2_time_cost, 2);
        assert_eq!(config.argon2_lanes, 2);
    }

    #[test]
    fn test_fast_config() {
        let config = CryptoConfig::fast();
        assert!(config.argon2_mem_cost_kib < ARGON2_MEM_COST_KIB);
        assert!(config.argon2_time_cost < ARGON2_TIME_COST);
    }

    #[test]
    fn test_paranoid_config() {
        let config = CryptoConfig::paranoid();
        assert!(config.argon2_mem_cost_kib > ARGON2_MEM_COST_KIB);
        assert!(config.argon2_time_cost > ARGON2_TIME_COST);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAGIC_BYTES, b"SCRYPTv1");
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(MAX_SALT_LEN, 255);
    }
}

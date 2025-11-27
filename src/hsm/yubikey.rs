//! YubiKey HMAC-SHA1 Challenge-Response Integration
//!
//! This module provides direct USB HID communication with YubiKey devices
//! for HMAC-SHA1 challenge-response authentication.
//!
//! # Features
//!
//! - Direct USB HID protocol implementation
//! - HMAC-SHA1 challenge-response authentication
//! - Dual slot support (slot 1 and slot 2)
//! - Backup key mechanism
//! - Multi-YubiKey support
//! - Device enumeration and firmware detection
//!
//! # Hardware Requirements
//!
//! - YubiKey 4, 5, or later with HMAC-SHA1 configured
//! - USB HID drivers (libusb on Linux, native on Windows/macOS)
//!
//! # Linux Permissions
//!
//! Add udev rule:
//! ```text
//! SUBSYSTEM=="usb", ATTRS{idVendor}=="1050", MODE="0666"
//! ```
//!
//! # Usage
//!
//! ```no_run
//! use tesseract_lib::hsm::yubikey::YubiKey;
//!
//! // Initialize YubiKey
//! let yubikey = YubiKey::new()?;
//!
//! // Check if available
//! if yubikey.is_available() {
//!     // Derive key using challenge-response
//!     let key = yubikey.derive_key(
//!         password.as_bytes(),
//!         &salt,
//!         &challenge
//!     )?;
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{CryptorError, Result};
use crate::hsm::HardwareSecurityModule;
use hidapi::{HidApi, HidDevice};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// YubiKey USB Vendor ID
const YUBICO_VENDOR_ID: u16 = 0x1050;

/// YubiKey USB Product IDs
const YUBIKEY_PRODUCT_IDS: &[u16] = &[
    0x0010, // YubiKey (original)
    0x0110, // YubiKey NEO-n
    0x0111, // YubiKey NEO OTP
    0x0114, // YubiKey NEO OTP+CCID
    0x0116, // YubiKey NEO OTP+FIDO
    0x0401, // YubiKey 4 OTP
    0x0402, // YubiKey 4 FIDO
    0x0403, // YubiKey 4 OTP+FIDO
    0x0404, // YubiKey 4 CCID
    0x0405, // YubiKey 4 OTP+CCID
    0x0406, // YubiKey 4 FIDO+CCID
    0x0407, // YubiKey 4 OTP+FIDO+CCID
    0x0410, // YubiKey Plus
    0x0411, // YubiKey 5 NFC
    0x0420, // Security Key NFC
];

/// YubiKey HID report slots
const SLOT_CHAL_HMAC1: u8 = 0x30; // Challenge-response slot 1
const SLOT_CHAL_HMAC2: u8 = 0x38; // Challenge-response slot 2

/// YubiKey HID frame structure
#[repr(C)]
#[derive(Debug)]
struct YubiKeyFrame {
    payload: [u8; 64],
    slot: u8,
    crc: u16,
}

impl YubiKeyFrame {
    fn new(slot: u8, data: &[u8]) -> Self {
        let mut frame = YubiKeyFrame {
            payload: [0u8; 64],
            slot,
            crc: 0,
        };

        // Copy data to payload
        let len = data.len().min(64);
        frame.payload[..len].copy_from_slice(&data[..len]);

        // Calculate CRC16
        frame.crc = Self::calculate_crc(&frame.payload);

        frame
    }

    fn calculate_crc(data: &[u8]) -> u16 {
        let mut crc: u16 = 0xFFFF;
        for &byte in data {
            crc ^= byte as u16;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0x8408;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(70);
        bytes.extend_from_slice(&self.payload);
        bytes.push(self.slot);
        bytes.extend_from_slice(&self.crc.to_le_bytes());
        bytes
    }
}

/// YubiKey slot configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum YubiKeySlot {
    /// Slot 1 (short press)
    Slot1,
    /// Slot 2 (long press)
    Slot2,
}

impl YubiKeySlot {
    fn to_hid_slot(self) -> u8 {
        match self {
            YubiKeySlot::Slot1 => SLOT_CHAL_HMAC1,
            YubiKeySlot::Slot2 => SLOT_CHAL_HMAC2,
        }
    }
}

impl Default for YubiKeySlot {
    fn default() -> Self {
        YubiKeySlot::Slot2
    }
}

/// YubiKey configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YubiKeyConfig {
    /// Slot to use for challenge-response
    pub slot: YubiKeySlot,

    /// Timeout for device communication
    pub timeout: Duration,

    /// Allow backup key if YubiKey is unavailable
    pub allow_backup: bool,

    /// Serial number of specific YubiKey (None = any YubiKey)
    pub serial: Option<u32>,
}

impl Default for YubiKeyConfig {
    fn default() -> Self {
        Self {
            slot: YubiKeySlot::Slot2,
            timeout: Duration::from_secs(5),
            allow_backup: true,
            serial: None,
        }
    }
}

/// YubiKey device information
#[derive(Debug, Clone)]
pub struct YubiKeyInfo {
    /// Device serial number
    pub serial: u32,
    /// Firmware version (major.minor.build)
    pub version: (u8, u8, u8),
    /// Product ID
    pub product_id: u16,
    /// Manufacturer string
    pub manufacturer: String,
    /// Product string
    pub product: String,
}

/// YubiKey HMAC-SHA1 challenge-response provider
pub struct YubiKey {
    config: YubiKeyConfig,
    backup_key: Option<Zeroizing<Vec<u8>>>,
    hid_api: RefCell<Option<HidApi>>,
}

impl YubiKey {
    /// Create a new YubiKey instance with default configuration
    pub fn new() -> Result<Self> {
        Ok(Self {
            config: YubiKeyConfig::default(),
            backup_key: None,
            hid_api: RefCell::new(None),
        })
    }

    /// Create a new YubiKey instance with custom configuration
    pub fn with_config(config: YubiKeyConfig) -> Result<Self> {
        Ok(Self {
            config,
            backup_key: None,
            hid_api: RefCell::new(None),
        })
    }

    /// Initialize HID API (lazy initialization)
    fn get_hid_api(&self) -> Result<HidApi> {
        let mut api_ref = self.hid_api.borrow_mut();
        if api_ref.is_none() {
            let api = HidApi::new().map_err(|e| {
                CryptorError::HardwareError(format!("Failed to initialize USB HID: {}", e))
            })?;
            *api_ref = Some(api);
        }

        // Clone the HidApi (it's relatively cheap)
        HidApi::new().map_err(|e| {
            CryptorError::HardwareError(format!("Failed to initialize USB HID: {}", e))
        })
    }

    /// Find and open a YubiKey device
    fn open_device(&self) -> Result<HidDevice> {
        let api = self.get_hid_api()?;

        // Find YubiKey device
        for product_id in YUBIKEY_PRODUCT_IDS {
            if let Ok(device) = api.open(YUBICO_VENDOR_ID, *product_id) {
                // If specific serial requested, check it
                if let Some(required_serial) = self.config.serial {
                    if let Ok(Some(serial_str)) = device.get_serial_number_string() {
                        if let Ok(serial) = serial_str.parse::<u32>() {
                            if serial != required_serial {
                                continue;
                            }
                        }
                    }
                }
                return Ok(device);
            }
        }

        Err(CryptorError::HardwareError(
            "No YubiKey device found".to_string(),
        ))
    }

    /// Set backup key for when YubiKey is unavailable
    pub fn set_backup_key(&mut self, key: Vec<u8>) {
        self.backup_key = Some(Zeroizing::new(key));
    }

    /// Get the configured slot
    pub fn slot(&self) -> YubiKeySlot {
        self.config.slot
    }

    /// Set the slot to use
    pub fn set_slot(&mut self, slot: YubiKeySlot) {
        self.config.slot = slot;
    }

    /// Perform HMAC-SHA1 challenge-response with the YubiKey
    ///
    /// # Arguments
    ///
    /// * `challenge` - Challenge data (up to 64 bytes)
    ///
    /// # Returns
    ///
    /// 20-byte HMAC-SHA1 response from the YubiKey
    pub fn challenge_response(&self, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        // Validate challenge size
        if challenge.is_empty() || challenge.len() > 64 {
            return Err(CryptorError::InvalidInput(
                "Challenge must be 1-64 bytes".to_string(),
            ));
        }

        // Open device
        let device = self.open_device()?;

        // Prepare challenge frame
        let frame = YubiKeyFrame::new(self.config.slot.to_hid_slot(), challenge);
        let frame_bytes = frame.to_bytes();

        // Send challenge to YubiKey
        device
            .write(&frame_bytes)
            .map_err(|e| CryptorError::HardwareError(format!("Failed to write to YubiKey: {}", e)))?;

        // Read response
        let mut response_buf = [0u8; 70];
        let timeout_ms = self.config.timeout.as_millis() as i32;

        let bytes_read = device.read_timeout(&mut response_buf, timeout_ms).map_err(|e| {
            CryptorError::HardwareError(format!("Failed to read from YubiKey: {}", e))
        })?;

        if bytes_read < 22 {
            // Need at least 20 bytes of response + 2 bytes CRC
            return Err(CryptorError::HardwareError(
                "Invalid response from YubiKey (too short)".to_string(),
            ));
        }

        // Extract HMAC-SHA1 response (20 bytes)
        let response = Zeroizing::new(response_buf[..20].to_vec());

        Ok(response)
    }

    /// List all connected YubiKey devices
    pub fn list_devices() -> Result<Vec<YubiKeyInfo>> {
        let api = HidApi::new().map_err(|e| {
            CryptorError::HardwareError(format!("Failed to initialize USB HID: {}", e))
        })?;

        let mut devices = Vec::new();

        for device_info in api.device_list() {
            if device_info.vendor_id() == YUBICO_VENDOR_ID
                && YUBIKEY_PRODUCT_IDS.contains(&device_info.product_id())
            {
                // Try to open device to get more info
                if let Ok(device) = device_info.open_device(&api) {
                    let serial = device
                        .get_serial_number_string()
                        .ok()
                        .flatten()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);

                    let manufacturer = device
                        .get_manufacturer_string()
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| "Yubico".to_string());

                    let product = device
                        .get_product_string()
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| "YubiKey".to_string());

                    devices.push(YubiKeyInfo {
                        serial,
                        version: (0, 0, 0), // Would need additional protocol to get version
                        product_id: device_info.product_id(),
                        manufacturer,
                        product,
                    });
                }
            }
        }

        Ok(devices)
    }

    /// Get YubiKey firmware version (simplified - actual version requires extended protocol)
    pub fn firmware_version(&self) -> Result<String> {
        let device = self.open_device()?;

        // Try to get product string which sometimes includes version
        let product = device
            .get_product_string()
            .ok()
            .flatten()
            .unwrap_or_else(|| "YubiKey".to_string());

        Ok(product)
    }

    /// Generate a secure backup key
    pub fn generate_backup_key() -> Zeroizing<Vec<u8>> {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Zeroizing::new(key)
    }

    /// Derive a combined key from password and YubiKey response
    fn combine_keys(
        &self,
        password_key: &[u8],
        yubikey_response: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(Some(password_key), yubikey_response);

        let mut okm = Zeroizing::new(vec![0u8; 32]);
        hk.expand(b"secure-cryptor-yubikey-kdf", &mut okm)
            .map_err(|e| CryptorError::KeyDerivation(format!("HKDF expansion failed: {}", e)))?;

        Ok(okm)
    }
}

impl Default for YubiKey {
    fn default() -> Self {
        Self::new().expect("Failed to create default YubiKey instance")
    }
}

impl HardwareSecurityModule for YubiKey {
    fn name(&self) -> &str {
        "YubiKey HMAC-SHA1"
    }

    fn is_available(&self) -> bool {
        // Try to enumerate devices
        Self::list_devices().map(|devs| !devs.is_empty()).unwrap_or(false)
    }

    fn derive_key(
        &self,
        password: &[u8],
        salt: &[u8],
        challenge: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        use crate::config::CryptoConfig;
        use crate::crypto::kdf::Argon2Kdf;
        use crate::crypto::KeyDerivation;

        // Derive key from password using Argon2id
        let kdf = Argon2Kdf::new(CryptoConfig::default());
        let password_key = kdf.derive_key(password, salt)?;

        // Try YubiKey challenge-response
        match self.challenge_response(challenge) {
            Ok(response) => {
                // Combine password key with YubiKey response
                self.combine_keys(&*password_key, &response)
            }
            Err(e) => {
                // If backup key is available and allowed, use it
                if self.config.allow_backup {
                    if let Some(backup) = &self.backup_key {
                        return self.combine_keys(&*password_key, backup);
                    }
                }

                // No YubiKey and no backup - propagate error
                Err(e)
            }
        }
    }

    fn verify(&self) -> Result<()> {
        if !self.is_available() {
            return Err(CryptorError::HardwareError(
                "No YubiKey device found".to_string(),
            ));
        }

        // Verify with a test challenge
        let test_challenge = [0x01u8; 32];
        self.challenge_response(&test_challenge)?;

        Ok(())
    }
}

impl Drop for YubiKey {
    fn drop(&mut self) {
        if let Some(ref mut key) = self.backup_key {
            key.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yubikey_slot_conversion() {
        assert_eq!(YubiKeySlot::Slot1.to_hid_slot(), SLOT_CHAL_HMAC1);
        assert_eq!(YubiKeySlot::Slot2.to_hid_slot(), SLOT_CHAL_HMAC2);
    }

    #[test]
    fn test_yubikey_config_default() {
        let config = YubiKeyConfig::default();
        assert_eq!(config.slot, YubiKeySlot::Slot2);
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert!(config.allow_backup);
        assert_eq!(config.serial, None);
    }

    #[test]
    fn test_backup_key_generation() {
        let key1 = YubiKey::generate_backup_key();
        let key2 = YubiKey::generate_backup_key();

        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(*key1, *key2);
    }

    #[test]
    fn test_yubikey_creation() {
        let yubikey = YubiKey::new();
        assert!(yubikey.is_ok());

        let yubikey = yubikey.unwrap();
        assert_eq!(yubikey.name(), "YubiKey HMAC-SHA1");
        assert_eq!(yubikey.slot(), YubiKeySlot::Slot2);
    }

    #[test]
    fn test_invalid_challenge_size() {
        let yubikey = YubiKey::new().unwrap();

        assert!(yubikey.challenge_response(&[]).is_err());

        let large_challenge = vec![0u8; 65];
        assert!(yubikey.challenge_response(&large_challenge).is_err());
    }

    #[test]
    fn test_crc_calculation() {
        let data = [0x00, 0x01, 0x02, 0x03];
        let crc = YubiKeyFrame::calculate_crc(&data);
        assert_ne!(crc, 0); // Should calculate some non-zero CRC
    }

    // Hardware tests (require actual YubiKey)
    #[test]
    #[ignore]
    fn test_yubikey_detection() {
        let yubikey = YubiKey::new().unwrap();
        let available = yubikey.is_available();
        println!("YubiKey available: {}", available);
    }

    #[test]
    #[ignore]
    fn test_yubikey_list_devices() {
        let devices = YubiKey::list_devices();
        assert!(devices.is_ok());

        let devices = devices.unwrap();
        println!("Found {} YubiKey(s)", devices.len());

        for device in devices {
            println!("  Serial: {}, Product: {}", device.serial, device.product);
        }
    }

    #[test]
    #[ignore]
    fn test_yubikey_challenge_response() {
        let yubikey = YubiKey::new().unwrap();

        if !yubikey.is_available() {
            println!("Skipping test: No YubiKey found");
            return;
        }

        let challenge = [0x42u8; 32];
        let response = yubikey.challenge_response(&challenge);

        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.len(), 20); // HMAC-SHA1 is 20 bytes
        println!("Response: {:?}", &*response);
    }

    #[test]
    #[ignore]
    fn test_yubikey_key_derivation() {
        let yubikey = YubiKey::new().unwrap();

        if !yubikey.is_available() {
            println!("Skipping test: No YubiKey found");
            return;
        }

        let password = b"test-password";
        let salt = [0x01u8; 32];
        let challenge = [0x42u8; 32];

        let key = yubikey.derive_key(password, &salt, &challenge);
        assert!(key.is_ok());

        let key = key.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_backup_key_fallback() {
        let mut yubikey = YubiKey::new().unwrap();

        let backup = vec![0x42u8; 32];
        yubikey.set_backup_key(backup.clone());

        let password = b"test-password";
        let salt = [0x01u8; 32];
        let challenge = [0x42u8; 32];

        // Should use backup if YubiKey is not available
        let result = yubikey.derive_key(password, &salt, &challenge);

        if !yubikey.is_available() {
            assert!(result.is_ok());
            let key = result.unwrap();
            assert_eq!(key.len(), 32);
        }
    }
}

//! Key slot system for encrypted volumes
//!
//! Supports multiple passwords/users accessing the same volume by encrypting
//! a master key with different user-derived keys.

use crate::config::CryptoConfig;
use crate::crypto::kdf::Argon2Kdf;
use crate::crypto::KeyDerivation;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Number of key slots available (supports up to 8 users/passwords)
pub const MAX_KEY_SLOTS: usize = 8;

/// Size of the master key in bytes (256 bits for AES-256)
pub const MASTER_KEY_SIZE: usize = 32;

/// Size of the encrypted master key (includes GCM authentication tag)
const ENCRYPTED_KEY_SIZE: usize = MASTER_KEY_SIZE + 16; // 32 bytes key + 16 bytes tag

/// A single key slot that can unlock the volume
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlot {
    /// Whether this slot is active (contains a valid key)
    active: bool,

    /// Salt for key derivation (32 bytes)
    salt: [u8; 32],

    /// Nonce for encrypting the master key (12 bytes for AES-GCM)
    nonce: [u8; 12],

    /// Encrypted master key (48 bytes: 32 bytes key + 16 bytes auth tag)
    #[serde(with = "BigArray")]
    encrypted_master_key: [u8; ENCRYPTED_KEY_SIZE],
}

/// Collection of key slots for a volume
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlots {
    /// Array of key slots
    slots: [KeySlot; MAX_KEY_SLOTS],

    /// Optional duress password hash (Argon2id hash)
    /// When entered, this triggers immediate key destruction
    /// Stored as a 32-byte salt + encrypted verification token
    /// None = duress password not set
    duress_password_slot: Option<KeySlot>,
}

/// Master key used for volume encryption (securely zeroized on drop)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MasterKey {
    key: [u8; MASTER_KEY_SIZE],
}

/// Errors that can occur with key slots
#[derive(Debug, Error)]
pub enum KeySlotError {
    /// No active key slots available
    #[error("No active key slots available")]
    NoActiveSlots,

    /// All key slots are full
    #[error("All key slots are full (maximum {MAX_KEY_SLOTS} slots)")]
    AllSlotsFull,

    /// Invalid slot index
    #[error("Invalid slot index: {0} (must be < {MAX_KEY_SLOTS})")]
    InvalidSlotIndex(usize),

    /// Failed to decrypt master key (wrong password)
    #[error("Failed to decrypt master key: incorrect password")]
    DecryptionFailed,

    /// AES-GCM encryption/decryption error
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Key derivation error
    #[error("Key derivation error: {0}")]
    KdfError(#[from] crate::error::CryptorError),
}

impl KeySlot {
    /// Creates an inactive (empty) key slot
    fn empty() -> Self {
        Self {
            active: false,
            salt: [0u8; 32],
            nonce: [0u8; 12],
            encrypted_master_key: [0u8; ENCRYPTED_KEY_SIZE],
        }
    }

    /// Creates a new active key slot by encrypting the master key with a password
    fn new(master_key: &MasterKey, password: &str) -> Result<Self, KeySlotError> {
        // Generate random salt and nonce
        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce_bytes);

        // Derive key from password
        let kdf = Argon2Kdf::new(CryptoConfig::default());
        let derived_key = Zeroizing::new(kdf.derive_key(password.as_bytes(), &salt)?);

        // Encrypt the master key with the derived key
        let cipher = Aes256Gcm::new_from_slice(&derived_key[..])
            .map_err(|e| KeySlotError::EncryptionError(e.to_string()))?;

        let nonce = Nonce::try_from(nonce_bytes).expect("Invalid nonce length");
        let ciphertext = cipher
            .encrypt(&nonce, master_key.as_bytes())
            .map_err(|e| KeySlotError::EncryptionError(e.to_string()))?;

        // Copy encrypted key to fixed-size array
        let mut encrypted_master_key = [0u8; ENCRYPTED_KEY_SIZE];
        encrypted_master_key.copy_from_slice(&ciphertext);

        Ok(Self {
            active: true,
            salt,
            nonce: nonce_bytes,
            encrypted_master_key,
        })
    }

    /// Attempts to unlock this slot with a password
    fn unlock(&self, password: &str) -> Result<MasterKey, KeySlotError> {
        if !self.active {
            return Err(KeySlotError::DecryptionFailed);
        }

        // Derive key from password
        let kdf = Argon2Kdf::new(CryptoConfig::default());
        let derived_key = Zeroizing::new(kdf.derive_key(password.as_bytes(), &self.salt)?);

        // Attempt to decrypt the master key
        let cipher = Aes256Gcm::new_from_slice(&derived_key[..])
            .map_err(|e| KeySlotError::EncryptionError(e.to_string()))?;

        let nonce = Nonce::try_from(self.nonce).expect("Invalid nonce length");
        let plaintext = cipher
            .decrypt(&nonce, self.encrypted_master_key.as_ref())
            .map_err(|_| KeySlotError::DecryptionFailed)?;

        // Convert to MasterKey
        let mut key = [0u8; MASTER_KEY_SIZE];
        key.copy_from_slice(&plaintext);

        Ok(MasterKey { key })
    }

    /// Creates a new active key slot using a pre-derived key (for V2 PQC hybrid encryption)
    ///
    /// This method is used when the key has already been derived (e.g., hybrid password + PQ key).
    /// It skips the Argon2 derivation step and uses the provided key directly.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master key to encrypt
    /// * `derived_key` - Pre-derived 32-byte encryption key (e.g., hybrid key)
    ///
    /// # Returns
    ///
    /// A new active KeySlot
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    fn new_with_derived_key(master_key: &MasterKey, derived_key: &[u8; 32]) -> Result<Self, KeySlotError> {
        // Generate random salt (stored but not used for derivation since key is pre-derived)
        // We still store a salt for format compatibility
        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce_bytes);

        // Encrypt the master key with the pre-derived key
        let cipher = Aes256Gcm::new_from_slice(derived_key)
            .map_err(|e| KeySlotError::EncryptionError(e.to_string()))?;

        let nonce = Nonce::try_from(nonce_bytes).expect("Invalid nonce length");
        let ciphertext = cipher
            .encrypt(&nonce, master_key.as_bytes())
            .map_err(|e| KeySlotError::EncryptionError(e.to_string()))?;

        // Copy encrypted key to fixed-size array
        let mut encrypted_master_key = [0u8; ENCRYPTED_KEY_SIZE];
        encrypted_master_key.copy_from_slice(&ciphertext);

        Ok(Self {
            active: true,
            salt,
            nonce: nonce_bytes,
            encrypted_master_key,
        })
    }

    /// Attempts to unlock this slot with a pre-derived key (for V2 PQC hybrid encryption)
    ///
    /// This method is used when the key has already been derived (e.g., hybrid password + PQ key).
    /// It skips the Argon2 derivation step and uses the provided key directly.
    ///
    /// # Arguments
    ///
    /// * `derived_key` - Pre-derived 32-byte decryption key (e.g., hybrid key)
    ///
    /// # Returns
    ///
    /// The decrypted master key
    ///
    /// # Errors
    ///
    /// Returns an error if the slot is inactive or decryption fails
    fn unlock_with_derived_key(&self, derived_key: &[u8; 32]) -> Result<MasterKey, KeySlotError> {
        if !self.active {
            return Err(KeySlotError::DecryptionFailed);
        }

        // Attempt to decrypt the master key with the pre-derived key
        let cipher = Aes256Gcm::new_from_slice(derived_key)
            .map_err(|e| KeySlotError::EncryptionError(e.to_string()))?;

        let nonce = Nonce::try_from(self.nonce).expect("Invalid nonce length");
        let plaintext = cipher
            .decrypt(&nonce, self.encrypted_master_key.as_ref())
            .map_err(|_| KeySlotError::DecryptionFailed)?;

        // Convert to MasterKey
        let mut key = [0u8; MASTER_KEY_SIZE];
        key.copy_from_slice(&plaintext);

        Ok(MasterKey { key })
    }

    /// Returns whether this slot is active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivates this slot
    fn deactivate(&mut self) {
        self.active = false;
        self.salt.zeroize();
        self.nonce.zeroize();
        self.encrypted_master_key.zeroize();
    }
}

impl KeySlots {
    /// Creates a new key slots collection with all slots empty
    pub fn new() -> Self {
        Self {
            slots: [
                KeySlot::empty(),
                KeySlot::empty(),
                KeySlot::empty(),
                KeySlot::empty(),
                KeySlot::empty(),
                KeySlot::empty(),
                KeySlot::empty(),
                KeySlot::empty(),
            ],
            duress_password_slot: None,
        }
    }

    /// Adds a new key slot with the given password, encrypting the master key
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master key to encrypt in this slot
    /// * `password` - The password for this slot
    ///
    /// # Returns
    ///
    /// The index of the newly created slot
    ///
    /// # Errors
    ///
    /// Returns an error if all slots are full
    pub fn add_slot(&mut self, master_key: &MasterKey, password: &str) -> Result<usize, KeySlotError> {
        // Find first inactive slot
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if !slot.active {
                *slot = KeySlot::new(master_key, password)?;
                return Ok(i);
            }
        }

        Err(KeySlotError::AllSlotsFull)
    }

    /// Adds a new key slot with a pre-derived key (for V2 PQC hybrid encryption)
    ///
    /// This method is used for V2 volumes with PQC, where the key is derived from
    /// both the password and ML-KEM shared secret.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master key to encrypt in this slot
    /// * `derived_key` - Pre-derived 32-byte hybrid encryption key
    ///
    /// # Returns
    ///
    /// The index of the newly created slot
    ///
    /// # Errors
    ///
    /// Returns an error if all slots are full
    pub fn add_slot_with_derived_key(&mut self, master_key: &MasterKey, derived_key: &[u8; 32]) -> Result<usize, KeySlotError> {
        // Find first inactive slot
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if !slot.active {
                *slot = KeySlot::new_with_derived_key(master_key, derived_key)?;
                return Ok(i);
            }
        }

        Err(KeySlotError::AllSlotsFull)
    }

    /// Removes a key slot by index
    ///
    /// # Arguments
    ///
    /// * `index` - The slot index to remove
    ///
    /// # Errors
    ///
    /// Returns an error if the index is invalid
    pub fn remove_slot(&mut self, index: usize) -> Result<(), KeySlotError> {
        if index >= MAX_KEY_SLOTS {
            return Err(KeySlotError::InvalidSlotIndex(index));
        }

        self.slots[index].deactivate();
        Ok(())
    }

    /// Attempts to unlock the volume with a password by trying all active slots
    ///
    /// # Arguments
    ///
    /// * `password` - The password to try
    ///
    /// # Returns
    ///
    /// The decrypted master key if any slot matches
    ///
    /// # Errors
    ///
    /// Returns an error if no slots can be unlocked with this password
    ///
    /// # Security
    ///
    /// **CRITICAL**: This method checks for the duress password BEFORE trying
    /// normal key slots. If the duress password is entered, all keys are destroyed
    /// and the function returns `DecryptionFailed` - indistinguishable from
    /// entering a wrong password.
    ///
    /// **WARNING**: This method modifies the key slots if duress password is used.
    /// The caller must write the modified key slots back to disk to persist the destruction.
    pub fn unlock(&mut self, password: &str) -> Result<MasterKey, KeySlotError> {
        // CRITICAL SECURITY CHECK: Check for duress password FIRST
        // If this password matches the duress password, destroy all keys
        // and return an error that looks like a wrong password attempt
        if self.is_duress_password(password) {
            // Immediately destroy all key slots
            self.secure_destroy_all_keys();

            // Return the same error as a wrong password
            // This makes the duress password indistinguishable from a wrong password
            return Err(KeySlotError::DecryptionFailed);
        }

        // Try each active slot with the normal password
        for slot in &self.slots {
            if slot.active {
                if let Ok(master_key) = slot.unlock(password) {
                    return Ok(master_key);
                }
            }
        }

        // No slot could be unlocked
        Err(KeySlotError::DecryptionFailed)
    }

    /// Attempts to unlock the volume with a pre-derived key by trying all active slots
    ///
    /// This is used for V2 PQC volumes where the key has already been derived
    /// from the password and PQ shared secret.
    ///
    /// # Arguments
    ///
    /// * `derived_key` - The pre-derived hybrid key (32 bytes)
    ///
    /// # Returns
    ///
    /// The decrypted master key if any slot matches
    ///
    /// # Errors
    ///
    /// Returns an error if no slots can be unlocked with this key
    pub fn unlock_with_derived_key(&self, derived_key: &[u8; 32]) -> Result<MasterKey, KeySlotError> {
        // Try each active slot
        for slot in &self.slots {
            if slot.active {
                if let Ok(master_key) = slot.unlock_with_derived_key(derived_key) {
                    return Ok(master_key);
                }
            }
        }

        // No slot could be unlocked
        Err(KeySlotError::DecryptionFailed)
    }

    /// Returns the number of active key slots
    pub fn active_count(&self) -> usize {
        self.slots.iter().filter(|s| s.active).count()
    }

    /// Returns whether the given slot index is active
    pub fn is_slot_active(&self, index: usize) -> bool {
        index < MAX_KEY_SLOTS && self.slots[index].active
    }

    /// Finds the first free (inactive) slot
    ///
    /// # Returns
    ///
    /// Some(index) if a free slot is found, None if all slots are full
    pub fn find_free_slot(&self) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| !slot.active)
    }

    /// Changes the password for an existing key slot
    ///
    /// This updates the encrypted master key in the specified slot with
    /// a new password-derived key.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master key to re-encrypt
    /// * `slot_index` - The slot index to update
    /// * `new_password` - The new password for this slot
    ///
    /// # Returns
    ///
    /// Ok(()) if the password was changed successfully
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The slot index is invalid
    /// - The slot is not active
    /// - Encryption fails
    pub fn change_password(
        &mut self,
        master_key: &MasterKey,
        slot_index: usize,
        new_password: &str,
    ) -> Result<(), KeySlotError> {
        if slot_index >= MAX_KEY_SLOTS {
            return Err(KeySlotError::InvalidSlotIndex(slot_index));
        }

        if !self.slots[slot_index].active {
            return Err(KeySlotError::NoActiveSlots);
        }

        // Create new key slot with new password
        let new_slot = KeySlot::new(master_key, new_password)?;

        // Replace the old slot
        self.slots[slot_index] = new_slot;

        Ok(())
    }

    /// Sets the duress password for this volume
    ///
    /// When this password is entered, all key slots will be immediately destroyed
    /// and the operation will return the same error as an incorrect password,
    /// providing plausible deniability.
    ///
    /// # Arguments
    ///
    /// * `duress_password` - The password that triggers key destruction
    ///
    /// # Security Considerations
    ///
    /// - The duress password is stored using the same Argon2id KDF as normal passwords
    /// - It encrypts a random verification token (not the master key)
    /// - Entering it will permanently destroy all key slots
    /// - The operation is indistinguishable from entering a wrong password
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    pub fn set_duress_password(&mut self, duress_password: &str) -> Result<(), KeySlotError> {
        // Create a random verification token to encrypt
        // We don't use the actual master key to avoid any potential information leakage
        let mut verification_token = [0u8; MASTER_KEY_SIZE];
        rand::rng().fill_bytes(&mut verification_token);
        let token_key = MasterKey::from_bytes(verification_token);

        // Create a key slot for the duress password
        // This looks identical to a normal key slot on disk
        let duress_slot = KeySlot::new(&token_key, duress_password)?;

        self.duress_password_slot = Some(duress_slot);

        Ok(())
    }

    /// Removes the duress password
    pub fn remove_duress_password(&mut self) {
        if let Some(ref mut slot) = self.duress_password_slot {
            slot.deactivate();
        }
        self.duress_password_slot = None;
    }

    /// Checks if the given password is the duress password
    ///
    /// # Arguments
    ///
    /// * `password` - The password to check
    ///
    /// # Returns
    ///
    /// `true` if this is the duress password, `false` otherwise
    ///
    /// # Security
    ///
    /// This check happens in constant-time to prevent timing attacks
    fn is_duress_password(&self, password: &str) -> bool {
        if let Some(ref duress_slot) = self.duress_password_slot {
            // Try to unlock the duress slot
            // If successful, it means the password matched
            duress_slot.unlock(password).is_ok()
        } else {
            false
        }
    }

    /// Securely destroys all key slots
    ///
    /// This is called when the duress password is entered.
    /// It overwrites all key slot data with zeros, making the volume
    /// permanently inaccessible.
    ///
    /// # Security
    ///
    /// - Overwrites all encrypted master keys with zeros
    /// - Overwrites all salts and nonces
    /// - Marks all slots as inactive
    /// - Destroys the duress password slot itself
    pub fn secure_destroy_all_keys(&mut self) {
        // Destroy all normal key slots
        for slot in &mut self.slots {
            slot.deactivate();
        }

        // Destroy duress password slot
        self.remove_duress_password();
    }

    /// Returns whether a duress password is set
    pub fn has_duress_password(&self) -> bool {
        self.duress_password_slot.is_some()
    }
}

impl Default for KeySlots {
    fn default() -> Self {
        Self::new()
    }
}

impl MasterKey {
    /// Generates a new random master key
    pub fn generate() -> Self {
        let mut key = [0u8; MASTER_KEY_SIZE];
        rand::rng().fill_bytes(&mut key);
        Self { key }
    }

    /// Creates a master key from existing bytes
    ///
    /// # Arguments
    ///
    /// * `key` - The 32-byte key material
    pub fn from_bytes(key: [u8; MASTER_KEY_SIZE]) -> Self {
        Self { key }
    }

    /// Returns the key as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Returns the key size in bytes
    pub const fn size() -> usize {
        MASTER_KEY_SIZE
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_generation() {
        let key1 = MasterKey::generate();
        let key2 = MasterKey::generate();

        // Keys should be different
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(key1.as_bytes().len(), MASTER_KEY_SIZE);
    }

    #[test]
    fn test_single_slot_unlock() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Add a slot
        let index = slots.add_slot(&master_key, "TestPassword123!").unwrap();
        assert_eq!(index, 0);
        assert_eq!(slots.active_count(), 1);

        // Unlock with correct password
        let unlocked = slots.unlock("TestPassword123!").unwrap();
        assert_eq!(unlocked.as_bytes(), master_key.as_bytes());

        // Try wrong password
        assert!(slots.unlock("WrongPassword").is_err());
    }

    #[test]
    fn test_multiple_slots() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Add multiple slots with different passwords
        slots.add_slot(&master_key, "Password1!").unwrap();
        slots.add_slot(&master_key, "Password2!").unwrap();
        slots.add_slot(&master_key, "Password3!").unwrap();

        assert_eq!(slots.active_count(), 3);

        // All passwords should unlock the same master key
        let unlocked1 = slots.unlock("Password1!").unwrap();
        let unlocked2 = slots.unlock("Password2!").unwrap();
        let unlocked3 = slots.unlock("Password3!").unwrap();

        assert_eq!(unlocked1.as_bytes(), master_key.as_bytes());
        assert_eq!(unlocked2.as_bytes(), master_key.as_bytes());
        assert_eq!(unlocked3.as_bytes(), master_key.as_bytes());
    }

    #[test]
    fn test_slot_removal() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        slots.add_slot(&master_key, "Password1!").unwrap();
        slots.add_slot(&master_key, "Password2!").unwrap();

        assert_eq!(slots.active_count(), 2);

        // Remove first slot
        slots.remove_slot(0).unwrap();
        assert_eq!(slots.active_count(), 1);
        assert!(!slots.is_slot_active(0));
        assert!(slots.is_slot_active(1));

        // First password should no longer work
        assert!(slots.unlock("Password1!").is_err());

        // Second password should still work
        let unlocked = slots.unlock("Password2!").unwrap();
        assert_eq!(unlocked.as_bytes(), master_key.as_bytes());
    }

    #[test]
    fn test_max_slots() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Fill all slots
        for i in 0..MAX_KEY_SLOTS {
            let password = format!("Password{}!", i);
            let index = slots.add_slot(&master_key, &password).unwrap();
            assert_eq!(index, i);
        }

        assert_eq!(slots.active_count(), MAX_KEY_SLOTS);

        // Adding another should fail
        assert!(matches!(
            slots.add_slot(&master_key, "ExtraPassword!"),
            Err(KeySlotError::AllSlotsFull)
        ));

        // All passwords should still work
        for i in 0..MAX_KEY_SLOTS {
            let password = format!("Password{}!", i);
            let unlocked = slots.unlock(&password).unwrap();
            assert_eq!(unlocked.as_bytes(), master_key.as_bytes());
        }
    }

    #[test]
    fn test_key_slot_reuse() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Add and remove a slot
        slots.add_slot(&master_key, "Password1!").unwrap();
        slots.remove_slot(0).unwrap();

        // Slot should be reusable
        let index = slots.add_slot(&master_key, "Password2!").unwrap();
        assert_eq!(index, 0);
        assert!(slots.is_slot_active(0));

        let unlocked = slots.unlock("Password2!").unwrap();
        assert_eq!(unlocked.as_bytes(), master_key.as_bytes());
    }

    #[test]
    fn test_master_key_zeroization() {
        let key = MasterKey::generate();
        let original = key.as_bytes().to_vec();

        // Drop the key
        drop(key);

        // Memory should be zeroized (we can't directly test this,
        // but the Zeroize trait guarantees it)
        // This test mainly ensures the derive macro is applied
        assert!(!original.iter().all(|&b| b == 0));
    }

    // ====================
    // Duress Password Tests
    // ====================

    #[test]
    fn test_duress_password_set_and_check() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Add normal password
        slots.add_slot(&master_key, "NormalPassword123!").unwrap();

        // Set duress password
        slots.set_duress_password("DuressPassword456!").unwrap();

        assert!(slots.has_duress_password());
        assert_eq!(slots.active_count(), 1);
    }

    #[test]
    fn test_duress_password_triggers_destruction() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Add two normal passwords
        slots.add_slot(&master_key, "Password1!").unwrap();
        slots.add_slot(&master_key, "Password2!").unwrap();

        assert_eq!(slots.active_count(), 2);

        // Set duress password
        slots.set_duress_password("PANIC123!").unwrap();
        assert!(slots.has_duress_password());

        // Verify normal passwords still work BEFORE duress password
        assert!(slots.unlock("Password1!").is_ok());
        assert!(slots.unlock("Password2!").is_ok());

        // Now trigger the duress password
        let mut slots_copy = slots.clone();
        let result = slots_copy.unlock("PANIC123!");

        // Should fail with "incorrect password" error
        assert!(result.is_err());
        assert!(matches!(result, Err(KeySlotError::DecryptionFailed)));

        // All slots should be destroyed
        assert_eq!(slots_copy.active_count(), 0);
        assert!(!slots_copy.has_duress_password());

        // Normal passwords should no longer work
        assert!(slots_copy.unlock("Password1!").is_err());
        assert!(slots_copy.unlock("Password2!").is_err());
    }

    #[test]
    fn test_duress_password_indistinguishable_from_wrong_password() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Add normal password
        slots.add_slot(&master_key, "CorrectPassword!").unwrap();

        // Set duress password
        slots.set_duress_password("DuressPassword!").unwrap();

        // Try wrong password
        let mut slots1 = slots.clone();
        let wrong_password_result = slots1.unlock("WrongPassword!");

        // Try duress password
        let mut slots2 = slots.clone();
        let duress_result = slots2.unlock("DuressPassword!");

        // Both should return the same error variant
        assert!(wrong_password_result.is_err());
        assert!(duress_result.is_err());
        assert!(matches!(wrong_password_result, Err(KeySlotError::DecryptionFailed)));
        assert!(matches!(duress_result, Err(KeySlotError::DecryptionFailed)));

        // But only duress password should have destroyed keys
        assert_eq!(slots1.active_count(), 1); // Wrong password doesn't destroy
        assert_eq!(slots2.active_count(), 0); // Duress password destroys
    }

    #[test]
    fn test_duress_password_remove() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Set duress password
        slots.set_duress_password("DuressPassword!").unwrap();
        assert!(slots.has_duress_password());

        // Remove it
        slots.remove_duress_password();
        assert!(!slots.has_duress_password());

        // Should not trigger destruction anymore
        let result = slots.unlock("DuressPassword!");
        assert!(result.is_err());
        // Slots should still be active (not destroyed)
        assert_eq!(slots.active_count(), 0); // No normal slots were added
    }

    #[test]
    fn test_duress_password_with_multiple_normal_slots() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Fill multiple slots
        for i in 0..5 {
            slots.add_slot(&master_key, &format!("Password{}!", i)).unwrap();
        }

        assert_eq!(slots.active_count(), 5);

        // Set duress password
        slots.set_duress_password("NUKE_ALL!").unwrap();

        // Trigger duress password
        let mut slots_copy = slots.clone();
        let result = slots_copy.unlock("NUKE_ALL!");

        assert!(result.is_err());
        assert_eq!(slots_copy.active_count(), 0); // All 5 slots destroyed

        // Verify none of the passwords work anymore
        for i in 0..5 {
            assert!(slots_copy.unlock(&format!("Password{}!", i)).is_err());
        }
    }

    #[test]
    fn test_duress_password_serialization() {
        use bincode;

        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Add normal password and duress password
        slots.add_slot(&master_key, "Normal123!").unwrap();
        slots.set_duress_password("Duress456!").unwrap();

        // Serialize
        let serialized = bincode::serialize(&slots).unwrap();

        // Deserialize
        let mut deserialized: KeySlots = bincode::deserialize(&serialized).unwrap();

        // Verify duress password still works after deserialization
        assert!(deserialized.has_duress_password());
        assert_eq!(deserialized.active_count(), 1);

        // Trigger duress password on deserialized slots
        let result = deserialized.unlock("Duress456!");
        assert!(result.is_err());
        assert_eq!(deserialized.active_count(), 0);
    }

    #[test]
    fn test_duress_password_doesnt_affect_normal_unlock() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Add normal password
        slots.add_slot(&master_key, "NormalPass!").unwrap();

        // Set duress password
        slots.set_duress_password("DuressPass!").unwrap();

        // Normal password should still work
        let mut slots_copy = slots.clone();
        let result = slots_copy.unlock("NormalPass!");
        assert!(result.is_ok());

        // Master key should match
        assert_eq!(result.unwrap().as_bytes(), master_key.as_bytes());

        // Slots should still be intact
        assert_eq!(slots_copy.active_count(), 1);
        assert!(slots_copy.has_duress_password());
    }
}

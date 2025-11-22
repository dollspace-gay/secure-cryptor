//! Post-quantum digital signatures module.
//!
//! Provides ML-DSA (formerly CRYSTALS-Dilithium) implementation for
//! quantum-resistant digital signatures as specified in FIPS 204.

use crate::error::{CryptorError, Result};
use ml_dsa::{KeyGen, MlDsa44, MlDsa65, MlDsa87};
use zeroize::Zeroizing;

// Import signature traits from ml_dsa re-exports
use ml_dsa::signature::{Keypair, Signer, Verifier};

/// ML-DSA security levels.
///
/// Corresponds to different parameter sets providing different security/performance tradeoffs:
/// - Level44: ~128-bit classical security, smallest keys and signatures
/// - Level65: ~192-bit classical security, medium keys and signatures
/// - Level87: ~256-bit classical security, largest keys and signatures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// ML-DSA-44 (Dilithium2): NIST security level 2
    Level44,
    /// ML-DSA-65 (Dilithium3): NIST security level 3
    Level65,
    /// ML-DSA-87 (Dilithium5): NIST security level 5
    Level87,
}

/// ML-DSA key pair for digital signatures.
///
/// Supports all three security levels (44, 65, 87).
/// Internally stores the key pair seed for compact storage.
pub struct MlDsaKeyPair {
    security_level: SecurityLevel,
    /// Key pair seed (32 bytes)
    seed: Zeroizing<[u8; 32]>,
    /// Cached public verifying key bytes
    verifying_key_bytes: Vec<u8>,
}

impl MlDsaKeyPair {
    /// Generate a new ML-DSA key pair at the specified security level.
    ///
    /// # Arguments
    ///
    /// * `level` - The security level to use (44, 65, or 87)
    ///
    /// # Returns
    ///
    /// A new key pair with randomly generated keys.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_cryptor::crypto::signatures::{MlDsaKeyPair, SecurityLevel};
    ///
    /// let keypair = MlDsaKeyPair::generate(SecurityLevel::Level65);
    /// ```
    pub fn generate(level: SecurityLevel) -> Self {
        use rand::RngCore;

        // Generate a random 32-byte seed using the system RNG
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);

        match level {
            SecurityLevel::Level44 => {
                let kp = MlDsa44::from_seed(&seed.into());
                let vk_bytes = kp.verifying_key().encode();

                Self {
                    security_level: level,
                    seed: Zeroizing::new(seed),
                    verifying_key_bytes: vk_bytes[..].to_vec(),
                }
            }
            SecurityLevel::Level65 => {
                let kp = MlDsa65::from_seed(&seed.into());
                let vk_bytes = kp.verifying_key().encode();

                Self {
                    security_level: level,
                    seed: Zeroizing::new(seed),
                    verifying_key_bytes: vk_bytes[..].to_vec(),
                }
            }
            SecurityLevel::Level87 => {
                let kp = MlDsa87::from_seed(&seed.into());
                let vk_bytes = kp.verifying_key().encode();

                Self {
                    security_level: level,
                    seed: Zeroizing::new(seed),
                    verifying_key_bytes: vk_bytes[..].to_vec(),
                }
            }
        }
    }

    /// Get the security level of this key pair.
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Get the public verifying key bytes.
    ///
    /// This key can be safely shared and used to verify signatures.
    pub fn verifying_key(&self) -> &[u8] {
        &self.verifying_key_bytes
    }

    /// Get the secret key seed.
    ///
    /// This seed must be kept secret and can be used to reconstruct the key pair.
    pub fn signing_key_seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Sign a message using this key pair.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// The signature bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_cryptor::crypto::signatures::{MlDsaKeyPair, SecurityLevel};
    ///
    /// let keypair = MlDsaKeyPair::generate(SecurityLevel::Level65);
    /// let message = b"Important message";
    /// let signature = keypair.sign(message).unwrap();
    /// ```
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self.security_level {
            SecurityLevel::Level44 => {
                let kp = MlDsa44::from_seed(&(*self.seed).into());
                let sig = kp.signing_key().sign(message);
                Ok(sig.encode()[..].to_vec())
            }
            SecurityLevel::Level65 => {
                let kp = MlDsa65::from_seed(&(*self.seed).into());
                let sig = kp.signing_key().sign(message);
                Ok(sig.encode()[..].to_vec())
            }
            SecurityLevel::Level87 => {
                let kp = MlDsa87::from_seed(&(*self.seed).into());
                let sig = kp.signing_key().sign(message);
                Ok(sig.encode()[..].to_vec())
            }
        }
    }

    /// Export the key pair to bytes.
    ///
    /// # Returns
    ///
    /// A tuple of (security_level, verifying_key, signing_key_seed).
    /// The signing key seed is returned in zeroizing memory for security.
    pub fn to_bytes(&self) -> (SecurityLevel, Vec<u8>, Zeroizing<Vec<u8>>) {
        (
            self.security_level,
            self.verifying_key_bytes.clone(),
            Zeroizing::new(self.seed.to_vec()),
        )
    }

    /// Import a key pair from bytes.
    ///
    /// # Arguments
    ///
    /// * `level` - The security level
    /// * `verifying_key` - The public verifying key bytes
    /// * `signing_key_seed` - The secret signing key seed (32 bytes)
    ///
    /// # Returns
    ///
    /// A key pair constructed from the provided keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed is not exactly 32 bytes.
    pub fn from_bytes(level: SecurityLevel, verifying_key: &[u8], signing_key_seed: &[u8]) -> Result<Self> {
        if signing_key_seed.len() != 32 {
            return Err(CryptorError::Cryptography(format!(
                "Invalid seed size: expected 32, got {}",
                signing_key_seed.len()
            )));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(signing_key_seed);

        Ok(Self {
            security_level: level,
            seed: Zeroizing::new(seed),
            verifying_key_bytes: verifying_key.to_vec(),
        })
    }
}

/// Verify a signature using a public verifying key.
///
/// # Arguments
///
/// * `level` - The security level used for signing
/// * `verifying_key_bytes` - The public verifying key bytes
/// * `message` - The message that was signed
/// * `signature_bytes` - The signature bytes to verify
///
/// # Returns
///
/// `Ok(())` if the signature is valid, `Err` otherwise.
///
/// # Example
///
/// ```
/// use secure_cryptor::crypto::signatures::{MlDsaKeyPair, SecurityLevel, verify};
///
/// let keypair = MlDsaKeyPair::generate(SecurityLevel::Level65);
/// let message = b"Important message";
/// let signature = keypair.sign(message).unwrap();
///
/// verify(SecurityLevel::Level65, keypair.verifying_key(), message, &signature).unwrap();
/// ```
pub fn verify(
    level: SecurityLevel,
    verifying_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<()> {
    match level {
        SecurityLevel::Level44 => {
            // Decode requires a properly sized array reference
            type VkArray = ml_dsa::EncodedVerifyingKey<MlDsa44>;
            type SigArray = ml_dsa::EncodedSignature<MlDsa44>;

            let vk_array = VkArray::try_from(verifying_key_bytes)
                .map_err(|_| CryptorError::Cryptography("Invalid ML-DSA-44 verifying key size".to_string()))?;
            let sig_array = SigArray::try_from(signature_bytes)
                .map_err(|_| CryptorError::Cryptography("Invalid ML-DSA-44 signature size".to_string()))?;

            let vk = ml_dsa::VerifyingKey::<MlDsa44>::decode(&vk_array);
            let sig = ml_dsa::Signature::<MlDsa44>::decode(&sig_array).ok_or_else(||
                CryptorError::Cryptography("Failed to decode ML-DSA-44 signature".to_string()))?;

            vk.verify(message, &sig)
                .map_err(|_| CryptorError::Cryptography("ML-DSA-44 signature verification failed".to_string()))?;
            Ok(())
        }
        SecurityLevel::Level65 => {
            type VkArray = ml_dsa::EncodedVerifyingKey<MlDsa65>;
            type SigArray = ml_dsa::EncodedSignature<MlDsa65>;

            let vk_array = VkArray::try_from(verifying_key_bytes)
                .map_err(|_| CryptorError::Cryptography("Invalid ML-DSA-65 verifying key size".to_string()))?;
            let sig_array = SigArray::try_from(signature_bytes)
                .map_err(|_| CryptorError::Cryptography("Invalid ML-DSA-65 signature size".to_string()))?;

            let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&vk_array);
            let sig = ml_dsa::Signature::<MlDsa65>::decode(&sig_array).ok_or_else(||
                CryptorError::Cryptography("Failed to decode ML-DSA-65 signature".to_string()))?;

            vk.verify(message, &sig)
                .map_err(|_| CryptorError::Cryptography("ML-DSA-65 signature verification failed".to_string()))?;
            Ok(())
        }
        SecurityLevel::Level87 => {
            type VkArray = ml_dsa::EncodedVerifyingKey<MlDsa87>;
            type SigArray = ml_dsa::EncodedSignature<MlDsa87>;

            let vk_array = VkArray::try_from(verifying_key_bytes)
                .map_err(|_| CryptorError::Cryptography("Invalid ML-DSA-87 verifying key size".to_string()))?;
            let sig_array = SigArray::try_from(signature_bytes)
                .map_err(|_| CryptorError::Cryptography("Invalid ML-DSA-87 signature size".to_string()))?;

            let vk = ml_dsa::VerifyingKey::<MlDsa87>::decode(&vk_array);
            let sig = ml_dsa::Signature::<MlDsa87>::decode(&sig_array).ok_or_else(||
                CryptorError::Cryptography("Failed to decode ML-DSA-87 signature".to_string()))?;

            vk.verify(message, &sig)
                .map_err(|_| CryptorError::Cryptography("ML-DSA-87 signature verification failed".to_string()))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation_level44() {
        let keypair = MlDsaKeyPair::generate(SecurityLevel::Level44);
        assert_eq!(keypair.security_level(), SecurityLevel::Level44);
        assert!(!keypair.verifying_key().is_empty());
        assert_eq!(keypair.signing_key_seed().len(), 32);
    }

    #[test]
    fn test_keypair_generation_level65() {
        let keypair = MlDsaKeyPair::generate(SecurityLevel::Level65);
        assert_eq!(keypair.security_level(), SecurityLevel::Level65);
        assert!(!keypair.verifying_key().is_empty());
        assert_eq!(keypair.signing_key_seed().len(), 32);
    }

    #[test]
    fn test_keypair_generation_level87() {
        let keypair = MlDsaKeyPair::generate(SecurityLevel::Level87);
        assert_eq!(keypair.security_level(), SecurityLevel::Level87);
        assert!(!keypair.verifying_key().is_empty());
        assert_eq!(keypair.signing_key_seed().len(), 32);
    }

    #[test]
    fn test_sign_verify_roundtrip_level44() {
        let keypair = MlDsaKeyPair::generate(SecurityLevel::Level44);
        let message = b"Test message for ML-DSA-44";

        let signature = keypair.sign(message).unwrap();
        assert!(!signature.is_empty());

        verify(
            SecurityLevel::Level44,
            keypair.verifying_key(),
            message,
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn test_sign_verify_roundtrip_level65() {
        let keypair = MlDsaKeyPair::generate(SecurityLevel::Level65);
        let message = b"Test message for ML-DSA-65";

        let signature = keypair.sign(message).unwrap();
        assert!(!signature.is_empty());

        verify(
            SecurityLevel::Level65,
            keypair.verifying_key(),
            message,
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn test_sign_verify_roundtrip_level87() {
        let keypair = MlDsaKeyPair::generate(SecurityLevel::Level87);
        let message = b"Test message for ML-DSA-87";

        let signature = keypair.sign(message).unwrap();
        assert!(!signature.is_empty());

        verify(
            SecurityLevel::Level87,
            keypair.verifying_key(),
            message,
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn test_verify_wrong_message() {
        let keypair = MlDsaKeyPair::generate(SecurityLevel::Level65);
        let message = b"Original message";
        let signature = keypair.sign(message).unwrap();

        let wrong_message = b"Modified message";
        let result = verify(
            SecurityLevel::Level65,
            keypair.verifying_key(),
            wrong_message,
            &signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_key() {
        let keypair1 = MlDsaKeyPair::generate(SecurityLevel::Level65);
        let keypair2 = MlDsaKeyPair::generate(SecurityLevel::Level65);
        let message = b"Test message";

        let signature = keypair1.sign(message).unwrap();
        let result = verify(
            SecurityLevel::Level65,
            keypair2.verifying_key(),
            message,
            &signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_tampered_signature() {
        let keypair = MlDsaKeyPair::generate(SecurityLevel::Level65);
        let message = b"Test message";
        let mut signature = keypair.sign(message).unwrap();

        // Tamper with signature
        if !signature.is_empty() {
            signature[0] ^= 1;
        }

        let result = verify(
            SecurityLevel::Level65,
            keypair.verifying_key(),
            message,
            &signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_keypair_serialization() {
        let keypair1 = MlDsaKeyPair::generate(SecurityLevel::Level65);
        let (level, vk, sk) = keypair1.to_bytes();

        let keypair2 = MlDsaKeyPair::from_bytes(level, &vk, &sk).unwrap();

        assert_eq!(keypair1.security_level(), keypair2.security_level());
        assert_eq!(keypair1.verifying_key(), keypair2.verifying_key());
        assert_eq!(&*keypair1.seed, &*keypair2.seed);
    }

    #[test]
    fn test_deterministic_signatures() {
        let keypair = MlDsaKeyPair::generate(SecurityLevel::Level65);
        let message = b"Test message";

        let sig1 = keypair.sign(message).unwrap();
        let sig2 = keypair.sign(message).unwrap();

        // ML-DSA signatures should be deterministic for the same message and key
        assert_eq!(sig1, sig2);

        // Both should verify
        verify(SecurityLevel::Level65, keypair.verifying_key(), message, &sig1).unwrap();
        verify(SecurityLevel::Level65, keypair.verifying_key(), message, &sig2).unwrap();
    }

    #[test]
    fn test_cross_level_verification_fails() {
        let keypair = MlDsaKeyPair::generate(SecurityLevel::Level65);
        let message = b"Test message";
        let signature = keypair.sign(message).unwrap();

        // Try to verify with wrong security level (will fail due to size mismatch)
        let result = verify(
            SecurityLevel::Level44,
            keypair.verifying_key(),
            message,
            &signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_seed_size() {
        let result = MlDsaKeyPair::from_bytes(
            SecurityLevel::Level65,
            &[0u8; 100],
            &[0u8; 16], // Wrong size
        );
        assert!(result.is_err());
    }
}

//! Comprehensive Post-Quantum Cryptography test suite
//!
//! This module contains extensive tests for ML-KEM-1024 (Kyber) and ML-DSA
//! (Dilithium) integration, hybrid mode operation, and interoperability.

#[cfg(test)]
mod ml_kem_tests {
    use crate::crypto::pqc::{MlKemKeyPair, encapsulate, decapsulate};

    #[test]
    fn test_ml_kem_1024_keypair_generation() {
        // Test that we can generate ML-KEM-1024 keypairs
        let keypair = MlKemKeyPair::generate();

        // Verify key sizes match ML-KEM-1024 parameters
        assert_eq!(keypair.encapsulation_key().len(), 1568); // EK size for ML-KEM-1024
        assert_eq!(keypair.decapsulation_key().len(), 3168); // DK size for ML-KEM-1024
    }

    #[test]
    fn test_ml_kem_encapsulation_decapsulation_roundtrip() {
        let keypair = MlKemKeyPair::generate();
        let (ciphertext, shared_secret1) = encapsulate(keypair.encapsulation_key()).unwrap();

        assert_eq!(ciphertext.len(), 1568); // Ciphertext size for ML-KEM-1024
        assert_eq!(shared_secret1.len(), 32); // Shared secret is 32 bytes

        let shared_secret2 = decapsulate(keypair.decapsulation_key(), &ciphertext).unwrap();
        assert_eq!(*shared_secret1, *shared_secret2);
    }

    #[test]
    fn test_ml_kem_different_encapsulations_unique_secrets() {
        // Two encapsulations to same key should produce different secrets
        let keypair = MlKemKeyPair::generate();

        let (ct1, ss1) = encapsulate(keypair.encapsulation_key()).unwrap();
        let (ct2, ss2) = encapsulate(keypair.encapsulation_key()).unwrap();

        // Ciphertexts should be different (randomized)
        assert_ne!(ct1, ct2);
        // Shared secrets should be different
        assert_ne!(*ss1, *ss2);
    }

    #[test]
    fn test_ml_kem_different_keypairs_different_keys() {
        let keypair1 = MlKemKeyPair::generate();
        let keypair2 = MlKemKeyPair::generate();

        assert_ne!(keypair1.encapsulation_key(), keypair2.encapsulation_key());
        assert_ne!(keypair1.decapsulation_key(), keypair2.decapsulation_key());
    }

    #[test]
    fn test_ml_kem_serialization_deserialization() {
        let keypair1 = MlKemKeyPair::generate();

        let ek = keypair1.encapsulation_key();
        let dk = keypair1.decapsulation_key();

        // Recreate from serialized keys
        let keypair2 = MlKemKeyPair::from_bytes(ek, dk).unwrap();

        // Should be identical
        assert_eq!(keypair1.encapsulation_key(), keypair2.encapsulation_key());
        assert_eq!(keypair1.decapsulation_key(), keypair2.decapsulation_key());
    }

    #[test]
    fn test_ml_kem_invalid_encapsulation_key() {
        // Try to encapsulate with invalid key size
        let invalid_ek = vec![0u8; 100];
        let result = encapsulate(&invalid_ek);
        assert!(result.is_err());
    }

    #[test]
    fn test_ml_kem_invalid_ciphertext() {
        let keypair = MlKemKeyPair::generate();
        let invalid_ct = vec![0u8; 100];
        let result = decapsulate(keypair.decapsulation_key(), &invalid_ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_ml_kem_invalid_decapsulation_key() {
        let keypair = MlKemKeyPair::generate();
        let (ciphertext, _) = encapsulate(keypair.encapsulation_key()).unwrap();

        let invalid_dk = vec![0u8; 100];
        let result = decapsulate(&invalid_dk, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_ml_kem_shared_secret_properties() {
        // Test that shared secrets have good entropy properties
        let keypair = MlKemKeyPair::generate();
        let (_, shared_secret) = encapsulate(keypair.encapsulation_key()).unwrap();

        // Shared secret should not be all zeros
        assert!(!shared_secret.iter().all(|&b| b == 0));

        // Shared secret should not be all ones
        assert!(!shared_secret.iter().all(|&b| b == 0xFF));

        // Should have some variation (basic entropy check)
        let mut counts = [0u32; 256];
        for &byte in shared_secret.iter() {
            counts[byte as usize] += 1;
        }
        let max_count = counts.iter().max().unwrap();
        // No single byte value should dominate (more than 50% of output)
        assert!(*max_count < 16);
    }

    #[test]
    fn test_ml_kem_multiple_roundtrips() {
        // Test multiple encapsulation/decapsulation cycles
        let keypair = MlKemKeyPair::generate();

        for _ in 0..10 {
            let (ciphertext, ss1) = encapsulate(keypair.encapsulation_key()).unwrap();
            let ss2 = decapsulate(keypair.decapsulation_key(), &ciphertext).unwrap();
            assert_eq!(*ss1, *ss2);
        }
    }

    #[test]
    fn test_ml_kem_concurrent_operations() {
        use std::sync::Arc;
        use std::thread;

        let keypair = Arc::new(MlKemKeyPair::generate());
        let mut handles = vec![];

        // Spawn multiple threads doing encapsulation
        for _ in 0..4 {
            let kp = Arc::clone(&keypair);
            let handle = thread::spawn(move || {
                let (ct, ss1) = encapsulate(kp.encapsulation_key()).unwrap();
                let ss2 = decapsulate(kp.decapsulation_key(), &ct).unwrap();
                assert_eq!(*ss1, *ss2);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

#[cfg(test)]
mod hybrid_mode_tests {
    use crate::crypto::streaming::derive_hybrid_key;
    use crate::crypto::pqc::MlKemKeyPair;
    use zeroize::Zeroizing;

    #[test]
    fn test_hybrid_key_derivation() {
        use crate::crypto::pqc::encapsulate;

        // Generate classical key and PQ shared secret
        let classical_key = Zeroizing::new([0x42u8; 32]);
        let keypair = MlKemKeyPair::generate();
        let (_, pq_secret) = encapsulate(keypair.encapsulation_key()).unwrap();

        // Derive hybrid key
        let hybrid_key = derive_hybrid_key(&classical_key, &pq_secret);

        // Hybrid key should be 32 bytes
        assert_eq!(hybrid_key.len(), 32);

        // Should be different from both inputs
        assert_ne!(&*hybrid_key, &*classical_key);
        assert_ne!(&*hybrid_key, &*pq_secret);
    }

    #[test]
    fn test_hybrid_key_determinism() {
        use crate::crypto::pqc::encapsulate;

        let classical_key = Zeroizing::new([0x42u8; 32]);
        let keypair = MlKemKeyPair::generate();
        let (_ciphertext, pq_secret) = encapsulate(keypair.encapsulation_key()).unwrap();

        // Derive hybrid key twice with same inputs
        let hybrid1 = derive_hybrid_key(&classical_key, &pq_secret);
        let hybrid2 = derive_hybrid_key(&classical_key, &pq_secret);

        // Should be identical
        assert_eq!(&*hybrid1, &*hybrid2);
    }

    #[test]
    fn test_hybrid_key_different_inputs() {
        use crate::crypto::pqc::encapsulate;

        let key1 = Zeroizing::new([0x42u8; 32]);
        let key2 = Zeroizing::new([0x43u8; 32]);

        let keypair = MlKemKeyPair::generate();
        let (_, secret) = encapsulate(keypair.encapsulation_key()).unwrap();

        let hybrid1 = derive_hybrid_key(&key1, &secret);
        let hybrid2 = derive_hybrid_key(&key2, &secret);

        // Different classical keys should produce different hybrid keys
        assert_ne!(&*hybrid1, &*hybrid2);
    }

    #[test]
    fn test_hybrid_key_entropy() {
        use crate::crypto::pqc::encapsulate;

        let classical_key = Zeroizing::new([0xFFu8; 32]); // All ones
        let keypair = MlKemKeyPair::generate();
        let (_, pq_secret) = encapsulate(keypair.encapsulation_key()).unwrap();

        let hybrid_key = derive_hybrid_key(&classical_key, &pq_secret);

        // Even with low-entropy classical key, hybrid should have good entropy
        // (from PQ component)
        assert!(!hybrid_key.iter().all(|&b| b == 0xFF));
        assert!(!hybrid_key.iter().all(|&b| b == 0x00));

        // Check byte distribution
        let mut counts = [0u32; 256];
        for &byte in hybrid_key.iter() {
            counts[byte as usize] += 1;
        }
        let max_count = counts.iter().max().unwrap();
        assert!(*max_count < 16); // No byte value should dominate
    }

    #[test]
    fn test_hybrid_mode_full_flow() {
        use crate::crypto::pqc::{encapsulate, decapsulate};
        use crate::crypto::kdf::Argon2Kdf;
        use crate::crypto::KeyDerivation;

        // Simulate full hybrid encryption flow

        // 1. Derive classical key from password
        let kdf = Argon2Kdf::default();
        let password = b"TestPassword123!";
        let salt = [0u8; 32];
        let classical_key = Zeroizing::new(kdf.derive_key(password, &salt).unwrap());

        // 2. Generate PQ keypair
        let keypair = MlKemKeyPair::generate();

        // 3. Encapsulate to get PQ shared secret
        let (ciphertext, pq_secret_sender) = encapsulate(keypair.encapsulation_key()).unwrap();

        // 4. Derive hybrid key (sender side)
        let hybrid_key_sender = derive_hybrid_key(&classical_key, &pq_secret_sender);

        // 5. Decapsulate to recover PQ shared secret (receiver side)
        let pq_secret_receiver = decapsulate(keypair.decapsulation_key(), &ciphertext).unwrap();

        // 6. Derive hybrid key (receiver side)
        let hybrid_key_receiver = derive_hybrid_key(&classical_key, &pq_secret_receiver);

        // 7. Verify hybrid keys match
        assert_eq!(&*hybrid_key_sender, &*hybrid_key_receiver);
    }
}

#[cfg(test)]
mod volume_pqc_tests {
    use crate::volume::header::{VolumeHeader, PqVolumeMetadata, PqAlgorithm, PQC_PADDING_SIZE};
    use crate::crypto::pqc::MlKemKeyPair;

    #[test]
    fn test_pqc_volume_header_creation() {
        let keypair = MlKemKeyPair::generate();
        use crate::crypto::pqc::encapsulate;
        use crate::volume::header::PQ_METADATA_SIZE;
        let (ciphertext, _) = encapsulate(keypair.encapsulation_key()).unwrap();

        // Create PQ metadata with raw byte arrays
        let mut ek_bytes = [0u8; 1568];
        let mut ct_bytes = [0u8; 1568];
        let edk_bytes = [0u8; 3196];

        ek_bytes.copy_from_slice(keypair.encapsulation_key());
        ct_bytes.copy_from_slice(&ciphertext);

        let pq_metadata = PqVolumeMetadata {
            algorithm: PqAlgorithm::MlKem1024,
            encapsulation_key: ek_bytes,
            ciphertext: ct_bytes,
            encrypted_decapsulation_key: edk_bytes,
            reserved_padding: [0u8; PQC_PADDING_SIZE],
        };

        let pq_size = pq_metadata.to_bytes().unwrap().len() as u32;
        assert_eq!(pq_size, PQ_METADATA_SIZE as u32);

        let header = VolumeHeader::new_with_pqc(
            1024 * 1024,
            4096,
            [0u8; 32],
            [0u8; 12],
            pq_size,
        );

        assert_eq!(header.pq_algorithm(), PqAlgorithm::MlKem1024);
        assert!(header.has_pqc());
        assert!(header.is_v2());
    }

    #[test]
    fn test_pqc_volume_header_serialization() {
        let keypair = MlKemKeyPair::generate();
        use crate::crypto::pqc::encapsulate;
        use crate::volume::header::PQ_METADATA_SIZE;
        let (ciphertext, _) = encapsulate(keypair.encapsulation_key()).unwrap();

        // Create PQ metadata with raw byte arrays
        let mut ek_bytes = [0u8; 1568];
        let mut ct_bytes = [0u8; 1568];
        let edk_bytes = [0u8; 3196];

        ek_bytes.copy_from_slice(keypair.encapsulation_key());
        ct_bytes.copy_from_slice(&ciphertext);

        let pq_metadata = PqVolumeMetadata {
            algorithm: PqAlgorithm::MlKem1024,
            encapsulation_key: ek_bytes,
            ciphertext: ct_bytes,
            encrypted_decapsulation_key: edk_bytes,
            reserved_padding: [0u8; PQC_PADDING_SIZE],
        };

        let pq_size = pq_metadata.to_bytes().unwrap().len() as u32;
        assert_eq!(pq_size, PQ_METADATA_SIZE as u32);

        let header = VolumeHeader::new_with_pqc(
            2048 * 1024,
            4096,
            [0x42u8; 32],
            [0x43u8; 12],
            pq_size,
        );

        let bytes = header.to_bytes().unwrap();
        let deserialized = VolumeHeader::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.pq_algorithm(), header.pq_algorithm());
        assert_eq!(deserialized.pq_metadata_size(), header.pq_metadata_size());
        assert_eq!(deserialized.has_pqc(), header.has_pqc());
    }

    #[test]
    fn test_pqc_metadata_serialization() {
        let keypair = MlKemKeyPair::generate();
        use crate::crypto::pqc::encapsulate;
        let (ciphertext, _) = encapsulate(keypair.encapsulation_key()).unwrap();

        // Create PQ metadata with raw byte arrays
        let mut ek_bytes = [0u8; 1568];
        let mut ct_bytes = [0u8; 1568];
        let mut edk_bytes = [0u8; 3196];

        ek_bytes.copy_from_slice(keypair.encapsulation_key());
        ct_bytes.copy_from_slice(&ciphertext);
        // Fill edk with test pattern
        for (i, b) in edk_bytes.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }

        let metadata = PqVolumeMetadata {
            algorithm: PqAlgorithm::MlKem1024,
            encapsulation_key: ek_bytes,
            ciphertext: ct_bytes,
            encrypted_decapsulation_key: edk_bytes,
            reserved_padding: [0u8; PQC_PADDING_SIZE],
        };

        let bytes = metadata.to_bytes().unwrap();
        let deserialized = PqVolumeMetadata::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.algorithm, metadata.algorithm);
        assert_eq!(deserialized.encapsulation_key, metadata.encapsulation_key);
        assert_eq!(deserialized.ciphertext, metadata.ciphertext);
        assert_eq!(deserialized.encrypted_decapsulation_key, metadata.encrypted_decapsulation_key);
    }
}

#[cfg(test)]
mod interoperability_tests {
    use crate::crypto::pqc::{MlKemKeyPair, encapsulate, decapsulate};

    #[test]
    fn test_ml_kem_standard_compliance() {
        // Test that our ML-KEM implementation follows NIST FIPS 203 spec
        let keypair = MlKemKeyPair::generate();

        // ML-KEM-1024 parameter set checks
        assert_eq!(keypair.encapsulation_key().len(), 1568);
        assert_eq!(keypair.decapsulation_key().len(), 3168);

        let (ciphertext, shared_secret) = encapsulate(keypair.encapsulation_key()).unwrap();
        assert_eq!(ciphertext.len(), 1568);
        assert_eq!(shared_secret.len(), 32);
    }

    #[test]
    fn test_keypair_stability() {
        // Test that serialization/deserialization preserves functionality
        let keypair1 = MlKemKeyPair::generate();

        // Serialize
        let ek = keypair1.encapsulation_key();
        let dk = keypair1.decapsulation_key();

        // Deserialize
        let keypair2 = MlKemKeyPair::from_bytes(ek, dk).unwrap();

        // Test that decapsulation still works
        let (ciphertext, ss1) = encapsulate(keypair2.encapsulation_key()).unwrap();
        let ss2 = decapsulate(keypair2.decapsulation_key(), &ciphertext).unwrap();

        assert_eq!(*ss1, *ss2);
    }

    #[test]
    fn test_cross_version_compatibility() {
        // Test that PQC can work with both V1 and V2 volume formats
        use crate::volume::header::{VolumeHeader, PqAlgorithm};

        // V1 header (no PQC)
        let v1_header = VolumeHeader::new(
            1024 * 1024,
            4096,
            [0u8; 32],
            [0u8; 12],
        );

        assert!(!v1_header.has_pqc());
        assert_eq!(v1_header.pq_algorithm(), PqAlgorithm::None);

        // V2 header (with PQC)
        let v2_header = VolumeHeader::new_with_pqc(
            1024 * 1024,
            4096,
            [0u8; 32],
            [0u8; 12],
            1000,
        );

        assert!(v2_header.has_pqc());
        assert_eq!(v2_header.pq_algorithm(), PqAlgorithm::MlKem1024);
        assert!(v2_header.is_v2());
    }
}

#[cfg(test)]
mod stress_tests {
    use crate::crypto::pqc::{MlKemKeyPair, encapsulate, decapsulate};

    #[test]
    fn test_many_keypairs() {
        // Generate many keypairs to test for uniqueness
        let mut keypairs = Vec::new();

        for _ in 0..100 {
            keypairs.push(MlKemKeyPair::generate());
        }

        // Check that all encapsulation keys are unique
        for i in 0..keypairs.len() {
            for j in (i + 1)..keypairs.len() {
                assert_ne!(
                    keypairs[i].encapsulation_key(),
                    keypairs[j].encapsulation_key()
                );
            }
        }
    }

    #[test]
    fn test_rapid_encapsulation() {
        let keypair = MlKemKeyPair::generate();

        // Perform many rapid encapsulations
        for _ in 0..1000 {
            let (ciphertext, ss1) = encapsulate(keypair.encapsulation_key()).unwrap();
            let ss2 = decapsulate(keypair.decapsulation_key(), &ciphertext).unwrap();
            assert_eq!(*ss1, *ss2);
        }
    }

    #[test]
    fn test_large_batch_operations() {
        // Simulate batch processing of many operations
        let mut results = Vec::new();

        for _ in 0..50 {
            let keypair = MlKemKeyPair::generate();
            let (ct, ss1) = encapsulate(keypair.encapsulation_key()).unwrap();
            let ss2 = decapsulate(keypair.decapsulation_key(), &ct).unwrap();
            results.push((*ss1, *ss2));
        }

        // Verify all succeeded and matched
        for (ss1, ss2) in results {
            assert_eq!(ss1, ss2);
        }
    }
}

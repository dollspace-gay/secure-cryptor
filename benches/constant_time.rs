//! Constant-Time Execution Verification using DudeCT
//!
//! This benchmark suite uses statistical analysis to detect timing leaks in
//! cryptographic operations. It implements the DudeCT methodology to verify
//! that our crypto functions execute in constant time regardless of input values.
//!
//! ## Methodology
//!
//! DudeCT (Dude, is my code Constant Time?) uses Welch's t-test to statistically
//! compare execution times between two classes of inputs:
//! - Class A: "Fixed" inputs (e.g., all zeros, known patterns)
//! - Class B: "Random" inputs (varying data)
//!
//! If the code is constant-time, there should be no statistically significant
//! difference in execution time between the classes.
//!
//! ## Running
//!
//! ```bash
//! cargo bench --bench constant_time
//! ```
//!
//! A t-value below 4.5 indicates no timing leak detected (with high confidence).
//! Values above 4.5 suggest potential timing vulnerabilities.
//!
//! ## References
//!
//! - Original paper: https://eprint.iacr.org/2016/1123.pdf
//! - dudect-bencher: https://crates.io/crates/dudect-bencher

use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, PasswordHasher};
use subtle::ConstantTimeEq;

/// Test that AES-GCM encryption is constant-time with respect to plaintext content.
///
/// This verifies that encrypting different plaintexts takes the same amount of time,
/// preventing attackers from learning plaintext content through timing analysis.
fn aes_gcm_encrypt_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Fixed key and nonce for consistent testing
    let key = [0x42u8; 32];
    let nonce_bytes = [0x24u8; 12];

    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from(nonce_bytes);

    // Fixed plaintext (Class A) vs Random plaintext (Class B)
    let fixed_plaintext = [0u8; 64];
    let mut random_plaintext = [0u8; 64];

    runner.run_one(Class::Left, || {
        // Class A: Encrypt fixed (all-zero) plaintext
        let _ = cipher.encrypt(&nonce, fixed_plaintext.as_ref());
    });

    // Generate random plaintext for Class B
    for byte in random_plaintext.iter_mut() {
        *byte = rng.rand_u8();
    }

    runner.run_one(Class::Right, || {
        // Class B: Encrypt random plaintext
        let _ = cipher.encrypt(&nonce, random_plaintext.as_ref());
    });
}

/// Test that AES-GCM decryption is constant-time with respect to ciphertext validity.
///
/// CRITICAL: This tests whether decryption takes the same time for valid vs invalid
/// tags. Timing differences here could allow tag-guessing attacks.
fn aes_gcm_decrypt_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = [0x42u8; 32];
    let nonce_bytes = [0x24u8; 12];

    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from(nonce_bytes);

    // Create a valid ciphertext
    let plaintext = [0x55u8; 64];
    let valid_ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

    // Create an invalid ciphertext (corrupted tag)
    let mut invalid_ciphertext = valid_ciphertext.clone();
    if let Some(last) = invalid_ciphertext.last_mut() {
        *last ^= 0xFF; // Flip bits in the tag
    }

    runner.run_one(Class::Left, || {
        // Class A: Decrypt valid ciphertext (should succeed)
        let _ = cipher.decrypt(&nonce, valid_ciphertext.as_ref());
    });

    runner.run_one(Class::Right, || {
        // Class B: Decrypt invalid ciphertext (should fail, but in constant time!)
        let _ = cipher.decrypt(&nonce, invalid_ciphertext.as_ref());
    });
}

/// Test that AES-GCM decryption timing doesn't leak tag position.
///
/// This verifies that an attacker cannot determine WHERE in the tag the
/// corruption occurred based on timing.
fn aes_gcm_tag_position_ct(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let key = [0x42u8; 32];
    let nonce_bytes = [0x24u8; 12];

    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from(nonce_bytes);

    // Create a valid ciphertext
    let plaintext = [0x55u8; 64];
    let valid_ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

    // Corrupt first byte of tag (at position ciphertext.len() - 16)
    let mut early_corrupt = valid_ciphertext.clone();
    let tag_start = early_corrupt.len().saturating_sub(16);
    if tag_start < early_corrupt.len() {
        early_corrupt[tag_start] ^= 0xFF;
    }

    // Corrupt last byte of tag
    let mut late_corrupt = valid_ciphertext.clone();
    if let Some(last) = late_corrupt.last_mut() {
        *last ^= 0xFF;
    }

    runner.run_one(Class::Left, || {
        // Class A: Early tag corruption
        let _ = cipher.decrypt(&nonce, early_corrupt.as_ref());
    });

    runner.run_one(Class::Right, || {
        // Class B: Late tag corruption
        let _ = cipher.decrypt(&nonce, late_corrupt.as_ref());
    });
}

/// Test that constant-time byte comparison works correctly.
///
/// Uses the `subtle` crate's ConstantTimeEq which should have no timing leaks.
fn subtle_compare_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Two identical arrays
    let fixed_a = [0x42u8; 32];
    let fixed_b = [0x42u8; 32];

    // Array that differs at first byte
    let mut differ_first = fixed_a;
    differ_first[0] = 0x00;

    // Array that differs at last byte
    let mut differ_last = fixed_a;
    differ_last[31] = 0x00;

    // Randomly pick between "differs at first" and "differs at last"
    let class = if rng.rand_u8() & 1 == 0 {
        runner.run_one(Class::Left, || {
            // Compare where mismatch is at the beginning
            let _ = fixed_a.ct_eq(&differ_first);
        });
        Class::Left
    } else {
        runner.run_one(Class::Right, || {
            // Compare where mismatch is at the end
            let _ = fixed_a.ct_eq(&differ_last);
        });
        Class::Right
    };

    // Also run the equal case to ensure it's not optimized away
    if class == Class::Left {
        runner.run_one(Class::Right, || {
            let _ = fixed_a.ct_eq(&fixed_b);
        });
    }
}

/// Test that Argon2 key derivation is constant-time with respect to password content.
///
/// This verifies that deriving keys from different passwords takes the same time,
/// preventing attackers from learning password content through timing.
///
/// Note: Argon2 is memory-hard, so we use minimal parameters to keep benchmark fast.
fn argon2_derive_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
    use argon2::password_hash::SaltString;

    // Use minimal parameters for faster testing
    // In production, we use much stronger parameters
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(1024, 1, 1, Some(32)).unwrap(),
    );

    // Fixed salt for consistent testing
    let salt = SaltString::encode_b64(b"testsalttestsalt").unwrap();

    // Fixed password (all same character)
    let fixed_password = b"aaaaaaaaaaaaaaaa";

    // Random password
    let mut random_password = [0u8; 16];
    for byte in random_password.iter_mut() {
        *byte = rng.rand_u8() | 0x20; // Ensure printable ASCII
    }

    runner.run_one(Class::Left, || {
        let _ = argon2.hash_password(fixed_password, &salt);
    });

    runner.run_one(Class::Right, || {
        let _ = argon2.hash_password(&random_password, &salt);
    });
}

/// Test encryption with Additional Authenticated Data (AAD).
///
/// Verifies that different AAD values don't affect encryption timing.
fn aes_gcm_aad_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = [0x42u8; 32];
    let nonce_bytes = [0x24u8; 12];

    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from(nonce_bytes);

    let plaintext = [0x55u8; 64];

    // Fixed AAD
    let fixed_aad = [0u8; 32];

    // Random AAD
    let mut random_aad = [0u8; 32];
    for byte in random_aad.iter_mut() {
        *byte = rng.rand_u8();
    }

    runner.run_one(Class::Left, || {
        let payload = Payload {
            msg: &plaintext,
            aad: &fixed_aad,
        };
        let _ = cipher.encrypt(&nonce, payload);
    });

    runner.run_one(Class::Right, || {
        let payload = Payload {
            msg: &plaintext,
            aad: &random_aad,
        };
        let _ = cipher.encrypt(&nonce, payload);
    });
}

/// Test that key value doesn't leak through encryption timing.
///
/// Different keys should result in identical encryption times.
fn aes_gcm_key_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
    let nonce_bytes = [0x24u8; 12];
    let nonce = Nonce::from(nonce_bytes);
    let plaintext = [0x55u8; 64];

    // Fixed key (all zeros - potentially weak, but timing should be same)
    let fixed_key = [0u8; 32];
    let cipher_fixed = Aes256Gcm::new(&fixed_key.into());

    // Random key
    let mut random_key = [0u8; 32];
    for byte in random_key.iter_mut() {
        *byte = rng.rand_u8();
    }
    let cipher_random = Aes256Gcm::new(&random_key.into());

    runner.run_one(Class::Left, || {
        let _ = cipher_fixed.encrypt(&nonce, plaintext.as_ref());
    });

    runner.run_one(Class::Right, || {
        let _ = cipher_random.encrypt(&nonce, plaintext.as_ref());
    });
}

// Register all constant-time benchmarks
ctbench_main!(
    aes_gcm_encrypt_ct,
    aes_gcm_decrypt_ct,
    aes_gcm_tag_position_ct,
    subtle_compare_ct,
    argon2_derive_ct,
    aes_gcm_aad_ct,
    aes_gcm_key_ct
);

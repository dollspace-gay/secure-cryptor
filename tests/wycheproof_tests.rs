//! Wycheproof Test Suite Integration
//!
//! This module runs the C2SP Wycheproof test vectors against our cryptographic
//! implementations to verify correctness and resistance to known attacks.
//!
//! Test vectors repository: https://github.com/C2SP/wycheproof

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

/// Wycheproof test group structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    #[serde(rename = "type")]
    test_type: String,
    key_size: usize,
    iv_size: usize,
    tag_size: usize,
    tests: Vec<TestCase>,
}

/// Wycheproof test case structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    tc_id: usize,
    comment: String,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: TestResult,
    flags: Vec<String>,
}

/// Test result expectation
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum TestResult {
    Valid,
    Invalid,
    Acceptable,
}

/// Top-level Wycheproof test file structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WycheproofTestFile {
    algorithm: String,
    number_of_tests: usize,
    test_groups: Vec<TestGroup>,
}

/// Helper function to decode hex strings
fn decode_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}

#[test]
fn test_aes_gcm_wycheproof() {
    let test_file_path = "tests/wycheproof/testvectors_v1/aes_gcm_test.json";

    // Skip if test vectors aren't cloned yet
    if !Path::new(test_file_path).exists() {
        eprintln!("Wycheproof test vectors not found. Run:");
        eprintln!("  git clone https://github.com/C2SP/wycheproof.git tests/wycheproof");
        return;
    }

    let test_data = fs::read_to_string(test_file_path)
        .expect("Failed to read Wycheproof AES-GCM test file");

    let test_file: WycheproofTestFile = serde_json::from_str(&test_data)
        .expect("Failed to parse Wycheproof test JSON");

    println!("Running {} AES-GCM tests from Wycheproof", test_file.number_of_tests);

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for group in &test_file.test_groups {
        // Only test 256-bit keys (our implementation uses AES-256)
        if group.key_size != 256 {
            skipped += group.tests.len();
            continue;
        }

        // Only test 96-bit IVs (12 bytes - our NONCE_LEN)
        if group.iv_size != 96 {
            skipped += group.tests.len();
            continue;
        }

        // Only test 128-bit tags (16 bytes - standard GCM tag size)
        if group.tag_size != 128 {
            skipped += group.tests.len();
            continue;
        }

        for test in &group.tests {
            // Decode test vectors
            let key = match decode_hex(&test.key) {
                Ok(k) => k,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            let nonce = match decode_hex(&test.iv) {
                Ok(n) => n,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            let aad = match decode_hex(&test.aad) {
                Ok(a) => a,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            let msg = match decode_hex(&test.msg) {
                Ok(m) => m,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            let ct = match decode_hex(&test.ct) {
                Ok(c) => c,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            let tag = match decode_hex(&test.tag) {
                Ok(t) => t,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            // Convert key to [u8; 32]
            let mut key_array = [0u8; 32];
            if key.len() != 32 {
                skipped += 1;
                continue;
            }
            key_array.copy_from_slice(&key);

            // Create cipher
            let cipher = Aes256Gcm::new(&key_array.into());
            let nonce_array: [u8; 12] = match nonce.as_slice().try_into() {
                Ok(n) => n,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            let gcm_nonce = Nonce::from(nonce_array);

            // Test encryption and decryption
            match test.result {
                TestResult::Valid => {
                    // Should encrypt successfully
                    let payload = Payload {
                        msg: &msg,
                        aad: &aad,
                    };

                    match cipher.encrypt(&gcm_nonce, payload) {
                        Ok(ciphertext) => {
                            // Expected ciphertext is ct || tag
                            let mut expected = ct.clone();
                            expected.extend_from_slice(&tag);

                            if ciphertext == expected {
                                passed += 1;
                            } else {
                                println!("Test {} FAILED: Ciphertext mismatch", test.tc_id);
                                println!("  Comment: {}", test.comment);
                                println!("  Expected: {}", hex::encode(&expected));
                                println!("  Got:      {}", hex::encode(&ciphertext));
                                failed += 1;
                            }
                        }
                        Err(e) => {
                            println!("Test {} FAILED: Encryption failed: {:?}", test.tc_id, e);
                            println!("  Comment: {}", test.comment);
                            failed += 1;
                        }
                    }

                    // Test decryption
                    let mut full_ciphertext = ct.clone();
                    full_ciphertext.extend_from_slice(&tag);

                    let decrypt_payload = Payload {
                        msg: &full_ciphertext,
                        aad: &aad,
                    };

                    match cipher.decrypt(&gcm_nonce, decrypt_payload) {
                        Ok(plaintext) => {
                            if plaintext == msg {
                                // Already counted in encryption pass
                            } else {
                                println!("Test {} FAILED: Decryption plaintext mismatch", test.tc_id);
                                println!("  Comment: {}", test.comment);
                                failed += 1;
                            }
                        }
                        Err(e) => {
                            println!("Test {} FAILED: Decryption failed: {:?}", test.tc_id, e);
                            println!("  Comment: {}", test.comment);
                            failed += 1;
                        }
                    }
                }
                TestResult::Invalid => {
                    // Should reject invalid ciphertext
                    let mut full_ciphertext = ct.clone();
                    full_ciphertext.extend_from_slice(&tag);

                    let decrypt_payload = Payload {
                        msg: &full_ciphertext,
                        aad: &aad,
                    };

                    match cipher.decrypt(&gcm_nonce, decrypt_payload) {
                        Ok(_) => {
                            println!("Test {} FAILED: Invalid ciphertext was accepted", test.tc_id);
                            println!("  Comment: {}", test.comment);
                            println!("  Flags: {:?}", test.flags);
                            failed += 1;
                        }
                        Err(_) => {
                            // Correctly rejected
                            passed += 1;
                        }
                    }
                }
                TestResult::Acceptable => {
                    // Implementation may accept or reject
                    // We don't count these as pass/fail
                    skipped += 1;
                }
            }
        }
    }

    println!("\nWycheproof AES-GCM Test Results:");
    println!("  Passed:  {}", passed);
    println!("  Failed:  {}", failed);
    println!("  Skipped: {}", skipped);
    println!("  Total:   {}", test_file.number_of_tests);

    assert_eq!(failed, 0, "Wycheproof tests failed");
}

#[test]
fn test_aes_gcm_wycheproof_known_issues() {
    // This test checks for known weak cases that implementations might handle differently
    // AAD with empty messages, unusual IV sizes, etc.

    let test_file_path = "tests/wycheproof/testvectors_v1/aes_gcm_test.json";

    if !Path::new(test_file_path).exists() {
        eprintln!("Wycheproof test vectors not found");
        return;
    }

    let test_data = fs::read_to_string(test_file_path)
        .expect("Failed to read test file");

    let test_file: WycheproofTestFile = serde_json::from_str(&test_data)
        .expect("Failed to parse test JSON");

    // Track tests with specific flags
    let mut edge_cases = std::collections::HashMap::new();

    for group in &test_file.test_groups {
        if group.key_size != 256 || group.iv_size != 96 || group.tag_size != 128 {
            continue;
        }

        for test in &group.tests {
            for flag in &test.flags {
                *edge_cases.entry(flag.clone()).or_insert(0) += 1;
            }
        }
    }

    println!("\nEdge cases in Wycheproof AES-GCM tests:");
    for (flag, count) in edge_cases.iter() {
        println!("  {}: {} tests", flag, count);
    }
}

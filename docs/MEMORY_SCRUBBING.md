# Memory Scrubbing Best Practices

This document provides guidelines for securely handling sensitive data in memory using Secure Cryptor's memory scrubbing utilities.

## Overview

Memory scrubbing (also called memory wiping or sanitization) is the process of securely overwriting sensitive data in RAM before it's deallocated. This prevents:

- **Memory dumps** from exposing secrets
- **Cold boot attacks** from recovering data from RAM
- **Accidental leaks** via core dumps or crash reports
- **Side-channel attacks** that analyze memory access patterns

## Available Tools

Secure Cryptor provides multiple levels of memory protection:

### 1. Automatic Zeroization

The simplest and most common approach - using types that automatically zero themselves on drop:

```rust
use zeroize::Zeroizing;

fn process_key() {
    let key = Zeroizing::new([0u8; 32]);
    // Key is automatically zeroed when it goes out of scope
}
```

**When to use:**
- Cryptographic keys
- Passwords and passphrases
- Authentication tokens
- Any secret that should be automatically cleaned up

### 2. Manual Scrubbing

Explicit scrubbing for more control:

```rust
use secure_cryptor::memory::scrub::scrub_bytes;

fn process_data() {
    let mut sensitive_data = vec![0x42; 1024];

    // ... use the data ...

    // Explicitly scrub before returning
    scrub_bytes(&mut sensitive_data);
}
```

**When to use:**
- Large buffers that need explicit cleanup timing
- Data that outlives its containing scope
- Conditional scrubbing based on security level

### 3. Multi-Pass Scrubbing

For high-security contexts requiring defense-in-depth:

```rust
use secure_cryptor::memory::scrub::{scrub_bytes_pattern, ScrubPattern};

fn high_security_cleanup(data: &mut [u8]) {
    // DoD 5220.22-M standard (3 passes)
    scrub_bytes_pattern(data, ScrubPattern::Dod522022M);

    // Or paranoid mode (7 passes)
    scrub_bytes_pattern(data, ScrubPattern::Paranoid);
}
```

**When to use:**
- Classified or highly sensitive data
- Compliance with specific standards (DoD, NIST)
- Defense against advanced memory forensics

### 4. Scrub Guards

RAII pattern for automatic scrubbing with early returns:

```rust
use secure_cryptor::memory::scrub::ScrubGuard;

fn process_with_early_return(password: Vec<u8>) -> Result<(), Error> {
    let _guard = ScrubGuard::new(password);

    if some_condition() {
        return Err(Error::Failed); // Guard scrubs automatically
    }

    // ... use _guard.as_ref() or _guard.as_mut() ...

    Ok(()) // Guard scrubs on success too
}
```

**When to use:**
- Functions with multiple return paths
- Error-prone code that might panic
- Ensuring cleanup even with early returns

## Scrubbing Patterns

### Available Patterns

| Pattern | Passes | Use Case | Performance |
|---------|--------|----------|-------------|
| `Zero` | 1 | Default - single zero pass | Fastest |
| `Ones` | 2 | Write 0xFF then zero | Fast |
| `NistSp80088` | 1 | NIST SP 800-88 compliance | Fast |
| `Dod522022M` | 4 | DoD 5220.22-M standard | Moderate |
| `Paranoid` | 7 | Maximum security | Slowest |
| `Custom(byte)` | 2 | Write custom pattern then zero | Fast |

### Performance Considerations

**RAM vs. Disk:** Modern RAM doesn't have data remanence like magnetic media. Multi-pass scrubbing provides marginal security benefit for RAM but significant compliance value.

**Benchmark results** (10MB buffer on typical workstation):
- Single-pass (Zero): ~5 ms
- DoD 5220.22-M: ~20 ms
- Paranoid (7-pass): ~35 ms

**Recommendation:** Use `Zero` or `NistSp80088` for most cases. Reserve multi-pass for compliance requirements or maximum security scenarios.

## Integration Patterns

### With LockedMemory

Combine scrubbing with memory locking for complete protection:

```rust
use secure_cryptor::memory::LockedMemory;
use secure_cryptor::memory::scrub::scrub_bytes;

fn handle_master_key(key_data: Vec<u8>) {
    let mut locked = LockedMemory::new(key_data).unwrap();

    // Memory is locked (won't swap to disk)
    // ... use the key ...

    // Explicitly scrub before drop
    scrub_bytes(&mut *locked);

    // Drop unlocks and LockedMemory also zeroizes
}
```

### With Encrypted Memory Pool

The encrypted memory pool automatically handles scrubbing:

```rust
use secure_cryptor::memory::pool::{EncryptedMemoryPool, SecurityLevel};

fn use_encrypted_pool() {
    let pool = EncryptedMemoryPool::new(SecurityLevel::High).unwrap();
    let mut allocation = pool.allocate(1024).unwrap();

    allocation.write(b"sensitive data").unwrap();

    // No manual scrubbing needed - automatic on drop
    // Encryption key, nonce, and data all zeroed
}
```

### Stack Scrubbing

For sensitive stack variables:

```rust
use secure_cryptor::scrub_stack_variable;

fn process_password(password: &str) {
    let mut password_copy = password.to_string();

    // ... process password ...

    // Scrub stack variable before return
    scrub_stack_variable!(password_copy);
}
```

## Common Pitfalls

### ❌ DON'T: Rely on Drop for Error Paths Without Guards

```rust
// BAD: If process_data panics, data won't be scrubbed
fn bad_example() {
    let mut sensitive = vec![0x42; 1024];
    process_data(&mut sensitive); // Could panic
    scrub_bytes(&mut sensitive); // Might not execute
}
```

### ✅ DO: Use ScrubGuard for Safety

```rust
// GOOD: ScrubGuard ensures cleanup even on panic
fn good_example() {
    let sensitive = vec![0x42; 1024];
    let mut guard = ScrubGuard::new(sensitive);
    process_data(guard.as_mut()); // Safe even if panics
    // Automatically scrubbed on drop
}
```

### ❌ DON'T: Forget About Copies

```rust
// BAD: Original data isn't scrubbed
fn bad_copy() {
    let original = vec![0x42; 256];
    let copy = original.clone(); // Now in two places!
    scrub_bytes(&copy); // Only scrubs the copy
    // Original still in memory!
}
```

### ✅ DO: Track All Copies

```rust
// GOOD: Scrub all copies
fn good_copy() {
    let mut original = vec![0x42; 256];
    let mut copy = original.clone();

    // ... use both ...

    scrub_bytes(&mut copy);
    scrub_bytes(&mut original);
}
```

### ❌ DON'T: Assume Compiler Won't Optimize Away

```rust
// BAD: Compiler might optimize this away
fn naive_scrub(data: &mut [u8]) {
    for byte in data {
        *byte = 0; // Might be optimized out as "dead store"
    }
}
```

### ✅ DO: Use Volatile Writes

```rust
// GOOD: Our scrub_bytes uses volatile writes + compiler fences
use secure_cryptor::memory::scrub::scrub_bytes;

fn proper_scrub(data: &mut [u8]) {
    scrub_bytes(data); // Won't be optimized away
}
```

## Verification

Always verify scrubbing in critical code:

```rust
use secure_cryptor::memory::scrub::{scrub_and_verify, ScrubPattern};

fn critical_cleanup(data: &mut [u8]) {
    let stats = scrub_and_verify(data, ScrubPattern::Dod522022M);

    if stats.verified != Some(true) {
        panic!("Memory scrubbing verification failed!");
    }
}
```

## Compliance Mapping

### NIST SP 800-88

**Guideline:** Single-pass overwrite sufficient for RAM sanitization.

```rust
use secure_cryptor::memory::scrub::{scrub_bytes_pattern, ScrubPattern};

// NIST compliant
scrub_bytes_pattern(data, ScrubPattern::NistSp80088);
```

### DoD 5220.22-M

**Standard:** 3-pass overwrite (0x00, 0xFF, random).

```rust
// DoD 5220.22-M compliant
scrub_bytes_pattern(data, ScrubPattern::Dod522022M);
```

### Common Criteria (EAL4+)

**Requirement:** Demonstrable secure deletion of sensitive data.

```rust
// Use verification for audit trail
let stats = scrub_and_verify(data, ScrubPattern::Dod522022M);
log_security_event("Memory scrubbed", stats);
```

## Performance Optimization

### Batch Scrubbing

Scrub multiple buffers efficiently:

```rust
use secure_cryptor::memory::scrub::scrub_multiple;

fn cleanup_session(keys: &mut [u8], tokens: &mut [u8], cache: &mut [u8]) {
    scrub_multiple(&mut [keys, tokens, cache]);
}
```

### Deferred Scrubbing

For performance-critical paths, defer scrubbing to cleanup phase:

```rust
struct Session {
    sensitive_buffers: Vec<Vec<u8>>,
}

impl Session {
    fn cleanup(&mut self) {
        for buffer in &mut self.sensitive_buffers {
            scrub_bytes(buffer);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.cleanup();
    }
}
```

## Testing Memory Scrubbing

While you can't reliably test that memory was actually zeroed without forensics tools, you can:

1. **Test the interface:**
```rust
#[test]
fn test_scrubbing_interface() {
    let mut data = vec![0x42; 256];
    scrub_bytes(&mut data);
    assert!(data.iter().all(|&b| b == 0));
}
```

2. **Verify non-optimization:**
```rust
#[test]
fn test_volatile_writes() {
    let mut data = vec![0xFF; 1024];
    // Multiple scrubs should all execute
    for _ in 0..10 {
        scrub_bytes(&mut data);
    }
    assert!(data.iter().all(|&b| b == 0));
}
```

3. **Use verification mode:**
```rust
#[test]
fn test_with_verification() {
    let mut data = vec![0x42; 512];
    let stats = scrub_and_verify(&mut data, ScrubPattern::Zero);
    assert_eq!(stats.verified, Some(true));
}
```

## Summary

**Default Choice:**
- Use `Zeroizing<T>` for automatic scrubbing
- Use `scrub_bytes()` for explicit control
- Use `ScrubGuard` for error-prone code

**High Security:**
- Combine `LockedMemory` + scrubbing
- Use `EncryptedMemoryPool` for encrypted-at-rest
- Apply multi-pass patterns (DoD, Paranoid)

**Compliance:**
- NIST SP 800-88: `ScrubPattern::NistSp80088`
- DoD 5220.22-M: `ScrubPattern::Dod522022M`
- Custom standards: `ScrubPattern::Custom(byte)`

**Always:**
- Track all copies of sensitive data
- Use guards for panic safety
- Verify in critical code paths
- Test scrubbing interfaces

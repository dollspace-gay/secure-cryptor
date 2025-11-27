# Formal Specifications for Tesseract Vault Cryptographic Primitives

## Overview

This document defines the formal correctness properties, security invariants, and behavioral specifications for Tesseract Vault's cryptographic core. These specifications serve as:

1. **Verification targets** for Kani and Prusti
2. **Security documentation** for auditors
3. **Implementation contracts** for developers

## Notation

- **Precondition** (`requires`): Must be true when function is called
- **Postcondition** (`ensures`): Must be true when function returns
- **Invariant**: Must hold throughout execution
- **Pure function**: No side effects, deterministic output

## Module 1: AES-GCM Encryption (aes_gcm.rs)

### 1.1 Type Definitions

```rust
struct AesGcmEncryptor;
```

**Invariants**:
- `NONCE_LEN == 12` (96-bit nonces for GCM)
- Key size is always 32 bytes (256-bit AES)

### 1.2 encrypt() Function

**Signature**:
```rust
fn encrypt(&self, key: &[u8; 32], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>
```

**Preconditions** (`#[requires]`):
1. `key.len() == 32` - Exactly 256-bit key
2. `nonce.len() == NONCE_LEN` (12 bytes)
3. `plaintext.len() < 2^36 - 32` - GCM input size limit (68GB - tag)

**Postconditions** (`#[ensures]`):
1. `result.is_ok() ==> result.unwrap().len() == plaintext.len() + 16`
   - Output is plaintext + 128-bit authentication tag
2. `result.is_ok() ==> result.unwrap() != plaintext`
   - Ciphertext differs from plaintext (unless empty)
3. `result.is_err() ==> nonce.len() != NONCE_LEN`
   - Only fails on invalid nonce length

**Security Properties**:
1. **Confidentiality**: No plaintext bit leaks to ciphertext without key
2. **Authentication**: 128-bit tag provides 2^-128 forgery probability
3. **Nonce uniqueness**: Same (key, nonce) must never encrypt twice (caller responsibility)

**Verification Strategy**:
- **Kani**: Verify no panics, no integer overflow, correct length calculations
- **Prusti**: Verify pre/postcondition contracts
- **Manual audit**: Verify nonce handling and key usage patterns

### 1.3 decrypt() Function

**Signature**:
```rust
fn decrypt(&self, key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>
```

**Preconditions**:
1. `key.len() == 32`
2. `nonce.len() == NONCE_LEN`
3. `ciphertext.len() >= 16` - At least the tag
4. `ciphertext.len() < 2^36` - GCM output size limit

**Postconditions**:
1. `result.is_ok() ==> result.unwrap().len() == ciphertext.len() - 16`
   - Plaintext is ciphertext minus tag
2. `result.is_err() ==> (nonce.len() != NONCE_LEN || tag_invalid)`
   - Fails on nonce error or authentication failure
3. **Decryption correctness**: For all valid (key, nonce, plaintext):
   ```
   decrypt(key, nonce, encrypt(key, nonce, plaintext)) == plaintext
   ```

**Security Properties**:
1. **Authentication**: Rejects tampered ciphertext with probability 1 - 2^-128
2. **No plaintext leak on failure**: Returns error immediately on tag mismatch
3. **Constant-time tag comparison**: No timing side-channel (delegated to AES-GCM crate)

**Verification Strategy**:
- **Kani**: Round-trip property (encrypt/decrypt identity)
- **Kani**: Authentication rejection (modified ciphertext fails)
- **Prusti**: Contract verification

## Module 2: Argon2id Key Derivation (kdf.rs)

### 2.1 Type Definitions

```rust
struct Argon2Kdf {
    config: CryptoConfig,
}
```

**Invariants**:
1. `config.argon2_mem_cost_kib >= 8` - Minimum 8 KiB memory (OWASP rec: 46MB)
2. `config.argon2_time_cost >= 1` - Minimum 1 iteration (OWASP rec: 2)
3. `config.argon2_lanes >= 1` - At least 1 parallel lane
4. `config.argon2_lanes <= 16` - Reasonable parallelism limit

### 2.2 derive_key() Function

**Signature**:
```rust
fn derive_key(&self, password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>>
```

**Preconditions**:
1. `password.len() > 0` - Non-empty password
2. `password.len() <= 2^32 - 1` - Argon2 input limit
3. `salt.len() >= 8` - Minimum salt length (OWASP: 16 bytes)
4. `salt.len() <= 2^32 - 1` - Argon2 salt limit
5. Argon2 parameters are valid (checked in constructor)

**Postconditions**:
1. `result.is_ok() ==> result.unwrap().len() == 32`
   - Always produces 256-bit key
2. **Determinism**: For fixed (password, salt, config):
   ```
   derive_key(p, s) == derive_key(p, s)
   ```
3. **Key zeroization**: On drop, key memory is securely wiped
4. `result.is_err() ==> invalid_params`
   - Only fails on parameter validation errors

**Security Properties**:
1. **Preimage resistance**: Computationally infeasible to find password from key
2. **Collision resistance**: Infeasible to find (p1, s1) != (p2, s2) with same key
3. **Slow hashing**: Parameterized to resist brute force (memory-hard)
4. **Side-channel resistance**: Argon2id resists timing/cache attacks
5. **Salt uniqueness**: Different salts produce independent keys (caller responsibility)

**Verification Strategy**:
- **Kani**: Verify no integer overflow in parameter calculations
- **Kani**: Verify determinism property
- **Prusti**: Verify output is always 32 bytes
- **Prusti**: Verify zeroization guarantee
- **Manual**: Audit parameter choices against OWASP recommendations

### 2.3 generate_salt() Function

**Signature**:
```rust
fn generate_salt(&self) -> Vec<u8>
```

**Postconditions**:
1. `result.len() >= Salt::RECOMMENDED_LENGTH` (typically 16 bytes)
2. **Randomness**: Output is cryptographically random (from `OsRng`)
3. **Uniqueness**: Probability of collision < 2^-128 (birthday bound)

**Security Properties**:
1. **Unpredictability**: Cannot predict salt before generation
2. **Entropy**: Full entropy from OS CSPRNG
3. **No bias**: Uniform distribution over salt space

**Verification Strategy**:
- **Kani**: Verify length postcondition
- **Manual**: Verify OsRng is properly seeded
- **Testing**: Statistical randomness tests (if needed)

## Module 3: XTS-AES Streaming Encryption (streaming.rs)

### 3.1 Type Definitions

```rust
struct XtsAes256Encryptor;
```

**Constants**:
- `XTS_BLOCK_SIZE = 16` - AES block size
- `XTS_KEY_SIZE = 64` - 512-bit key (2 × 256-bit for XTS)

**Invariants**:
- XTS requires two independent keys (key1, key2)
- Sector/tweak values must be unique per encrypted block

### 3.2 encrypt_sector() Function

**Signature**:
```rust
fn encrypt_sector(&self, key: &[u8; 64], sector: u64, data: &mut [u8]) -> Result<()>
```

**Preconditions**:
1. `key.len() == 64` - Full XTS key
2. `data.len() > 0`
3. `data.len() % XTS_BLOCK_SIZE == 0` - Block-aligned data
4. `sector` is unique for this key (caller responsibility)

**Postconditions**:
1. `result.is_ok() ==> data is encrypted in-place`
2. `result.is_ok() ==> data.len() unchanged`
3. `data` is fully overwritten (no partial encryption)
4. `result.is_err() ==> data unchanged` - Atomic operation

**Security Properties**:
1. **Sector tweak**: Each sector gets unique IV derived from sector number
2. **No ciphertext expansion**: In-place encryption, no overhead
3. **Malleability**: XTS is NOT authenticated (caller must add MAC layer)
4. **Wide-block semantics**: Bit flips in ciphertext affect full plaintext block

**Verification Strategy**:
- **Kani**: Verify no buffer overflows in-place encryption
- **Kani**: Verify length preservation
- **Prusti**: Verify atomicity (no partial updates on error)

### 3.3 decrypt_sector() Function

**Signature**:
```rust
fn decrypt_sector(&self, key: &[u8; 64], sector: u64, data: &mut [u8]) -> Result<()>
```

**Preconditions**: Same as `encrypt_sector`

**Postconditions**:
1. **Decryption correctness**: For all valid (key, sector, plaintext):
   ```
   let mut data = plaintext.clone();
   encrypt_sector(key, sector, &mut data)?;
   decrypt_sector(key, sector, &mut data)?;
   assert_eq!(data, plaintext);
   ```
2. Same atomicity and length guarantees as encryption

## Cross-Module Security Properties

### Global Invariant 1: Key Zeroization

**Property**: All cryptographic keys must be zeroized on drop.

**Applies to**:
- `Zeroizing<[u8; 32]>` in `derive_key()`
- Master keys in VolumeManager
- Session keys in streaming encryption

**Verification**:
```rust
#[ensures(after_expiry(key.iter().all(|&b| b == 0)))]
fn use_key(mut key: Zeroizing<[u8; 32]>) {
    // use key
    // Prusti verifies zeroization on drop
}
```

### Global Invariant 2: Nonce Uniqueness

**Property**: For AES-GCM, the same (key, nonce) pair must NEVER encrypt twice.

**Enforcement**:
- Nonces derived from monotonic counters
- Different volumes use different keys
- Sequential nonce allocation per volume

**Verification**:
- **Manual audit**: Review nonce generation in VolumeIO
- **Testing**: Nonce collision detection in test harness
- **Kani**: Verify counter increment logic has no overflow

### Global Invariant 3: Constant-Time Operations

**Property**: Cryptographic operations must not leak secrets via timing.

**Critical functions**:
- Tag comparison in `decrypt()`
- Key derivation in `derive_key()`
- Key equality checks

**Verification**:
- **Delegation**: Rely on constant-time guarantees from aes-gcm, argon2 crates
- **Manual**: Audit any custom crypto logic
- **Testing**: Timing attack test harnesses (advanced)

## Verification Coverage Plan

### Phase 1: Core Crypto (High Priority)

| Module | Function | Kani | Prusti | Status |
|--------|----------|------|--------|--------|
| aes_gcm.rs | encrypt() | ✅ Length, no-panic | ✅ Contracts | Pending |
| aes_gcm.rs | decrypt() | ✅ Round-trip | ✅ Contracts | Pending |
| kdf.rs | derive_key() | ✅ Determinism | ✅ Zeroization | Pending |
| kdf.rs | generate_salt() | ✅ Length | - | Pending |

### Phase 2: Streaming & Advanced

| Module | Function | Kani | Prusti | Status |
|--------|----------|------|--------|--------|
| streaming.rs | encrypt_sector() | ✅ In-place safety | ✅ Atomicity | Pending |
| streaming.rs | decrypt_sector() | ✅ Round-trip | ✅ Atomicity | Pending |
| pqc.rs | ML-KEM operations | ✅ No-panic | - | Pending |

### Phase 3: Volume Management

| Module | Function | Kani | Prusti | Status |
|--------|----------|------|--------|--------|
| volumeio_fs.rs | write_block() | ✅ Bounds | ✅ Consistency | Pending |
| volumeio_fs.rs | read_block() | ✅ Bounds | ✅ Consistency | Pending |
| container.rs | create() | - | ✅ Invariants | Pending |

## Formal Property Catalog

### Correctness Properties

1. **CP-1: Encryption/Decryption Identity**
   ```
   ∀ key, nonce, plaintext:
     decrypt(key, nonce, encrypt(key, nonce, plaintext)) = plaintext
   ```
   **Verification**: Kani harness with symbolic inputs

2. **CP-2: KDF Determinism**
   ```
   ∀ password, salt, config:
     derive_key(password, salt) = derive_key(password, salt)
   ```
   **Verification**: Kani harness with fixed inputs

3. **CP-3: Length Preservation**
   ```
   ∀ plaintext:
     encrypt(plaintext).len() = plaintext.len() + TAG_LEN
     decrypt(ciphertext).len() = ciphertext.len() - TAG_LEN
   ```
   **Verification**: Prusti postconditions

### Safety Properties

1. **SP-1: Memory Safety**
   - No buffer overflows in crypto operations
   - No use-after-free in key handling
   - **Verification**: Kani automatic checks

2. **SP-2: No Panics**
   - All crypto operations handle errors gracefully
   - No unwrap() or expect() in production paths
   - **Verification**: Kani panic detection

3. **SP-3: Integer Safety**
   - No arithmetic overflow in length calculations
   - No undefined behavior in indexing
   - **Verification**: Kani overflow checks

### Security Properties

1. **SEC-1: Key Confidentiality**
   - Keys never leave secure memory unencrypted
   - Keys zeroized immediately after use
   - **Verification**: Prusti lifetime analysis

2. **SEC-2: Authentication**
   - Tampered ciphertext rejected with high probability
   - No plaintext leak before authentication
   - **Verification**: Kani harness with modified ciphertext

3. **SEC-3: Nonce Freshness**
   - No (key, nonce) reuse across encryptions
   - Monotonic nonce counters
   - **Verification**: Manual audit + testing

## Appendix: Prusti Syntax Reference

### Basic Annotations

```rust
use prusti_contracts::*;

#[requires(x > 0)]
#[ensures(result > x)]
fn increment(x: i32) -> i32 {
    x + 1
}

#[pure]
fn is_valid(data: &[u8]) -> bool {
    data.len() == 32
}

#[invariant(self.count >= 0)]
struct Counter {
    count: usize,
}
```

### Advanced Features

```rust
// Zeroization guarantee
#[after_expiry(key.iter().all(|&b| b == 0))]
fn use_key(mut key: Vec<u8>) { }

// Old values in postconditions
#[ensures(result.len() == old(plaintext.len()) + 16)]
fn encrypt(plaintext: &[u8]) -> Vec<u8> { }

// Conditional postconditions
#[ensures(result.is_ok() ==> result.unwrap().len() == 32)]
fn derive() -> Result<Vec<u8>> { }
```

## Appendix: Kani Syntax Reference

### Basic Harness

```rust
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn verify_encrypt_length() {
        let key: [u8; 32] = kani::any();
        let nonce: [u8; 12] = kani::any();
        let plaintext_len: usize = kani::any();
        kani::assume(plaintext_len <= 1024);

        let plaintext = vec![0u8; plaintext_len];
        let result = encrypt(&key, &nonce, &plaintext);

        if let Ok(ciphertext) = result {
            assert_eq!(ciphertext.len(), plaintext.len() + 16);
        }
    }
}
```

### Advanced Techniques

```rust
#[kani::proof]
#[kani::unwind(32)]  // Increase loop bound
fn verify_no_overflow() {
    let size: usize = kani::any();
    kani::assume(size < 1000);  // Bound state space

    let result = allocate(size);
    assert!(result.is_ok());
}

#[kani::proof]
#[kani::stub(expensive_fn, cheap_stub)]  // Stub dependencies
fn verify_with_stubs() { }
```

---

**Document Status**: Complete
**Next Steps**: Implement Prusti annotations in source code
**Verification Target**: 90% specification coverage by Phase 3

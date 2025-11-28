# Supply Chain Provenance

This document tracks the provenance of critical cryptographic dependencies used in Tesseract Vault. All dependencies are locked to specific versions with verified checksums to ensure supply chain security.

## Critical Cryptographic Dependencies

### Post-Quantum Cryptography (PQC)

| Crate | Version | Checksum (SHA-256) | Source | Maintainer |
|-------|---------|-------------------|--------|------------|
| ml-kem | 0.3.0-pre.2 | `f9f13cd59336171067bfd7b9ac2d38646539d1167f75db226037cf8f8973bbce` | crates.io | RustCrypto |
| ml-dsa | 0.1.0-rc.2 | `2eb6c592d7a88fe8a0f866e37c9940792e5b204fe74f73dd78fa56b5c3ee9830` | crates.io | RustCrypto |

### Classical Cryptography

| Crate | Version | Checksum (SHA-256) | Source | Maintainer |
|-------|---------|-------------------|--------|------------|
| aes-gcm | 0.11.0-rc.2 | `7f5c07f414d7dc0755870f84c7900425360288d24e0eae4836f9dee19a30fa5f` | crates.io | RustCrypto |
| argon2 | 0.6.0-rc.2 | `e1a213fe583d472f454ae47407edc78848bebd950493528b1d4f7327a7dc335f` | crates.io | RustCrypto |
| chacha20poly1305 | 0.10.0-rc.5 | (from Cargo.lock) | crates.io | RustCrypto |
| blake3 | 1.8.2 | (from Cargo.lock) | crates.io | BLAKE3 team |
| sha3 | 0.11.0-rc.3 | (from Cargo.lock) | crates.io | RustCrypto |

### Memory Safety

| Crate | Version | Checksum (SHA-256) | Source | Maintainer |
|-------|---------|-------------------|--------|------------|
| zeroize | 1.8.2 | (from Cargo.lock) | crates.io | RustCrypto |
| subtle | 2.6.1 | (from Cargo.lock) | crates.io | RustCrypto |

## Verification Process

### 1. Cargo.lock Commitment

The `Cargo.lock` file is committed to version control, ensuring:
- Reproducible builds across all environments
- Exact version pinning for all transitive dependencies
- Checksum verification on every `cargo build`

### 2. Checksum Verification

Cargo automatically verifies checksums from `Cargo.lock` against crates.io registry. If a checksum mismatch occurs, the build fails immediately.

```bash
# Verify all dependencies match Cargo.lock
cargo verify-project
```

### 3. Source Verification

All critical dependencies are sourced from:
- **crates.io**: Official Rust package registry
- **RustCrypto organization**: https://github.com/RustCrypto

The RustCrypto organization maintains high-security cryptographic implementations with:
- Peer review by cryptography experts
- Constant-time implementations to prevent timing attacks
- Regular security audits
- FIPS algorithm compliance testing

## RustCrypto GitHub Repositories

For transparency, here are the source repositories:

| Crate | Repository | License |
|-------|------------|---------|
| ml-kem | https://github.com/RustCrypto/KEMs | MIT/Apache-2.0 |
| ml-dsa | https://github.com/RustCrypto/signatures | MIT/Apache-2.0 |
| aes-gcm | https://github.com/RustCrypto/AEADs | MIT/Apache-2.0 |
| argon2 | https://github.com/RustCrypto/password-hashes | MIT/Apache-2.0 |
| chacha20poly1305 | https://github.com/RustCrypto/AEADs | MIT/Apache-2.0 |
| blake3 | https://github.com/BLAKE3-team/BLAKE3 | CC0-1.0/Apache-2.0 |
| sha3 | https://github.com/RustCrypto/hashes | MIT/Apache-2.0 |
| zeroize | https://github.com/RustCrypto/utils | MIT/Apache-2.0 |
| subtle | https://github.com/dalek-cryptography/subtle | BSD-3-Clause |

## Version Pinning Strategy

### Why Pre-Release Versions?

We use pre-release (rc) versions of some PQC crates because:
1. ML-KEM and ML-DSA are newly standardized by NIST (FIPS 203/204)
2. The stable RustCrypto implementations are still in release candidate phase
3. These versions implement the final FIPS standards, not draft algorithms
4. Pre-release allows access to latest security fixes

### Upgrade Policy

1. **Security patches**: Applied immediately after verification
2. **Minor versions**: Reviewed and tested before upgrade
3. **Major versions**: Full security review required before adoption
4. **RC to stable**: Upgrade when stable versions are released

## Auditing Dependencies

### Regular Audit Commands

```bash
# Check for known vulnerabilities
cargo audit

# Verify dependency licenses
cargo license

# Show dependency tree
cargo tree

# Check for outdated dependencies
cargo outdated
```

### CI/CD Integration

The GitHub Actions workflow runs:
- `cargo audit` on every push
- Dependency vulnerability scanning via rustsec/audit-check
- Build verification with locked dependencies

## Vendoring (Optional)

For air-gapped environments or maximum supply chain control, dependencies can be vendored:

```bash
# Vendor all dependencies
cargo vendor vendor/

# Configure .cargo/config.toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
```

This copies all source code locally, allowing:
- Offline builds
- Source code inspection
- Protection against registry compromises

## SBOM (Software Bill of Materials)

Generate a complete SBOM for compliance:

```bash
# Using cargo-sbom
cargo install cargo-sbom
cargo sbom > sbom.json

# Using cyclonedx
cargo install cargo-cyclonedx
cargo cyclonedx > bom.xml
```

## Incident Response

If a dependency is compromised:

1. **Immediately**: Pin to last known good version in Cargo.toml
2. **Verify**: Compare checksums against known good values above
3. **Audit**: Review Cargo.lock changes in version control
4. **Update**: Apply security patches once verified safe
5. **Document**: Record incident in security changelog

## Version History

| Date | Action | Dependencies Affected |
|------|--------|----------------------|
| 2025-11-27 | Initial provenance documentation | All |

## References

- RustCrypto Security Policy: https://github.com/RustCrypto/.github/blob/master/SECURITY.md
- crates.io Security: https://doc.rust-lang.org/cargo/reference/registry-index.html
- cargo-audit: https://github.com/rustsec/rustsec
- NIST FIPS 203 (ML-KEM): https://csrc.nist.gov/publications/detail/fips/203/final
- NIST FIPS 204 (ML-DSA): https://csrc.nist.gov/publications/detail/fips/204/final

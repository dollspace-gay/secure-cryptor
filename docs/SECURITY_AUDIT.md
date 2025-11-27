# Security Audit Status

This document tracks the security audit status of Tesseract Vault dependencies and explains how we handle security advisories.

## Current Status

**Last Audit**: 2025-11-27
**Result**: ✅ PASS (0 vulnerabilities, 10 acknowledged warnings)

## Dependency Security

### Critical Cryptographic Dependencies

The following dependencies are critical to security and are regularly audited:

- **aes-gcm** 0.11.0-rc.2 - AES-256-GCM authenticated encryption
- **argon2** 0.6.0-rc.2 - Password hashing and key derivation
- **chacha20poly1305** - Alternative AEAD cipher
- **ml-kem** 0.3.0-pre.2 - Post-quantum key encapsulation (ML-KEM-1024)
- **ml-dsa** 0.1.0-rc.2 - Post-quantum digital signatures
- **blake3** 1.8.2 - Cryptographic hashing
- **sha3** 0.11.0-rc.3 - SHA-3 family hashing
- **zeroize** 1.8.2 - Secure memory clearing

✅ All cryptographic dependencies are **actively maintained** and have **no known vulnerabilities**.

### Acknowledged Warnings

We acknowledge the following warnings via `.cargo/audit.toml`:

#### 1. GTK3 Bindings (7 warnings)

**Status**: Acknowledged - Not security-critical
**Affected**: `gtk`, `gdk`, `atk`, `gtk-sys`, `gdk-sys`, `atk-sys`, `gtk3-macros`
**Reason**:
- Required by `tray-icon` for Linux system tray support
- UI-only dependencies, **not used in cryptographic operations**
- No known security vulnerabilities (only "unmaintained" status)
- GTK3 is stable and still receives security updates from distribution vendors
- GTK4 migration tracked in upstream `tray-icon` project

**Risk Assessment**: LOW
- Isolated to UI layer (system tray functionality)
- No access to cryptographic keys or sensitive data
- Sandboxed from core encryption logic
- Alternative: Remove system tray feature (would degrade UX)

#### 2. glib::VariantStrIter Unsoundness

**Advisory**: RUSTSEC-2024-0429
**Status**: Acknowledged - Not applicable
**Reason**: We do not use `glib::VariantStrIter` anywhere in our codebase
**Risk Assessment**: NONE (unused type)

#### 3. paste Crate Unmaintained

**Advisory**: RUSTSEC-2024-0436
**Status**: Acknowledged - Build-time only
**Affected**: Transitive dependency (winfsp, rav1e, accesskit)
**Reason**:
- Macro-only crate used at build time
- No runtime code generation
- Stable functionality with no active bugs

**Risk Assessment**: MINIMAL (build-time only)

#### 4. proc-macro-error Unmaintained

**Advisory**: RUSTSEC-2024-0370
**Status**: Acknowledged - Build-time only
**Affected**: GTK3 macro dependencies
**Reason**:
- Build-time procedural macro helper
- No runtime presence in final binary
- Stable, well-tested code

**Risk Assessment**: MINIMAL (build-time only)

## Mitigation Strategy

### 1. Dependency Updates

We regularly update dependencies with:
```bash
cargo update
cargo audit
```

### 2. Supply Chain Security

- **cargo-audit**: Scans dependencies against RustSec Advisory Database
- **Cargo.lock**: Committed to ensure reproducible builds
- **Automated CI**: GitHub Actions runs `cargo audit` on every push
- **Future**: `cargo-vet` and `cargo-deny` planned (see `docs/advanced-verification.md`)

### 3. Cryptographic Core Isolation

Our security architecture ensures:
- Cryptographic code has **zero dependencies on GTK/UI libraries**
- Core crypto modules: `crypto/`, `volume/`, `memory/` - isolated from UI
- GUI code: `bin/gui/` - completely separate from crypto primitives
- Clear separation enforced by module boundaries

```
tesseract-vault/
├── src/
│   ├── crypto/         ← No GTK dependencies (pure crypto)
│   ├── volume/         ← No GTK dependencies (volume management)
│   ├── memory/         ← No GTK dependencies (secure memory)
│   └── bin/
│       └── gui/        ← GTK3 used only here (UI layer)
```

### 4. Verification Infrastructure

See `docs/advanced-verification.md` for our multi-layered verification:

- **Kani**: Formal verification of crypto code (21 proof harnesses)
- **Wycheproof**: Cryptographic test vectors (66/66 passing)
- **Miri**: Undefined behavior detection
- **cargo-audit**: Dependency vulnerability scanning

## Running Security Audits

### Manual Audit

```bash
# Run security audit
cargo audit

# Update dependencies and re-audit
cargo update
cargo audit

# Check for outdated dependencies
cargo outdated
```

### CI/CD Integration

GitHub Actions workflow `.github/workflows/formal-verification.yml` includes:

```yaml
security-audit:
  name: Supply Chain Security Audit
  runs-on: ubuntu-latest
  steps:
    - uses: rustsec/audit-check@v1.4.1
```

Runs on:
- Every push to main/develop
- Every pull request
- Daily scheduled scans

## Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email: [security contact to be added]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fixes (if any)

## Version History

| Date       | Auditor | Result | Notes |
|------------|---------|--------|-------|
| 2025-11-27 | Claude  | PASS   | 10 acknowledged warnings (GTK3 UI deps) |

## References

- RustSec Advisory Database: https://rustsec.org/advisories/
- cargo-audit: https://github.com/rustsec/rustsec
- Tesseract Verification Docs: `docs/advanced-verification.md`
- Formal Specifications: `docs/formal-specifications.md`

---

**Document Status**: Living document
**Next Audit**: On next dependency update or monthly review

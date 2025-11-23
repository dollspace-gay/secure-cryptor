# Tesseract

**Tesseract** is an advanced encryption suite providing military-grade file and volume encryption with post-quantum cryptography support.

Built in Rust for performance and memory safety, Tesseract employs state-of-the-art cryptographic practices to ensure your data remains confidential, tamper-proof, and secure against future quantum computing threats.

## 🛡️ Security Features

Tesseract is designed with a strong focus on defensive security and future-proofing:

### Core Cryptography
- **AES-256-GCM**: Authenticated Encryption mode ensuring both data confidentiality and integrity (tamper detection)
- **Argon2id Key Derivation**: Memory-hard KDF providing excellent resistance against brute-force and side-channel attacks
- **Post-Quantum Cryptography (PQC)**:
  - **ML-KEM-1024** (Module-Lattice Key Encapsulation Mechanism) for quantum-resistant key exchange
  - **ML-DSA** (Module-Lattice Digital Signature Algorithm) for quantum-resistant signatures
  - Hybrid encryption combining classical and post-quantum algorithms
- **DEFLATE Compression**: Optional transparent compression to reduce encrypted file sizes

### Hardware Security
- **YubiKey Support**: HMAC-SHA1 challenge-response authentication via USB HID
- Hardware-backed key derivation for enhanced security

### Memory Protection
- **Atomic Secret Zeroization**: Sensitive data securely wiped from memory immediately after use
- **Locked Memory Pages**: Prevents sensitive data from being swapped to disk
- **Constant-Time Operations**: Protects against timing-based side-channel attacks
- **Secure Memory Pool**: Custom allocator with encryption and scrubbing

### File Safety
- **Atomic File Writes**: Guarantees files are never left in corrupted or partially written states
- **Strong Password Policy**: Enforces minimum 12 characters with mixed character types
- **Streaming Encryption**: Memory-efficient chunked processing for files of any size

## 🛠️ Build and Setup

This project requires the Rust toolchain (including Cargo) to be installed.

### Basic Build

Clone the repository or navigate to the project directory:

```bash
cd tesseract
```

Build the release binary:

```bash
cargo build --release
```

The compiled binary will be located at [target/release/tesseract](target/release/tesseract) (or `tesseract.exe` on Windows).

### Build Features

Tesseract supports several optional feature flags:

| Feature | Default | Description |
|---------|---------|-------------|
| `post-quantum` | ✓ | ML-KEM-1024 and ML-DSA post-quantum cryptography |
| `compression` | ✓ | DEFLATE compression support |
| `encrypted-volumes` | ✗ | Virtual filesystem mounting (requires system dependencies) |
| `yubikey` | ✗ | YubiKey hardware security module support |
| `wasm-minimal` | ✗ | Minimal WASM build (AES-256-GCM + Argon2id only) |
| `wasm-full` | ✗ | Full WASM build with PQC and compression |

**Building with all features:**

```bash
cargo build --release --all-features
```

**Building without default features:**

```bash
cargo build --release --no-default-features
```

### Encrypted Volumes System Requirements

The `encrypted-volumes` feature requires platform-specific dependencies:

- **Windows**: [WinFsp](https://winfsp.dev/) must be installed
- **Linux**: FUSE kernel driver and libraries (`fusermount`, `libfuse`)
- **macOS**: [macFUSE](https://macfuse.github.io/) 5.1.1 or later

**Note**: The encrypted-volumes feature is optional. File encryption/decryption works without these dependencies.

## 🚀 Usage

Tesseract provides multiple modes of operation: file encryption, encrypted volumes, and daemon services.

### File Encryption

#### Encrypting a File

```bash
tesseract encrypt --input <INPUT_FILE> --output <OUTPUT_FILE>
```

Example:
```bash
tesseract encrypt --input secrets.txt --output secrets.enc
```

The program will prompt you to enter and confirm a strong password. Your file will be encrypted using AES-256-GCM with post-quantum key encapsulation (if enabled).

#### Decrypting a File

```bash
tesseract decrypt --input <INPUT_FILE> --output <OUTPUT_FILE>
```

Example:
```bash
tesseract decrypt --input secrets.enc --output secrets_decrypted.txt
```

Enter your password when prompted. If correct, the original data will be restored.

### Encrypted Volumes

Tesseract can create encrypted virtual filesystems that appear as regular drives when mounted.

#### Creating a Volume

```bash
tesseract volume create --container my_vault.enc --size 1G --mount-point /mnt/vault
```

Sizes can be specified as: `100M` (megabytes), `1G` (gigabytes), `500M`, etc.

#### Mounting a Volume

```bash
tesseract volume mount --container my_vault.enc --mount-point /mnt/vault
```

Add `--read-only` flag for read-only access.

#### Unmounting a Volume

```bash
tesseract volume unmount /mnt/vault
```

#### Listing Mounted Volumes

```bash
tesseract volume list
```

#### Volume Information

```bash
tesseract volume info --container my_vault.enc
```

Shows volume metadata, size, encryption algorithms, and key slots.

#### Password Management

Change or add a password:
```bash
tesseract volume change-password --container my_vault.enc
```

Add to a specific slot (0-7):
```bash
tesseract volume change-password --container my_vault.enc --slot 2
```

#### Recovery Keys

Generate a recovery key:
```bash
tesseract volume generate-recovery-key --output recovery.key --name "My Vault"
```

Add recovery key to volume:
```bash
tesseract volume add-recovery-key --container my_vault.enc --recovery-key recovery.key
```

Reset password using recovery key:
```bash
tesseract volume reset-password --container my_vault.enc --recovery-key recovery.key
```

#### Hidden Volumes

Create a hidden volume inside an existing volume for plausible deniability:

```bash
tesseract volume create-hidden --container my_vault.enc --size 100M
```

Hidden volumes:
- Use separate password from outer volume
- Support post-quantum cryptography
- Provide plausible deniability
- Cannot be detected without the hidden volume password

Mount hidden volume using its dedicated password when prompted.

### Daemon Service

Tesseract includes a background daemon for automated volume management and power state monitoring.

#### Starting the Daemon

```bash
tesseract daemon start
```

#### Checking Status

```bash
tesseract daemon status
```

#### Stopping the Daemon

```bash
tesseract daemon stop
```

#### Installing as System Service

**Windows:**
```bash
tesseract daemon install-service
tesseract daemon start-service
```

**Linux:**
```bash
sudo tesseract daemon install-service
sudo systemctl start tesseract
```

**macOS:**
```bash
sudo tesseract daemon install-service
sudo launchctl start com.tesseract.daemon
```

The daemon provides:
- Automatic volume unmounting on sleep/hibernate
- Power state monitoring and callbacks
- Background encryption tasks
- System integration

## 🖥️ GUI Application

Tesseract includes a native cross-platform GUI application with a beautiful, user-friendly interface.

### Building the GUI

```bash
cargo build --release --bin tesseract-gui
```

The GUI executable will be located at [target/release/tesseract-gui](target/release/tesseract-gui) (or `tesseract-gui.exe` on Windows).

### Features

- **Beautiful interface**: Modern gradient design with smooth animations
- **Cross-platform**: Native look and feel on Windows, Linux, and macOS
- **Auto-detection**: Automatically switches to decrypt mode for `.enc` files
- **Drag and drop**: Pre-populates fields when launched from file associations
- **Real-time progress**: Visual progress bar with percentage indicator and speed
- **Volume management**: Create, mount, and manage encrypted volumes from GUI
- **System tray integration**: Background operation with quick access (Windows)

### System Integration

Register file associations and context menu entries for seamless system integration.

#### Windows

**Note: Requires Administrator privileges**

1. Open Command Prompt or PowerShell as Administrator
2. Navigate to the project directory
3. Run the registration utility:

```bash
.\target\release\tesseract-register.exe install
```

This will register:
- **File Association**: Double-click `.enc` files to open them in Tesseract GUI
- **Context Menu (All Files)**: Right-click any file → "Encrypt with Tesseract"
- **Context Menu (.enc Files)**: Right-click .enc files → "Decrypt with Tesseract"

To uninstall:

```bash
.\target\release\tesseract-register.exe uninstall
```

#### Linux

Run the registration utility:

```bash
./target/release/tesseract-register install
```

This will:
- Create `.desktop` file in `~/.local/share/applications/`
- Register MIME type for `.enc` files
- Add file associations to `~/.config/mimeapps.list`
- Update MIME database

To uninstall:

```bash
./target/release/tesseract-register uninstall
```

#### macOS

Run the registration utility:

```bash
./target/release/tesseract-register install
```

**Note**: macOS file associations work best with `.app` bundles. For full integration, install the `duti` tool:

```bash
brew install duti
```

Then run the installer again. Alternatively, manually associate `.enc` files through Finder's "Get Info" panel.

To uninstall:

```bash
./target/release/tesseract-register uninstall
```

## 🌐 WebAssembly Support

Tesseract can be compiled to WebAssembly for use in browsers and other WASM environments.

### Building for WASM

Minimal build (smallest size, ~100KB):
```bash
wasm-pack build --target web --release -- --no-default-features --features wasm-minimal
```

Full build (with PQC and compression):
```bash
wasm-pack build --target web --release -- --features wasm-full
```

### WASM Features

The WASM build provides:
- File encryption/decryption in the browser
- Same security guarantees as native builds
- Streaming support for large files
- Optional post-quantum cryptography
- Optional compression

### Usage Example

```javascript
import init, { encrypt_file, decrypt_file } from './pkg/tesseract.js';

await init();

// Encrypt data
const encrypted = await encrypt_file(plaintext, password);

// Decrypt data
const decrypted = await decrypt_file(encrypted, password);
```

## 🔐 YubiKey Integration

Tesseract supports hardware-backed authentication using YubiKey devices.

### Building with YubiKey Support

```bash
cargo build --release --features yubikey
```

### Requirements

- YubiKey 4, YubiKey 5, or YubiKey Neo
- HMAC-SHA1 challenge-response configured in slot 2

### Usage

When encrypting or creating volumes with YubiKey support enabled, Tesseract will:
1. Prompt for your password
2. Challenge your YubiKey
3. Combine both factors for enhanced security

This provides hardware-backed two-factor authentication for your encrypted data.

## 🏗️ Architecture

Tesseract is built with a modular architecture:

- **`tesseract` (library)**: Core cryptographic primitives and algorithms
- **`tesseract` (binary)**: Command-line interface for file and volume operations
- **`tesseract-gui`**: Native GUI application using eframe/egui
- **`tesseract-register`**: System integration utility for file associations
- **Daemon**: Background service for volume management and power monitoring

### Key Modules

- **`crypto`**: AES-GCM, Argon2id, ML-KEM, ML-DSA implementations
- **`volume`**: Encrypted container management and filesystem operations
- **`memory`**: Secure allocator, memory pool, and scrubbing
- **`storage`**: Streaming I/O with chunked encryption
- **`power`**: Power state monitoring and callbacks
- **`daemon`**: Background service and IPC protocol
- **`hsm`**: Hardware security module integration (YubiKey)

## 🔒 Security Considerations

### Best Practices

1. **Use strong passwords**: Minimum 12 characters with mixed types
2. **Enable YubiKey**: Add hardware authentication when possible
3. **Recovery keys**: Generate and securely store recovery keys for volumes
4. **Hidden volumes**: Use for plausible deniability in high-risk scenarios
5. **Daemon service**: Enable for automatic unmounting on system sleep

### Threat Model

Tesseract is designed to protect against:
- ✅ Brute-force attacks (Argon2id memory-hard KDF)
- ✅ Quantum computer attacks (ML-KEM-1024, ML-DSA)
- ✅ Cold boot attacks (memory locking and scrubbing)
- ✅ Timing attacks (constant-time operations)
- ✅ Data tampering (authenticated encryption)
- ✅ Coercion (hidden volumes)

Tesseract does NOT protect against:
- ❌ Malware on the system while volumes are mounted
- ❌ Hardware keyloggers
- ❌ Physical access to running system with mounted volumes
- ❌ Sophisticated targeted attacks with unlimited resources

### Audit Status

Tesseract has not undergone a formal security audit. Use at your own risk for sensitive data. Community security reviews are welcome.

## 🌍 Platform Support

| Platform | File Encryption | Volumes | Daemon | GUI | Status |
|----------|----------------|---------|--------|-----|--------|
| Windows 10/11 | ✅ | ✅ | ✅ | ✅ | Full support |
| Linux (x64) | ✅ | ✅ | ✅ | ✅ | Full support |
| macOS | ✅ | ✅ | ✅ | ✅ | Full support |
| WebAssembly | ✅ | ❌ | ❌ | ❌ | File encryption only |

### Tested Platforms

- **Windows**: Windows 10/11 (x64)
- **Linux**: Fedora, Ubuntu, Debian, Arch
- **macOS**: macOS 11+ (Big Sur and later)

## 📊 Performance

Tesseract is optimized for both speed and security:

- **Streaming encryption**: Constant memory usage regardless of file size
- **Parallel processing**: Multi-threaded encryption using Rayon
- **Memory pool**: Reusable encrypted buffers to reduce allocations
- **SIMD optimization**: Hardware-accelerated AES-NI when available
- **Compression**: Reduces encrypted file sizes by up to 60% for text

### Benchmarks

On a modern CPU (Intel i7-12700K):
- File encryption: ~800 MB/s
- Volume I/O: ~600 MB/s (WinFsp/FUSE overhead)
- ML-KEM-1024 key generation: ~0.5ms
- Argon2id KDF: ~100ms (configurable difficulty)

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for details.

## 🙏 Acknowledgments

Tesseract builds upon excellent work from the Rust cryptography community:

- **RustCrypto**: AES-GCM, Argon2, and other cryptographic primitives
- **ml-kem/ml-dsa**: Post-quantum cryptography implementations
- **WinFsp/FUSE**: Virtual filesystem frameworks
- **egui**: Immediate mode GUI framework

## 🤝 Contributing

Contributions are welcome! Please:

1. Follow Rust best practices and the project's coding standards
2. Add tests for new features
3. Update documentation
4. Follow the security-first principles outlined in [CLAUDE.md](CLAUDE.md)
5. Test on multiple platforms when possible

## 🐛 Reporting Issues

Found a bug or security issue?

- **Security vulnerabilities**: Please report privately via GitHub Security Advisories
- **Bugs and features**: Open an issue on GitHub with detailed information

## 📚 Documentation

- **API Documentation**: Run `cargo doc --open` to view full API docs
- **Examples**: See the `examples/` directory for usage examples
- **Project Instructions**: See [CLAUDE.md](CLAUDE.md) for development guidelines

---

**⚠️ Disclaimer**: This software is provided "as is" without warranty. Always maintain backups of important data. While Tesseract uses industry-standard cryptography, no encryption is absolutely unbreakable.
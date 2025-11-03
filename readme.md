Secure Cryptor

Secure Cryptor is a command-line utility for securely encrypting and decrypting files using industry-standard cryptography.

It is built in Rust for performance and memory safety, and employs robust practices to ensure that your data remains confidential and tamper-proof.

🛡️ Security Features

This utility is designed with a strong focus on defensive security:

AES-256-GCM: Uses the recommended Authenticated Encryption mode to ensure both data confidentiality and integrity (tamper detection).

Argon2id Key Derivation: Uses the modern, computationally intensive Argon2id algorithm to derive a strong 256-bit encryption key from your password, providing excellent resistance against brute-force and side-channel attacks.

Atomic Secret Zeroization: Sensitive data (passwords and derived keys) are wrapped with zeroize::Zeroizing to ensure their memory is securely wiped as soon as they are no longer needed, even in the event of a program crash (panic).

Constant-Time Password Comparison: Uses constant-time operations when validating passwords to protect against subtle timing attacks.

Atomic File Writes: Writes encrypted and decrypted data to a temporary file before atomically renaming it, guaranteeing that the output file is never left in a corrupted or partially written state if the program is interrupted.

Strong Password Policy: Enforces a minimum length of 12 characters and a mix of character types (uppercase, lowercase, numeric, special) to encourage robust passwords.

🛠️ Build and Setup

This project requires the Rust toolchain (including Cargo) to be installed.

Clone the Repository (If applicable) or navigate to the project directory:

cd secure-cryptor


Build the Release Binary:

cargo build --release


The compiled binary will be located at target/release/secure-cryptor.

🚀 Usage

The program uses subcommands: encrypt and decrypt.

1. Encrypting a File

To encrypt a file, use the encrypt subcommand, providing the input and desired output file paths.

./target/release/secure-cryptor encrypt --input <INPUT_FILE> --output <OUTPUT_FILE>


Example:

./target/release/secure-cryptor encrypt --input secrets.txt --output secrets.enc


The program will then prompt you to enter and confirm a strong password, which it will use to derive the encryption key.

2. Decrypting a File

To decrypt a file, use the decrypt subcommand. The program will automatically read the salt and nonce from the encrypted file.

./target/release/secure-cryptor decrypt --input <INPUT_FILE> --output <OUTPUT_FILE>


Example:

./target/release/secure-cryptor decrypt --input secrets.enc --output secrets_decrypted.txt


The program will prompt you to enter the password. If the password is correct and the file is intact, the original data will be written to the output file.
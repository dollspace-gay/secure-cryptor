use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    self,
    password_hash::{rand_core::OsRng as ArgonRng, SaltString},
    Argon2, Params,
};
use clap::{Parser, Subcommand};
use rand_core::RngCore;
use rpassword::read_password;
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;
use tempfile::Builder;
use thiserror::Error;
use zeroize::Zeroizing;

// --- Define Constants ---
const MAGIC_BYTES: &[u8] = b"SCRYPTv1"; // NEW: Magic number to identify our files
const NONCE_LEN: usize = 12; // AES-GCM standard nonce size is 96 bits
const MAX_SALT_LEN: usize = 1024; // Sanity limit for salt length to prevent DoS

// --- Define Custom Error Types for Clarity ---
#[derive(Error, Debug)]
pub enum CryptorError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Password validation failed: {0}")]
    PasswordValidation(String),
    #[error("Cryptography error: {0}")]
    Cryptography(String),
    #[error("Password hashing error: {0}")]
    PasswordHash(String),
    #[error("Argon2 error: {0}")]
    Argon2(String),
    #[error("Decryption failed. The file may be corrupt or the password incorrect.")]
    Decryption,
    #[error("Invalid file format or header.")]
    InvalidFormat,
    #[error("Failed to persist temporary file: {0}")]
    TempFilePersist(#[from] tempfile::PersistError),
    #[error("Output file path is invalid.")]
    InvalidOutputPath,
}

// Manual implementation to handle the non-standard error type from argon2
impl From<argon2::Error> for CryptorError {
    fn from(err: argon2::Error) -> Self {
        CryptorError::Argon2(err.to_string())
    }
}

// --- Define Command-Line Interface ---
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = "A secure file encryptor/decryptor using AES-256-GCM.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Input file to encrypt
        #[arg(short, long)]
        input: PathBuf,
        /// Output file to write encrypted data to
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Decrypt a file
    Decrypt {
        /// Input file to decrypt
        #[arg(short, long)]
        input: PathBuf,
        /// Output file to write decrypted data to
        #[arg(short, long)]
        output: PathBuf,
    },
}

// --- Main Application Logic ---
fn main() -> Result<(), CryptorError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output } => {
            println!("Encrypting '{}' -> '{}'", input.display(), output.display());
            encrypt_file(&input, &output)?;
            println!("Encryption successful.");
        }
        Commands::Decrypt { input, output } => {
            println!("Decrypting '{}' -> '{}'", input.display(), output.display());
            decrypt_file(&input, &output)?;
            println!("Decryption successful.");
        }
    }

    Ok(())
}

/// Handles the entire file encryption process.
fn encrypt_file(input_path: &PathBuf, output_path: &PathBuf) -> Result<(), CryptorError> {
    let password = get_and_validate_password()?;
    let mut plaintext = Vec::new();
    File::open(input_path)?.read_to_end(&mut plaintext)?;

    let salt = SaltString::generate(&mut ArgonRng);
    let key = derive_key(password.as_bytes(), &salt)?;

    let cipher = Aes256Gcm::new(&(*key).into());

    // CHANGED: Explicitly use a CSPRNG for nonce generation
    let mut nonce_bytes = [0u8; NONCE_LEN];
    ArgonRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| CryptorError::Cryptography(e.to_string()))?;

    write_atomically(output_path, |file| {
        let salt_str = salt.as_str();
        let salt_len = salt_str.len() as u16;

        // NEW: Write the magic number first
        file.write_all(MAGIC_BYTES)?;
        file.write_all(&salt_len.to_le_bytes())?;
        file.write_all(salt_str.as_bytes())?;
        file.write_all(&nonce_bytes)?;
        file.write_all(&ciphertext)?;
        Ok(())
    })?;

    Ok(())
}

/// Handles the entire file decryption process.
fn decrypt_file(input_path: &PathBuf, output_path: &PathBuf) -> Result<(), CryptorError> {
    let password = {
        print!("Enter password: ");
        std::io::stdout().flush()?;
        Zeroizing::new(read_password()?)
    };

    let mut file = File::open(input_path)?;

    // NEW: Read and verify the magic number
    let mut magic_buf = [0u8; MAGIC_BYTES.len()];
    file.read_exact(&mut magic_buf)?;
    if magic_buf != MAGIC_BYTES {
        return Err(CryptorError::InvalidFormat);
    }

    let mut salt_len_bytes = [0u8; 2];
    file.read_exact(&mut salt_len_bytes)?;
    let salt_len = u16::from_le_bytes(salt_len_bytes) as usize;

    if salt_len > MAX_SALT_LEN {
        return Err(CryptorError::InvalidFormat);
    }

    let mut salt_bytes = vec![0u8; salt_len];
    file.read_exact(&mut salt_bytes)?;
    let salt_str = std::str::from_utf8(&salt_bytes).map_err(|_| CryptorError::InvalidFormat)?;
    let salt = SaltString::from_b64(salt_str)
        .map_err(|e| CryptorError::PasswordHash(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    file.read_exact(&mut nonce_bytes)?;

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;

    let key = derive_key(password.as_bytes(), &salt)?;

    let cipher = Aes256Gcm::new(&(*key).into());
    let nonce = Nonce::from(nonce_bytes);
    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|_| CryptorError::Decryption)?;

    write_atomically(output_path, |file| {
        file.write_all(&plaintext)?;
        Ok(())
    })?;

    Ok(())
}

/// Derives a 32-byte key from a password and salt using Argon2 with explicit parameters.
fn derive_key(password: &[u8], salt: &SaltString) -> Result<Zeroizing<[u8; 32]>, CryptorError> {
    let params = Params::new(19 * 1024, 2, 1, None)
        .map_err(|e| CryptorError::Argon2(e.to_string()))?;
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    let mut key = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(password, salt.as_str().as_bytes(), &mut *key)?;
    Ok(key)
}

/// Helper function for performing atomic file writes.
fn write_atomically<F>(path: &Path, write_fn: F) -> Result<(), CryptorError>
where
    F: FnOnce(&mut File) -> Result<(), std::io::Error>,
{
    let output_dir = path.parent().ok_or(CryptorError::InvalidOutputPath)?;
    let mut temp_file = Builder::new()
        .prefix("secure-cryptor")
        .suffix(".tmp")
        .tempfile_in(output_dir)?;

    write_fn(temp_file.as_file_mut())?;

    temp_file.persist(path)?;
    Ok(())
}

/// Prompts the user for a password and confirms it, enforcing complexity rules.
fn get_and_validate_password() -> Result<Zeroizing<String>, CryptorError> {
    print!("Enter a strong password: ");
    std::io::stdout().flush()?;
    let pass1 = Zeroizing::new(read_password()?);

    validate_password(&pass1)?;

    print!("Confirm password: ");
    std::io::stdout().flush()?;
    let pass2 = Zeroizing::new(read_password()?);

    // CHANGED: Use idiomatic boolean conversion for subtle::Choice
    if !bool::from(pass1.as_bytes().ct_eq(pass2.as_bytes())) {
        return Err(CryptorError::PasswordValidation("Passwords do not match.".to_string()));
    }

    Ok(pass1)
}

/// Enforces strong password requirements.
fn validate_password(password: &str) -> Result<(), CryptorError> {
    if password.len() < 12 {
        return Err(CryptorError::PasswordValidation("Password must be at least 12 characters long.".to_string()));
    }
    if !password.chars().any(char::is_uppercase) {
        return Err(CryptorError::PasswordValidation("Password must contain at least one uppercase letter.".to_string()));
    }
    if !password.chars().any(char::is_lowercase) {
        return Err(CryptorError::PasswordValidation("Password must contain at least one lowercase letter.".to_string()));
    }
    if !password.chars().any(char::is_numeric) {
        return Err(CryptorError::PasswordValidation("Password must contain at least one number.".to_string()));
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err(CryptorError::PasswordValidation("Password must contain at least one special character (e.g., !@#$%).".to_string()));
    }
    Ok(())
}

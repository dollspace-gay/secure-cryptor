//! Secure Cryptor - Command-line file encryption tool
//!
//! A secure file encryptor/decryptor using AES-256-GCM encryption
//! with Argon2id key derivation.

use clap::{Parser, Subcommand};
use secure_cryptor::{validation, CryptorError};
use std::path::PathBuf;

/// Command-line interface definition
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "A secure file encryptor/decryptor using AES-256-GCM with Argon2id key derivation."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt a file with password-based encryption
    Encrypt {
        /// Input file to encrypt
        #[arg(short, long)]
        input: PathBuf,
        /// Output file to write encrypted data to
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Decrypt a previously encrypted file
    Decrypt {
        /// Input file to decrypt
        #[arg(short, long)]
        input: PathBuf,
        /// Output file to write decrypted data to
        #[arg(short, long)]
        output: PathBuf,
    },
}

/// Main application entry point
fn main() -> Result<(), CryptorError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output } => {
            println!("Encrypting '{}' -> '{}'", input.display(), output.display());
            encrypt_file_interactive(&input, &output)?;
            println!("✓ Encryption successful.");
        }
        Commands::Decrypt { input, output } => {
            println!("Decrypting '{}' -> '{}'", input.display(), output.display());
            decrypt_file_interactive(&input, &output)?;
            println!("✓ Decryption successful.");
        }
    }

    Ok(())
}

/// Encrypt a file with interactive password prompt and validation
fn encrypt_file_interactive(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
) -> Result<(), CryptorError> {
    let password = validation::get_and_validate_password()?;
    secure_cryptor::encrypt_file(input_path, output_path, &password)?;
    Ok(())
}

/// Decrypt a file with interactive password prompt
fn decrypt_file_interactive(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
) -> Result<(), CryptorError> {
    let password = validation::get_password()?;
    secure_cryptor::decrypt_file(input_path, output_path, &password)?;
    Ok(())
}

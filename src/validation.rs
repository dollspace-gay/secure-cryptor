//! Password validation and input handling.
//!
//! This module provides functionality for validating password strength
//! and securely collecting passwords from users.

use crate::error::{CryptorError, Result};
#[cfg(not(target_arch = "wasm32"))]
use rpassword::read_password;
#[cfg(not(target_arch = "wasm32"))]
use std::io::Write;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Minimum password length required.
pub const MIN_PASSWORD_LENGTH: usize = 12;

/// Minimum complexity score (number of character types required).
pub const MIN_COMPLEXITY_SCORE: u8 = 3;

/// Prompts the user for a password and validates it.
///
/// This function:
/// - Prompts for a password (hidden input)
/// - Validates password strength
/// - Prompts for confirmation
/// - Verifies both passwords match using constant-time comparison
///
/// # Errors
///
/// Returns an error if:
/// - Password fails validation
/// - Passwords don't match
/// - I/O error occurs during input
///
/// # Security
///
/// - Uses zeroizing memory to prevent password leakage
/// - Constant-time comparison to prevent timing attacks
#[cfg(not(target_arch = "wasm32"))]
pub fn get_and_validate_password() -> Result<Zeroizing<String>> {
    print!("Enter a strong password: ");
    std::io::stdout().flush()?;
    let pass1 = Zeroizing::new(read_password()?);

    validate_password(&pass1)?;

    print!("Confirm password: ");
    std::io::stdout().flush()?;
    let pass2 = Zeroizing::new(read_password()?);

    if !bool::from(pass1.as_bytes().ct_eq(pass2.as_bytes())) {
        return Err(CryptorError::PasswordValidation(
            "Passwords do not match.".to_string(),
        ));
    }

    Ok(pass1)
}

/// Prompts the user for a password without validation (for decryption).
///
/// # Errors
///
/// Returns an error if I/O error occurs during input.
#[cfg(not(target_arch = "wasm32"))]
pub fn get_password() -> Result<Zeroizing<String>> {
    print!("Enter password: ");
    std::io::stdout().flush()?;
    Ok(Zeroizing::new(read_password()?))
}

/// Enforces strong password requirements.
///
/// Password must:
/// - Be at least 12 characters long
/// - Contain at least 3 of the following:
///   - Uppercase letters
///   - Lowercase letters
///   - Numbers
///   - Special characters
///
/// # Arguments
///
/// * `password` - The password to validate
///
/// # Errors
///
/// Returns an error if password doesn't meet requirements.
///
/// # Examples
///
/// ```
/// # use tesseract_lib::validation::validate_password;
/// assert!(validate_password("Abcdef123!@#").is_ok());
/// assert!(validate_password("weak").is_err());
/// ```
pub fn validate_password(password: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(CryptorError::PasswordValidation(format!(
            "Password must be at least {} characters long.",
            MIN_PASSWORD_LENGTH
        )));
    }

    let has_uppercase = password.chars().any(char::is_uppercase);
    let has_lowercase = password.chars().any(char::is_lowercase);
    let has_numeric = password.chars().any(char::is_numeric);
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    let complexity_score =
        has_uppercase as u8 + has_lowercase as u8 + has_numeric as u8 + has_special as u8;

    if complexity_score < MIN_COMPLEXITY_SCORE {
        return Err(CryptorError::PasswordValidation(
            format!("Password must contain at least {} of the following categories: uppercase, lowercase, numbers, special characters.", MIN_COMPLEXITY_SCORE)
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_too_short() {
        assert!(validate_password("Short1!").is_err());
    }

    #[test]
    fn test_password_low_complexity() {
        assert!(validate_password("alllowercase").is_err());
        assert!(validate_password("ALLUPPERCASE").is_err());
        assert!(validate_password("12345678901234567890").is_err());
    }

    #[test]
    fn test_password_valid_three_types() {
        assert!(validate_password("Abcdefghij12").is_ok()); // upper + lower + number
        assert!(validate_password("Abcdefghij!!").is_ok()); // upper + lower + special
        assert!(validate_password("abcdefghij12!").is_ok()); // lower + number + special
        assert!(validate_password("ABCDEFGHIJ12!").is_ok()); // upper + number + special
    }

    #[test]
    fn test_password_valid_four_types() {
        assert!(validate_password("Abcd1234!@#$").is_ok());
        assert!(validate_password("MyP@ssw0rd123").is_ok());
    }

    #[test]
    fn test_password_exactly_min_length() {
        assert!(validate_password("Abcdefgh123!").is_ok());
    }

    #[test]
    fn test_password_unicode() {
        // Unicode characters count as special characters
        assert!(validate_password("Abcdefgh123😀").is_ok());
    }
}

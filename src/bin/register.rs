// Windows Registry Installer for Secure Cryptor
// Handles file associations and context menu integration
//
// Usage:
//   secure-cryptor-register install   - Register file associations and context menus
//   secure-cryptor-register uninstall - Remove all registry entries

#![cfg(windows)]

use std::env;
use std::path::PathBuf;
use winreg::enums::*;
use winreg::RegKey;

const PROGID: &str = "SecureCryptor.EncryptedFile";
const APP_NAME: &str = "Secure Cryptor";

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [install|uninstall]", args[0]);
        eprintln!();
        eprintln!("Commands:");
        eprintln!("  install   - Register file associations and context menus");
        eprintln!("  uninstall - Remove all registry entries");
        std::process::exit(1);
    }

    let exe_path = get_gui_exe_path();

    match args[1].as_str() {
        "install" => {
            println!("Installing Secure Cryptor file associations and context menus...");
            println!("GUI executable: {}", exe_path.display());

            if let Err(e) = install_file_association(&exe_path) {
                eprintln!("Error installing file association: {}", e);
                std::process::exit(1);
            }

            if let Err(e) = install_context_menus(&exe_path) {
                eprintln!("Error installing context menus: {}", e);
                std::process::exit(1);
            }

            println!("✓ Installation complete!");
            println!("\nFile associations registered:");
            println!("  - .enc files will open with Secure Cryptor GUI");
            println!("\nContext menu items added:");
            println!("  - Right-click any file → 'Encrypt with Secure Cryptor'");
            println!("  - Right-click .enc file → 'Decrypt with Secure Cryptor'");
        }
        "uninstall" => {
            println!("Uninstalling Secure Cryptor file associations and context menus...");

            if let Err(e) = uninstall_file_association() {
                eprintln!("Error uninstalling file association: {}", e);
            }

            if let Err(e) = uninstall_context_menus() {
                eprintln!("Error uninstalling context menus: {}", e);
            }

            println!("✓ Uninstallation complete!");
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            eprintln!("Use 'install' or 'uninstall'");
            std::process::exit(1);
        }
    }
}

/// Get the path to the GUI executable
fn get_gui_exe_path() -> PathBuf {
    let current_exe = env::current_exe().expect("Failed to get current executable path");
    let exe_dir = current_exe.parent().expect("Failed to get executable directory");
    exe_dir.join("secure-cryptor-gui.exe")
}

/// Install .enc file association
fn install_file_association(gui_exe: &PathBuf) -> std::io::Result<()> {
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);

    // Register .enc extension
    let (enc_key, _) = hkcr.create_subkey(".enc")?;
    enc_key.set_value("", &PROGID)?;
    enc_key.set_value("Content Type", &"application/x-encrypted")?;

    // Register ProgID
    let (progid_key, _) = hkcr.create_subkey(PROGID)?;
    progid_key.set_value("", &format!("{} Encrypted File", APP_NAME))?;

    // Set default icon
    let (icon_key, _) = progid_key.create_subkey("DefaultIcon")?;
    icon_key.set_value("", &format!("{},0", gui_exe.display()))?;

    // Set open command
    let (shell_key, _) = progid_key.create_subkey("shell")?;
    let (open_key, _) = shell_key.create_subkey("open")?;
    open_key.set_value("", &"Open with Secure Cryptor")?;
    let (command_key, _) = open_key.create_subkey("command")?;
    command_key.set_value("", &format!("\"{}\" \"%1\"", gui_exe.display()))?;

    println!("✓ Registered .enc file association");
    Ok(())
}

/// Uninstall .enc file association
fn uninstall_file_association() -> std::io::Result<()> {
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);

    // Remove .enc extension
    if let Err(e) = hkcr.delete_subkey_all(".enc") {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e);
        }
    }

    // Remove ProgID
    if let Err(e) = hkcr.delete_subkey_all(PROGID) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e);
        }
    }

    println!("✓ Removed .enc file association");
    Ok(())
}

/// Install context menu entries
fn install_context_menus(gui_exe: &PathBuf) -> std::io::Result<()> {
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);

    // Add "Encrypt" to all files (*)
    let (all_files, _) = hkcr.create_subkey("*\\shell\\SecureCryptor.Encrypt")?;
    all_files.set_value("", &"Encrypt with Secure Cryptor")?;
    all_files.set_value("Icon", &format!("{},0", gui_exe.display()))?;

    let (encrypt_command, _) = all_files.create_subkey("command")?;
    encrypt_command.set_value("", &format!("\"{}\" --encrypt \"%1\"", gui_exe.display()))?;

    println!("✓ Added 'Encrypt with Secure Cryptor' context menu");

    // Add "Decrypt" specifically for .enc files
    let enc_key = hkcr.open_subkey(".enc")?;
    let (enc_shell, _) = enc_key.create_subkey("shell\\SecureCryptor.Decrypt")?;
    enc_shell.set_value("", &"Decrypt with Secure Cryptor")?;
    enc_shell.set_value("Icon", &format!("{},0", gui_exe.display()))?;

    let (decrypt_command, _) = enc_shell.create_subkey("command")?;
    decrypt_command.set_value("", &format!("\"{}\" --decrypt \"%1\"", gui_exe.display()))?;

    println!("✓ Added 'Decrypt with Secure Cryptor' context menu");

    Ok(())
}

/// Uninstall context menu entries
fn uninstall_context_menus() -> std::io::Result<()> {
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);

    // Remove "Encrypt" from all files
    if let Ok(all_files) = hkcr.open_subkey("*\\shell") {
        if let Err(e) = all_files.delete_subkey_all("SecureCryptor.Encrypt") {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("Warning: Failed to remove Encrypt context menu: {}", e);
            }
        }
    }
    println!("✓ Removed 'Encrypt' context menu");

    // Remove "Decrypt" from .enc files
    if let Ok(enc_key) = hkcr.open_subkey(".enc\\shell") {
        if let Err(e) = enc_key.delete_subkey_all("SecureCryptor.Decrypt") {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("Warning: Failed to remove Decrypt context menu: {}", e);
            }
        }
    }
    println!("✓ Removed 'Decrypt' context menu");

    Ok(())
}

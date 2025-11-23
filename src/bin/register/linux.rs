// Linux Desktop Integration for Tesseract
// Handles file associations and desktop entries via XDG standards

#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Install Linux file associations and desktop entries
pub fn install(gui_exe: &PathBuf) -> std::io::Result<()> {
    let home = get_home_dir()?;

    // Ensure directories exist
    let apps_dir = home.join(".local/share/applications");
    let mime_dir = home.join(".local/share/mime/packages");
    let config_dir = home.join(".config");

    fs::create_dir_all(&apps_dir)?;
    fs::create_dir_all(&mime_dir)?;
    fs::create_dir_all(&config_dir)?;

    // Install .desktop file
    install_desktop_file(&apps_dir, gui_exe)?;

    // Install MIME type definition
    install_mime_type(&mime_dir)?;

    // Update MIME database
    update_mime_database(&home)?;

    // Associate MIME type with application
    associate_mime_type(&config_dir)?;

    println!("\nFile associations registered:");
    println!("  - .enc files will open with Tesseract GUI");
    println!("\nDesktop entries added:");
    println!("  - Application menu entry for Tesseract");
    println!("  - MIME type application/x-enc registered");

    Ok(())
}

/// Uninstall Linux file associations and desktop entries
pub fn uninstall() -> std::io::Result<()> {
    let home = get_home_dir()?;

    // Remove .desktop file
    let desktop_file = home.join(".local/share/applications/tesseract.desktop");
    if desktop_file.exists() {
        fs::remove_file(&desktop_file)?;
        println!("✓ Removed desktop file");
    }

    // Remove MIME type definition
    let mime_file = home.join(".local/share/mime/packages/tesseract.xml");
    if mime_file.exists() {
        fs::remove_file(&mime_file)?;
        println!("✓ Removed MIME type definition");
    }

    // Update MIME database
    update_mime_database(&home)?;

    // Remove MIME association from mimeapps.list
    remove_mime_association(&home.join(".config"))?;

    Ok(())
}

/// Get user's home directory
fn get_home_dir() -> std::io::Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "HOME environment variable not set"))
}

/// Install .desktop file for the application
fn install_desktop_file(apps_dir: &Path, gui_exe: &PathBuf) -> std::io::Result<()> {
    let desktop_content = format!(
        r#"[Desktop Entry]
Version=1.0
Type=Application
Name=Tesseract
Comment=Secure file encryption and decryption tool
Exec={} %f
Icon=tesseract
Terminal=false
Categories=Utility;Security;
MimeType=application/x-enc;
Keywords=encryption;decryption;security;crypto;
"#,
        gui_exe.display()
    );

    let desktop_file = apps_dir.join("tesseract.desktop");
    let mut file = fs::File::create(&desktop_file)?;
    file.write_all(desktop_content.as_bytes())?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&desktop_file)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&desktop_file, perms)?;
    }

    println!("✓ Created desktop file: {}", desktop_file.display());
    Ok(())
}

/// Install MIME type definition for .enc files
fn install_mime_type(mime_dir: &Path) -> std::io::Result<()> {
    let mime_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
    <mime-type type="application/x-enc">
        <comment>Tesseract Encrypted File</comment>
        <icon name="application-x-enc"/>
        <glob pattern="*.enc"/>
    </mime-type>
</mime-info>
"#;

    let mime_file = mime_dir.join("tesseract.xml");
    let mut file = fs::File::create(&mime_file)?;
    file.write_all(mime_content.as_bytes())?;

    println!("✓ Created MIME type definition: {}", mime_file.display());
    Ok(())
}

/// Update the MIME database
fn update_mime_database(home: &Path) -> std::io::Result<()> {
    let mime_dir = home.join(".local/share/mime");

    // Try to run update-mime-database
    match Command::new("update-mime-database").arg(&mime_dir).status() {
        Ok(status) if status.success() => {
            println!("✓ Updated MIME database");
            Ok(())
        }
        Ok(status) => {
            eprintln!("Warning: update-mime-database exited with status: {}", status);
            Ok(())
        }
        Err(e) => {
            eprintln!("Warning: Failed to run update-mime-database: {}", e);
            eprintln!("You may need to run: update-mime-database {}", mime_dir.display());
            Ok(())
        }
    }
}

/// Associate MIME type with application
fn associate_mime_type(config_dir: &Path) -> std::io::Result<()> {
    let mimeapps_file = config_dir.join("mimeapps.list");

    // Read existing content or create new
    let mut content = if mimeapps_file.exists() {
        fs::read_to_string(&mimeapps_file)?
    } else {
        String::from("[Default Applications]\n")
    };

    // Check if association already exists
    if !content.contains("application/x-enc=tesseract.desktop") {
        // Find [Default Applications] section or create it
        if !content.contains("[Default Applications]") {
            content.push_str("\n[Default Applications]\n");
        }

        // Add association after [Default Applications]
        if let Some(pos) = content.find("[Default Applications]") {
            let insert_pos = content[pos..]
                .find('\n')
                .map(|p| pos + p + 1)
                .unwrap_or(content.len());

            content.insert_str(insert_pos, "application/x-enc=tesseract.desktop\n");
        }

        // Write back
        fs::write(&mimeapps_file, content)?;
        println!("✓ Associated MIME type with application");
    } else {
        println!("✓ MIME association already exists");
    }

    Ok(())
}

/// Remove MIME association from mimeapps.list
fn remove_mime_association(config_dir: &Path) -> std::io::Result<()> {
    let mimeapps_file = config_dir.join("mimeapps.list");

    if !mimeapps_file.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(&mimeapps_file)?;
    let new_content: String = content
        .lines()
        .filter(|line| !line.contains("application/x-enc=tesseract.desktop"))
        .collect::<Vec<_>>()
        .join("\n");

    if new_content != content {
        fs::write(&mimeapps_file, new_content)?;
        println!("✓ Removed MIME association");
    }

    Ok(())
}

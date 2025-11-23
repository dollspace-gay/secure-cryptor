// macOS Launch Services Integration for Tesseract
// Handles file associations via UTI (Uniform Type Identifiers) and Launch Services
//
// NOTE: macOS file association typically requires .app bundles with Info.plist.
// This implementation provides basic support using available command-line tools.

#![cfg(target_os = "macos")]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Install macOS file associations
pub fn install(gui_exe: &PathBuf) -> std::io::Result<()> {
    println!("\nNOTE: macOS file associations work best with .app bundles.");
    println!("This installer will do its best with the standalone executable.\n");

    // Try using 'duti' if available (third-party tool for setting default apps)
    if is_duti_available() {
        install_with_duti(gui_exe)?;
    } else {
        println!("Warning: 'duti' tool not found.");
        println!("For full file association support on macOS, install duti:");
        println!("  brew install duti");
        println!("\nAlternatively, manually associate .enc files:");
        println!("  1. Right-click an .enc file");
        println!("  2. Select 'Get Info'");
        println!("  3. Under 'Open with:', select {}", gui_exe.display());
        println!("  4. Click 'Change All...'");
    }

    // Create a launch agent plist for better integration (optional)
    create_launch_services_plist(gui_exe)?;

    println!("\n✓ macOS integration configured");
    Ok(())
}

/// Uninstall macOS file associations
pub fn uninstall() -> std::io::Result<()> {
    // Remove launch services plist if it exists
    let home = get_home_dir()?;
    let plist_path = home.join("Library/LaunchAgents/com.securecryptor.plist");

    if plist_path.exists() {
        fs::remove_file(&plist_path)?;
        println!("✓ Removed launch agent plist");
    }

    println!("\nNOTE: To fully remove file associations on macOS:");
    println!("  1. Right-click an .enc file");
    println!("  2. Select 'Get Info'");
    println!("  3. Under 'Open with:', select another application");
    println!("  4. Click 'Change All...'");

    Ok(())
}

/// Check if 'duti' command is available
fn is_duti_available() -> bool {
    Command::new("which")
        .arg("duti")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Install file associations using duti
fn install_with_duti(gui_exe: &PathBuf) -> std::io::Result<()> {
    // Create a temporary UTI configuration file for duti
    let home = get_home_dir()?;
    let config_path = home.join(".tesseract-duti");

    let config_content = format!(
        "# Tesseract file associations\n{} .enc all\n",
        gui_exe.display()
    );

    fs::write(&config_path, config_content)?;

    // Run duti to install associations
    match Command::new("duti").arg(&config_path).status() {
        Ok(status) if status.success() => {
            println!("✓ Installed file associations using duti");
            fs::remove_file(&config_path)?;
            Ok(())
        }
        Ok(status) => {
            eprintln!("Warning: duti exited with status: {}", status);
            fs::remove_file(&config_path)?;
            Ok(())
        }
        Err(e) => {
            fs::remove_file(&config_path)?;
            Err(e)
        }
    }
}

/// Create a Launch Services property list for better system integration
fn create_launch_services_plist(gui_exe: &PathBuf) -> std::io::Result<()> {
    let home = get_home_dir()?;
    let launch_agents_dir = home.join("Library/LaunchAgents");
    fs::create_dir_all(&launch_agents_dir)?;

    let plist_path = launch_agents_dir.join("com.securecryptor.plist");

    // Note: This is a minimal plist. Full .app bundle integration would be better.
    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.securecryptor</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
"#,
        gui_exe.display()
    );

    let mut file = fs::File::create(&plist_path)?;
    file.write_all(plist_content.as_bytes())?;

    println!("✓ Created Launch Services plist: {}", plist_path.display());

    // Notify Launch Services of the change
    let _ = Command::new("/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister")
        .arg("-v")
        .arg("-f")
        .arg(gui_exe)
        .status();

    Ok(())
}

/// Get user's home directory
fn get_home_dir() -> std::io::Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "HOME environment variable not set",
            )
        })
}

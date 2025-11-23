/// macOS launchd service integration for Tesseract daemon
///
/// Manages LaunchAgent plist installation and service control

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SERVICE_LABEL: &str = "com.tesseract.daemon";
const PLIST_FILE: &str = "com.tesseract.daemon.plist";

/// Get the LaunchAgents directory for the current user
fn get_launch_agents_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Ok(home) = std::env::var("HOME") {
        Ok(PathBuf::from(home).join("Library/LaunchAgents"))
    } else {
        Err("Could not determine HOME directory".into())
    }
}

/// Generate the launchd plist file content
fn generate_plist(exe_path: &Path, socket_path: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>/tmp/tesseract-daemon.log</string>

    <key>StandardErrorPath</key>
    <string>/tmp/tesseract-daemon-error.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>

    <key>Sockets</key>
    <dict>
        <key>Listener</key>
        <dict>
            <key>SockPathName</key>
            <string>{}</string>
            <key>SockPathMode</key>
            <integer>384</integer>
        </dict>
    </dict>
</dict>
</plist>
"#,
        SERVICE_LABEL,
        exe_path.display(),
        socket_path.display()
    )
}

/// Install the daemon as a LaunchAgent
pub fn install_service() -> Result<(), Box<dyn std::error::Error>> {
    let exe_path = std::env::current_exe()?;
    let launch_agents_dir = get_launch_agents_dir()?;

    // Determine socket path
    let socket_path = if let Ok(runtime_dir) = std::env::var("TMPDIR") {
        PathBuf::from(runtime_dir).join("tesseract-daemon.sock")
    } else {
        PathBuf::from("/tmp/tesseract-daemon.sock")
    };

    println!("Installing Tesseract Daemon as LaunchAgent...");
    println!("Executable: {}", exe_path.display());
    println!("LaunchAgents directory: {}", launch_agents_dir.display());

    // Create LaunchAgents directory if it doesn't exist
    fs::create_dir_all(&launch_agents_dir)?;

    // Write the plist file
    let plist_path = launch_agents_dir.join(PLIST_FILE);
    let plist_content = generate_plist(&exe_path, &socket_path);
    fs::write(&plist_path, plist_content)?;

    println!("✓ LaunchAgent plist created: {}", plist_path.display());
    println!("\n✓ Service installed successfully");
    println!("\nYou can now:");
    println!("  • Load the service:    launchctl load {}", plist_path.display());
    println!("  • Unload the service:  launchctl unload {}", plist_path.display());
    println!("  • Check status:        launchctl list | grep {}", SERVICE_LABEL);
    println!("\nNote: The service will automatically start at login");

    Ok(())
}

/// Uninstall the LaunchAgent
pub fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    let launch_agents_dir = get_launch_agents_dir()?;
    let plist_path = launch_agents_dir.join(PLIST_FILE);

    println!("Uninstalling Tesseract Daemon LaunchAgent...");

    // Unload the service if loaded
    if plist_path.exists() {
        let _ = Command::new("launchctl")
            .args(&["unload", plist_path.to_str().unwrap()])
            .output();

        // Remove the plist file
        fs::remove_file(&plist_path)?;
        println!("✓ LaunchAgent plist removed: {}", plist_path.display());
    }

    println!("✓ Service uninstalled successfully");

    Ok(())
}

/// Load the LaunchAgent (start the service)
pub fn load_service() -> Result<(), Box<dyn std::error::Error>> {
    let launch_agents_dir = get_launch_agents_dir()?;
    let plist_path = launch_agents_dir.join(PLIST_FILE);

    if !plist_path.exists() {
        return Err("Service is not installed. Run install-service first.".into());
    }

    let output = Command::new("launchctl")
        .args(&["load", plist_path.to_str().unwrap()])
        .output()?;

    if output.status.success() {
        println!("✓ Service loaded");
        Ok(())
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to load service: {}", error).into())
    }
}

/// Unload the LaunchAgent (stop the service)
pub fn unload_service() -> Result<(), Box<dyn std::error::Error>> {
    let launch_agents_dir = get_launch_agents_dir()?;
    let plist_path = launch_agents_dir.join(PLIST_FILE);

    if !plist_path.exists() {
        return Err("Service is not installed".into());
    }

    let output = Command::new("launchctl")
        .args(&["unload", plist_path.to_str().unwrap()])
        .output()?;

    if output.status.success() {
        println!("✓ Service unloaded");
        Ok(())
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to unload service: {}", error).into())
    }
}

#[cfg(not(target_os = "macos"))]
compile_error!("This module is only for macOS");

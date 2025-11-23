/// Linux systemd service integration for Tesseract daemon
///
/// Manages systemd unit file installation and service control

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SERVICE_NAME: &str = "tesseract-daemon";
const SERVICE_FILE: &str = "tesseract-daemon.service";

/// Get the systemd user service directory
fn get_systemd_user_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
        Ok(PathBuf::from(config_home).join("systemd/user"))
    } else if let Ok(home) = std::env::var("HOME") {
        Ok(PathBuf::from(home).join(".config/systemd/user"))
    } else {
        Err("Could not determine systemd user directory".into())
    }
}

/// Get the systemd system service directory
fn get_systemd_system_dir() -> PathBuf {
    PathBuf::from("/etc/systemd/system")
}

/// Generate the systemd service unit file content
fn generate_service_file(exe_path: &Path) -> String {
    format!(
        r#"[Unit]
Description=Tesseract Volume Manager Daemon
Documentation=https://github.com/your-repo/tesseract
After=network.target

[Service]
Type=simple
ExecStart={}
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/tmp

[Install]
WantedBy=default.target
"#,
        exe_path.display()
    )
}

/// Install the daemon as a systemd user service
pub fn install_service() -> Result<(), Box<dyn std::error::Error>> {
    let exe_path = std::env::current_exe()?;
    let systemd_dir = get_systemd_user_dir()?;

    println!("Installing Tesseract Daemon as systemd user service...");
    println!("Executable: {}", exe_path.display());
    println!("Service directory: {}", systemd_dir.display());

    // Create systemd user directory if it doesn't exist
    fs::create_dir_all(&systemd_dir)?;

    // Write the service file
    let service_path = systemd_dir.join(SERVICE_FILE);
    let service_content = generate_service_file(&exe_path);
    fs::write(&service_path, service_content)?;

    println!("✓ Service file created: {}", service_path.display());

    // Reload systemd to recognize the new service
    let output = Command::new("systemctl")
        .args(&["--user", "daemon-reload"])
        .output()?;

    if !output.status.success() {
        eprintln!("Warning: Failed to reload systemd daemon");
    }

    println!("\n✓ Service installed successfully");
    println!("\nYou can now:");
    println!("  • Enable the service:  systemctl --user enable {}", SERVICE_NAME);
    println!("  • Start the service:   systemctl --user start {}", SERVICE_NAME);
    println!("  • Stop the service:    systemctl --user stop {}", SERVICE_NAME);
    println!("  • Check status:        systemctl --user status {}", SERVICE_NAME);
    println!("  • View logs:           journalctl --user -u {}", SERVICE_NAME);

    Ok(())
}

/// Install the daemon as a systemd system service (requires root)
pub fn install_system_service() -> Result<(), Box<dyn std::error::Error>> {
    let exe_path = std::env::current_exe()?;
    let systemd_dir = get_systemd_system_dir();

    println!("Installing Tesseract Daemon as systemd system service...");
    println!("Note: This requires root privileges");

    // Check if running as root
    if !nix::unistd::Uid::effective().is_root() {
        return Err("System service installation requires root privileges. Run with sudo.".into());
    }

    // Write the service file
    let service_path = systemd_dir.join(SERVICE_FILE);
    let service_content = generate_service_file(&exe_path);
    fs::write(&service_path, service_content)?;

    println!("✓ Service file created: {}", service_path.display());

    // Reload systemd
    let output = Command::new("systemctl")
        .args(&["daemon-reload"])
        .output()?;

    if !output.status.success() {
        eprintln!("Warning: Failed to reload systemd daemon");
    }

    println!("\n✓ System service installed successfully");
    println!("\nYou can now:");
    println!("  • Enable the service:  systemctl enable {}", SERVICE_NAME);
    println!("  • Start the service:   systemctl start {}", SERVICE_NAME);
    println!("  • Stop the service:    systemctl stop {}", SERVICE_NAME);
    println!("  • Check status:        systemctl status {}", SERVICE_NAME);

    Ok(())
}

/// Uninstall the systemd user service
pub fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    let systemd_dir = get_systemd_user_dir()?;
    let service_path = systemd_dir.join(SERVICE_FILE);

    println!("Uninstalling Tesseract Daemon systemd service...");

    // Stop the service if running
    let _ = Command::new("systemctl")
        .args(&["--user", "stop", SERVICE_NAME])
        .output();

    // Disable the service if enabled
    let _ = Command::new("systemctl")
        .args(&["--user", "disable", SERVICE_NAME])
        .output();

    // Remove the service file
    if service_path.exists() {
        fs::remove_file(&service_path)?;
        println!("✓ Service file removed: {}", service_path.display());
    }

    // Reload systemd
    let _ = Command::new("systemctl")
        .args(&["--user", "daemon-reload"])
        .output();

    println!("✓ Service uninstalled successfully");

    Ok(())
}

/// Enable the service to start on boot
pub fn enable_service() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("systemctl")
        .args(&["--user", "enable", SERVICE_NAME])
        .output()?;

    if output.status.success() {
        println!("✓ Service enabled");
        Ok(())
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to enable service: {}", error).into())
    }
}

/// Start the service
pub fn start_service() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("systemctl")
        .args(&["--user", "start", SERVICE_NAME])
        .output()?;

    if output.status.success() {
        println!("✓ Service started");
        Ok(())
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to start service: {}", error).into())
    }
}

/// Stop the service
pub fn stop_service() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("systemctl")
        .args(&["--user", "stop", SERVICE_NAME])
        .output()?;

    if output.status.success() {
        println!("✓ Service stopped");
        Ok(())
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to stop service: {}", error).into())
    }
}

#[cfg(not(target_os = "linux"))]
compile_error!("This module is only for Linux");

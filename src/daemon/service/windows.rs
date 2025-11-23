/// Windows Service implementation for Tesseract daemon
///
/// Integrates with Windows Service Control Manager (SCM)

use std::ffi::OsString;
use std::time::Duration;
use std::sync::mpsc;

use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use crate::daemon::DaemonServer;

const SERVICE_NAME: &str = "TesseractDaemon";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Install the daemon as a Windows service
pub fn install_service() -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    // Get the current executable path
    let exe_path = std::env::current_exe()?;

    println!("Installing Tesseract Daemon as Windows Service...");
    println!("Executable: {}", exe_path.display());

    // Use sc.exe to create the service
    let output = Command::new("sc")
        .args(&[
            "create",
            SERVICE_NAME,
            &format!("binPath= \"{}\" --service", exe_path.display()),
            "DisplayName= \"Tesseract Volume Manager Daemon\"",
            "start= auto",
            "type= own",
        ])
        .output()?;

    if output.status.success() {
        println!("✓ Service installed successfully");
        println!("\nYou can now:");
        println!("  • Start the service: sc start {}", SERVICE_NAME);
        println!("  • Stop the service:  sc stop {}", SERVICE_NAME);
        println!("  • Query status:      sc query {}", SERVICE_NAME);
        Ok(())
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to install service: {}", error).into())
    }
}

/// Uninstall the daemon Windows service
pub fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    println!("Uninstalling Tesseract Daemon Windows Service...");

    // Stop the service first if it's running
    let _ = Command::new("sc")
        .args(&["stop", SERVICE_NAME])
        .output();

    // Delete the service
    let output = Command::new("sc")
        .args(&["delete", SERVICE_NAME])
        .output()?;

    if output.status.success() {
        println!("✓ Service uninstalled successfully");
        Ok(())
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to uninstall service: {}", error).into())
    }
}

/// Run the daemon as a Windows service
pub fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    // Register the service entry point
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

// Define the service entry point
define_windows_service!(ffi_service_main, service_main);

/// Service main function
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service_impl() {
        eprintln!("Service error: {}", e);
    }
}

/// Implementation of the service main logic
fn run_service_impl() -> Result<(), Box<dyn std::error::Error>> {
    // Create a channel to receive service control events
    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    // Define the service control handler
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register the service control handler
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Report that the service is starting
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Start the daemon server in a separate thread
    let server_handle = std::thread::spawn(|| {
        let server = DaemonServer::new();
        if let Err(e) = server.run() {
            eprintln!("Daemon server error: {}", e);
        }
    });

    // Report that the service is running
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Wait for shutdown signal
    let _ = shutdown_rx.recv();

    // Report that the service is stopping
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(5),
        process_id: None,
    })?;

    // TODO: Send shutdown signal to daemon server
    // For now, we'll just terminate the thread
    drop(server_handle);

    // Report that the service has stopped
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

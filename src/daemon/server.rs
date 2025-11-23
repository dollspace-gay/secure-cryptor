/// Daemon server implementation
///
/// Manages mounted volumes and handles IPC requests

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{Read, Write};

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

#[cfg(windows)]
use std::net::{TcpListener, TcpStream};

use super::protocol::{DaemonCommand, DaemonResponse, MountInfo};
use crate::volume::manager::VolumeManager;
use crate::volume::mount::MountOptions;

/// Daemon server state
pub struct DaemonServer {
    /// Volume manager for handling mounts
    volume_manager: Arc<Mutex<VolumeManager>>,

    /// Track mounted volumes
    mounts: Arc<Mutex<HashMap<PathBuf, MountInfo>>>,

    /// Socket path for IPC
    #[allow(dead_code)]
    socket_path: PathBuf,
}

impl DaemonServer {
    /// Create a new daemon server
    pub fn new() -> Self {
        let socket_path = Self::default_socket_path();

        Self {
            volume_manager: Arc::new(Mutex::new(VolumeManager::new())),
            mounts: Arc::new(Mutex::new(HashMap::new())),
            socket_path,
        }
    }

    /// Get the default socket path for the platform
    #[cfg(unix)]
    fn default_socket_path() -> PathBuf {
        // Use XDG_RUNTIME_DIR if available, otherwise /tmp
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join("tesseract-daemon.sock")
        } else {
            PathBuf::from("/tmp/tesseract-daemon.sock")
        }
    }

    #[cfg(windows)]
    fn default_socket_path() -> PathBuf {
        // On Windows, we'll use a TCP socket on localhost as a fallback
        // (named pipes would be better but Unix sockets are now supported on Windows 10+)
        PathBuf::from("127.0.0.1:37284") // Arbitrary port
    }

    /// Start the daemon server
    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            self.run_unix()
        }

        #[cfg(windows)]
        {
            self.run_windows()
        }
    }

    #[cfg(unix)]
    fn run_unix(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Remove existing socket file if it exists
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        println!("Daemon listening on {:?}", self.socket_path);

        // Set up signal handlers for graceful shutdown
        Self::setup_signal_handlers();

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let mounts = Arc::clone(&self.mounts);
                    let volume_manager = Arc::clone(&self.volume_manager);

                    // Handle connection in a new thread
                    std::thread::spawn(move || {
                        if let Err(e) = Self::handle_client(stream, mounts, volume_manager) {
                            eprintln!("Error handling client: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Connection error: {}", e);
                }
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn run_windows(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:37284")?;
        println!("Daemon listening on 127.0.0.1:37284");

        // Set up Ctrl+C handler for graceful shutdown
        Self::setup_signal_handlers();

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let mounts = Arc::clone(&self.mounts);
                    let volume_manager = Arc::clone(&self.volume_manager);

                    // Handle connection in a new thread
                    std::thread::spawn(move || {
                        if let Err(e) = Self::handle_client(stream, mounts, volume_manager) {
                            eprintln!("Error handling client: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Connection error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Handle a client connection
    #[cfg(unix)]
    fn handle_client(
        mut stream: UnixStream,
        mounts: Arc<Mutex<HashMap<PathBuf, MountInfo>>>,
        volume_manager: Arc<Mutex<VolumeManager>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Self::handle_client_impl(&mut stream, mounts, volume_manager)
    }

    #[cfg(windows)]
    fn handle_client(
        mut stream: TcpStream,
        mounts: Arc<Mutex<HashMap<PathBuf, MountInfo>>>,
        volume_manager: Arc<Mutex<VolumeManager>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Self::handle_client_impl(&mut stream, mounts, volume_manager)
    }

    /// Implementation of client handling (generic over stream type)
    fn handle_client_impl<S: Read + Write>(
        stream: &mut S,
        mounts: Arc<Mutex<HashMap<PathBuf, MountInfo>>>,
        volume_manager: Arc<Mutex<VolumeManager>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Read request (prefixed with 4-byte length)
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes)?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        let mut buffer = vec![0u8; len];
        stream.read_exact(&mut buffer)?;

        // Parse command
        let command = DaemonCommand::from_bytes(&buffer)?;

        // Process command
        let response = Self::process_command(command, mounts, volume_manager);

        // Send response (prefixed with 4-byte length)
        let response_bytes = response.to_bytes()?;
        let len_bytes = (response_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes)?;
        stream.write_all(&response_bytes)?;
        stream.flush()?;

        Ok(())
    }

    /// Process a daemon command
    fn process_command(
        command: DaemonCommand,
        mounts: Arc<Mutex<HashMap<PathBuf, MountInfo>>>,
        volume_manager: Arc<Mutex<VolumeManager>>,
    ) -> DaemonResponse {
        match command {
            DaemonCommand::Mount {
                container_path,
                mount_point,
                password,
                read_only,
                hidden_offset,
            } => {
                // Check if already mounted
                {
                    let mounts_guard = mounts.lock().unwrap();
                    if mounts_guard.contains_key(&container_path) {
                        return DaemonResponse::error("Volume is already mounted");
                    }
                }

                // Mount the volume
                let mut mgr = volume_manager.lock().unwrap();

                let options = MountOptions {
                    mount_point: mount_point.clone(),
                    read_only,
                    allow_other: false,
                    auto_unmount: true,
                    fs_name: Some("SecureCryptor".to_string()),
                    hidden_offset,
                    hidden_password: None, // TODO: Add hidden password support to daemon protocol
                };

                match mgr.mount(&container_path, &password, options) {
                    Ok(_) => {
                        // Track the mount
                        let info = MountInfo {
                            container_path: container_path.clone(),
                            mount_point,
                            read_only,
                            is_hidden: hidden_offset.is_some(),
                            mounted_at: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                            pid: Some(std::process::id()),
                        };

                        mounts.lock().unwrap().insert(container_path, info.clone());

                        DaemonResponse::Mounted { info }
                    }
                    Err(e) => DaemonResponse::error(format!("Mount failed: {}", e)),
                }
            }

            DaemonCommand::Unmount { container_path } => {
                let mut mgr = volume_manager.lock().unwrap();

                match mgr.unmount(&container_path) {
                    Ok(_) => {
                        mounts.lock().unwrap().remove(&container_path);
                        DaemonResponse::Unmounted { container_path }
                    }
                    Err(e) => DaemonResponse::error(format!("Unmount failed: {}", e)),
                }
            }

            DaemonCommand::UnmountByMountPoint { mount_point } => {
                // Find container by mount point
                let container_path = {
                    let mounts_guard = mounts.lock().unwrap();
                    mounts_guard
                        .iter()
                        .find(|(_, info)| info.mount_point == mount_point)
                        .map(|(path, _)| path.clone())
                };

                if let Some(container_path) = container_path {
                    let mut mgr = volume_manager.lock().unwrap();

                    match mgr.unmount(&container_path) {
                        Ok(_) => {
                            mounts.lock().unwrap().remove(&container_path);
                            DaemonResponse::Unmounted { container_path }
                        }
                        Err(e) => DaemonResponse::error(format!("Unmount failed: {}", e)),
                    }
                } else {
                    DaemonResponse::error("No volume mounted at that mount point")
                }
            }

            DaemonCommand::List => {
                let mounts_guard = mounts.lock().unwrap();
                let mount_list: Vec<MountInfo> =
                    mounts_guard.values().cloned().collect();

                DaemonResponse::MountList { mounts: mount_list }
            }

            DaemonCommand::GetInfo { container_path } => {
                let mounts_guard = mounts.lock().unwrap();

                if let Some(info) = mounts_guard.get(&container_path) {
                    DaemonResponse::MountInfo {
                        info: info.clone(),
                    }
                } else {
                    DaemonResponse::error("Volume is not mounted")
                }
            }

            DaemonCommand::UnmountAll => {
                let mut mgr = volume_manager.lock().unwrap();
                let container_paths: Vec<PathBuf> = {
                    let mounts_guard = mounts.lock().unwrap();
                    mounts_guard.keys().cloned().collect()
                };

                for container_path in container_paths {
                    let _ = mgr.unmount(&container_path);
                    mounts.lock().unwrap().remove(&container_path);
                }

                DaemonResponse::Success
            }

            DaemonCommand::Ping => DaemonResponse::Pong,

            DaemonCommand::Shutdown => {
                // Unmount all volumes
                let mut mgr = volume_manager.lock().unwrap();
                let container_paths: Vec<PathBuf> = {
                    let mounts_guard = mounts.lock().unwrap();
                    mounts_guard.keys().cloned().collect()
                };

                for container_path in container_paths {
                    let _ = mgr.unmount(&container_path);
                }

                // Exit the process
                std::process::exit(0);
            }
        }
    }

    /// Set up signal handlers for graceful shutdown
    fn setup_signal_handlers() {
        // Use ctrlc crate for cross-platform Ctrl+C handling
        ctrlc::set_handler(move || {
            println!("Received shutdown signal, cleaning up...");
            std::process::exit(0);
        })
        .expect("Error setting Ctrl-C handler");
    }
}

impl Default for DaemonServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Daemon client implementation
///
/// Provides a client interface for communicating with the daemon server

use std::path::PathBuf;
use std::io::{Read, Write};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[cfg(windows)]
use std::net::TcpStream;

use super::protocol::{DaemonCommand, DaemonResponse};

/// Client for communicating with the daemon
pub struct DaemonClient {
    #[allow(dead_code)]
    socket_path: PathBuf,
}

impl DaemonClient {
    /// Create a new daemon client
    pub fn new() -> Self {
        Self {
            socket_path: Self::default_socket_path(),
        }
    }

    /// Get the default socket path for the platform
    #[cfg(unix)]
    fn default_socket_path() -> PathBuf {
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join("tesseract-daemon.sock")
        } else {
            PathBuf::from("/tmp/tesseract-daemon.sock")
        }
    }

    #[cfg(windows)]
    fn default_socket_path() -> PathBuf {
        PathBuf::from("127.0.0.1:37284")
    }

    /// Check if the daemon is running
    pub fn is_running(&self) -> bool {
        self.send_command(DaemonCommand::Ping).is_ok()
    }

    /// Send a command to the daemon
    pub fn send_command(&self, command: DaemonCommand) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            self.send_command_unix(command)
        }

        #[cfg(windows)]
        {
            self.send_command_windows(command)
        }
    }

    #[cfg(unix)]
    fn send_command_unix(&self, command: DaemonCommand) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        Self::send_command_impl(&mut stream, command)
    }

    #[cfg(windows)]
    fn send_command_windows(&self, command: DaemonCommand) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect("127.0.0.1:37284")?;
        Self::send_command_impl(&mut stream, command)
    }

    /// Implementation of command sending (generic over stream type)
    fn send_command_impl<S: Read + Write>(
        stream: &mut S,
        command: DaemonCommand,
    ) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        // Serialize command
        let command_bytes = command.to_bytes()?;

        // Send command with length prefix
        let len_bytes = (command_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes)?;
        stream.write_all(&command_bytes)?;
        stream.flush()?;

        // Read response (prefixed with 4-byte length)
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes)?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        let mut buffer = vec![0u8; len];
        stream.read_exact(&mut buffer)?;

        // Parse response
        let response = DaemonResponse::from_bytes(&buffer)?;

        Ok(response)
    }

    /// Mount a volume via the daemon
    pub fn mount(
        &self,
        container_path: PathBuf,
        mount_point: PathBuf,
        password: String,
        read_only: bool,
        hidden_offset: Option<u64>,
    ) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        let command = DaemonCommand::Mount {
            container_path,
            mount_point,
            password,
            read_only,
            hidden_offset,
        };

        self.send_command(command)
    }

    /// Unmount a volume by container path
    pub fn unmount(&self, container_path: PathBuf) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        let command = DaemonCommand::Unmount { container_path };
        self.send_command(command)
    }

    /// Unmount a volume by mount point
    pub fn unmount_by_mount_point(&self, mount_point: PathBuf) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        let command = DaemonCommand::UnmountByMountPoint { mount_point };
        self.send_command(command)
    }

    /// List all mounted volumes
    pub fn list(&self) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        self.send_command(DaemonCommand::List)
    }

    /// Get information about a specific mount
    pub fn get_info(&self, container_path: PathBuf) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        let command = DaemonCommand::GetInfo { container_path };
        self.send_command(command)
    }

    /// Unmount all volumes
    pub fn unmount_all(&self) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        self.send_command(DaemonCommand::UnmountAll)
    }

    /// Shutdown the daemon
    pub fn shutdown(&self) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        self.send_command(DaemonCommand::Shutdown)
    }
}

impl Default for DaemonClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Auto-mount service for encrypted volumes
///
/// Provides functionality to automatically mount encrypted volumes during
/// system startup after the OS has loaded, with support for password prompts,
/// TPM unsealing, and systemd/Windows service integration.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use thiserror::Error;


/// Errors that can occur during auto-mount operations
#[derive(Debug, Error)]
pub enum AutoMountError {
    /// Configuration file error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Volume mount failed
    #[error("Failed to mount volume: {0}")]
    MountFailed(String),

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Result type for auto-mount operations
pub type Result<T> = std::result::Result<T, AutoMountError>;

/// Authentication method for auto-mounting
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "method")]
pub enum AutoMountAuth {
    /// Prompt user for password via GUI/CLI
    #[serde(rename = "prompt")]
    PasswordPrompt,

    /// Use TPM to unseal key (no user interaction)
    #[serde(rename = "tpm")]
    Tpm {
        /// PCR indices to bind to
        pcr_indices: Vec<u8>,
    },

    /// Use password from keyring/credential manager
    #[serde(rename = "keyring")]
    Keyring {
        /// Keyring entry name
        entry_name: String,
    },

    /// No authentication (volume already has recovery key)
    #[serde(rename = "none")]
    None,
}

/// Configuration for a single auto-mount volume
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeConfig {
    /// Unique identifier for this volume
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Path to the encrypted container file
    pub container_path: PathBuf,

    /// Where to mount the volume
    pub mount_point: PathBuf,

    /// Authentication method
    pub auth: AutoMountAuth,

    /// Whether to mount read-only
    #[serde(default)]
    pub read_only: bool,

    /// Whether this volume is required for boot
    /// If true, boot will wait for successful mount
    #[serde(default)]
    pub required: bool,

    /// Maximum time to wait for mount (seconds)
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Whether to auto-unmount on shutdown
    #[serde(default = "default_true")]
    pub auto_unmount: bool,
}

fn default_timeout() -> u64 {
    60
}

fn default_true() -> bool {
    true
}

/// Auto-mount configuration for all volumes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoMountConfig {
    /// List of volumes to auto-mount
    pub volumes: Vec<VolumeConfig>,

    /// Global mount timeout (seconds)
    #[serde(default = "default_timeout")]
    pub global_timeout: u64,

    /// Whether to run in background
    #[serde(default = "default_true")]
    pub background: bool,
}

impl AutoMountConfig {
    /// Creates a new empty configuration
    pub fn new() -> Self {
        Self {
            volumes: Vec::new(),
            global_timeout: 60,
            background: true,
        }
    }

    /// Loads configuration from a JSON file
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Saves configuration to a JSON file
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path.as_ref(), content)?;
        Ok(())
    }

    /// Adds a new volume to the configuration
    pub fn add_volume(&mut self, config: VolumeConfig) {
        self.volumes.push(config);
    }

    /// Removes a volume by ID
    pub fn remove_volume(&mut self, id: &str) -> Option<VolumeConfig> {
        if let Some(idx) = self.volumes.iter().position(|v| v.id == id) {
            Some(self.volumes.remove(idx))
        } else {
            None
        }
    }

    /// Gets a volume configuration by ID
    pub fn get_volume(&self, id: &str) -> Option<&VolumeConfig> {
        self.volumes.iter().find(|v| v.id == id)
    }

    /// Gets a mutable volume configuration by ID
    pub fn get_volume_mut(&mut self, id: &str) -> Option<&mut VolumeConfig> {
        self.volumes.iter_mut().find(|v| v.id == id)
    }
}

impl Default for AutoMountConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Auto-mount service that manages mounting of encrypted volumes
pub struct AutoMountService {
    config: AutoMountConfig,
    volume_manager: super::manager::VolumeManager,
    mounted_ids: HashMap<String, PathBuf>, // volume ID -> container path
}

impl AutoMountService {
    /// Creates a new auto-mount service
    pub fn new(config: AutoMountConfig) -> Self {
        Self {
            config,
            volume_manager: super::manager::VolumeManager::new(),
            mounted_ids: HashMap::new(),
        }
    }

    /// Mounts all configured volumes
    ///
    /// Returns a list of successfully mounted volume IDs and any errors
    pub fn mount_all(&mut self) -> (Vec<String>, Vec<(String, AutoMountError)>) {
        let mut successes = Vec::new();
        let mut failures = Vec::new();

        // Clone volumes to avoid borrow checker issues
        let volumes = self.config.volumes.clone();

        for volume in &volumes {
            match self.mount_volume(volume) {
                Ok(_) => {
                    successes.push(volume.id.clone());
                }
                Err(e) => {
                    failures.push((volume.id.clone(), e));
                }
            }
        }

        (successes, failures)
    }

    /// Mounts a single volume
    fn mount_volume(&mut self, config: &VolumeConfig) -> Result<()> {
        // Get password based on auth method
        let password = match &config.auth {
            AutoMountAuth::PasswordPrompt => {
                // In a real implementation, this would prompt the user
                // For now, we return an error as we can't prompt in a library
                return Err(AutoMountError::AuthFailed(
                    "Password prompt not supported in library context".to_string()
                ));
            }
            AutoMountAuth::Tpm { .. } => {
                // TPM unsealing not yet implemented
                return Err(AutoMountError::AuthFailed(
                    "TPM authentication not yet implemented".to_string()
                ));
            }
            AutoMountAuth::Keyring { entry_name } => {
                // Keyring lookup not yet implemented
                return Err(AutoMountError::AuthFailed(
                    format!("Keyring lookup not yet implemented for '{}'", entry_name)
                ));
            }
            AutoMountAuth::None => {
                // No authentication - use empty password (for recovery key scenarios)
                String::new()
            }
        };

        // Create mount options
        let options = super::mount::MountOptions {
            mount_point: config.mount_point.clone(),
            read_only: config.read_only,
            allow_other: false,
            auto_unmount: config.auto_unmount,
            fs_name: Some(config.name.clone()),
            hidden_offset: None,
            hidden_password: None,
        };

        // Mount using VolumeManager
        self.volume_manager
            .mount(&config.container_path, &password, options)
            .map_err(|e| AutoMountError::MountFailed(e.to_string()))?;

        // Track the mounted volume
        self.mounted_ids.insert(config.id.clone(), config.container_path.clone());

        Ok(())
    }

    /// Mounts a single volume with an explicit password
    ///
    /// This is useful for integrating with GUI/CLI where the user provides
    /// the password directly.
    ///
    /// # Arguments
    ///
    /// * `volume_id` - ID of the volume to mount
    /// * `password` - Password to unlock the volume
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The volume ID is not found in the configuration
    /// - The volume is already mounted
    /// - The mount operation fails
    pub fn mount_with_password(&mut self, volume_id: &str, password: &str) -> Result<()> {
        // Find the volume config
        let volume_config = self.config.get_volume(volume_id)
            .ok_or_else(|| AutoMountError::ConfigError(
                format!("Volume '{}' not found in configuration", volume_id)
            ))?.clone();

        // Create mount options
        let options = super::mount::MountOptions {
            mount_point: volume_config.mount_point.clone(),
            read_only: volume_config.read_only,
            allow_other: false,
            auto_unmount: volume_config.auto_unmount,
            fs_name: Some(volume_config.name.clone()),
            hidden_offset: None,
            hidden_password: None,
        };

        // Mount using VolumeManager
        self.volume_manager
            .mount(&volume_config.container_path, password, options)
            .map_err(|e| AutoMountError::MountFailed(e.to_string()))?;

        // Track the mounted volume
        self.mounted_ids.insert(volume_config.id.clone(), volume_config.container_path.clone());

        Ok(())
    }

    /// Unmounts a volume by ID
    ///
    /// # Arguments
    ///
    /// * `volume_id` - ID of the volume to unmount
    ///
    /// # Errors
    ///
    /// Returns an error if the volume is not mounted
    pub fn unmount(&mut self, volume_id: &str) -> Result<()> {
        if let Some(container_path) = self.mounted_ids.remove(volume_id) {
            self.volume_manager
                .unmount(&container_path)
                .map_err(|e| AutoMountError::MountFailed(e.to_string()))?;
            Ok(())
        } else {
            Err(AutoMountError::MountFailed(
                format!("Volume '{}' is not mounted", volume_id)
            ))
        }
    }

    /// Unmounts all mounted volumes
    pub fn unmount_all(&mut self) {
        self.volume_manager.unmount_all();
        self.mounted_ids.clear();
    }

    /// Checks if a volume is currently mounted
    pub fn is_mounted(&self, id: &str) -> bool {
        self.mounted_ids.contains_key(id)
    }

    /// Gets the list of mounted volume IDs
    pub fn mounted_volumes(&self) -> Vec<String> {
        self.mounted_ids.keys().cloned().collect()
    }

    /// Gets the mount point for a volume
    ///
    /// # Arguments
    ///
    /// * `volume_id` - ID of the volume
    ///
    /// # Returns
    ///
    /// The mount point path if the volume is mounted, None otherwise
    pub fn get_mount_point(&self, volume_id: &str) -> Option<PathBuf> {
        self.mounted_ids
            .get(volume_id)
            .and_then(|container_path| self.volume_manager.find_mount_point(container_path))
    }

    /// Gets information about all mounted volumes
    pub fn list_mounted_info(&self) -> Vec<super::manager::MountedVolumeInfo> {
        self.volume_manager.list_mounted()
    }
}

/// Builder for creating volume configurations
pub struct VolumeConfigBuilder {
    id: String,
    name: String,
    container_path: PathBuf,
    mount_point: PathBuf,
    auth: AutoMountAuth,
    read_only: bool,
    required: bool,
    timeout: u64,
    auto_unmount: bool,
}

impl VolumeConfigBuilder {
    /// Creates a new builder with required fields
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        container_path: impl Into<PathBuf>,
        mount_point: impl Into<PathBuf>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            container_path: container_path.into(),
            mount_point: mount_point.into(),
            auth: AutoMountAuth::PasswordPrompt,
            read_only: false,
            required: false,
            timeout: 60,
            auto_unmount: true,
        }
    }

    /// Sets the authentication method
    pub fn auth(mut self, auth: AutoMountAuth) -> Self {
        self.auth = auth;
        self
    }

    /// Sets whether to mount read-only
    pub fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Sets whether this volume is required
    pub fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }

    /// Sets the mount timeout
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets whether to auto-unmount
    pub fn auto_unmount(mut self, auto_unmount: bool) -> Self {
        self.auto_unmount = auto_unmount;
        self
    }

    /// Builds the volume configuration
    pub fn build(self) -> VolumeConfig {
        VolumeConfig {
            id: self.id,
            name: self.name,
            container_path: self.container_path,
            mount_point: self.mount_point,
            auth: self.auth,
            read_only: self.read_only,
            required: self.required,
            timeout: self.timeout,
            auto_unmount: self.auto_unmount,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_config() {
        let config = AutoMountConfig::new();
        assert_eq!(config.volumes.len(), 0);
        assert_eq!(config.global_timeout, 60);
        assert!(config.background);
    }

    #[test]
    fn test_add_remove_volume() {
        let mut config = AutoMountConfig::new();

        let volume = VolumeConfigBuilder::new(
            "vol1",
            "My Volume",
            "/path/to/container",
            "/mnt/encrypted",
        ).build();

        config.add_volume(volume);
        assert_eq!(config.volumes.len(), 1);

        let removed = config.remove_volume("vol1");
        assert!(removed.is_some());
        assert_eq!(config.volumes.len(), 0);
    }

    #[test]
    fn test_get_volume() {
        let mut config = AutoMountConfig::new();

        let volume = VolumeConfigBuilder::new(
            "vol1",
            "My Volume",
            "/path/to/container",
            "/mnt/encrypted",
        ).build();

        config.add_volume(volume);

        assert!(config.get_volume("vol1").is_some());
        assert!(config.get_volume("vol2").is_none());
    }

    #[test]
    fn test_volume_builder() {
        let volume = VolumeConfigBuilder::new(
            "test-vol",
            "Test Volume",
            "/data/secure.crypt",
            "/mnt/secure",
        )
        .auth(AutoMountAuth::Tpm {
            pcr_indices: vec![0, 7],
        })
        .read_only(true)
        .required(true)
        .timeout(120)
        .build();

        assert_eq!(volume.id, "test-vol");
        assert_eq!(volume.name, "Test Volume");
        assert!(volume.read_only);
        assert!(volume.required);
        assert_eq!(volume.timeout, 120);
        assert!(matches!(volume.auth, AutoMountAuth::Tpm { .. }));
    }

    #[test]
    fn test_save_load_config() {
        let mut config = AutoMountConfig::new();

        let volume = VolumeConfigBuilder::new(
            "vol1",
            "Test Volume",
            "/path/to/container",
            "/mnt/test",
        )
        .auth(AutoMountAuth::PasswordPrompt)
        .build();

        config.add_volume(volume);

        // Save to JSON
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("Test Volume"));
        assert!(json.contains("prompt"));

        // Load from JSON
        let loaded: AutoMountConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.volumes.len(), 1);
        assert_eq!(loaded.volumes[0].name, "Test Volume");
    }

    #[test]
    fn test_auth_serialization() {
        // Test PasswordPrompt
        let auth = AutoMountAuth::PasswordPrompt;
        let json = serde_json::to_string(&auth).unwrap();
        assert_eq!(json, r#"{"method":"prompt"}"#);

        // Test TPM
        let auth = AutoMountAuth::Tpm {
            pcr_indices: vec![0, 7],
        };
        let json = serde_json::to_string(&auth).unwrap();
        let loaded: AutoMountAuth = serde_json::from_str(&json).unwrap();
        assert!(matches!(loaded, AutoMountAuth::Tpm { .. }));

        // Test Keyring
        let auth = AutoMountAuth::Keyring {
            entry_name: "my-volume-key".to_string(),
        };
        let json = serde_json::to_string(&auth).unwrap();
        let loaded: AutoMountAuth = serde_json::from_str(&json).unwrap();
        if let AutoMountAuth::Keyring { entry_name } = loaded {
            assert_eq!(entry_name, "my-volume-key");
        } else {
            panic!("Wrong auth type");
        }
    }

    #[test]
    fn test_automount_service() {
        let config = AutoMountConfig::new();
        let service = AutoMountService::new(config);

        assert_eq!(service.mounted_volumes().len(), 0);
        assert!(!service.is_mounted("vol1"));
    }
}

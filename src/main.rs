//! Tesseract - Command-line file encryption tool
//!
//! A secure file encryptor/decryptor using AES-256-GCM encryption
//! with Argon2id key derivation.

use clap::{Parser, Subcommand};
use tesseract::{validation, CryptorError};
use std::path::PathBuf;

/// Command-line interface definition
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "A secure file encryptor/decryptor using AES-256-GCM with Argon2id key derivation."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt a file with password-based encryption
    Encrypt {
        /// Input file to encrypt
        #[arg(short, long)]
        input: PathBuf,
        /// Output file to write encrypted data to
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Decrypt a previously encrypted file
    Decrypt {
        /// Input file to decrypt
        #[arg(short, long)]
        input: PathBuf,
        /// Output file to write decrypted data to
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Encrypted volume management commands
    #[command(subcommand)]
    Volume(VolumeCommands),
    /// Daemon management commands
    #[command(subcommand)]
    Daemon(DaemonCommands),
}

/// Volume subcommands
#[derive(Subcommand, Debug)]
enum VolumeCommands {
    /// Create a new encrypted volume
    Create {
        /// Path for the new volume container
        #[arg(short, long)]
        container: PathBuf,
        /// Size of the volume (e.g., "100M", "1G", "500M")
        #[arg(short, long)]
        size: String,
        /// Mount point for the volume (optional)
        #[arg(short, long)]
        mount_point: Option<PathBuf>,
    },
    /// Mount an encrypted volume
    Mount {
        /// Path to the volume container
        #[arg(short, long)]
        container: PathBuf,
        /// Mount point path
        #[arg(short, long)]
        mount_point: PathBuf,
        /// Mount as read-only
        #[arg(short, long, default_value = "false")]
        read_only: bool,
    },
    /// Unmount an encrypted volume
    Unmount {
        /// Path to the volume container (or mount point)
        path: PathBuf,
    },
    /// List all mounted volumes
    List,
    /// Show information about a volume
    Info {
        /// Path to the volume container
        container: PathBuf,
    },
    /// Change password for a volume
    ChangePassword {
        /// Path to the volume container
        #[arg(short, long)]
        container: PathBuf,
        /// Slot index to change (0-7), or add a new slot if not specified
        #[arg(short, long)]
        slot: Option<usize>,
    },
    /// Generate a new recovery key
    GenerateRecoveryKey {
        /// Path where to save the recovery key file
        #[arg(short, long)]
        output: PathBuf,
        /// Optional name/description for the container
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Add a recovery key to a volume
    AddRecoveryKey {
        /// Path to the volume container
        #[arg(short, long)]
        container: PathBuf,
        /// Recovery key (64 hex characters) or path to recovery key file
        #[arg(short, long)]
        recovery_key: String,
    },
    /// Reset password using a recovery key
    ResetPassword {
        /// Path to the volume container
        #[arg(short, long)]
        container: PathBuf,
        /// Recovery key (64 hex characters) or path to recovery key file
        #[arg(short, long)]
        recovery_key: String,
    },
    /// Create a hidden volume within a container
    CreateHidden {
        /// Path to the outer volume container
        #[arg(short, long)]
        container: PathBuf,
        /// Size of the hidden volume (e.g., "100M", "1G")
        #[arg(short, long)]
        size: String,
        /// Offset from start of outer data area (e.g., "500M", "1G")
        #[arg(short, long)]
        offset: String,
    },
    /// Mount a hidden volume
    MountHidden {
        /// Path to the outer volume container
        #[arg(short, long)]
        container: PathBuf,
        /// Mount point path
        #[arg(short, long)]
        mount_point: PathBuf,
        /// Offset from start of outer data area (e.g., "500M", "1G")
        #[arg(short, long)]
        offset: String,
        /// Mount as read-only
        #[arg(short, long, default_value = "false")]
        read_only: bool,
    },
    /// Check if a hidden volume exists at an offset
    CheckHidden {
        /// Path to the outer volume container
        #[arg(short, long)]
        container: PathBuf,
        /// Offset to check (e.g., "500M", "1G")
        #[arg(short, long)]
        offset: String,
    },
    /// Migrate a V1 volume to V2 with post-quantum cryptography
    MigrateToPqc {
        /// Path to the volume container
        #[arg(short, long)]
        container: PathBuf,
        /// Path to save the PQC keypair (optional, will save to container.pqc-keypair if not specified)
        #[arg(short, long)]
        keypair_output: Option<PathBuf>,
    },
}

/// Daemon subcommands
#[derive(Subcommand, Debug)]
enum DaemonCommands {
    /// Start the daemon in foreground mode
    Start,
    /// Stop the running daemon
    Stop,
    /// Check if the daemon is running
    Status,
    /// Install the daemon as a system service
    InstallService,
    /// Uninstall the daemon system service
    UninstallService,
    /// Start the system service
    StartService,
    /// Stop the system service
    StopService,
}

/// Main application entry point
fn main() -> Result<(), CryptorError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output } => {
            println!("Encrypting '{}' -> '{}'", input.display(), output.display());
            encrypt_file_interactive(&input, &output)?;
            println!("✓ Encryption successful.");
        }
        Commands::Decrypt { input, output } => {
            println!("Decrypting '{}' -> '{}'", input.display(), output.display());
            decrypt_file_interactive(&input, &output)?;
            println!("✓ Decryption successful.");
        }
        Commands::Volume(volume_cmd) => {
            handle_volume_command(volume_cmd)?;
        }
        Commands::Daemon(daemon_cmd) => {
            handle_daemon_command(daemon_cmd)?;
        }
    }

    Ok(())
}

/// Encrypt a file with interactive password prompt and validation
fn encrypt_file_interactive(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
) -> Result<(), CryptorError> {
    let password = validation::get_and_validate_password()?;
    tesseract::encrypt_file(input_path, output_path, &password)?;
    Ok(())
}

/// Decrypt a file with interactive password prompt
fn decrypt_file_interactive(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
) -> Result<(), CryptorError> {
    let password = validation::get_password()?;
    tesseract::decrypt_file(input_path, output_path, &password)?;
    Ok(())
}

/// Handle volume subcommands
#[cfg(feature = "encrypted-volumes")]
fn handle_volume_command(cmd: VolumeCommands) -> Result<(), CryptorError> {
    use tesseract::volume::{Container, VolumeManager, MountOptions};

    match cmd {
        VolumeCommands::Create { container, size, mount_point } => {
            println!("Creating encrypted volume at '{}'", container.display());

            // Parse size string (e.g., "100M", "1G")
            let size_bytes = parse_size(&size)?;

            // Get password with validation
            let password = validation::get_and_validate_password()?;

            // Create the container
            Container::create(
                &container,
                size_bytes,
                &password,
                4096, // Default sector size
            ).map_err(|e| CryptorError::Io(
                std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
            ))?;

            println!("✓ Volume created successfully.");
            println!("  Container: {}", container.display());
            println!("  Size: {} bytes ({} MB)", size_bytes, size_bytes / 1024 / 1024);

            // Mount if requested
            if let Some(mount_pt) = mount_point {
                println!("Mounting volume at '{}'...", mount_pt.display());
                let mut manager = VolumeManager::new();
                let options = MountOptions {
                    mount_point: mount_pt.clone(),
                    read_only: false,
                    allow_other: false,
                    auto_unmount: true,
                    fs_name: Some("Tesseract".to_string()),
                };

                manager.mount(&container, &password, options)
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;

                println!("✓ Volume mounted at '{}'", mount_pt.display());
                println!("  Press Ctrl+C to unmount and exit.");

                // Wait for Ctrl+C
                let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
                let r = running.clone();
                ctrlc::set_handler(move || {
                    r.store(false, std::sync::atomic::Ordering::SeqCst);
                }).expect("Error setting Ctrl-C handler");

                while running.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }

                println!("\nUnmounting volume...");
                manager.unmount(&container)
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;
                println!("✓ Volume unmounted.");
            }
        }
        VolumeCommands::Mount { container, mount_point, read_only } => {
            println!("Mounting '{}' at '{}'", container.display(), mount_point.display());

            let password = validation::get_password()?;
            let mut manager = VolumeManager::new();

            let options = MountOptions {
                mount_point: mount_point.clone(),
                read_only,
                allow_other: false,
                auto_unmount: true,
                fs_name: Some("Tesseract".to_string()),
            };

            manager.mount(&container, &password, options)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            println!("✓ Volume mounted successfully.");
            println!("  Mount point: {}", mount_point.display());
            if read_only {
                println!("  Mode: Read-only");
            }
            println!("  Press Ctrl+C to unmount and exit.");

            // Wait for Ctrl+C
            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let r = running.clone();
            ctrlc::set_handler(move || {
                r.store(false, std::sync::atomic::Ordering::SeqCst);
            }).expect("Error setting Ctrl-C handler");

            while running.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }

            println!("\nUnmounting volume...");
            manager.unmount(&container)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;
            println!("✓ Volume unmounted.");
        }
        VolumeCommands::Unmount { path } => {
            use tesseract::daemon::DaemonClient;

            // Try to use daemon for unmount
            let client = DaemonClient::new();

            if !client.is_running() {
                println!("Error: Daemon is not running.");
                println!("Start the daemon with: tesseract daemon start");
                return Err(CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, "Daemon not running")
                ));
            }

            // Unmount by path (could be container or mount point)
            match client.unmount(path.clone()) {
                Ok(response) => {
                    if let tesseract::daemon::DaemonResponse::Success { message } = response {
                        println!("✓ {}", message);
                    } else {
                        println!("✓ Volume unmounted successfully.");
                    }
                }
                Err(e) => {
                    return Err(CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, format!("Unmount failed: {}", e))
                    ));
                }
            }
        }
        VolumeCommands::List => {
            use tesseract::daemon::DaemonClient;

            // Try to use daemon for list
            let client = DaemonClient::new();

            if !client.is_running() {
                println!("Error: Daemon is not running.");
                println!("Start the daemon with: tesseract daemon start");
                return Err(CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, "Daemon not running")
                ));
            }

            match client.list() {
                Ok(response) => {
                    if let tesseract::daemon::DaemonResponse::MountList { mounts } = response {
                        if mounts.is_empty() {
                            println!("No volumes currently mounted.");
                        } else {
                            println!("Mounted volumes:");
                            println!();
                            for mount in mounts {
                                println!("  Container: {}", mount.container_path.display());
                                println!("  Mount Point: {}", mount.mount_point.display());
                                println!("  Read-Only: {}", mount.read_only);
                                println!("  Hidden: {}", mount.is_hidden);
                                if let Some(pid) = mount.pid {
                                    println!("  PID: {}", pid);
                                }
                                println!();
                            }
                        }
                    } else {
                        println!("Unexpected response from daemon.");
                    }
                }
                Err(e) => {
                    return Err(CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, format!("List failed: {}", e))
                    ));
                }
            }
        }
        VolumeCommands::Info { container } => {
            println!("Volume information for '{}'", container.display());

            let password = validation::get_password()?;
            let cont = Container::open(&container, &password)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            println!("\nContainer Information:");
            println!("  Path: {}", container.display());
            println!("  Data Size: {} bytes ({} MB)",
                cont.data_size(),
                cont.data_size() / 1024 / 1024
            );
            println!("  Total Size: {} bytes ({} MB)",
                cont.total_size(),
                cont.total_size() / 1024 / 1024
            );
            println!("  Sector Size: {} bytes", cont.sector_size());
            println!("  Active Key Slots: {}", cont.key_slots().active_count());
            println!("  Unlocked: {}", if cont.is_unlocked() { "Yes" } else { "No" });
        }
        VolumeCommands::ChangePassword { container, slot } => {
            println!("Changing password for '{}'", container.display());

            let old_password = {
                print!("Enter current password: ");
                std::io::Write::flush(&mut std::io::stdout()).unwrap();
                validation::get_password()?
            };

            let mut cont = Container::open(&container, &old_password)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            if let Some(slot_idx) = slot {
                // Change password in specific slot
                println!("Changing password in slot {}...", slot_idx);
                let new_password = validation::get_and_validate_password()?;

                // This would require a new method on Container
                // For now, we remove and add
                if cont.key_slots().is_slot_active(slot_idx) {
                    cont.remove_password(slot_idx)
                        .map_err(|e| CryptorError::Io(
                            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                        ))?;
                }

                cont.add_password(&new_password)
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;

                println!("✓ Password changed successfully in slot {}.", slot_idx);
            } else {
                // Add a new password slot
                println!("Adding new password...");
                let new_password = validation::get_and_validate_password()?;

                let slot_idx = cont.add_password(&new_password)
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;

                println!("✓ New password added in slot {}.", slot_idx);
            }
        }
        VolumeCommands::GenerateRecoveryKey { output, name } => {
            println!("Generating recovery key...");

            // Generate a new recovery key
            let recovery_key = Container::generate_recovery_key();

            // Export to file
            Container::export_recovery_key_file(
                &recovery_key,
                &output,
                name.as_deref(),
            ).map_err(|e| CryptorError::Io(
                std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
            ))?;

            println!("✓ Recovery key generated and saved to '{}'", output.display());
            println!("\n  IMPORTANT: Store this file in a secure location!");
            println!("  Anyone with this recovery key can access encrypted volumes.");
            println!("\n  You can use this recovery key to:");
            println!("  - Add it to a volume: tesseract volume add-recovery-key -c <container> -r {}", output.display());
            println!("  - Reset a password: tesseract volume reset-password -c <container> -r {}", output.display());
        }
        VolumeCommands::AddRecoveryKey { container, recovery_key } => {
            println!("Adding recovery key to '{}'", container.display());

            // Get the recovery key (from file or direct input)
            let key = load_recovery_key(&recovery_key)?;

            // Get password to unlock the container
            let password = validation::get_password()?;

            // Open container
            let mut cont = Container::open(&container, &password)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            // Add recovery key
            let slot_idx = cont.add_recovery_key(&key)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            println!("✓ Recovery key added to slot {}.", slot_idx);
            println!("  You can now use this recovery key to reset the password if forgotten.");
        }
        VolumeCommands::ResetPassword { container, recovery_key } => {
            println!("Resetting password for '{}'", container.display());

            // Get the recovery key (from file or direct input)
            let key = load_recovery_key(&recovery_key)?;

            // Open container using a temporary password attempt
            // We need to open it first, so we'll try to unlock with the recovery key directly
            println!("Note: Opening container with recovery key...");

            let mut cont = Container::open(&container, &key)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other,
                        format!("Failed to unlock with recovery key: {}", e))
                ))?;

            // Get new password
            println!("Enter new password:");
            let new_password = validation::get_and_validate_password()?;

            // Reset password
            cont.reset_password_with_recovery_key(&key, &new_password)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            println!("✓ Password reset successfully.");
            println!("  You can now use the new password to access the volume.");
        }
        VolumeCommands::CreateHidden { container, size, offset } => {
            println!("Creating hidden volume in '{}'", container.display());

            // Parse size and offset
            let hidden_size = parse_size(&size)?;
            let hidden_offset = parse_size(&offset)?;

            // Get outer volume password
            println!("Enter outer volume password:");
            let outer_password = validation::get_password()?;

            // Open outer container
            let mut outer = Container::open(&container, &outer_password)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            // Get hidden volume password
            println!("Enter hidden volume password (use a different password!):");
            let hidden_password = validation::get_and_validate_password()?;

            // Verify passwords are different
            if outer_password == hidden_password {
                return Err(CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::InvalidInput,
                        "Hidden volume password must be different from outer volume password")
                ));
            }

            // Create hidden volume
            outer.create_hidden_volume(hidden_size, &hidden_password, hidden_offset)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            println!("✓ Hidden volume created successfully.");
            println!("  Container: {}", container.display());
            println!("  Hidden Size: {} bytes ({} MB)", hidden_size, hidden_size / 1024 / 1024);
            println!("  Offset: {} bytes ({} MB)", hidden_offset, hidden_offset / 1024 / 1024);
            println!("\n  IMPORTANT SECURITY NOTES:");
            println!("  1. Fill the outer volume with decoy data to hide the hidden volume");
            println!("  2. Never reveal the hidden volume password under duress");
            println!("  3. Be careful not to overwrite the hidden volume when using the outer volume");
            println!("  4. The hidden volume is located at offset {} in the outer data area", hidden_offset);
        }
        VolumeCommands::MountHidden { container, mount_point, offset, read_only } => {
            println!("Mounting hidden volume from '{}' at '{}'",
                container.display(), mount_point.display());

            // Parse offset
            let hidden_offset = parse_size(&offset)?;

            // Get outer volume password
            println!("Enter outer volume password:");
            let outer_password = validation::get_password()?;

            // Verify outer container can be opened
            let outer = Container::open(&container, &outer_password)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            // Get hidden volume password
            println!("Enter hidden volume password:");
            let hidden_password = validation::get_password()?;

            // Verify hidden volume can be opened
            let hidden = outer.open_hidden_volume(&hidden_password, hidden_offset)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            let hidden_size = hidden.data_size();
            drop(hidden);
            drop(outer);

            // Mount the hidden volume using VolumeManager
            let mut manager = VolumeManager::new();
            let options = MountOptions {
                mount_point: mount_point.clone(),
                read_only,
                allow_other: false,
                auto_unmount: true,
                fs_name: Some("Tesseract-Hidden".to_string()),
                hidden_offset: Some(hidden_offset),
                hidden_password: Some(hidden_password.clone()),
            };

            // Pass the outer password to mount() - it will use hidden_password from options
            manager.mount(&container, &outer_password, options)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            println!("✓ Hidden volume mounted successfully.");
            println!("  Container: {}", container.display());
            println!("  Mount point: {}", mount_point.display());
            println!("  Offset: {} bytes ({} MB)", hidden_offset, hidden_offset / 1024 / 1024);
            println!("  Size: {} bytes ({} MB)", hidden_size, hidden_size / 1024 / 1024);
            if read_only {
                println!("  Mode: Read-only");
            }
            println!("  Press Ctrl+C to unmount and exit.");

            // Wait for Ctrl+C
            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let r = running.clone();
            ctrlc::set_handler(move || {
                r.store(false, std::sync::atomic::Ordering::SeqCst);
            }).expect("Error setting Ctrl-C handler");

            while running.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }

            println!("\nUnmounting hidden volume...");
            manager.unmount(&container)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;
            println!("✓ Hidden volume unmounted.");
        }
        VolumeCommands::CheckHidden { container, offset } => {
            println!("Checking for hidden volume in '{}'", container.display());

            // Parse offset
            let hidden_offset = parse_size(&offset)?;

            // Get outer volume password
            let outer_password = validation::get_password()?;

            // Open outer container
            let outer = Container::open(&container, &outer_password)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            // Check if hidden volume exists
            if outer.has_hidden_volume(hidden_offset) {
                println!("✓ A volume header was found at offset {} ({} MB).",
                    hidden_offset, hidden_offset / 1024 / 1024);
                println!("  This may be a hidden volume.");
                println!("  Use 'mount-hidden' to mount it with the correct password.");
            } else {
                println!("✗ No volume header found at offset {} ({} MB).",
                    hidden_offset, hidden_offset / 1024 / 1024);
                println!("  No hidden volume exists at this location.");
            }
        }
        VolumeCommands::MigrateToPqc { container, keypair_output } => {
            use tesseract::volume::VolumeMigration;
            use std::fs;

            println!("Migrating volume '{}' to V2 with post-quantum cryptography", container.display());
            println!();
            println!("⚠️  WARNING: This will modify your volume header.");
            println!("   A backup will be created, but please ensure you have backups of your data.");
            println!();

            // Get password to unlock volume
            let password = validation::get_password()?;

            // Create migration manager
            let mut migration = VolumeMigration::new(&container);

            // Perform migration
            println!("Starting migration...");
            let pqc_keypair = migration.migrate(&password)
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            // Determine output path for keypair
            let keypair_path = keypair_output.unwrap_or_else(|| {
                let mut path = container.clone();
                path.set_extension("pqc-keypair");
                path
            });

            // Save PQC keypair
            let (ek_bytes, dk_bytes) = pqc_keypair.to_bytes();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let keypair_data = serde_json::json!({
                "encapsulation_key": hex::encode(&ek_bytes),
                "decapsulation_key": hex::encode(&*dk_bytes),
                "algorithm": "ML-KEM-1024",
                "created_timestamp": timestamp,
            });

            let json_str = serde_json::to_string_pretty(&keypair_data)
                .map_err(|e| CryptorError::Io(std::io::Error::other(e)))?;
            fs::write(&keypair_path, json_str)
                .map_err(|e| CryptorError::Io(e))?;

            println!();
            println!("✓ Migration successful!");
            println!("  Volume is now V2 with ML-KEM-1024 post-quantum cryptography");
            println!("  PQC keypair saved to: {}", keypair_path.display());

            if let Some(backup_path) = migration.backup_path() {
                println!("  Backup saved to: {}", backup_path.display());
                println!();
                println!("IMPORTANT:");
                println!("  - Keep the PQC keypair file secure - you need it to access the volume");
                println!("  - Keep the backup file until you verify the migration worked");
                println!("  - Test mounting the volume before deleting the backup");
            }
        }
    }

    Ok(())
}

/// Load a recovery key from a file or use it directly if it's 64 hex characters
#[cfg(feature = "encrypted-volumes")]
fn load_recovery_key(input: &str) -> Result<String, CryptorError> {
    use std::fs;
    use std::path::Path;

    // If it's exactly 64 characters and all hex, use it directly
    if input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(input.to_string());
    }

    // Otherwise, try to load from file
    let path = Path::new(input);
    if !path.exists() {
        return Err(CryptorError::Io(
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Recovery key file not found: {}", input)
            )
        ));
    }

    // Read file and extract recovery key
    let content = fs::read_to_string(path)
        .map_err(|e| CryptorError::Io(e))?;

    // Look for the recovery key line (64 hex characters on its own line)
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(trimmed.to_string());
        }
    }

    Err(CryptorError::Io(
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Could not find valid recovery key (64 hex characters) in file"
        )
    ))
}

/// Handle volume subcommands (stub when feature is disabled)
#[cfg(not(feature = "encrypted-volumes"))]
fn handle_volume_command(_cmd: VolumeCommands) -> Result<(), CryptorError> {
    eprintln!("Error: Encrypted volumes feature is not enabled.");
    eprintln!("Please recompile with --features encrypted-volumes");
    std::process::exit(1);
}

/// Handle daemon subcommands
fn handle_daemon_command(cmd: DaemonCommands) -> Result<(), CryptorError> {
    use tesseract::daemon::{DaemonServer, DaemonClient};

    match cmd {
        DaemonCommands::Start => {
            println!("Starting Tesseract Daemon...");
            let server = DaemonServer::new();
            server.run()
                .map_err(|e| CryptorError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;
        }
        DaemonCommands::Stop => {
            println!("Stopping Tesseract Daemon...");
            let client = DaemonClient::new();

            if !client.is_running() {
                println!("Daemon is not running.");
                return Ok(());
            }

            match client.send_command(tesseract::daemon::DaemonCommand::Shutdown) {
                Ok(_) => println!("✓ Daemon stopped successfully."),
                Err(e) => {
                    return Err(CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to stop daemon: {}", e))
                    ));
                }
            }
        }
        DaemonCommands::Status => {
            let client = DaemonClient::new();

            if client.is_running() {
                println!("✓ Daemon is running.");

                // Try to get ping response
                match client.send_command(tesseract::daemon::DaemonCommand::Ping) {
                    Ok(response) => {
                        if let tesseract::daemon::DaemonResponse::Pong = response {
                            println!("  Status: Healthy");
                        }
                    }
                    Err(_) => {
                        println!("  Status: Not responding");
                    }
                }
            } else {
                println!("✗ Daemon is not running.");
            }
        }
        DaemonCommands::InstallService => {
            #[cfg(windows)]
            {
                use tesseract::daemon::service;
                service::install_service()
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;
            }
            #[cfg(target_os = "linux")]
            {
                use tesseract::daemon::service;
                service::install_service()
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;
            }
            #[cfg(target_os = "macos")]
            {
                use tesseract::daemon::service;
                service::install_service()
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;
            }
        }
        DaemonCommands::UninstallService => {
            #[cfg(windows)]
            {
                use tesseract::daemon::service;
                service::uninstall_service()
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;
            }
            #[cfg(target_os = "linux")]
            {
                use tesseract::daemon::service;
                service::uninstall_service()
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;
            }
            #[cfg(target_os = "macos")]
            {
                use tesseract::daemon::service;
                service::uninstall_service()
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;
            }
        }
        DaemonCommands::StartService => {
            #[cfg(windows)]
            {
                use std::process::Command;
                let output = Command::new("sc")
                    .args(&["start", "TesseractDaemon"])
                    .output()
                    .map_err(|e| CryptorError::Io(e))?;

                if output.status.success() {
                    println!("✓ Service started successfully.");
                } else {
                    let error = String::from_utf8_lossy(&output.stderr);
                    return Err(CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to start service: {}", error))
                    ));
                }
            }
            #[cfg(target_os = "linux")]
            {
                use tesseract::daemon::service;
                service::start_service()
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;
            }
            #[cfg(target_os = "macos")]
            {
                use tesseract::daemon::service;
                service::load_service()
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;
            }
        }
        DaemonCommands::StopService => {
            #[cfg(windows)]
            {
                use std::process::Command;
                let output = Command::new("sc")
                    .args(&["stop", "TesseractDaemon"])
                    .output()
                    .map_err(|e| CryptorError::Io(e))?;

                if output.status.success() {
                    println!("✓ Service stopped successfully.");
                } else {
                    let error = String::from_utf8_lossy(&output.stderr);
                    return Err(CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to stop service: {}", error))
                    ));
                }
            }
            #[cfg(target_os = "linux")]
            {
                use tesseract::daemon::service;
                service::stop_service()
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;
            }
            #[cfg(target_os = "macos")]
            {
                use tesseract::daemon::service;
                service::unload_service()
                    .map_err(|e| CryptorError::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;
            }
        }
    }

    Ok(())
}

/// Parse a size string like "100M", "1G", "500M" into bytes
#[cfg(feature = "encrypted-volumes")]
fn parse_size(size_str: &str) -> Result<u64, CryptorError> {
    let size_str = size_str.trim().to_uppercase();

    if size_str.ends_with('K') {
        let num = size_str[..size_str.len()-1].parse::<u64>()
            .map_err(|e| CryptorError::Io(
                std::io::Error::new(std::io::ErrorKind::InvalidInput,
                    format!("Invalid size: {}", e))
            ))?;
        Ok(num * 1024)
    } else if size_str.ends_with('M') {
        let num = size_str[..size_str.len()-1].parse::<u64>()
            .map_err(|e| CryptorError::Io(
                std::io::Error::new(std::io::ErrorKind::InvalidInput,
                    format!("Invalid size: {}", e))
            ))?;
        Ok(num * 1024 * 1024)
    } else if size_str.ends_with('G') {
        let num = size_str[..size_str.len()-1].parse::<u64>()
            .map_err(|e| CryptorError::Io(
                std::io::Error::new(std::io::ErrorKind::InvalidInput,
                    format!("Invalid size: {}", e))
            ))?;
        Ok(num * 1024 * 1024 * 1024)
    } else {
        // Assume bytes
        size_str.parse::<u64>()
            .map_err(|e| CryptorError::Io(
                std::io::Error::new(std::io::ErrorKind::InvalidInput,
                    format!("Invalid size: {}", e))
            ))
    }
}

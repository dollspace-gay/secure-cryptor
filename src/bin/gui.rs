// Native GUI for Secure Cryptor using egui
// Matches the exact design from mockup

#![windows_subsystem = "windows"]

mod tray;

use eframe::egui;
use secure_cryptor::{
    ChunkedDecryptor, ChunkedEncryptor, ChunkedReader, StreamConfig,
    crypto::{aes_gcm::AesGcmEncryptor, kdf::Argon2Kdf, KeyDerivation},
    validation::validate_password,
};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

fn main() -> eframe::Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    let mut initial_file: Option<String> = None;
    let mut initial_mode: Option<Mode> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--encrypt" => {
                initial_mode = Some(Mode::Encrypt);
                if i + 1 < args.len() {
                    initial_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--decrypt" => {
                initial_mode = Some(Mode::Decrypt);
                if i + 1 < args.len() {
                    initial_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            arg => {
                // If it's a file path without a flag, assume it's a file to open
                if !arg.starts_with("--") {
                    initial_file = Some(arg.to_string());
                }
            }
        }
        i += 1;
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_resizable(true)
            .with_min_inner_size([900.0, 700.0])
            .with_title("Secure Cryptor"),
        ..Default::default()
    };

    eframe::run_native(
        "Secure Cryptor",
        options,
        Box::new(move |cc| {
            // Set custom theme with rounded corners
            let mut style = (*cc.egui_ctx.style()).clone();
            style.visuals.widgets.inactive.rounding = egui::Rounding::same(20.0);
            style.visuals.widgets.hovered.rounding = egui::Rounding::same(20.0);
            style.visuals.widgets.active.rounding = egui::Rounding::same(20.0);
            cc.egui_ctx.set_style(style);

            Ok(Box::new(CryptorApp::new(initial_file, initial_mode)))
        }),
    )
}

#[derive(Serialize, Deserialize, Clone)]
struct Settings {
    default_compression: bool,
    last_input_directory: Option<String>,
    last_output_directory: Option<String>,
    panel_transparency: u8,
    enable_notifications: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_compression: false,
            last_input_directory: None,
            last_output_directory: None,
            panel_transparency: 100,
            enable_notifications: true,
        }
    }
}

impl Settings {
    fn load() -> Self {
        let config_path = Self::config_path();
        if let Ok(contents) = fs::read_to_string(&config_path) {
            serde_json::from_str(&contents).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    fn save(&self) -> std::io::Result<()> {
        let config_path = Self::config_path();
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(&config_path, contents)
    }

    fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("SecureCryptor")
            .join("settings.json")
    }
}

// Notification helper functions (cross-platform)
fn show_notification(title: &str, message: &str, _is_error: bool) {
    use notify_rust::Notification;
    let _ = Notification::new()
        .summary(title)
        .body(message)
        .appname("Secure Cryptor")
        .show();
}

fn notify_success(operation: &str, filename: &str, enabled: bool) {
    if !enabled {
        return;
    }
    show_notification(
        "Secure Cryptor",
        &format!("{} completed: {}", operation, filename),
        false,
    );
}

fn notify_error(operation: &str, error: &str, enabled: bool) {
    if !enabled {
        return;
    }
    show_notification(
        "Secure Cryptor - Error",
        &format!("{} failed: {}", operation, error),
        true,
    );
}

fn notify_queue_complete(total: usize, succeeded: usize, failed: usize, enabled: bool) {
    if !enabled {
        return;
    }
    let message = if failed == 0 {
        format!("Queue processing complete! {} items processed successfully.", succeeded)
    } else {
        format!("Queue processing complete! {} succeeded, {} failed out of {} total.", succeeded, failed, total)
    };
    show_notification("Secure Cryptor - Queue Complete", &message, failed > 0);
}

#[derive(PartialEq, Clone)]
enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(Clone)]
enum QueueStatus {
    Pending,
    Processing,
    Completed,
    Failed(String),
}

#[derive(Clone)]
struct QueueItem {
    input_path: String,
    output_path: String,
    mode: Mode,
    password: String,
    use_compression: bool,
    status: QueueStatus,
    progress: f32,
}

impl QueueItem {
    fn new(input_path: String, output_path: String, mode: Mode, password: String, use_compression: bool) -> Self {
        Self {
            input_path,
            output_path,
            mode,
            password,
            use_compression,
            status: QueueStatus::Pending,
            progress: 0.0,
        }
    }
}

struct CryptorApp {
    mode: Option<Mode>,
    input_path: String,
    output_path: String,
    password: String,
    confirm_password: String,
    use_compression: bool,
    status_message: String,
    is_processing: bool,
    progress: f32,
    runtime: Option<Runtime>,
    settings: Settings,
    show_settings: bool,
    queue: Vec<QueueItem>,
    is_processing_queue: bool,
    show_queue_panel: bool,
    tray_manager: Option<tray::TrayManager>,
    window_visible: bool,
}

impl Default for CryptorApp {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl CryptorApp {
    /// Create a new CryptorApp with optional initial file and mode
    fn new(initial_file: Option<String>, initial_mode: Option<Mode>) -> Self {
        let settings = Settings::load();

        // Initialize system tray
        let tray_manager = match tray::TrayManager::new() {
            Ok(tray) => {
                eprintln!("System tray initialized successfully");
                Some(tray)
            }
            Err(e) => {
                eprintln!("Failed to initialize system tray: {}. Running without tray icon.", e);
                None
            }
        };

        let mut app = Self {
            mode: None,
            input_path: String::new(),
            output_path: String::new(),
            password: String::new(),
            confirm_password: String::new(),
            use_compression: settings.default_compression,
            status_message: String::new(),
            is_processing: false,
            progress: 0.0,
            runtime: None,
            settings: settings.clone(),
            show_settings: false,
            queue: Vec::new(),
            is_processing_queue: false,
            show_queue_panel: false,
            tray_manager,
            window_visible: true,
        };

        // If initial file is provided, set it up
        if let Some(file_path) = initial_file {
            app.input_path = file_path.clone();

            // Auto-detect mode if not explicitly provided
            let detected_mode = if file_path.ends_with(".enc") || file_path.ends_with(".encrypted") {
                Mode::Decrypt
            } else {
                Mode::Encrypt
            };

            // Use provided mode or detected mode
            app.mode = Some(initial_mode.unwrap_or(detected_mode));

            // Set output path based on mode
            match &app.mode {
                Some(Mode::Encrypt) => {
                    app.output_path = format!("{}.enc", file_path);
                    app.status_message = format!("Ready to encrypt: {}", file_path);
                }
                Some(Mode::Decrypt) => {
                    app.output_path = file_path
                        .trim_end_matches(".enc")
                        .trim_end_matches(".encrypted")
                        .to_string();
                    app.status_message = format!("Ready to decrypt: {}", file_path);
                }
                None => {}
            }
        }

        app
    }

    fn select_input_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            self.input_path = path.display().to_string();

            // Auto-detect mode based on file
            if self.input_path.ends_with(".enc") || self.input_path.ends_with(".encrypted") {
                self.mode = Some(Mode::Decrypt);
                self.output_path = self.input_path.trim_end_matches(".enc")
                    .trim_end_matches(".encrypted").to_string();
                self.status_message = "Encrypted file detected - switched to Decrypt mode".to_string();
            } else {
                self.mode = Some(Mode::Encrypt);
                self.output_path = format!("{}.enc", self.input_path);
                self.status_message = format!("Selected: {}", path.display());
            }
        }
    }

    fn select_output_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name(&self.output_path)
            .save_file()
        {
            self.output_path = path.display().to_string();
            self.status_message = format!("Output: {}", path.display());
        }
    }

    fn add_to_queue(&mut self) {
        // Validation
        if self.input_path.is_empty() {
            self.status_message = "Error: No input file selected".to_string();
            return;
        }

        if self.output_path.is_empty() {
            self.status_message = "Error: No output file specified".to_string();
            return;
        }

        if self.password.is_empty() {
            self.status_message = "Error: Password required".to_string();
            return;
        }

        if let Some(Mode::Encrypt) = self.mode {
            if self.password != self.confirm_password {
                self.status_message = "Error: Passwords do not match".to_string();
                return;
            }

            if let Err(e) = validate_password(&self.password) {
                self.status_message = format!("Error: {}", e);
                return;
            }
        }

        // Add to queue
        let item = QueueItem::new(
            self.input_path.clone(),
            self.output_path.clone(),
            self.mode.clone().unwrap(),
            self.password.clone(),
            self.use_compression,
        );

        self.queue.push(item);
        self.status_message = format!("Added to queue: {}", self.input_path);
        self.show_queue_panel = true;

        // Clear fields for next file
        self.input_path.clear();
        self.output_path.clear();
        self.password.clear();
        self.confirm_password.clear();
    }

    fn process_queue(&mut self) {
        if self.queue.is_empty() {
            self.status_message = "Queue is empty".to_string();
            return;
        }

        self.is_processing_queue = true;

        // Get or create runtime
        let rt = self.runtime.get_or_insert_with(|| {
            tokio::runtime::Runtime::new().expect("Failed to create runtime")
        });

        let mut succeeded = 0;
        let mut failed = 0;
        let total = self.queue.len();

        // Process each item in the queue
        for item in &mut self.queue {
            if matches!(item.status, QueueStatus::Completed) {
                succeeded += 1;
                continue;
            }

            item.status = QueueStatus::Processing;
            item.progress = 0.0;

            let result = match item.mode {
                Mode::Encrypt => rt.block_on(async {
                    encrypt_file(&item.input_path, &item.output_path, &item.password, item.use_compression)
                }),
                Mode::Decrypt => rt.block_on(async {
                    decrypt_file(&item.input_path, &item.output_path, &item.password)
                }),
            };

            match result {
                Ok(_) => {
                    item.status = QueueStatus::Completed;
                    item.progress = 1.0;
                    succeeded += 1;
                }
                Err(e) => {
                    item.status = QueueStatus::Failed(e.to_string());
                    item.progress = 0.0;
                    failed += 1;
                }
            }
        }

        self.is_processing_queue = false;
        self.status_message = "Queue processing complete".to_string();

        // Show completion notification
        notify_queue_complete(total, succeeded, failed, self.settings.enable_notifications);
    }

    fn clear_queue(&mut self) {
        self.queue.clear();
        self.status_message = "Queue cleared".to_string();
    }

    fn remove_from_queue(&mut self, index: usize) {
        if index < self.queue.len() {
            self.queue.remove(index);
            self.status_message = "Item removed from queue".to_string();
        }
    }

    fn render_queue_panel(&mut self, ctx: &egui::Context) {
        egui::Window::new("Batch Queue")
            .fixed_size([700.0, 500.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                let panel_frame = egui::Frame::default()
                    .fill(egui::Color32::from_rgba_unmultiplied(255, 255, 255, self.settings.panel_transparency))
                    .rounding(egui::Rounding::same(15.0))
                    .inner_margin(egui::Margin::same(20.0));

                panel_frame.show(ui, |ui| {
                    ui.heading(egui::RichText::new("Batch Operations Queue")
                        .size(24.0)
                        .color(egui::Color32::from_rgb(50, 50, 50)));

                    ui.add_space(15.0);

                    ui.label(egui::RichText::new(format!("Items in queue: {}", self.queue.len()))
                        .size(14.0)
                        .color(egui::Color32::from_rgb(80, 80, 80)));

                    ui.add_space(10.0);

                    // Queue items list
                    egui::ScrollArea::vertical()
                        .max_height(300.0)
                        .show(ui, |ui| {
                            let mut items_to_remove = Vec::new();

                            for (index, item) in self.queue.iter().enumerate() {
                                ui.group(|ui| {
                                    ui.set_min_width(640.0);

                                    ui.horizontal(|ui| {
                                        // Status icon
                                        let (status_icon, status_color) = match &item.status {
                                            QueueStatus::Pending => ("⏳", egui::Color32::from_rgb(200, 200, 200)),
                                            QueueStatus::Processing => ("⚙", egui::Color32::from_rgb(91, 206, 250)),
                                            QueueStatus::Completed => ("✓", egui::Color32::from_rgb(100, 200, 100)),
                                            QueueStatus::Failed(_) => ("✗", egui::Color32::from_rgb(255, 100, 100)),
                                        };

                                        ui.label(egui::RichText::new(status_icon)
                                            .size(18.0)
                                            .color(status_color));

                                        ui.vertical(|ui| {
                                            // File path
                                            let filename = std::path::Path::new(&item.input_path)
                                                .file_name()
                                                .and_then(|n| n.to_str())
                                                .unwrap_or(&item.input_path);

                                            ui.label(egui::RichText::new(filename)
                                                .size(14.0)
                                                .color(egui::Color32::from_rgb(50, 50, 50)));

                                            // Mode indicator
                                            let mode_text = match item.mode {
                                                Mode::Encrypt => "Encrypt",
                                                Mode::Decrypt => "Decrypt",
                                            };
                                            ui.label(egui::RichText::new(mode_text)
                                                .size(11.0)
                                                .color(egui::Color32::from_rgb(120, 120, 120)));

                                            // Error message if failed
                                            if let QueueStatus::Failed(err) = &item.status {
                                                ui.label(egui::RichText::new(format!("Error: {}", err))
                                                    .size(11.0)
                                                    .color(egui::Color32::from_rgb(255, 100, 100)));
                                            }
                                        });

                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            // Remove button
                                            if !matches!(item.status, QueueStatus::Processing) {
                                                let remove_btn = egui::Button::new(
                                                    egui::RichText::new("✗").size(14.0).color(egui::Color32::WHITE)
                                                )
                                                .fill(egui::Color32::from_rgb(245, 169, 184))
                                                .min_size(egui::vec2(30.0, 30.0))
                                                .rounding(egui::Rounding::same(15.0));

                                                if ui.add(remove_btn).clicked() {
                                                    items_to_remove.push(index);
                                                }
                                            }
                                        });
                                    });
                                });

                                ui.add_space(5.0);
                            }

                            // Remove items outside the loop
                            for index in items_to_remove.iter().rev() {
                                self.remove_from_queue(*index);
                            }
                        });

                    ui.add_space(15.0);

                    // Action buttons
                    ui.horizontal(|ui| {
                        let process_btn = egui::Button::new(
                            egui::RichText::new("⚙ Process Queue").size(16.0).color(egui::Color32::WHITE)
                        )
                        .fill(egui::Color32::from_rgb(91, 206, 250))
                        .min_size(egui::vec2(180.0, 40.0))
                        .rounding(egui::Rounding::same(20.0));

                        if ui.add_enabled(!self.is_processing_queue && !self.queue.is_empty(), process_btn).clicked() {
                            self.process_queue();
                        }

                        ui.add_space(10.0);

                        let clear_btn = egui::Button::new(
                            egui::RichText::new("Clear Queue").size(16.0).color(egui::Color32::WHITE)
                        )
                        .fill(egui::Color32::from_rgb(245, 169, 184))
                        .min_size(egui::vec2(150.0, 40.0))
                        .rounding(egui::Rounding::same(20.0));

                        if ui.add_enabled(!self.is_processing_queue, clear_btn).clicked() {
                            self.clear_queue();
                        }

                        ui.add_space(10.0);

                        let close_btn = egui::Button::new(
                            egui::RichText::new("Close").size(16.0).color(egui::Color32::WHITE)
                        )
                        .fill(egui::Color32::from_rgb(120, 120, 120))
                        .min_size(egui::vec2(100.0, 40.0))
                        .rounding(egui::Rounding::same(20.0));

                        if ui.add(close_btn).clicked() {
                            self.show_queue_panel = false;
                        }
                    });

                    if self.is_processing_queue {
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new("Processing queue...")
                            .size(13.0)
                            .color(egui::Color32::from_rgb(91, 206, 250)));
                    }
                });
            });
    }

    fn render_settings_panel(&mut self, ctx: &egui::Context) {
        egui::Window::new("Settings")
            .fixed_size([500.0, 400.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                // Apply trans pride theme to settings panel
                let panel_frame = egui::Frame::default()
                    .fill(egui::Color32::from_rgba_unmultiplied(255, 255, 255, self.settings.panel_transparency))
                    .rounding(egui::Rounding::same(15.0))
                    .inner_margin(egui::Margin::same(25.0))
                    .shadow(egui::epaint::Shadow {
                        offset: egui::Vec2::new(0.0, 4.0),
                        blur: 15.0,
                        spread: 0.0,
                        color: egui::Color32::from_black_alpha(40),
                    });

                panel_frame.show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new("⚙ Settings")
                            .size(28.0)
                            .color(egui::Color32::from_rgb(50, 50, 50)));
                    });

                    ui.add_space(20.0);

                    // Default compression checkbox
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Default Compression:").size(14.0));
                        ui.add_space(10.0);
                        if ui.checkbox(&mut self.settings.default_compression, "").changed() {
                            self.use_compression = self.settings.default_compression;
                            let _ = self.settings.save();
                        }
                    });

                    ui.add_space(15.0);

                    // Enable notifications checkbox
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Enable Notifications:").size(14.0));
                        ui.add_space(10.0);
                        if ui.checkbox(&mut self.settings.enable_notifications, "").changed() {
                            let _ = self.settings.save();
                        }
                    });

                    ui.add_space(15.0);

                    // Panel transparency slider
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Panel Transparency:").size(14.0));
                        ui.add_space(10.0);
                    });

                    ui.add_space(5.0);

                    ui.horizontal(|ui| {
                        let slider = egui::Slider::new(&mut self.settings.panel_transparency, 50..=255)
                            .text("Alpha")
                            .show_value(true);
                        if ui.add(slider).changed() {
                            let _ = self.settings.save();
                        }
                    });

                    ui.add_space(20.0);

                    // Settings info
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new("Settings are automatically saved")
                            .size(11.0)
                            .color(egui::Color32::from_rgb(100, 100, 100)));

                        ui.add_space(10.0);

                        let config_path = Settings::config_path();
                        ui.label(egui::RichText::new(format!("Location: {}", config_path.display()))
                            .size(10.0)
                            .color(egui::Color32::from_rgb(120, 120, 120)));
                    });

                    ui.add_space(20.0);

                    // Close button
                    ui.vertical_centered(|ui| {
                        let close_btn = egui::Button::new(
                            egui::RichText::new("Close").size(16.0).color(egui::Color32::WHITE)
                        )
                        .fill(egui::Color32::from_rgb(91, 206, 250))
                        .min_size(egui::vec2(150.0, 40.0))
                        .rounding(egui::Rounding::same(20.0));

                        if ui.add(close_btn).clicked() {
                            self.show_settings = false;
                        }
                    });
                });
            });
    }

    fn process_file(&mut self) {
        // Validation
        if self.input_path.is_empty() {
            self.status_message = "Error: No input file selected".to_string();
            return;
        }

        if self.output_path.is_empty() {
            self.status_message = "Error: No output file specified".to_string();
            return;
        }

        if self.password.is_empty() {
            self.status_message = "Error: Password required".to_string();
            return;
        }

        if let Some(Mode::Encrypt) = self.mode {
            if self.password != self.confirm_password {
                self.status_message = "Error: Passwords do not match".to_string();
                return;
            }

            if let Err(e) = validate_password(&self.password) {
                self.status_message = format!("Error: {}", e);
                return;
            }
        }

        // Get or create runtime
        let rt = self.runtime.get_or_insert_with(|| {
            tokio::runtime::Runtime::new().expect("Failed to create runtime")
        });

        let input_path = self.input_path.clone();
        let output_path = self.output_path.clone();
        let password = self.password.clone();
        let use_compression = self.use_compression;
        let mode = self.mode.as_ref().unwrap();

        self.is_processing = true;
        self.progress = 0.0;

        match mode {
            Mode::Encrypt => {
                let result = rt.block_on(async {
                    encrypt_file(&input_path, &output_path, &password, use_compression)
                });

                match result {
                    Ok(msg) => {
                        self.status_message = msg;
                        self.progress = 1.0;

                        // Show success notification
                        let filename = std::path::Path::new(&output_path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(&output_path);
                        notify_success("Encryption", filename, self.settings.enable_notifications);
                    }
                    Err(e) => {
                        self.status_message = format!("Encryption failed: {}", e);
                        self.progress = 0.0;

                        // Show error notification
                        notify_error("Encryption", &e.to_string(), self.settings.enable_notifications);
                    }
                }
            }
            Mode::Decrypt => {
                let result = rt.block_on(async {
                    decrypt_file(&input_path, &output_path, &password)
                });

                match result {
                    Ok(msg) => {
                        self.status_message = msg;
                        self.progress = 1.0;

                        // Show success notification
                        let filename = std::path::Path::new(&output_path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(&output_path);
                        notify_success("Decryption", filename, self.settings.enable_notifications);
                    }
                    Err(e) => {
                        self.status_message = format!("Decryption failed: {}", e);
                        self.progress = 0.0;

                        // Show error notification
                        notify_error("Decryption", &e.to_string(), self.settings.enable_notifications);
                    }
                }
            }
        }

        self.is_processing = false;
    }
}

impl eframe::App for CryptorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Process system tray events
        if let Some(ref tray) = self.tray_manager {
            if let Some(event) = tray.process_events() {
                match event {
                    tray::TrayEvent::ToggleWindow => {
                        self.window_visible = !self.window_visible;
                        if self.window_visible {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                        } else {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                        }
                    }
                    tray::TrayEvent::QuickEncrypt => {
                        self.window_visible = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                        self.mode = Some(Mode::Encrypt);
                        self.select_input_file();
                    }
                    tray::TrayEvent::QuickDecrypt => {
                        self.window_visible = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                        self.mode = Some(Mode::Decrypt);
                        self.select_input_file();
                    }
                    tray::TrayEvent::ShowSettings => {
                        self.window_visible = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                        self.show_settings = true;
                    }
                    tray::TrayEvent::Quit => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
        }

        // Update tray status
        if let Some(ref mut tray) = self.tray_manager {
            if self.is_processing {
                tray.set_status("Processing...");
            } else if self.is_processing_queue {
                tray.set_status(&format!("Processing queue ({} items)", self.queue.len()));
            } else {
                tray.set_status("Ready");
            }
        }

        // Request repaint to keep checking for tray events
        ctx.request_repaint();

        // Draw gradient background
        let painter = ctx.layer_painter(egui::LayerId::background());
        let rect = ctx.screen_rect();

        // Trans pride gradient: blue -> pink
        let trans_blue = egui::Color32::from_rgb(135, 206, 250);
        let trans_pink = egui::Color32::from_rgb(245, 169, 200);

        // Create gradient mesh
        let mesh = {
            let mut mesh = egui::Mesh::default();
            mesh.colored_vertex(rect.left_top(), trans_blue);
            mesh.colored_vertex(rect.right_top(), trans_pink.gamma_multiply(0.6));
            mesh.colored_vertex(rect.left_bottom(), trans_blue.gamma_multiply(0.8));
            mesh.colored_vertex(rect.right_bottom(), trans_pink);
            mesh.add_triangle(0, 1, 2);
            mesh.add_triangle(1, 2, 3);
            mesh
        };
        painter.add(egui::Shape::mesh(mesh));

        // Menu bar
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if self.tray_manager.is_some() {
                        if ui.button("Minimize to Tray").clicked() {
                            self.window_visible = false;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                            ui.close_menu();
                        }
                    }
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("Queue", |ui| {
                    if ui.button(format!("📋 View Queue ({})", self.queue.len())).clicked() {
                        self.show_queue_panel = true;
                        ui.close_menu();
                    }
                });

                ui.menu_button("Settings", |ui| {
                    if ui.button("⚙ Open Settings").clicked() {
                        self.show_settings = true;
                        ui.close_menu();
                    }
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        ui.close_menu();
                    }
                });
            });
        });

        // Queue panel window
        if self.show_queue_panel {
            self.render_queue_panel(ctx);
        }

        // Settings panel window
        if self.show_settings {
            self.render_settings_panel(ctx);
        }

        // Main content panel
        egui::CentralPanel::default()
            .frame(egui::Frame::none())
            .show(ctx, |ui| {
                ui.add_space(60.0);

                // Center the main panel
                ui.vertical_centered(|ui| {
                    let panel_frame = egui::Frame::default()
                        .fill(egui::Color32::from_rgba_unmultiplied(255, 255, 255, self.settings.panel_transparency))
                        .rounding(egui::Rounding::same(20.0))
                        .inner_margin(egui::Margin::same(50.0))
                        .shadow(egui::epaint::Shadow {
                            offset: egui::Vec2::new(0.0, 8.0),
                            blur: 30.0,
                            spread: 0.0,
                            color: egui::Color32::from_black_alpha(60),
                        });

                    panel_frame.show(ui, |ui| {
                        ui.set_width(850.0);

                        // Title
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new("Secure Cryptor")
                                .size(42.0)
                                .color(egui::Color32::from_rgb(50, 50, 50)));
                        });

                        ui.add_space(30.0);

                        // Mode label
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new("Mode").size(16.0));
                            ui.add_space(10.0);

                            // Mode buttons
                            ui.horizontal(|ui| {
                                ui.allocate_space(egui::vec2(250.0, 0.0));

                                let encrypt_color = if self.mode == Some(Mode::Encrypt) {
                                    egui::Color32::from_rgb(91, 206, 250)
                                } else {
                                    egui::Color32::from_rgb(200, 200, 200)
                                };

                                let decrypt_color = if self.mode == Some(Mode::Decrypt) {
                                    egui::Color32::from_rgb(245, 169, 184)
                                } else {
                                    egui::Color32::from_rgb(200, 200, 200)
                                };

                                // Encrypt button
                                let encrypt_btn = egui::Button::new(
                                    egui::RichText::new("🔐 Encrypt").size(16.0).color(egui::Color32::WHITE)
                                )
                                .fill(encrypt_color)
                                .min_size(egui::vec2(140.0, 45.0))
                                .rounding(egui::Rounding::same(25.0));

                                if ui.add_enabled(!self.is_processing, encrypt_btn).clicked() {
                                    self.mode = Some(Mode::Encrypt);
                                    if !self.input_path.is_empty() {
                                        self.output_path = format!("{}.enc", self.input_path);
                                    }
                                }

                                ui.add_space(10.0);

                                // Decrypt button
                                let decrypt_btn = egui::Button::new(
                                    egui::RichText::new("🔓 Decrypt").size(16.0).color(egui::Color32::WHITE)
                                )
                                .fill(decrypt_color)
                                .min_size(egui::vec2(140.0, 45.0))
                                .rounding(egui::Rounding::same(25.0));

                                if ui.add_enabled(!self.is_processing, decrypt_btn).clicked() {
                                    self.mode = Some(Mode::Decrypt);
                                    if !self.input_path.is_empty() {
                                        self.output_path = if self.input_path.ends_with(".enc") {
                                            self.input_path.trim_end_matches(".enc").to_string()
                                        } else {
                                            format!("{}.dec", self.input_path)
                                        };
                                    }
                                }
                            });
                        });

                        ui.add_space(30.0);

                        // Input file row
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Input File").size(14.0));
                            ui.add_space(20.0);
                            ui.add(egui::TextEdit::singleline(&mut self.input_path)
                                .desired_width(500.0)
                                .interactive(false));
                            ui.add_space(10.0);
                            let browse_btn = egui::Button::new("Browse...")
                                .fill(egui::Color32::from_rgb(200, 230, 255))
                                .min_size(egui::vec2(100.0, 30.0));
                            if ui.add_enabled(!self.is_processing, browse_btn).clicked() {
                                self.select_input_file();
                            }
                        });

                        ui.add_space(15.0);

                        // Output file row
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Output File").size(14.0));
                            ui.add_space(10.0);
                            ui.add(egui::TextEdit::singleline(&mut self.output_path)
                                .desired_width(500.0));
                            ui.add_space(10.0);
                            let browse_btn = egui::Button::new("Browse...")
                                .fill(egui::Color32::from_rgb(200, 230, 255))
                                .min_size(egui::vec2(100.0, 30.0));
                            if ui.add_enabled(!self.is_processing, browse_btn).clicked() {
                                self.select_output_file();
                            }
                        });

                        ui.add_space(15.0);

                        // Password row
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Password").size(14.0));
                            ui.add_space(22.0);
                            ui.add(egui::TextEdit::singleline(&mut self.password)
                                .password(true)
                                .desired_width(500.0));
                            ui.add_space(10.0);
                            // Placeholder button to match layout (not functional)
                            let browse_btn = egui::Button::new("Browse...")
                                .fill(egui::Color32::from_rgb(200, 230, 255))
                                .min_size(egui::vec2(100.0, 30.0));
                            ui.add_enabled(false, browse_btn);
                        });

                        ui.add_space(30.0);

                        // Action buttons
                        ui.vertical_centered(|ui| {
                            ui.horizontal(|ui| {
                                ui.add_space(80.0);

                                let button_text = if self.is_processing {
                                    "⏳ Processing..."
                                } else {
                                    match &self.mode {
                                        Some(Mode::Encrypt) => "🔐 Encrypt File",
                                        Some(Mode::Decrypt) => "🔓 Decrypt File",
                                        None => "Select Mode First",
                                    }
                                };

                                let button_enabled = !self.is_processing
                                    && !self.is_processing_queue
                                    && self.mode.is_some()
                                    && !self.input_path.is_empty()
                                    && !self.output_path.is_empty()
                                    && !self.password.is_empty();

                                let button_color = egui::Color32::from_rgb(91, 206, 250);

                                let action_btn = egui::Button::new(
                                    egui::RichText::new(button_text).size(18.0).color(egui::Color32::WHITE)
                                )
                                .fill(button_color)
                                .min_size(egui::vec2(280.0, 50.0))
                                .rounding(egui::Rounding::same(25.0));

                                if ui.add_enabled(button_enabled, action_btn).clicked() {
                                    self.process_file();
                                }

                                ui.add_space(15.0);

                                // Add to Queue button
                                let queue_btn = egui::Button::new(
                                    egui::RichText::new("➕ Add to Queue").size(18.0).color(egui::Color32::WHITE)
                                )
                                .fill(egui::Color32::from_rgb(245, 169, 184))
                                .min_size(egui::vec2(200.0, 50.0))
                                .rounding(egui::Rounding::same(25.0));

                                if ui.add_enabled(button_enabled, queue_btn).clicked() {
                                    self.add_to_queue();
                                }
                            });
                        });

                        ui.add_space(20.0);

                        // Progress bar
                        if self.is_processing || self.progress > 0.0 {
                            ui.vertical_centered(|ui| {
                                ui.label(egui::RichText::new(format!("{}%", (self.progress * 100.0) as i32))
                                    .size(14.0));
                                ui.add_space(5.0);

                                // Custom striped progress bar
                                let progress_bar_height = 30.0;
                                let progress_bar_width = 650.0;
                                let (rect, _response) = ui.allocate_exact_size(
                                    egui::vec2(progress_bar_width, progress_bar_height),
                                    egui::Sense::hover(),
                                );

                                // Background
                                ui.painter().rect_filled(
                                    rect,
                                    egui::Rounding::same(15.0),
                                    egui::Color32::from_rgb(220, 220, 220),
                                );

                                // Progress fill with pink/white stripes
                                let fill_width = rect.width() * self.progress;
                                let fill_rect = egui::Rect::from_min_size(
                                    rect.min,
                                    egui::vec2(fill_width, rect.height()),
                                );

                                if fill_width > 0.0 {
                                    ui.painter().rect_filled(
                                        fill_rect,
                                        egui::Rounding::same(15.0),
                                        egui::Color32::from_rgb(245, 169, 184),
                                    );
                                }

                                // Border
                                ui.painter().rect_stroke(
                                    rect,
                                    egui::Rounding::same(15.0),
                                    egui::Stroke::new(2.0, egui::Color32::from_rgb(91, 206, 250)),
                                );
                            });

                            ui.add_space(10.0);
                        }

                        // Status message
                        if !self.status_message.is_empty() {
                            ui.vertical_centered(|ui| {
                                ui.label(egui::RichText::new(&self.status_message)
                                    .size(13.0)
                                    .color(egui::Color32::from_rgb(80, 80, 80)));
                            });
                        }

                        ui.add_space(20.0);

                        // Footer badges
                        ui.vertical_centered(|ui| {
                            ui.horizontal(|ui| {
                                ui.allocate_space(egui::vec2(100.0, 0.0));

                                // AES badge
                                let aes_badge = egui::Button::new(
                                    egui::RichText::new("🔒 AES-256-GCM").size(12.0).color(egui::Color32::WHITE)
                                )
                                .fill(egui::Color32::from_rgb(100, 180, 230))
                                .min_size(egui::vec2(140.0, 35.0))
                                .rounding(egui::Rounding::same(18.0));
                                ui.add_enabled(false, aes_badge);

                                ui.add_space(10.0);

                                // Argon2id badge
                                let argon_badge = egui::Button::new(
                                    egui::RichText::new("🌀 Argon2id").size(12.0).color(egui::Color32::WHITE)
                                )
                                .fill(egui::Color32::from_rgb(235, 150, 170))
                                .min_size(egui::vec2(110.0, 35.0))
                                .rounding(egui::Rounding::same(18.0));
                                ui.add_enabled(false, argon_badge);

                                ui.add_space(10.0);

                                // Authenticated badge
                                let auth_badge = egui::Button::new(
                                    egui::RichText::new("✓ Authenticated").size(12.0).color(egui::Color32::WHITE)
                                )
                                .fill(egui::Color32::from_rgb(100, 180, 230))
                                .min_size(egui::vec2(140.0, 35.0))
                                .rounding(egui::Rounding::same(18.0));
                                ui.add_enabled(false, auth_badge);
                            });
                        });

                        ui.add_space(10.0);
                    });
                });
            });
    }
}

fn encrypt_file(
    input_path: &str,
    output_path: &str,
    password: &str,
    use_compression: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    use argon2::password_hash::rand_core::{OsRng, RngCore};

    let input = PathBuf::from(input_path);
    let output = PathBuf::from(output_path);

    let mut config = StreamConfig::default();
    if use_compression {
        config = config.with_compression(true);
    }

    let reader = ChunkedReader::open(&input, config)?;
    let kdf = Argon2Kdf::default();
    let salt = kdf.generate_salt();
    let key = kdf.derive_key(password.as_bytes(), &salt)?;

    let mut base_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut base_nonce);

    let encryptor = ChunkedEncryptor::new(
        reader,
        Box::new(AesGcmEncryptor::new()),
        key,
        base_nonce,
        String::from_utf8(salt).unwrap(),
    );

    let mut output_file = std::fs::File::create(&output)?;
    encryptor.encrypt_to(&mut output_file)?;

    Ok(format!("File encrypted successfully: {}", output.display()))
}

fn decrypt_file(
    input_path: &str,
    output_path: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let input = PathBuf::from(input_path);
    let output = PathBuf::from(output_path);

    let input_file = std::fs::File::open(&input)?;
    let decryptor = ChunkedDecryptor::new(
        input_file,
        Box::new(AesGcmEncryptor::new()),
        Zeroizing::new([0u8; 32]),
    )?;

    let salt = decryptor.header().salt.as_bytes();
    let kdf = Argon2Kdf::default();
    let key = kdf.derive_key(password.as_bytes(), salt)?;

    let input_file = std::fs::File::open(&input)?;
    let mut decryptor = ChunkedDecryptor::new(
        input_file,
        Box::new(AesGcmEncryptor::new()),
        key,
    )?;

    let mut output_file = std::fs::File::create(&output)?;
    decryptor.decrypt_to(&mut output_file)?;

    Ok(format!("File decrypted successfully: {}", output.display()))
}

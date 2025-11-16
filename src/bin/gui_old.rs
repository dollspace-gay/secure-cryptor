// Native GUI for Secure Cryptor using egui
// No web bloat, just a fast native executable

#![windows_subsystem = "windows"]

use eframe::egui;
use secure_cryptor::{
    ChunkedDecryptor, ChunkedEncryptor, ChunkedReader, StreamConfig,
    crypto::{aes_gcm::AesGcmEncryptor, kdf::Argon2Kdf, KeyDerivation},
    validation::validate_password,
};
use std::path::PathBuf;
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 650.0])
            .with_resizable(true)
            .with_min_inner_size([800.0, 600.0])
            .with_title("Secure Cryptor"),
        ..Default::default()
    };

    eframe::run_native(
        "Secure Cryptor",
        options,
        Box::new(|cc| {
            // Set custom theme
            let mut style = (*cc.egui_ctx.style()).clone();

            // Increase rounding for pill-shaped buttons
            style.visuals.widgets.inactive.rounding = egui::Rounding::same(20.0);
            style.visuals.widgets.hovered.rounding = egui::Rounding::same(20.0);
            style.visuals.widgets.active.rounding = egui::Rounding::same(20.0);

            cc.egui_ctx.set_style(style);

            Ok(Box::new(CryptorApp::default()))
        }),
    )
}

#[derive(PartialEq)]
enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(Default)]
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
}

impl CryptorApp {
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
                    }
                    Err(e) => {
                        self.status_message = format!("Encryption failed: {}", e);
                        self.progress = 0.0;
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
                    }
                    Err(e) => {
                        self.status_message = format!("Decryption failed: {}", e);
                        self.progress = 0.0;
                    }
                }
            }
        }

        self.is_processing = false;
    }
}

impl eframe::App for CryptorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Draw gradient background
        let painter = ctx.layer_painter(egui::LayerId::background());
        let rect = ctx.screen_rect();

        // Trans pride gradient: blue -> pink
        let trans_blue = egui::Color32::from_rgb(135, 206, 250);
        let trans_pink = egui::Color32::from_rgb(245, 169, 200);

        painter.rect_filled(rect, 0.0, trans_blue);

        // Create gradient effect
        let mesh = {
            let mut mesh = egui::Mesh::default();
            mesh.colored_vertex(rect.left_top(), trans_blue);
            mesh.colored_vertex(rect.right_top(), trans_pink.gamma_multiply(0.7));
            mesh.colored_vertex(rect.left_bottom(), trans_blue.gamma_multiply(0.9));
            mesh.colored_vertex(rect.right_bottom(), trans_pink);
            mesh.add_triangle(0, 1, 2);
            mesh.add_triangle(1, 2, 3);
            mesh
        };
        painter.add(egui::Shape::mesh(mesh));

        egui::CentralPanel::default()
            .frame(egui::Frame::none())
            .show(ctx, |ui| {
            ui.add_space(40.0);

            // Main panel with rounded corners and white/translucent background
            let panel_frame = egui::Frame::default()
                .fill(egui::Color32::from_rgba_unmultiplied(255, 255, 255, 240))
                .rounding(egui::Rounding::same(25.0))
                .inner_margin(egui::Margin::same(40.0))
                .shadow(egui::epaint::Shadow {
                    offset: egui::Vec2::new(0.0, 4.0),
                    blur: 20.0,
                    spread: 0.0,
                    color: egui::Color32::from_black_alpha(40),
                });

            egui::Frame::none()
                .show(ui, |ui| {
                    ui.set_max_width(900.0);
                    ui.horizontal(|ui| {
                        ui.allocate_space(egui::vec2((ui.available_width() - 850.0) / 2.0, 0.0));

                        panel_frame.show(ui, |ui| {
                            ui.set_width(850.0);

                            // Header
                            ui.vertical_centered(|ui| {
                                ui.add_space(10.0);
                                ui.label(egui::RichText::new("Secure Cryptor")
                                    .size(36.0)
                                    .color(egui::Color32::from_rgb(40, 40, 40)));
                                ui.add_space(20.0);
                            });

                            // Mode selection with centered label
                            ui.vertical_centered(|ui| {
                                ui.label(egui::RichText::new("Mode").size(18.0));
                                ui.add_space(10.0);
                            });

            ui.add_space(5.0);

            // Mode selection (auto-detected, but can be manually changed)
            ui.horizontal(|ui| {
                ui.label("Mode:");
                ui.add_space(10.0);

                let trans_blue = egui::Color32::from_rgb(91, 206, 250);
                let trans_pink = egui::Color32::from_rgb(245, 169, 184);

                if ui.selectable_label(self.mode == Some(Mode::Encrypt), "🔐 Encrypt")
                    .clicked() && !self.is_processing
                {
                    self.mode = Some(Mode::Encrypt);
                    // Update output path if input is set
                    if !self.input_path.is_empty() {
                        self.output_path = format!("{}.enc", self.input_path);
                    }
                }
                if ui.selectable_label(self.mode == Some(Mode::Decrypt), "🔓 Decrypt")
                    .clicked() && !self.is_processing
                {
                    self.mode = Some(Mode::Decrypt);
                    // Update output path if input is set
                    if !self.input_path.is_empty() {
                        self.output_path = if self.input_path.ends_with(".enc") {
                            self.input_path.trim_end_matches(".enc").to_string()
                        } else {
                            format!("{}.dec", self.input_path)
                        };
                    }
                }

                if self.mode.is_none() {
                    ui.colored_label(trans_pink, "(Select a file to auto-detect mode)");
                }
            });

            ui.add_space(15.0);

            // File selection
            ui.add_enabled_ui(!self.is_processing, |ui| {
                ui.group(|ui| {

                ui.label("Input File:");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.input_path)
                            .desired_width(400.0)
                            .interactive(false),
                    );
                    if ui.button("Browse...").clicked() {
                        self.select_input_file();
                    }
                });

                ui.add_space(5.0);

                ui.label("Output File:");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.output_path)
                            .desired_width(400.0),
                    );
                    if ui.button("Browse...").clicked() {
                        self.select_output_file();
                    }
                });
                });
            });

            ui.add_space(15.0);

            // Password section
            ui.add_enabled_ui(!self.is_processing, |ui| {
                ui.group(|ui| {

                ui.label("Password:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.password)
                        .password(true)
                        .desired_width(500.0),
                );

                if let Some(Mode::Encrypt) = self.mode {
                    ui.add_space(5.0);
                    ui.label("Confirm Password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.confirm_password)
                            .password(true)
                            .desired_width(500.0),
                    );

                    if !self.confirm_password.is_empty() {
                        if self.password == self.confirm_password {
                            ui.colored_label(egui::Color32::GREEN, "✓ Passwords match");
                        } else {
                            ui.colored_label(egui::Color32::RED, "✗ Passwords do not match");
                        }
                    }
                }
                });
            });

            ui.add_space(10.0);

            // Options
            if let Some(Mode::Encrypt) = self.mode {
                ui.add_enabled_ui(!self.is_processing, |ui| {
                    ui.checkbox(&mut self.use_compression, "Enable compression (reduces file size)");
                });
            }

            ui.add_space(15.0);

            // Process button
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
                && self.mode.is_some()
                && !self.input_path.is_empty()
                && !self.output_path.is_empty()
                && !self.password.is_empty();

            ui.add_enabled_ui(button_enabled, |ui| {
                if ui.add_sized([550.0, 35.0], egui::Button::new(button_text)).clicked() {
                    self.process_file();
                }
            });

            ui.add_space(10.0);

            // Progress bar
            if self.is_processing || self.progress > 0.0 {
                ui.add(egui::ProgressBar::new(self.progress).show_percentage());
            }

            // Status message
            if !self.status_message.is_empty() {
                ui.add_space(10.0);
                ui.separator();

                let color = if self.status_message.starts_with("Error:") {
                    egui::Color32::RED
                } else if self.status_message.contains("success") {
                    egui::Color32::GREEN
                } else {
                    egui::Color32::GRAY
                };

                ui.colored_label(color, &self.status_message);
            }

            ui.add_space(10.0);
            ui.separator();

            // Footer with trans pride colors
            ui.horizontal(|ui| {
                let trans_blue = egui::Color32::from_rgb(91, 206, 250);
                let trans_pink = egui::Color32::from_rgb(245, 169, 184);

                ui.colored_label(trans_blue, "🔒 AES-256-GCM");
                ui.separator();
                ui.colored_label(trans_pink, "🔑 Argon2id");
                ui.separator();
                ui.colored_label(trans_blue, "✓ Authenticated");
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

    // Create stream configuration
    let mut config = StreamConfig::default();
    if use_compression {
        config = config.with_compression(true);
    }

    // Open input file
    let reader = ChunkedReader::open(&input, config)?;

    // Derive key from password
    let kdf = Argon2Kdf::default();
    let salt = kdf.generate_salt();
    let key = kdf.derive_key(password.as_bytes(), &salt)?;

    // Generate base nonce
    let mut base_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut base_nonce);

    // Create encryptor
    let encryptor = ChunkedEncryptor::new(
        reader,
        Box::new(AesGcmEncryptor::new()),
        key,
        base_nonce,
        String::from_utf8(salt).unwrap(),
    );

    // Open output file
    let mut output_file = std::fs::File::create(&output)?;

    // Encrypt
    encryptor.encrypt_to(&mut output_file)?;

    Ok(format!("✓ File encrypted successfully: {}", output.display()))
}

fn decrypt_file(
    input_path: &str,
    output_path: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let input = PathBuf::from(input_path);
    let output = PathBuf::from(output_path);

    // Open encrypted file
    let input_file = std::fs::File::open(&input)?;

    // Create decryptor (reads header to get salt)
    let decryptor = ChunkedDecryptor::new(
        input_file,
        Box::new(AesGcmEncryptor::new()),
        Zeroizing::new([0u8; 32]), // Placeholder
    )?;

    // Get salt from header
    let salt = decryptor.header().salt.as_bytes();

    // Derive key from password and salt
    let kdf = Argon2Kdf::default();
    let key = kdf.derive_key(password.as_bytes(), salt)?;

    // Re-create decryptor with correct key
    let input_file = std::fs::File::open(&input)?;
    let mut decryptor = ChunkedDecryptor::new(
        input_file,
        Box::new(AesGcmEncryptor::new()),
        key,
    )?;

    // Open output file
    let mut output_file = std::fs::File::create(&output)?;

    // Decrypt
    decryptor.decrypt_to(&mut output_file)?;

    Ok(format!("✓ File decrypted successfully: {}", output.display()))
}

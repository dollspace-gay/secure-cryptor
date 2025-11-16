// Native GUI for Secure Cryptor using egui
// Matches the exact design from mockup

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
            .with_inner_size([1024.0, 768.0])
            .with_resizable(true)
            .with_min_inner_size([900.0, 700.0])
            .with_title("Secure Cryptor"),
        ..Default::default()
    };

    eframe::run_native(
        "Secure Cryptor",
        options,
        Box::new(|cc| {
            // Set custom theme with rounded corners
            let mut style = (*cc.egui_ctx.style()).clone();
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

        // Main content panel
        egui::CentralPanel::default()
            .frame(egui::Frame::none())
            .show(ctx, |ui| {
                ui.add_space(60.0);

                // Center the main panel
                ui.vertical_centered(|ui| {
                    let panel_frame = egui::Frame::default()
                        .fill(egui::Color32::from_rgba_unmultiplied(255, 255, 255, 100))
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

                        // Action button
                        ui.vertical_centered(|ui| {
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

                            let button_color = if self.mode == Some(Mode::Encrypt) {
                                egui::Color32::from_rgb(91, 206, 250)
                            } else {
                                egui::Color32::from_rgb(91, 206, 250)
                            };

                            let action_btn = egui::Button::new(
                                egui::RichText::new(button_text).size(18.0).color(egui::Color32::WHITE)
                            )
                            .fill(button_color)
                            .min_size(egui::vec2(300.0, 50.0))
                            .rounding(egui::Rounding::same(25.0));

                            if ui.add_enabled(button_enabled, action_btn).clicked() {
                                self.process_file();
                            }
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

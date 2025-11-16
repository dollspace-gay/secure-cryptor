// System tray integration for Secure Cryptor
// Cross-platform support for Windows, Linux, and macOS

use std::path::PathBuf;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu},
    TrayIcon, TrayIconBuilder,
};

pub struct TrayManager {
    _tray_icon: TrayIcon,
    show_hide_item: MenuItem,
    encrypt_item: MenuItem,
    decrypt_item: MenuItem,
    settings_item: MenuItem,
    quit_item: MenuItem,
}

impl TrayManager {
    /// Creates a new system tray manager
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Load the icon
        let icon = Self::load_icon()?;

        // Create menu items
        let show_hide_item = MenuItem::new("Show/Hide Window", true, None);
        let separator1 = PredefinedMenuItem::separator();

        // Quick actions submenu
        let encrypt_item = MenuItem::new("Quick Encrypt...", true, None);
        let decrypt_item = MenuItem::new("Quick Decrypt...", true, None);
        let quick_actions = Submenu::new("Quick Actions", true);
        quick_actions.append(&encrypt_item)?;
        quick_actions.append(&decrypt_item)?;

        let separator2 = PredefinedMenuItem::separator();
        let settings_item = MenuItem::new("Settings", true, None);
        let separator3 = PredefinedMenuItem::separator();
        let quit_item = MenuItem::new("Quit", true, None);

        // Build the menu
        let tray_menu = Menu::new();
        tray_menu.append(&show_hide_item)?;
        tray_menu.append(&separator1)?;
        tray_menu.append(&quick_actions)?;
        tray_menu.append(&separator2)?;
        tray_menu.append(&settings_item)?;
        tray_menu.append(&separator3)?;
        tray_menu.append(&quit_item)?;

        // Create the tray icon
        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(tray_menu))
            .with_tooltip("Secure Cryptor")
            .with_icon(icon)
            .build()?;

        Ok(Self {
            _tray_icon: tray_icon,
            show_hide_item,
            encrypt_item,
            decrypt_item,
            settings_item,
            quit_item,
        })
    }

    /// Loads the tray icon from the icons directory
    fn load_icon() -> Result<tray_icon::Icon, Box<dyn std::error::Error>> {
        #[cfg(target_os = "windows")]
        {
            // On Windows, use the .ico file
            let icon_path = Self::get_icon_path("app_icon.ico");
            let icon_data = std::fs::read(&icon_path)?;
            let icon = image::load_from_memory(&icon_data)?;
            let rgba = icon.to_rgba8();
            let (width, height) = rgba.dimensions();
            let icon = tray_icon::Icon::from_rgba(rgba.into_raw(), width, height)?;
            Ok(icon)
        }

        #[cfg(not(target_os = "windows"))]
        {
            // On Linux and macOS, use the .png file
            let icon_path = Self::get_icon_path("logo.png");
            let icon_data = std::fs::read(&icon_path)?;
            let icon = image::load_from_memory(&icon_data)?;

            // Resize to appropriate size for tray (typically 22x22 or 32x32)
            let icon = icon.resize(32, 32, image::imageops::FilterType::Lanczos3);
            let rgba = icon.to_rgba8();
            let (width, height) = rgba.dimensions();
            let icon = tray_icon::Icon::from_rgba(rgba.into_raw(), width, height)?;
            Ok(icon)
        }
    }

    /// Gets the path to an icon file
    fn get_icon_path(filename: &str) -> PathBuf {
        // Try current directory first (for development)
        let current_dir = std::env::current_dir().unwrap_or_default();
        let icon_path = current_dir.join("icons").join(filename);

        if icon_path.exists() {
            return icon_path;
        }

        // Try executable directory (for installed app)
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let icon_path = exe_dir.join("icons").join(filename);
                if icon_path.exists() {
                    return icon_path;
                }
            }
        }

        // Fallback to just the filename
        PathBuf::from(filename)
    }

    /// Checks for and processes tray events
    /// Returns TrayEvent indicating what action should be taken
    pub fn process_events(&self) -> Option<TrayEvent> {
        if let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == self.show_hide_item.id() {
                return Some(TrayEvent::ToggleWindow);
            } else if event.id == self.encrypt_item.id() {
                return Some(TrayEvent::QuickEncrypt);
            } else if event.id == self.decrypt_item.id() {
                return Some(TrayEvent::QuickDecrypt);
            } else if event.id == self.settings_item.id() {
                return Some(TrayEvent::ShowSettings);
            } else if event.id == self.quit_item.id() {
                return Some(TrayEvent::Quit);
            }
        }
        None
    }

    /// Updates the tray tooltip with status information
    pub fn set_status(&mut self, status: &str) {
        let tooltip = format!("Secure Cryptor - {}", status);
        let _ = self._tray_icon.set_tooltip(Some(tooltip));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayEvent {
    ToggleWindow,
    QuickEncrypt,
    QuickDecrypt,
    ShowSettings,
    Quit,
}

// Cross-platform Registry/File Association Manager for Tesseract
//
// Usage:
//   tesseract-register install   - Register file associations and context menus
//   tesseract-register uninstall - Remove all registry entries

use std::env;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

/// Get the path to the GUI executable
fn get_gui_exe_path() -> PathBuf {
    let current_exe = env::current_exe().expect("Failed to get current executable path");
    let exe_dir = current_exe.parent().expect("Failed to get executable directory");

    #[cfg(target_os = "windows")]
    {
        exe_dir.join("tesseract-gui.exe")
    }
    #[cfg(not(target_os = "windows"))]
    {
        exe_dir.join("tesseract-gui")
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [install|uninstall]", args[0]);
        eprintln!();
        eprintln!("Commands:");
        eprintln!("  install   - Register file associations and context menus");
        eprintln!("  uninstall - Remove all registry entries");
        std::process::exit(1);
    }

    let exe_path = get_gui_exe_path();

    match args[1].as_str() {
        "install" => {
            println!("Installing Tesseract file associations and context menus...");
            println!("GUI executable: {}", exe_path.display());

            #[cfg(target_os = "windows")]
            {
                if let Err(e) = windows::install(&exe_path) {
                    eprintln!("Error during installation: {}", e);
                    std::process::exit(1);
                }
            }

            #[cfg(target_os = "linux")]
            {
                if let Err(e) = linux::install(&exe_path) {
                    eprintln!("Error during installation: {}", e);
                    std::process::exit(1);
                }
            }

            #[cfg(target_os = "macos")]
            {
                if let Err(e) = macos::install(&exe_path) {
                    eprintln!("Error during installation: {}", e);
                    std::process::exit(1);
                }
            }

            println!("\n✓ Installation complete!");
        }
        "uninstall" => {
            println!("Uninstalling Tesseract file associations and context menus...");

            #[cfg(target_os = "windows")]
            {
                if let Err(e) = windows::uninstall() {
                    eprintln!("Error during uninstallation: {}", e);
                }
            }

            #[cfg(target_os = "linux")]
            {
                if let Err(e) = linux::uninstall() {
                    eprintln!("Error during uninstallation: {}", e);
                }
            }

            #[cfg(target_os = "macos")]
            {
                if let Err(e) = macos::uninstall() {
                    eprintln!("Error during uninstallation: {}", e);
                }
            }

            println!("\n✓ Uninstallation complete!");
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            eprintln!("Use 'install' or 'uninstall'");
            std::process::exit(1);
        }
    }
}

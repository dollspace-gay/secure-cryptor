/// Secure Cryptor Daemon
///
/// Long-running background service for managing encrypted volume mounts

use tesseract::daemon::DaemonServer;

fn main() {
    println!("Starting Secure Cryptor Daemon...");

    let server = DaemonServer::new();

    if let Err(e) = server.run() {
        eprintln!("Daemon error: {}", e);
        std::process::exit(1);
    }
}

// Build script to embed Windows icon resource

fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("icons/app_icon.ico");
        res.set("ProductName", "Secure Cryptor");
        res.set("FileDescription", "Secure File Encryption Tool");
        res.set("CompanyName", "Secure Cryptor");
        if let Err(e) = res.compile() {
            eprintln!("Failed to compile Windows resources: {}", e);
        }
    }
}

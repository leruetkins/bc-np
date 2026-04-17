use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let dist_ui_path = Path::new(&manifest_dir).join("dist-ui");

    println!("cargo:rerun-if-changed={}", dist_ui_path.display());

    if !dist_ui_path.exists() {
        println!(
            "dist-ui folder not found at {}. Attempting to build UI assets automatically...",
            dist_ui_path.display()
        );
        // Best-effort: try to build UI assets so embedding works in normal scenarios.
        let mut cmd = if cfg!(windows) {
            std::process::Command::new("cmd")
        } else {
            std::process::Command::new("sh")
        };
        let script = if cfg!(windows) {
            "/C npm ci && npm run build"
        } else {
            "-lc npm ci && npm run build"
        };
        let status = cmd.arg(script).current_dir(&manifest_dir).status();
        match status {
            Ok(s) if s.success() => {
                println!("UI assets built successfully.");
            }
            _ => {
                eprintln!("Warning: failed to build UI assets. The binary will attempt to serve embedded assets if available, otherwise will rely on disk assets at runtime.");
            }
        }
    }

    let entries = fs::read_dir(&dist_ui_path).unwrap();
    println!("Files in dist-ui:");
    for entry in entries {
        let entry = entry.unwrap();
        println!("  {}", entry.path().display());
    }
}

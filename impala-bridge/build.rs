use std::process::Command;

fn main() {
    // Get the current date and time
    let build_date = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    println!("cargo:rustc-env=BUILD_DATE={}", build_date);

    // Get the Rust compiler version
    let rustc_version = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .unwrap_or_else(|| "unknown".to_string())
        .trim()
        .to_string();
    println!("cargo:rustc-env=RUSTC_VERSION={}", rustc_version);
}

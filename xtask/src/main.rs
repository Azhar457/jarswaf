use anyhow::Context;
use std::process::Command;

fn main() -> anyhow::Result<()> {
    println!("Building eBPF program...");

    let mut workspace_root = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?,
    );
    workspace_root.pop(); // Go up to workspace root
    let ebpf_cargo_toml = workspace_root.join("jarswaf-ebpf").join("Cargo.toml");

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
        .args(&[
            "build",
            "--release",
            "--manifest-path",
            ebpf_cargo_toml.to_str().unwrap(),
            "--target=bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .status()
        .context("Failed to build eBPF program")?;

    if !status.success() {
        anyhow::bail!("Failed to compile eBPF program");
    }

    println!("eBPF program built successfully!");
    Ok(())
}

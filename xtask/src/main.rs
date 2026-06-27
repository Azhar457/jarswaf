use anyhow::Context;
use std::process::Command;

fn main() -> anyhow::Result<()> {
    println!("Building eBPF program...");

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
        .args(&[
            "build",
            "--release",
            "--manifest-path",
            "aegis-ebpf/Cargo.toml",
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

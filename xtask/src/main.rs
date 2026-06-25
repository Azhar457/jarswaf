use anyhow::Context;
use std::process::Command;

fn main() -> anyhow::Result<()> {
    println!("Building eBPF program...");

    let status = Command::new("cargo")
        .args(&[
            "build",
            "--release",
            "--target=bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .current_dir("aegis-ebpf")
        .status()
        .context("Failed to build eBPF program")?;

    if !status.success() {
        anyhow::bail!("Failed to compile eBPF program");
    }

    println!("eBPF program built successfully!");
    Ok(())
}

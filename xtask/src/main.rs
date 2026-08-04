use anyhow::Context;
use std::env;
use std::process::Command;

mod redteam;
mod report;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("ebpf");

    match command {
        "ebpf" => build_ebpf()?,
        "clean" => clean_all()?,
        "check" => check_all()?,
        "build-all" => {
            println!("Building eBPF and WAF binaries...");
            build_ebpf()?;
            let status = Command::new("cargo")
                .args(["build", "--release"])
                .status()
                .context("Failed to build main workspace")?;
            if !status.success() {
                anyhow::bail!("Main workspace compilation failed");
            }
            println!("All binaries compiled successfully!");
        }
        "redteam" => {
            let target = args
                .get(2)
                .map(|s| s.as_str())
                .unwrap_or("http://127.0.0.1:8080");
            redteam::run_redteam(target).await;
        }
        "generate-report" => {
            let log_path = args
                .get(2)
                .map(|s| s.as_str())
                .unwrap_or("jarswaf.log.ecs.json");
            let output_path = args
                .get(3)
                .map(|s| s.as_str())
                .unwrap_or("compliance_report.md");
            report::generate_report(log_path, output_path);
        }
        _ => {
            println!("jarsWAF xtask runner - Available commands:");
            println!(
                "  cargo xtask ebpf            - Build eBPF XDP probe (bpfel-unknown-none target)"
            );
            println!("  cargo xtask build-all       - Compile eBPF + Main WAF workspace release binaries");
            println!(
                "  cargo xtask check           - Run static analysis & type check across crates"
            );
            println!("  cargo xtask clean           - Deep clean target build artifacts across all crates");
            println!("  cargo xtask redteam <URL>   - Run automated Sec/WAF attack benchmark");
            println!("  cargo xtask generate-report - Generate security compliance report");
        }
    }
    Ok(())
}

fn clean_all() -> anyhow::Result<()> {
    println!("Cleaning main cargo workspace...");
    let _ = Command::new("cargo").arg("clean").status();
    println!("Cleaning eBPF workspace...");
    let _ = Command::new("cargo")
        .args(["clean", "--manifest-path", "jarswaf-ebpf/Cargo.toml"])
        .status();
    println!("Clean completed.");
    Ok(())
}

fn check_all() -> anyhow::Result<()> {
    println!("Checking main workspace...");
    let status = Command::new("cargo").arg("check").status()?;
    if !status.success() {
        anyhow::bail!("Cargo check failed");
    }
    println!("All checks passed cleanly.");
    Ok(())
}

fn build_ebpf() -> anyhow::Result<()> {
    println!("Building eBPF program...");

    let mut workspace_root = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?,
    );
    workspace_root.pop(); // Go up to workspace root
    let ebpf_cargo_toml = workspace_root.join("jarswaf-ebpf").join("Cargo.toml");

    // Force nightly channel because -Z build-std=core requires it.
    // The CARGO env var set by `cargo run` points to a toolchain-specific binary,
    // so +nightly flag won't work. Call rustup directly instead.
    let status = Command::new("rustup")
        .args([
            "run",
            "nightly",
            "cargo",
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

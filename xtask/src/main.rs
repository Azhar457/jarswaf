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
            println!("Unknown command. Use 'ebpf', 'redteam', or 'generate-report'.");
            std::process::exit(1);
        }
    }
    Ok(())
}

fn build_ebpf() -> anyhow::Result<()> {
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

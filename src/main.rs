use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "jarswaf")]
#[command(about = "jarsWAF - Next Gen Layer 7 Web Application Firewall", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to config file (default: config.toml)
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Path to custom rules directory (default: rules/)
    #[arg(short = 'r', long, default_value = "rules")]
    rules_dir: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run WAF in Agent mode (default)
    Agent {
        /// URL of the central Controller
        #[arg(short, long)]
        controller: Option<String>,

        /// Registration token for the Controller
        #[arg(short, long)]
        token: Option<String>,
    },
    /// Run WAF in Controller mode (central logging and dashboard)
    Controller {
        /// Port to bind the Controller server
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
    },
    /// Run WAF in Standalone Bundle mode (Controller + Agent + Dashboard in 1 single binary)
    Bundle {
        /// Port to bind the Controller server (default: 8080)
        #[arg(short, long, default_value_t = 8080)]
        controller_port: u16,
    },
    /// Generate a binding token for a Machine ID
    GenerateToken {
        /// The Machine ID to generate a token for (defaults to local machine ID)
        machine_id: Option<String>,
    },
    /// Print the local Machine ID
    MachineId,
    /// Check jarsWAF service and runtime status
    Status,
    /// Start jarsWAF systemd service
    Start,
    /// Stop jarsWAF systemd service
    Stop,
    /// Restart jarsWAF systemd service
    Restart,
    /// Tail live jarsWAF logs
    Logs {
        /// Number of lines to view (default: 50)
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
    },
    /// Reload jarsWAF configuration
    Reload,
    /// Reset admin password to a new random password
    ResetPassword,
    /// Automatically configure local /etc/hosts (or Windows hosts) for dev domain
    SetupHosts {
        /// Domain name to bind to 127.0.0.1 (default: dev-waf.local)
        #[arg(short, long, default_value = "dev-waf.local")]
        domain: String,
        /// IP address to bind to (default: 127.0.0.1)
        #[arg(short, long, default_value = "127.0.0.1")]
        ip: String,
    },
}

fn get_machine_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown-machine-id".to_string())
}

#[tokio::main]
async fn main() {
    // Init ring crypto provider BEFORE any rustls usage
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring crypto provider");

    // Init tracing with OpenTelemetry-compatible structured JSON format
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_env_filter("info")
        .init();

    let cli = Cli::parse();

    let cfg = jarswaf::config::load_config(&cli.config).unwrap_or_else(|e| {
        eprintln!("Error loading config {}: {}", cli.config, e);
        std::process::exit(1);
    });

    let run_mode = if let Some(cmd) = cli.command {
        cmd
    } else {
        match cfg.global.mode.as_str() {
            "manager" => Commands::Controller { port: 8080 },
            _ => Commands::Agent {
                controller: cfg.global.manager_url,
                token: cfg.global.grpc_token,
            },
        }
    };

    match run_mode {
        Commands::Agent { controller, token } => {
            jarswaf::agent::run_agent(&cli.config, controller, token, &cli.rules_dir).await;
        }
        Commands::Controller { port } => {
            jarswaf::controller::run_controller(port, cli.config).await;
        }
        Commands::Bundle { controller_port } => {
            let config_path = cli.config.clone();
            let rules_dir = cli.rules_dir.clone();
            tokio::spawn(async move {
                jarswaf::controller::run_controller(controller_port, config_path).await;
            });

            // Active readiness check instead of 1-second sleep hack
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(500))
                .build()
                .unwrap();
            let health_url = format!("http://127.0.0.1:{}/health", controller_port);
            let mut ready = false;
            for _ in 0..20 {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                if let Ok(res) = client.get(&health_url).send().await {
                    if res.status().is_success() {
                        ready = true;
                        break;
                    }
                }
            }
            if !ready {
                eprintln!("Warning: Controller did not become ready within 5 seconds, starting agent anyway.");
            }

            jarswaf::agent::run_agent(
                &cli.config,
                Some(format!("http://127.0.0.1:{}", controller_port)),
                None,
                &rules_dir,
            )
            .await;
        }
        Commands::GenerateToken { machine_id } => {
            let m_id = machine_id.unwrap_or_else(get_machine_id);
            match jarswaf::config::load_config(&cli.config) {
                Ok(cfg) => {
                    if let Some(admin_token) = cfg.global.admin_token {
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(format!("{}:{}", m_id, admin_token).as_bytes());
                        let hash = format!("{:x}", hasher.finalize());
                        println!("{}.{}", m_id, hash);
                    } else {
                        eprintln!("Error: admin_token is not set in {}", cli.config);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error loading config {}: {}", cli.config, e);
                    std::process::exit(1);
                }
            }
        }
        Commands::MachineId => {
            println!("{}", get_machine_id());
        }
        Commands::Status => {
            println!("===============================================================");
            println!("🛡️  jarsWAF Status Overview");
            println!("===============================================================");
            let is_systemd_active = std::process::Command::new("systemctl")
                .args(["is-active", "--quiet", "jarswaf"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

            if is_systemd_active {
                println!("  Service Status:    ● ACTIVE (Running under systemd)");
            } else {
                println!("  Service Status:    ○ INACTIVE (Not running as systemd service)");
            }

            let opt_dir = std::path::Path::new("/opt/jarswaf");
            if opt_dir.exists() {
                println!("  Install Location:  /opt/jarswaf");
            } else {
                println!("  Install Location:  Local Workspace");
            }

            let config_path = if opt_dir.join("config.toml").exists() {
                "/opt/jarswaf/config.toml"
            } else {
                &cli.config
            };

            if let Ok(cfg) = jarswaf::config::load_config(config_path) {
                println!("  Config File:       {}", config_path);
                println!(
                    "  WAF Proxy Port:    http://0.0.0.0:{} (HTTP) / :{} (HTTPS)",
                    cfg.global.port_http, cfg.global.port_https
                );
                println!("  Dashboard GUI:     http://0.0.0.0:9443");
                println!("  Active VHosts:     {} domain(s)", cfg.vhosts.len());
            } else {
                println!("  Config File:       {}", config_path);
                println!("  WAF Proxy Port:    http://0.0.0.0:80");
                println!("  Dashboard GUI:     http://0.0.0.0:9443");
            }
            println!("===============================================================");
        }
        Commands::Start => {
            println!("🚀 Memulai service jarsWAF...");
            let res = std::process::Command::new("systemctl")
                .args(["start", "jarswaf"])
                .status();
            if res.map(|s| s.success()).unwrap_or(false) {
                println!("✅ [OK] Service jarsWAF berhasil dijalankan.");
            } else {
                eprintln!("❌ [ERROR] Gagal menjalankan service jarsWAF. Jalankan dengan sudo / periksa systemctl status jarswaf.");
            }
        }
        Commands::Stop => {
            println!("🛑 Menghentikan service jarsWAF...");
            let res = std::process::Command::new("systemctl")
                .args(["stop", "jarswaf"])
                .status();
            if res.map(|s| s.success()).unwrap_or(false) {
                println!("✅ [OK] Service jarsWAF berhasil dihentikan.");
            } else {
                eprintln!("❌ [ERROR] Gagal menghentikan service jarsWAF.");
            }
        }
        Commands::Restart => {
            println!("🔄 Me-restart service jarsWAF...");
            let res = std::process::Command::new("systemctl")
                .args(["restart", "jarswaf"])
                .status();
            if res.map(|s| s.success()).unwrap_or(false) {
                println!("✅ [OK] Service jarsWAF berhasil di-restart.");
            } else {
                eprintln!("❌ [ERROR] Gagal me-restart service jarsWAF.");
            }
        }
        Commands::Reload => {
            println!("♻️  Memuat ulang konfigurasi jarsWAF...");
            let res = std::process::Command::new("systemctl")
                .args(["restart", "jarswaf"])
                .status();
            if res.map(|s| s.success()).unwrap_or(false) {
                println!("✅ [OK] Konfigurasi jarsWAF berhasil dimuat ulang.");
            } else {
                eprintln!("❌ [ERROR] Gagal memuat ulang service jarsWAF.");
            }
        }
        Commands::Logs { lines } => {
            println!("📜 Menampilkan live log jarsWAF (Tekan Ctrl+C untuk keluar)...");
            let _ = std::process::Command::new("journalctl")
                .args(["-u", "jarswaf", "-n", &lines.to_string(), "-f"])
                .status();
        }
        Commands::ResetPassword => {
            let config_file = if std::path::Path::new("/opt/jarswaf/config.toml").exists() {
                "/opt/jarswaf/config.toml"
            } else {
                &cli.config
            };
            let new_pass = jarswaf::controller::auth::ensure_admin_credentials(config_file);
            println!("===============================================================");
            println!("🔐 Admin Password Berhasil Di-reset!");
            println!("===============================================================");
            println!("  Username      : admin");
            println!("  Password Baru : {}", new_pass);
            println!("===============================================================");
        }
        Commands::SetupHosts { domain, ip } => {
            let hosts_path = if cfg!(windows) {
                "C:\\Windows\\System32\\drivers\\etc\\hosts"
            } else {
                "/etc/hosts"
            };
            println!("===============================================================");
            println!("🛡️  jarsWAF HOSTS AUTOMATIC CONFIGURATOR");
            println!("===============================================================");
            println!("[INFO] Target File: {}", hosts_path);
            let content = std::fs::read_to_string(hosts_path).unwrap_or_default();
            if content.contains(&domain) {
                println!("[OK] Entry untuk '{:<15} {}' SUDAH TERDAFTAR.", ip, domain);
            } else {
                let entry = format!(
                    "\n# Added by jarsWAF auto-configurator\n{} {}\n",
                    ip, domain
                );
                if let Err(e) = std::fs::OpenOptions::new()
                    .append(true)
                    .open(hosts_path)
                    .and_then(|mut f| std::io::Write::write_all(&mut f, entry.as_bytes()))
                {
                    eprintln!("[ERROR] Gagal menulis ke file hosts: {}", e);
                    eprintln!("        Silakan jalankan perintah dengan 'sudo' (Linux/macOS) atau 'Run as Administrator' (Windows).");
                    std::process::exit(1);
                } else {
                    println!(
                        "[SUCCESS] Entri '{:<15} {}' berhasil ditambahkan ke {}.",
                        ip, domain, hosts_path
                    );
                }
            }
            println!("---------------------------------------------------------------");
            println!("📌 CARA AKSES REVERSE PROXY & DASHBOARD:");
            println!("   - Web App via WAF Proxy : http://{}:8000", domain);
            println!("   - HTTPS via WAF Proxy   : https://{}:8443", domain);
            println!("   - Dashboard GUI Admin   : http://localhost:8080");
            println!("===============================================================\n");
        }
    }
}

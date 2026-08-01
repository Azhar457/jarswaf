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
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
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

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
    /// Generate a binding token for a Machine ID
    GenerateToken {
        /// The Machine ID to generate a token for (defaults to local machine ID)
        machine_id: Option<String>,
    },
    /// Print the local Machine ID
    MachineId,
}

fn get_machine_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown-machine-id".to_string())
}

#[tokio::main]
async fn main() {
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
            jarswaf::agent::run_agent(&cli.config, controller, token).await;
        }
        Commands::Controller { port } => {
            jarswaf::controller::run_controller(port, cli.config).await;
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
    }
}

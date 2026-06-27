mod agent;
mod config;
mod controller;
mod logging;
mod proxy;
pub mod rules;
pub mod tls;
pub mod types;
pub mod vhost;
pub mod xdp;

pub use types::is_local_ip;

use clap::{Parser, Subcommand};
use once_cell::sync::Lazy;
use std::sync::Arc;

// Global XDP Manager
pub static XDP_MANAGER: Lazy<Arc<tokio::sync::Mutex<xdp::XdpManager>>> =
    Lazy::new(|| Arc::new(tokio::sync::Mutex::new(xdp::XdpManager::new())));

#[derive(Parser, Debug)]
#[command(name = "aegis-waf")]
#[command(about = "Aegis WAF - Next Gen Layer 7 Web Application Firewall", long_about = None)]
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
}

pub use agent::AppState;

#[tokio::main]
async fn main() {
    // Init tracing
    tracing_subscriber::fmt().with_env_filter("info").init();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Agent {
        controller: None,
        token: None,
    }) {
        Commands::Agent { controller, token } => {
            agent::run_agent(&cli.config, controller, token).await;
        }
        Commands::Controller { port } => {
            controller::run_controller(port, cli.config).await;
        }
    }
}

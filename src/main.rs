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

    match cli.command.unwrap_or(Commands::Agent {
        controller: None,
        token: None,
    }) {
        Commands::Agent { controller, token } => {
            jarswaf::agent::run_agent(&cli.config, controller, token).await;
        }
        Commands::Controller { port } => {
            jarswaf::controller::run_controller(port, cli.config).await;
        }
    }
}

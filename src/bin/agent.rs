use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "agent")]
#[command(about = "jarsWAF Agent - Layer 7 WAF Proxy Node", long_about = None)]
struct Cli {
    /// Path to config file (default: config.toml)
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// URL of the central Controller
    #[arg(short, long)]
    controller: Option<String>,

    /// Registration token for the Controller
    #[arg(short, long)]
    token: Option<String>,
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
    jarswaf::agent::run_agent(&cli.config, cli.controller, cli.token).await;
}

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "controller")]
#[command(about = "jarsWAF Controller - Management & Analytics Engine", long_about = None)]
struct Cli {
    /// Path to config file (default: config.toml)
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Port to bind the Controller server
    #[arg(short, long, default_value_t = 8080)]
    port: u16,
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
    jarswaf::controller::run_controller(cli.port, cli.config).await;
}

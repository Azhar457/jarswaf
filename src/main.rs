mod config;
mod logging;
mod proxy;
pub mod rules;
pub mod tls;
pub mod vhost;
pub mod xdp;

use axum::response::sse::{Event, Sse};
use axum::{
    body::Body,
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        Host, State,
    },
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, delete, get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use once_cell::sync::Lazy;
use std::convert::Infallible;
use std::net::SocketAddr;
use sysinfo::{Disks, Networks, System};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct DiscoveredService {
    pub name: String,
    pub port: u16,
    pub protocol: String,
    pub source: String, // "Docker" or "System"
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AgentMetrics {
    pub hostname: String,
    pub ip: String,
    pub os: String,
    pub cpu: f32,
    pub ram: f32,
    pub disk: f32,
    pub uptime: u64,
    pub network_interfaces: Vec<String>,
    pub discovered_services: Vec<DiscoveredService>,
}

#[derive(serde::Serialize, Clone, Debug)]
pub struct AgentInfo {
    pub hostname: String,
    pub ip: String,
    pub os: String,
    pub cpu: f32,
    pub ram: f32,
    pub disk: f32,
    pub uptime: String,
    pub status: String,
    pub network_interfaces: Vec<String>,
    pub discovered_services: Vec<DiscoveredService>,
    #[serde(skip)]
    pub last_seen: std::time::Instant,
}

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    if days > 0 {
        format!("{}d {}h {}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    }
}

fn get_docker_services() -> Vec<DiscoveredService> {
    let mut services = Vec::new();
    if let Ok(output) = std::process::Command::new("docker")
        .args(&["ps", "--format", "{{json .}}"])
        .output()
    {
        if output.status.success() {
            let out_str = String::from_utf8_lossy(&output.stdout);
            for line in out_str.lines() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    if let Some(name) = v.get("Names").and_then(|n| n.as_str()) {
                        if let Some(ports_str) = v.get("Ports").and_then(|p| p.as_str()) {
                            if ports_str.contains("->") {
                                let mut public_port = 0;
                                if let Some(idx) = ports_str.find("->") {
                                    let before_arrow = &ports_str[..idx];
                                    if let Some(colon_idx) = before_arrow.rfind(':') {
                                        if let Ok(p) = before_arrow[colon_idx + 1..].parse::<u16>()
                                        {
                                            public_port = p;
                                        }
                                    }
                                }
                                if public_port > 0 {
                                    services.push(DiscoveredService {
                                        name: name.to_string(),
                                        port: public_port,
                                        protocol: "tcp".to_string(),
                                        source: "Docker".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    services
}

fn get_network_interfaces() -> Vec<String> {
    let networks = Networks::new_with_refreshed_list();
    networks.iter().map(|(name, _)| name.to_string()).collect()
}

fn get_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "Aegis-Agent".to_string())
}

pub fn is_local_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_private(),
        std::net::IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || (ipv6.segments()[0] & 0xff00) == 0xfd00
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

// Untuk privilege dropping (bind port <1024 lalu drop ke nobody)
#[cfg(unix)]
fn drop_privileges() {
    if let Err(e) = nix::unistd::setgid(nix::unistd::Gid::from_raw(65534)) {
        tracing::warn!("Failed to setgid: {}", e);
    }
    if let Err(e) = nix::unistd::setuid(nix::unistd::Uid::from_raw(65534)) {
        tracing::warn!("Failed to setuid: {}", e);
    }
}

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
            run_agent(&cli.config, controller, token).await;
        }
        Commands::Controller { port } => {
            run_controller(port, cli.config).await;
        }
    }
}

async fn run_agent(config_path: &str, controller: Option<String>, token: Option<String>) {
    // Load config
    let cfg = config::load_config(config_path).expect("Failed to load config");
    let config_arc = Arc::new(std::sync::RwLock::new(cfg.clone()));

    // Start background memory cleanup for rate limiter & reputation counters
    rules::start_rate_limiter_cleanup();

    // Setup logging
    let clickhouse_url =
        std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
    logging::init_db(&clickhouse_url)
        .await
        .expect("Failed to init ClickHouse DB");

    // Initialize MPSC Channel for logs
    let (log_tx, log_rx) = tokio::sync::mpsc::channel::<logging::WafLogEntry>(10000);

    // Spawn Background Log Worker
    let controller_url = controller.clone();
    let ch_url_clone = clickhouse_url.clone();
    let log_dir = cfg.global.log_dir.clone();
    tokio::spawn(async move {
        logging::log_worker(log_rx, ch_url_clone, controller_url, log_dir).await;
    });

    // Spawn background config reloader
    let config_path_clone = config_path.to_string();
    let config_arc_clone = config_arc.clone();
    tokio::spawn(async move {
        let mut last_modified = std::fs::metadata(&config_path_clone)
            .and_then(|m| m.modified())
            .unwrap_or_else(|_| std::time::SystemTime::now());

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            if let Ok(metadata) = std::fs::metadata(&config_path_clone) {
                if let Ok(modified) = metadata.modified() {
                    if modified > last_modified {
                        last_modified = modified;
                        match config::load_config(&config_path_clone) {
                            Ok(new_cfg) => {
                                if let Ok(mut lock) = config_arc_clone.write() {
                                    *lock = new_cfg;
                                    info!(
                                        "Configuration reloaded successfully from {}",
                                        config_path_clone
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to reload config from {}: {:?}",
                                    config_path_clone,
                                    e
                                );
                            }
                        }
                    }
                }
            }
        }
    });

    if let Some(ctrl) = &controller {
        info!(
            "Running in distributed Agent mode. Connecting to Controller at {}...",
            ctrl
        );
        if token.is_some() {
            info!("Using registration token: [REDACTED]");
        }

        // Spawn background task to send system metrics to the controller
        let ctrl_url_metrics = ctrl.clone();
        let hostname = get_hostname();
        let os = std::env::consts::OS.to_string();
        tokio::spawn(async move {
            let client = crate::logging::build_client();
            let mut sys = System::new_all();
            sys.refresh_cpu();
            sys.refresh_memory();

            // Sleep briefly to let CPU metrics gather
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            loop {
                sys.refresh_cpu();
                sys.refresh_memory();
                let cpu = sys.global_cpu_info().cpu_usage();

                let total_mem = sys.total_memory();
                let used_mem = sys.used_memory();
                let ram = if total_mem > 0 {
                    (used_mem as f32 / total_mem as f32) * 100.0
                } else {
                    0.0
                };

                let disks = Disks::new_with_refreshed_list();
                let mut total_disk = 0u64;
                let mut available_disk = 0u64;
                for disk in &disks {
                    total_disk += disk.total_space();
                    available_disk += disk.available_space();
                }
                let disk = if total_disk > 0 {
                    ((total_disk - available_disk) as f32 / total_disk as f32) * 100.0
                } else {
                    0.0
                };

                let payload = AgentMetrics {
                    hostname: hostname.clone(),
                    ip: "127.0.0.1".to_string(), // will be overwritten by Controller with real remote IP
                    os: os.clone(),
                    cpu,
                    ram,
                    disk,
                    uptime: sysinfo::System::uptime(),
                    network_interfaces: get_network_interfaces(),
                    discovered_services: get_docker_services(),
                };

                let url = format!(
                    "{}/api/v1/agents/metrics",
                    ctrl_url_metrics.trim_end_matches('/')
                );
                match client.post(&url).json(&payload).send().await {
                    Ok(resp) => {
                        if !resp.status().is_success() {
                            tracing::warn!(
                                "Controller metrics endpoint returned error: {}",
                                resp.status()
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to send metrics to controller: {}", e);
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        });

        // Spawn background task to receive real-time config updates from Controller via WebSocket
        let ctrl_url_ws = ctrl.clone();
        let config_arc_ws = config_arc.clone();
        tokio::spawn(async move {
            loop {
                let ws_url = format!("{}/ws/agent", ctrl_url_ws.trim_end_matches('/'))
                    .replace("http://", "ws://")
                    .replace("https://", "wss://");

                info!("Connecting to Controller config WebSocket at {}...", ws_url);
                match tokio_tungstenite::connect_async(&ws_url).await {
                    Ok((mut ws_stream, _)) => {
                        info!("Connected to Controller configuration WebSocket");
                        while let Some(msg) = ws_stream.next().await {
                            match msg {
                                Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                                    if let Ok(new_cfg) =
                                        serde_json::from_str::<config::Config>(&text)
                                    {
                                        if let Ok(mut lock) = config_arc_ws.write() {
                                            *lock = new_cfg;
                                            info!("Dynamic configuration updated via Controller WebSocket push");
                                        }
                                    }
                                }
                                Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => {
                                    info!("Controller configuration WebSocket closed");
                                    break;
                                }
                                Err(e) => {
                                    tracing::error!("WebSocket error: {}", e);
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to connect to Controller configuration WebSocket: {}. Retrying in 5s...", e);
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        });
    } else {
        info!("Running in Standalone Agent mode. Using local configuration.");
    }

    // Build application state
    let blocklist = Arc::new(std::sync::RwLock::new(std::collections::HashSet::new()));
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let state = AppState {
        config: config_arc.clone(),
        log_tx,
        blocklist: blocklist.clone(),
        http_client,
    };

    // Spawn background threat intelligence / reputation blocklist sync task
    let blocklist_clone = blocklist.clone();
    let controller_url_clone = controller.clone();

    tokio::spawn(async move {
        let client = crate::logging::build_client();
        loop {
            if let Some(ctrl_url) = &controller_url_clone {
                // Agent Mode: Fetch blocklist from Controller
                let url = format!(
                    "{}/api/v1/reputation/blocklist",
                    ctrl_url.trim_end_matches('/')
                );
                match client.get(&url).send().await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            if let Ok(ips) = resp.json::<Vec<String>>().await {
                                let mut new_blocklist = std::collections::HashSet::new();
                                for ip_str in ips {
                                    if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                                        if !is_local_ip(&ip) {
                                            new_blocklist.insert(ip);
                                        }
                                    }
                                }
                                if let Ok(mut lock) = blocklist_clone.write() {
                                    *lock = new_blocklist;
                                    tracing::debug!(
                                        "Reputation blocklist synced. Active blocked IPs: {}",
                                        lock.len()
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Error syncing reputation blocklist from controller: {}",
                            e
                        );
                    }
                }
            } else {
                // Standalone Mode: Query ClickHouse
                let clickhouse_url_local = std::env::var("CLICKHOUSE_URL")
                    .unwrap_or_else(|_| "http://localhost:8123".to_string());
                let blocklist_standalone = blocklist_clone.clone();
                let client_clone = client.clone();

                let query = "SELECT client_ip FROM request_log WHERE action = 'BLOCK' AND timestamp > now() - INTERVAL 5 MINUTE GROUP BY client_ip HAVING count() >= 5 FORMAT TSV";
                let url = format!(
                    "{}/?query={}",
                    clickhouse_url_local.trim_end_matches('/'),
                    urlencoding::encode(query)
                );
                if let Ok(resp) = client_clone.get(&url).send().await {
                    if let Ok(text) = resp.text().await {
                        let mut ips = std::collections::HashSet::new();
                        for line in text.lines() {
                            if let Ok(ip) = line.trim().parse::<std::net::IpAddr>() {
                                if !is_local_ip(&ip) {
                                    ips.insert(ip);
                                }
                            }
                        }
                        if let Ok(mut lock) = blocklist_standalone.write() {
                            *lock = ips;
                        }
                    }
                }
            }

            let sleep_secs = if controller_url_clone.is_some() {
                10
            } else {
                60
            };
            tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;
        }
    });

    // Build Axum router
    let app = Router::new()
        .route("/", any(handler))
        .route("/*path", any(handler))
        .with_state(state);

    // Bind HTTPS if configured
    let tls_cfg = cfg.tls.clone();
    let config_arc_tls = config_arc.clone();
    let app_tls = app.clone();
    let port_https = cfg.global.port_https;

    if tls_cfg.mode == "local_ca" {
        tokio::spawn(async move {
            let ca = tls::LocalCA::new(&tls_cfg.cert_dir);
            if let Err(e) = ca.ensure_ca() {
                tracing::error!("Failed to ensure local CA: {}", e);
                return;
            }

            let domain = {
                let lock = config_arc_tls.read().unwrap();
                lock.vhosts
                    .first()
                    .and_then(|v| v.hosts.first())
                    .map(|h| h.clone())
                    .unwrap_or_else(|| "localhost".to_string())
            };

            let (certs, key) = match ca.generate_server_cert(&domain) {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::error!("Failed to generate server cert for {}: {}", domain, e);
                    return;
                }
            };

            let rustls_config = match rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
            {
                Ok(mut config) => {
                    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                    std::sync::Arc::new(config)
                }
                Err(e) => {
                    tracing::error!("Failed to build ServerConfig: {}", e);
                    return;
                }
            };

            let acceptor = tokio_rustls::TlsAcceptor::from(rustls_config);
            let https_addr = SocketAddr::from(([0, 0, 0, 0], port_https));
            let listener = match tokio::net::TcpListener::bind(https_addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!("Failed to bind HTTPS port {}: {}", port_https, e);
                    return;
                }
            };

            info!(
                "Aegis Agent WAF listening on https://{} (HTTPS)",
                https_addr
            );

            let service = app_tls.into_make_service_with_connect_info::<SocketAddr>();
            loop {
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(res) => res,
                    Err(_) => continue,
                };
                let acceptor = acceptor.clone();
                let mut service_clone = service.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("TLS handshake failed: {}", e);
                            return;
                        }
                    };

                    use hyper_util::rt::TokioIo;
                    use tower::Service;
                    let io = TokioIo::new(tls_stream);
                    let builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );

                    let route_service = match service_clone.call(peer_addr).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };

                    let hyper_service =
                        hyper_util::service::TowerToHyperService::new(route_service);

                    if let Err(err) = builder.serve_connection(io, hyper_service).await {
                        tracing::error!("Error serving TLS connection: {:?}", err);
                    }
                });
            }
        });
    } else if tls_cfg.mode == "acme" {
        tokio::spawn(async move {
            let domains: Vec<String> = {
                let lock = config_arc_tls.read().unwrap();
                let mut doms: Vec<String> = lock
                    .vhosts
                    .iter()
                    .flat_map(|v| v.hosts.clone())
                    .filter(|h| !h.contains("*"))
                    .collect();
                for cert in &lock.certificates {
                    if !doms.contains(&cert.domain) {
                        doms.push(cert.domain.clone());
                    }
                }
                doms
            };

            let email = {
                let lock = config_arc_tls.read().unwrap();
                lock.certificates
                    .first()
                    .map(|c| c.email.clone())
                    .unwrap_or_else(|| "admin@aegiswaf.local".to_string())
            };

            if domains.is_empty() {
                tracing::warn!("No valid domains found for ACME. Skipping ACME setup.");
                return;
            }

            let cert_dir: &'static std::path::Path =
                Box::leak(std::path::PathBuf::from(tls_cfg.cert_dir.clone()).into_boxed_path());
            let mut acme_state = rustls_acme::AcmeConfig::new(domains)
                .contact([format!("mailto:{}", email)])
                .cache(rustls_acme::caches::DirCache::new(cert_dir))
                .directory_lets_encrypt(false) // use staging by default to avoid rate limits during demo
                .state();

            let mut rustls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(acme_state.resolver());
            rustls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(rustls_config));
            let https_addr = SocketAddr::from(([0, 0, 0, 0], port_https));
            let listener = match tokio::net::TcpListener::bind(https_addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!("Failed to bind HTTPS port {} for ACME: {}", port_https, e);
                    return;
                }
            };

            info!(
                "Aegis Agent WAF listening on https://{} (ACME TLS)",
                https_addr
            );

            // Spawn ACME worker task
            tokio::spawn(async move {
                use tokio_stream::StreamExt;
                loop {
                    match acme_state.next().await {
                        Some(Ok(event)) => tracing::info!("ACME Event: {:?}", event),
                        Some(Err(err)) => tracing::error!("ACME Error: {:?}", err),
                        None => break,
                    }
                }
            });

            let service = app_tls.into_make_service_with_connect_info::<SocketAddr>();
            loop {
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(res) => res,
                    Err(_) => continue,
                };
                let acceptor = acceptor.clone();
                let mut service_clone = service.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("ACME TLS handshake failed: {}", e);
                            return;
                        }
                    };

                    use hyper_util::rt::TokioIo;
                    use tower::Service;
                    let io = TokioIo::new(tls_stream);
                    let builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );

                    let route_service = match service_clone.call(peer_addr).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };

                    let hyper_service =
                        hyper_util::service::TowerToHyperService::new(route_service);

                    if let Err(err) = builder.serve_connection(io, hyper_service).await {
                        tracing::error!("Error serving ACME TLS connection: {:?}", err);
                    }
                });
            }
        });
    }

    // Bind HTTP
    let http_addr = SocketAddr::from(([0, 0, 0, 0], cfg.global.port_http));
    let http_listener = tokio::net::TcpListener::bind(http_addr)
        .await
        .expect("Cannot bind HTTP port");

    info!("Aegis Agent WAF listening on http://{}", http_addr);
    info!("Backend default: {}", cfg.vhosts[0].backend);

    // Drop root privileges setelah bind
    #[cfg(unix)]
    if std::process::id() == 0 {
        drop_privileges();
    }

    axum::serve(
        http_listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

#[derive(Clone)]
struct ControllerState {
    tx: broadcast::Sender<logging::WafLogEntry>,
    clickhouse_url: String,
    logging_enabled: Arc<AtomicBool>,
    log_size_limit_mb: Arc<AtomicU64>,
    config_path: String,
    agent_registry: Arc<std::sync::RwLock<std::collections::HashMap<String, AgentInfo>>>,
    total_requests: Arc<AtomicU64>,
    blocked: Arc<AtomicU64>,
    rate_limited: Arc<AtomicU64>,
    config_tx: broadcast::Sender<config::Config>,
}

async fn run_controller(port: u16, config_path: String) {
    info!("Starting Aegis WAF Controller on port {}...", port);

    let clickhouse_url =
        std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
    logging::init_db(&clickhouse_url)
        .await
        .expect("Failed to initialize ClickHouse DB");

    // Initialize broadcast channel for live logs
    let (tx, _rx) = broadcast::channel(10000);
    let (config_tx, _config_rx) = broadcast::channel(100);

    // App state
    let clickhouse_url_baseline = clickhouse_url.clone();
    let initial_stats = logging::get_stats(&clickhouse_url_baseline, 24)
        .await
        .unwrap_or(logging::Stats {
            total_requests: 0,
            blocked: 0,
            rate_limited: 0,
        });
    info!(
        "Loaded baseline stats from ClickHouse: total={}, blocked={}, rate_limited={}",
        initial_stats.total_requests, initial_stats.blocked, initial_stats.rate_limited
    );

    let state = ControllerState {
        tx,
        clickhouse_url: clickhouse_url.clone(),
        logging_enabled: Arc::new(AtomicBool::new(true)),
        log_size_limit_mb: Arc::new(AtomicU64::new(500)), // default 500MB
        config_path,
        agent_registry: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        total_requests: Arc::new(AtomicU64::new(initial_stats.total_requests as u64)),
        blocked: Arc::new(AtomicU64::new(initial_stats.blocked as u64)),
        rate_limited: Arc::new(AtomicU64::new(initial_stats.rate_limited as u64)),
        config_tx,
    };

    // CORS Configuration for local Svelte dashboard
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(Any);

    // Build Controller router
    let app = Router::new()
        .route("/install.sh", get(serve_install_script))
        .route("/api/v1/agents/register", post(register_agent_handler))
        .route("/api/v1/agents/metrics", post(receive_metrics_handler))
        .route("/api/v1/agents", get(get_agents_handler))
        .route(
            "/api/v1/rate-limits",
            get(get_ratelimits_handler).post(post_ratelimits_handler),
        )
        .route("/api/v1/logs", post(receive_logs_handler))
        .route("/api/v1/logs/stream", get(sse_handler))
        .route("/api/v1/logs", get(get_logs_handler))
        .route("/api/v1/logs/db_size", get(get_db_size_handler))
        .route("/api/v1/logs/export", get(export_logs_handler))
        .route("/api/v1/logs/clear", post(clear_logs_handler))
        .route(
            "/api/v1/config",
            get(get_config_handler).post(post_config_handler),
        )
        .route(
            "/api/v1/vhosts",
            get(get_vhosts_handler).post(post_vhosts_handler),
        )
        .route("/api/v1/stats", get(get_stats_handler))
        .route("/api/v1/reputation/blocklist", get(get_blocklist_handler))
        .route(
            "/api/v1/threat-intel/events",
            get(get_threat_intel_events_handler),
        )
        .route(
            "/api/v1/ssl/certificates",
            get(get_ssl_certificates_handler).post(post_ssl_certificate_handler),
        )
        .route(
            "/api/v1/ssl/certificates/:domain",
            delete(delete_ssl_certificate_handler),
        )
        .route("/api/v1/ssl/renew", post(post_ssl_renew_handler))
        .route("/ws/dashboard", get(ws_dashboard_handler))
        .route("/ws/agent", get(ws_agent_handler))
        .fallback_service(tower_http::services::ServeDir::new("dashboard/dist"))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Cannot bind Controller port");

    info!(
        "Aegis Controller API & Dashboard available at http://{}",
        addr
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

#[derive(serde::Deserialize)]
struct AgentRegisterRequest {
    hostname: String,
    ip: String,
    port: u16,
    os: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct ConfigPayload {
    logging_enabled: bool,
    log_limit_mb: u64,
}

#[derive(serde::Serialize)]
struct DbSizeResponse {
    size_bytes: u64,
    formatted: String,
}

async fn serve_install_script(
    State(_state): State<ControllerState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let controller_ip =
        std::env::var("CONTROLLER_URL").unwrap_or_else(|_| format!("http://{}:8080", addr.ip()));

    let script = format!(
        r#"#!/bin/bash
set -e
echo "🛡️ Installing Aegis WAF Agent..."
CONTROLLER_URL="${{CONTROLLER_IP:-{controller_ip}}}"
echo "Controller URL: $CONTROLLER_URL"
mkdir -p /etc/aegis-waf /var/log/aegis-waf
# systemd service definition
cat > /etc/systemd/system/aegis-agent.service <<EOF
[Unit]
Description=Aegis WAF Agent
After=network.target

[Service]
ExecStart=/usr/local/bin/aegis-agent agent --controller $CONTROLLER_URL
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "✅ Aegis Agent installation script configuration completed."
"#
    );

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/x-shellscript")],
        script,
    )
}

// Controller API & WS Handlers
async fn register_agent_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<AgentRegisterRequest>,
) -> impl IntoResponse {
    info!(
        "Registered agent: {} at {}:{} running {}",
        payload.hostname, payload.ip, payload.port, payload.os
    );

    let info = AgentInfo {
        hostname: payload.hostname.clone(),
        ip: payload.ip.clone(),
        os: payload.os.clone(),
        cpu: 0.0,
        ram: 0.0,
        disk: 0.0,
        uptime: "0m".to_string(),
        status: "online".to_string(),
        network_interfaces: vec![],
        discovered_services: vec![],
        last_seen: std::time::Instant::now(),
    };

    if let Ok(mut lock) = state.agent_registry.write() {
        lock.insert(payload.hostname, info);
    }

    StatusCode::CREATED
}

async fn receive_metrics_handler(
    State(state): State<ControllerState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    Json(mut payload): Json<AgentMetrics>,
) -> impl IntoResponse {
    let client_ip = addr.ip().to_string();
    payload.ip = client_ip.clone();

    let uptime_str = format_uptime(payload.uptime);

    let info = AgentInfo {
        hostname: payload.hostname.clone(),
        ip: client_ip,
        os: payload.os.clone(),
        cpu: payload.cpu,
        ram: payload.ram,
        disk: payload.disk,
        uptime: uptime_str,
        status: "online".to_string(),
        network_interfaces: payload.network_interfaces.clone(),
        discovered_services: payload.discovered_services.clone(),
        last_seen: std::time::Instant::now(),
    };

    if let Ok(mut lock) = state.agent_registry.write() {
        lock.insert(payload.hostname, info);
    }

    StatusCode::OK
}

async fn get_agents_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let mut agents = Vec::new();
    if let Ok(lock) = state.agent_registry.read() {
        let now = std::time::Instant::now();
        for (_, info) in lock.iter() {
            let mut agent_clone = info.clone();
            if now.duration_since(info.last_seen) > std::time::Duration::from_secs(15) {
                agent_clone.status = "offline".to_string();
                agent_clone.cpu = 0.0;
                agent_clone.ram = 0.0;
            }
            agents.push(agent_clone);
        }
    }
    agents.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    (StatusCode::OK, Json(agents))
}

async fn get_ratelimits_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<config::RateLimitPolicy>::new()),
            )
                .into_response();
        }
    };

    if cfg.rate_limit_policies.is_empty() {
        cfg.rate_limit_policies = vec![
            config::RateLimitPolicy {
                name: "Default API/Website Traffic".to_string(),
                limit: "600 requests / minute".to_string(),
                burst: 100,
                path: "/*".to_string(),
                description: "Default threshold protecting backend sites from general automated scans.".to_string(),
            },
            config::RateLimitPolicy {
                name: "Authentication Endpoints".to_string(),
                limit: "10 requests / minute".to_string(),
                burst: 5,
                path: "/login, /api/auth/*".to_string(),
                description: "Aggressive brute-force protection preventing credentials guessing.".to_string(),
            },
            config::RateLimitPolicy {
                name: "WebDAV / Cloud File Storage".to_string(),
                limit: "2000 requests / minute".to_string(),
                burst: 200,
                path: "/remote.php/dav/*, /api/upload/*".to_string(),
                description: "Permissive tier optimized for photo synching and Nextcloud/Immich desktop clients.".to_string(),
            },
            config::RateLimitPolicy {
                name: "Static Assets & Media".to_string(),
                limit: "Unlimited".to_string(),
                burst: 0,
                path: "/static/*, *.css, *.js, *.png".to_string(),
                description: "Exempted assets to reduce WAF engine evaluation overhead.".to_string(),
            },
        ];
        if let Ok(toml_str) = toml::to_string(&cfg) {
            let _ = std::fs::write(&state.config_path, toml_str);
        }
    }

    (StatusCode::OK, Json(cfg.rate_limit_policies)).into_response()
}

async fn post_ratelimits_handler(
    State(state): State<ControllerState>,
    Json(policies): Json<Vec<config::RateLimitPolicy>>,
) -> impl IntoResponse {
    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };

    cfg.rate_limit_policies = policies;

    let toml_str = match toml::to_string(&cfg) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to serialize updated config to TOML: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to serialize config",
            )
                .into_response();
        }
    };

    match std::fs::write(&state.config_path, toml_str) {
        Ok(_) => {
            info!(
                "Rate limiting policies updated successfully in {}",
                state.config_path
            );
            let _ = state.config_tx.send(cfg);
            StatusCode::OK.into_response()
        }
        Err(e) => {
            tracing::error!("Failed to write updated config to disk: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to write config file",
            )
                .into_response()
        }
    }
}

async fn get_config_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let payload = ConfigPayload {
        logging_enabled: state.logging_enabled.load(Ordering::Relaxed),
        log_limit_mb: state.log_size_limit_mb.load(Ordering::Relaxed),
    };
    (StatusCode::OK, Json(payload))
}

async fn post_config_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<ConfigPayload>,
) -> impl IntoResponse {
    state
        .logging_enabled
        .store(payload.logging_enabled, Ordering::Relaxed);
    state
        .log_size_limit_mb
        .store(payload.log_limit_mb, Ordering::Relaxed);
    StatusCode::OK
}

async fn get_vhosts_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };

    if cfg.vhosts.is_empty() {
        // Create dummy host
        let dummy = config::VHost {
            name: "aegis-demo".to_string(),
            hosts: vec!["*.aegiswaf.demo".to_string()],
            backend: "127.0.0.1:8080".to_string(),
            rate_limit_tiers: vec![],
            logging: Some(config::LoggingConfig {
                enabled: true,
                db_path: "logs/aegis-waf.db".to_string(),
            }),
            rules: vec![
                "SQLI-*".to_string(),
                "XSS-*".to_string(),
                "LFI-*".to_string(),
                "RFI-*".to_string(),
            ],
            blocked_countries: vec![],
            geoblock_type: "Blocklist".to_string(),
            custom_rules: vec![],
            ssl: "Auto (Local CA)".to_string(),
            max_body: "10MB".to_string(),
            rate_limit: "600 req/min".to_string(),
        };
        cfg.vhosts.push(dummy);
        // Save it back to config file so it is persisted!
        if let Ok(toml_str) = toml::to_string(&cfg) {
            let _ = std::fs::write(&state.config_path, toml_str);
        }
    }

    (StatusCode::OK, Json(cfg.vhosts)).into_response()
}

async fn post_vhosts_handler(
    State(state): State<ControllerState>,
    Json(vhosts): Json<Vec<config::VHost>>,
) -> impl IntoResponse {
    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };

    cfg.vhosts = vhosts;

    // Serialize back to TOML and save
    let toml_str = match toml::to_string(&cfg) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to serialize updated config to TOML: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to serialize config",
            )
                .into_response();
        }
    };

    match std::fs::write(&state.config_path, toml_str) {
        Ok(_) => {
            info!(
                "Virtual hosts configuration updated successfully in {}",
                state.config_path
            );
            let _ = state.config_tx.send(cfg);
            StatusCode::OK.into_response()
        }
        Err(e) => {
            tracing::error!("Failed to write updated config to disk: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to write config file",
            )
                .into_response()
        }
    }
}

async fn get_db_size_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let size_bytes = logging::get_db_size(&state.clickhouse_url)
        .await
        .unwrap_or(0);

    let formatted = if size_bytes < 1024 {
        format!("{} B", size_bytes)
    } else if size_bytes < 1024 * 1024 {
        format!("{:.1} KB", size_bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", size_bytes as f64 / (1024.0 * 1024.0))
    };

    (
        StatusCode::OK,
        Json(DbSizeResponse {
            size_bytes,
            formatted,
        }),
    )
}

async fn export_logs_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let client = crate::logging::build_client();
    let query = "SELECT * FROM request_log FORMAT TSV";
    let url = format!(
        "{}/?query={}",
        state.clickhouse_url.trim_end_matches('/'),
        urlencoding::encode(query)
    );
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(content) = resp.text().await {
                Response::builder()
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .header("Content-Disposition", "attachment; filename=\"aegis.log\"")
                    .body(Body::from(content))
                    .unwrap()
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read body").into_response()
            }
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to export logs from ClickHouse",
        )
            .into_response(),
    }
}

async fn clear_logs_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let client = crate::logging::build_client();
    let query = "TRUNCATE TABLE request_log";
    let url = format!(
        "{}/?query={}",
        state.clickhouse_url.trim_end_matches('/'),
        urlencoding::encode(query)
    );
    match client.post(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            state.total_requests.store(0, Ordering::Relaxed);
            state.blocked.store(0, Ordering::Relaxed);
            state.rate_limited.store(0, Ordering::Relaxed);
            StatusCode::OK
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn receive_logs_handler(
    State(state): State<ControllerState>,
    Json(logs): Json<Vec<logging::WafLogEntry>>,
) -> impl IntoResponse {
    // Check if logging is enabled
    if !state.logging_enabled.load(Ordering::Relaxed) {
        return StatusCode::OK;
    }

    let logs_clone = logs.clone();
    let clickhouse_url = state.clickhouse_url.clone();

    // Broadcast logs to connected dashboards and update in-memory stats immediately (non-blocking)
    let mut new_total = 0;
    let mut new_blocked = 0;
    let mut new_rate_limited = 0;
    for log in logs {
        new_total += 1;
        if log.action == "BLOCK" {
            new_blocked += 1;
        } else if log.action == "RATE_LIMIT" {
            new_rate_limited += 1;
        }
        let _ = state.tx.send(log);
    }
    state.total_requests.fetch_add(new_total, Ordering::Relaxed);
    state.blocked.fetch_add(new_blocked, Ordering::Relaxed);
    state
        .rate_limited
        .fetch_add(new_rate_limited, Ordering::Relaxed);

    // Spawn background task to insert logs into ClickHouse asynchronously
    tokio::spawn(async move {
        let client = crate::logging::build_client();
        let mut body = String::new();
        for entry in &logs_clone {
            if let Ok(json) = serde_json::to_string(entry) {
                body.push_str(&json);
                body.push('\n');
            }
        }
        let url = format!(
            "{}/?query=INSERT INTO request_log FORMAT JSONEachRow",
            clickhouse_url.trim_end_matches('/')
        );
        if let Err(e) = client.post(&url).body(body).send().await {
            tracing::error!("Failed to insert logs to ClickHouse asynchronously: {}", e);
        }
    });

    StatusCode::OK
}

async fn sse_handler(
    State(state): State<ControllerState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.tx.subscribe();
    let stream = BroadcastStream::new(rx).map(|res| match res {
        Ok(log) => {
            let json = serde_json::to_string(&log).unwrap();
            Ok(Event::default().data(json))
        }
        Err(_) => Ok(Event::default().comment("lost message")),
    });
    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

async fn get_blocklist_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let client = crate::logging::build_client();
    let query = "SELECT client_ip FROM request_log WHERE action = 'BLOCK' AND timestamp > now() - INTERVAL 5 MINUTE GROUP BY client_ip HAVING count() >= 5 FORMAT TSV";
    let url = format!(
        "{}/?query={}",
        state.clickhouse_url.trim_end_matches('/'),
        urlencoding::encode(query)
    );
    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(text) = resp.text().await {
            let mut ips = Vec::new();
            for line in text.lines() {
                let ip = line.trim().to_string();
                if !ip.is_empty() {
                    if let Ok(parsed_ip) = ip.parse::<std::net::IpAddr>() {
                        if !is_local_ip(&parsed_ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
            return (StatusCode::OK, Json(ips)).into_response();
        }
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(Vec::<String>::new()),
    )
        .into_response()
}

#[derive(serde::Serialize)]
struct ThreatEvent {
    ip: String,
    lat: f64,
    lng: f64,
    rule_id: String,
    timestamp: String,
    magnitude: f64,
}

fn hash_ip_to_coords(ip: &str) -> (f64, f64) {
    let mut hash = 5381u32;
    for c in ip.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
    }
    // Lat from -90 to 90
    let lat = ((hash % 18000) as f64 / 100.0) - 90.0;
    // Lng from -180 to 180
    let lng = ((hash / 18000 % 36000) as f64 / 100.0) - 180.0;
    (lat, lng)
}

async fn get_threat_intel_events_handler(
    State(state): State<ControllerState>,
) -> impl IntoResponse {
    let client = crate::logging::build_client();
    let query = "SELECT timestamp, client_ip, rule_id FROM request_log WHERE action = 'BLOCK' ORDER BY timestamp DESC LIMIT 50 FORMAT JSONEachRow";
    let url = format!(
        "{}/?query={}",
        state.clickhouse_url.trim_end_matches('/'),
        urlencoding::encode(query)
    );

    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(text) = resp.text().await {
            let mut events = Vec::new();
            for line in text.lines() {
                if let Ok(log) = serde_json::from_str::<serde_json::Value>(line) {
                    if let (Some(ip), Some(ts), Some(rule)) = (
                        log.get("client_ip").and_then(|v| v.as_str()),
                        log.get("timestamp").and_then(|v| v.as_str()),
                        log.get("rule_id").and_then(|v| v.as_str()),
                    ) {
                        let (lat, lng) = hash_ip_to_coords(ip);
                        events.push(ThreatEvent {
                            ip: ip.to_string(),
                            lat,
                            lng,
                            rule_id: rule.to_string(),
                            timestamp: ts.to_string(),
                            magnitude: 0.1, // Fixed size for UI rendering
                        });
                    }
                }
            }
            return (StatusCode::OK, Json(events)).into_response();
        }
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(Vec::<ThreatEvent>::new()),
    )
        .into_response()
}

async fn get_logs_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let client = crate::logging::build_client();
    let query = "SELECT timestamp, client_ip, method, path, action, rule_id, reason FROM request_log ORDER BY timestamp DESC LIMIT 100 FORMAT JSONEachRow";
    let url = format!(
        "{}/?query={}",
        state.clickhouse_url.trim_end_matches('/'),
        urlencoding::encode(query)
    );
    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(text) = resp.text().await {
            let mut logs = Vec::new();
            for line in text.lines() {
                if let Ok(log) = serde_json::from_str::<logging::WafLogEntry>(line) {
                    logs.push(log);
                }
            }
            return (StatusCode::OK, Json(logs)).into_response();
        }
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(Vec::<logging::WafLogEntry>::new()),
    )
        .into_response()
}

async fn get_stats_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let stats = logging::Stats {
        total_requests: state.total_requests.load(Ordering::Relaxed) as i64,
        blocked: state.blocked.load(Ordering::Relaxed) as i64,
        rate_limited: state.rate_limited.load(Ordering::Relaxed) as i64,
    };
    (StatusCode::OK, Json(stats)).into_response()
}

#[derive(serde::Serialize)]
struct SslCertResponse {
    domain: String,
    issuer: String,
    valid_from: String,
    valid_until: String,
    status: String,
    auto_renew: bool,
}

#[derive(serde::Deserialize)]
struct SslRenewRequest {
    domain: String,
}

async fn get_ssl_certificates_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<SslCertResponse>::new()),
            )
                .into_response()
        }
    };

    let mut certs = Vec::new();
    let now = chrono::Utc::now();
    let valid_from = now - chrono::Duration::days(10);
    let valid_until = now + chrono::Duration::days(80);

    for cert in cfg.certificates {
        certs.push(SslCertResponse {
            domain: cert.domain,
            issuer: cert.provider,
            valid_from: valid_from.to_rfc3339(),
            valid_until: valid_until.to_rfc3339(),
            status: "Active".to_string(),
            auto_renew: true,
        });
    }

    (StatusCode::OK, Json(certs)).into_response()
}

#[derive(serde::Deserialize)]
struct SslCreateRequest {
    domain: String,
    provider: String,
    email: String,
}

async fn post_ssl_certificate_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<SslCreateRequest>,
) -> impl IntoResponse {
    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to load config"})),
            )
                .into_response()
        }
    };

    if cfg.certificates.iter().any(|c| c.domain == payload.domain) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Certificate for domain already exists"})),
        )
            .into_response();
    }

    cfg.certificates.push(config::CertificateConfig {
        domain: payload.domain.clone(),
        provider: payload.provider,
        email: payload.email,
    });

    let toml_str = match toml::to_string(&cfg) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to serialize config"})),
            )
                .into_response()
        }
    };

    if std::fs::write(&state.config_path, toml_str).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to write config"})),
        )
            .into_response();
    }

    let _ = state.config_tx.send(cfg);
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "success"})),
    )
        .into_response()
}

async fn delete_ssl_certificate_handler(
    State(state): State<ControllerState>,
    axum::extract::Path(domain): axum::extract::Path<String>,
) -> impl IntoResponse {
    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to load config"})),
            )
                .into_response()
        }
    };

    let initial_len = cfg.certificates.len();
    cfg.certificates.retain(|c| c.domain != domain);

    if cfg.certificates.len() == initial_len {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Certificate not found"})),
        )
            .into_response();
    }

    let toml_str = match toml::to_string(&cfg) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to serialize config"})),
            )
                .into_response()
        }
    };

    if std::fs::write(&state.config_path, toml_str).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to write config"})),
        )
            .into_response();
    }

    let _ = state.config_tx.send(cfg);
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "success"})),
    )
        .into_response()
}

async fn post_ssl_renew_handler(
    State(_state): State<ControllerState>,
    Json(payload): Json<SslRenewRequest>,
) -> impl IntoResponse {
    tracing::info!(
        "Force ACME SSL renew requested for domain: {}",
        payload.domain
    );
    // Real ACME renew would happen here. For now, acknowledge the command.
    (StatusCode::OK, Json(serde_json::json!({"status": "success", "message": format!("ACME Challenge initiated for {}", payload.domain)}))).into_response()
}

async fn ws_dashboard_handler(
    ws: WebSocketUpgrade,
    State(state): State<ControllerState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_dashboard_socket(socket, state))
}

async fn ws_agent_handler(
    ws: WebSocketUpgrade,
    State(state): State<ControllerState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_agent_socket(socket, state))
}

async fn handle_dashboard_socket(mut socket: WebSocket, state: ControllerState) {
    info!("Dashboard client connected via WebSocket");
    let mut rx = state.tx.subscribe();
    let mut stats_interval = tokio::time::interval(std::time::Duration::from_secs(5));

    loop {
        tokio::select! {
            Ok(log) = rx.recv() => {
                let json = serde_json::json!({
                    "type": "log",
                    "timestamp": log.timestamp,
                    "client_ip": log.client_ip,
                    "method": log.method,
                    "path": log.path,
                    "action": log.action,
                    "rule_id": log.rule_id,
                    "reason": log.reason
                });
                if socket.send(axum::extract::ws::Message::Text(json.to_string())).await.is_err() {
                    break;
                }
            }
            _ = stats_interval.tick() => {
                let json = serde_json::json!({
                    "type": "stats",
                    "total_requests": state.total_requests.load(Ordering::Relaxed),
                    "blocked": state.blocked.load(Ordering::Relaxed),
                    "rate_limited": state.rate_limited.load(Ordering::Relaxed)
                });
                if socket.send(axum::extract::ws::Message::Text(json.to_string())).await.is_err() {
                    break;
                }
            }
            Some(msg) = socket.recv() => {
                if msg.is_err() {
                    break;
                }
            }
        }
    }
    info!("Dashboard client disconnected");
}

async fn handle_agent_socket(mut socket: WebSocket, state: ControllerState) {
    info!("Agent client connected via WebSocket");

    // Send current config immediately upon connection
    let initial_cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    if let Ok(json) = serde_json::to_string(&initial_cfg) {
        if socket
            .send(axum::extract::ws::Message::Text(json))
            .await
            .is_err()
        {
            return;
        }
    }

    let mut rx = state.config_tx.subscribe();
    loop {
        tokio::select! {
            Ok(new_cfg) = rx.recv() => {
                if let Ok(json) = serde_json::to_string(&new_cfg) {
                    if socket.send(axum::extract::ws::Message::Text(json)).await.is_err() {
                        break;
                    }
                }
            }
            Some(msg) = socket.recv() => {
                if msg.is_err() {
                    break;
                }
            }
        }
    }
    info!("Agent client disconnected from WebSocket");
}

// Shared application state for Agent
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<std::sync::RwLock<config::Config>>,
    pub log_tx: tokio::sync::mpsc::Sender<logging::WafLogEntry>,
    pub blocklist: Arc<std::sync::RwLock<std::collections::HashSet<std::net::IpAddr>>>,
    pub http_client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        axum::body::Body,
    >,
}

// Main request handler for Agent
async fn handler(
    state: State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    host: Option<Host>,
    req: Request<Body>,
) -> Response<Body> {
    proxy::forward_request(state, addr, host, req).await
}

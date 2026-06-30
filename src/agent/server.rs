use crate::{config, logging, proxy_engine};
use std::sync::Arc;
use tracing::{error, info, warn};

#[cfg(unix)]
use pingora::server::Server;
use pingora_proxy::http_proxy_service;

// Shared application state for Agent
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<std::sync::RwLock<config::Config>>,
    pub log_tx: tokio::sync::mpsc::Sender<logging::WafLogEntry>,
    pub blocklist: Arc<std::sync::RwLock<std::collections::HashSet<std::net::IpAddr>>>,
}

#[cfg(unix)]
pub async fn run_server(cfg: &config::Config, state: AppState) {
    info!("Starting Pingora Proxy Engine...");

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    // Create our proxy instance
    let proxy = proxy_engine::JarsWafProxy {
        blocklist: state.blocklist.clone(),
        log_tx: state.log_tx.clone(),
    };

    // Store config in ArcSwap for lock-free reads in Pingora
    proxy_engine::GLOBAL_CONFIG.store(Arc::new(cfg.clone()));

    let mut proxy_service = http_proxy_service(&server.configuration, proxy);

    // Bind HTTP
    let http_addr = format!("0.0.0.0:{}", cfg.global.port_http);
    info!(
        "jarsWAF Agent Pingora proxy listening on http://{}",
        http_addr
    );
    proxy_service.add_tcp(&http_addr);

    // Add Pingora TLS (HTTPS) support if configured
    if cfg.tls.mode != "disabled" {
        let ca = crate::tls::LocalCA::new(&cfg.tls.cert_dir);
        if let Err(e) = ca.ensure_ca() {
            error!("Failed to ensure Local CA: {:?}", e);
        } else {
            let mut domains = vec!["localhost".to_string(), "127.0.0.1".to_string()];
            for vhost in &cfg.vhosts {
                for host in &vhost.hosts {
                    domains.push(host.clone());
                }
            }

            let cert_path = format!("{}/jarswaf.crt", cfg.tls.cert_dir);
            let key_path = format!("{}/jarswaf.key", cfg.tls.cert_dir);

            if let Err(e) = ca.generate_and_save_pem(domains, &cert_path, &key_path) {
                error!("Failed to generate server certificate: {:?}", e);
            } else {
                let https_addr = format!("0.0.0.0:{}", cfg.global.port_https);
                info!(
                    "jarsWAF Agent Pingora proxy listening on https://{}",
                    https_addr
                );
                // Bind TLS
                let cert_path_str: &str = &cert_path;
                let key_path_str: &str = &key_path;
                if let Err(e) = proxy_service.add_tls(&https_addr, cert_path_str, key_path_str) {
                    error!("Failed to bind TLS listener: {:?}", e);
                }
            }
        }
    }

    server.add_service(proxy_service);

    if std::process::id() == 0 {
        if let Err(e) = nix::unistd::setgid(nix::unistd::Gid::from_raw(65534)) {
            warn!("Failed to setgid: {}", e);
        }
        if let Err(e) = nix::unistd::setuid(nix::unistd::Uid::from_raw(65534)) {
            warn!("Failed to setuid: {}", e);
        }
    }

    // Pingora run_forever blocks the thread. We use spawn_blocking or just block.
    // Since we are in a tokio async fn, running a blocking loop is bad.
    // However, Pingora uses its own async runtime internally. We can run it in a blocking task.
    tokio::task::spawn_blocking(move || {
        server.run_forever();
    })
    .await
    .unwrap();
}

#[cfg(not(unix))]
pub async fn run_server(_cfg: &config::Config, _state: AppState) {
    error!("Pingora proxy engine is only supported on Unix systems (Linux/macOS).");
    error!("Please compile and run jarsWAF on WSL or a native Linux environment.");
    std::process::exit(1);
}

pub mod blocklist;
pub mod discovery;
pub mod metrics;
pub mod server;
pub mod websocket;

use crate::{config, logging, proxy_engine, rules};
pub use server::AppState;
use std::sync::Arc;
use tracing::info;

pub async fn run_agent(config_path: &str, controller: Option<String>, token: Option<String>) {
    // Load config
    let cfg = config::load_config(config_path).expect("Failed to load config");
    let config_arc = Arc::new(std::sync::RwLock::new(cfg.clone()));

    // Start background memory cleanup for rate limiter & reputation counters
    rules::start_rate_limiter_cleanup();

    // Attach eBPF XDP if an interface is configured
    if let Some(interface) = &cfg.global.xdp_interface {
        info!("Attaching eBPF XDP to interface: {}", interface);
        let mut xdp = crate::XDP_MANAGER.lock().await;
        if let Err(e) = xdp.attach(interface) {
            tracing::error!("Failed to attach eBPF XDP: {}", e);
        }
    }

    // Attach RASP Monitor (eBPF Kernel Monitor)
    {
        info!("Starting RASP Agent (eBPF Kernel Monitor)...");
        let (rasp_tx, mut rasp_rx) = tokio::sync::mpsc::channel::<()>(100);
        let mut xdp = crate::XDP_MANAGER.lock().await;
        if let Err(e) = xdp.attach_rasp(Some(rasp_tx)) {
            tracing::error!("Failed to attach RASP eBPF: {}", e);
        }

        tokio::spawn(async move {
            while rasp_rx.recv().await.is_some() {
                tracing::warn!("RASP Alert received! Flushing suspicious IPs to blocklist!");
                crate::proxy_engine::flush_suspicious_ips_to_blocklist().await;
            }
        });
    }

    // Initialize Gossip Protocol
    if cfg.gossip.enabled {
        info!("Starting Gossip protocol on {}", cfg.gossip.bind_addr);
        let mut gossip = crate::gossip::GossipNode::new(cfg.gossip.clone());
        gossip.set_handler(Arc::new(rules::WafGossipHandler));

        if let Err(e) = gossip.start().await {
            tracing::error!("Failed to start Gossip node: {}", e);
        } else {
            *crate::GOSSIP_MANAGER.lock().await = Some(gossip);
        }
    }

    // Determine logging mode from config
    let log_mode = cfg.logging.mode.clone();
    // Initialize SQLite database
    if log_mode == "sqlite" || log_mode == "clickhouse" {
        if let Err(e) = logging::init_sqlite_db(&cfg.logging.db_path) {
            tracing::error!("Failed to initialize SQLite database: {}", e);
        }
    }

    // Initialize MPSC Channel for logs
    let (log_tx, log_rx) = tokio::sync::mpsc::channel::<logging::WafLogEntry>(10000);

    // Build LogWorkerConfig from config.toml settings
    let worker_cfg = logging::LogWorkerConfig {
        mode: log_mode.clone(),
        log_path: cfg.logging.log_path.clone(),
        max_log_size_mb: cfg.logging.max_log_size_mb,
        max_log_files: cfg.logging.max_log_files,
        db_path: cfg.logging.db_path.clone(),
        controller_url: controller.clone(),
        remote_url: cfg.logging.remote_url.clone(),
        push_interval_secs: cfg.logging.push_interval_secs,
        push_batch_size: cfg.logging.push_batch_size,
        token: token.clone(),
    };

    // Spawn Background Log Worker (mode-aware)
    tokio::spawn(async move {
        logging::log_worker(log_rx, worker_cfg).await;
    });

    // Spawn background config reloader
    let config_path_clone = config_path.to_string();
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
                                // Atomic update via ArcSwap — no RwLock race window
                                crate::proxy_engine::GLOBAL_CONFIG.store(Arc::new(new_cfg));
                                info!(
                                    "Configuration reloaded successfully from {}",
                                    config_path_clone
                                );
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

    if cfg.global.mode == "agent" && cfg.global.manager_url.is_some() {
        let grpc_config = Arc::new(cfg.clone());
        tokio::spawn(async move {
            crate::grpc::client::run_agent_client(grpc_config).await;
        });
    }

    // Build application state — load blocklist from file
    let initial_blocklist = {
        let loaded = logging::load_blocklist_from_file(&cfg.logging.blocklist_path);
        let blocklist = dashmap::DashMap::new();
        if !loaded.is_empty() {
            info!(
                "Loaded {} blocked IPs from {}",
                loaded.len(),
                cfg.logging.blocklist_path
            );
            let mut xdp = crate::XDP_MANAGER.lock().await;
            for ip in loaded {
                blocklist.insert(
                    ip,
                    std::time::Instant::now() + std::time::Duration::from_secs(31536000),
                );
                if let std::net::IpAddr::V4(ipv4) = ip {
                    let _ = xdp.block_ip(ipv4);
                }
            }
        }
        blocklist
    };

    let blocklist = Arc::new(initial_blocklist);

    // Spawn background sweeper for expired blocklist entries
    let sweeper_blocklist = blocklist.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = std::time::Instant::now();

            // Clean up blocklist
            let mut expired_ips = Vec::new();
            for entry in sweeper_blocklist.iter() {
                if now > *entry.value() {
                    expired_ips.push(*entry.key());
                }
            }
            for ip in expired_ips {
                sweeper_blocklist.remove(&ip);
                if let std::net::IpAddr::V4(ipv4) = ip {
                    let mut xdp = crate::XDP_MANAGER.lock().await;
                    let _ = xdp.unblock_ip(ipv4);
                }
                tracing::info!("Unblocked IP {} after duration expired", ip);
            }
        }
    });
    let state = AppState {
        config: config_arc.clone(),
        log_tx,
        blocklist: blocklist.clone(),
    };

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
        let token_metrics = token.clone();
        tokio::spawn(async move {
            metrics::start_metrics_collector(ctrl_url_metrics, token_metrics).await;
        });

        // Spawn background task to receive real-time config updates from Controller via WebSocket
        let ctrl_url_ws = ctrl.clone();
        let config_arc_ws = config_arc.clone();
        let token_ws = token.clone();
        let blocklist_ws = blocklist.clone();
        tokio::spawn(async move {
            websocket::start_config_sync_websocket(
                ctrl_url_ws,
                token_ws,
                config_arc_ws,
                Some(blocklist_ws),
            )
            .await;
        });
    } else {
        info!("Running in Standalone Agent mode. Using local configuration.");
    }

    // Print active mode summary
    info!("──────────────────────────────────────────");
    info!("  jarsWAF Agent Configuration Summary");
    info!("  Logging mode:      {}", log_mode);
    info!("  Log file:          {}", cfg.logging.log_path);
    info!(
        "  SQLite Database:   {}",
        if log_mode == "sqlite" || log_mode == "clickhouse" {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    info!(
        "  Service Discovery: {}",
        if cfg.components.service_discovery {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    info!(
        "  GeoIP:             {}",
        if cfg.components.geoip {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    info!("──────────────────────────────────────────");

    // Spawn background threat intelligence / reputation blocklist sync task
    let blocklist_clone = blocklist.clone();
    let controller_url_clone = controller.clone();
    let token_blocklist = token.clone();
    let blocklist_file_path = cfg.logging.blocklist_path.clone();
    let use_sqlite = log_mode == "sqlite" || log_mode == "clickhouse";
    let db_path_local = cfg.logging.db_path.clone();

    tokio::spawn(async move {
        blocklist::start_blocklist_sync(
            controller_url_clone,
            token_blocklist,
            blocklist_clone,
            blocklist_file_path,
            use_sqlite,
            db_path_local,
        )
        .await;
    });

    // Spawn Public Threat Intelligence Fetcher
    let threat_blocklist = blocklist.clone();
    tokio::spawn(async move {
        // Fetch immediately on startup
        let ips = rules::threat_intel::fetch_threat_intel_ips().await;
        for ip in ips {
            threat_blocklist.insert(
                ip,
                std::time::Instant::now() + std::time::Duration::from_secs(86400),
            );
            if let std::net::IpAddr::V4(ipv4) = ip {
                let mut xdp = crate::XDP_MANAGER.lock().await;
                let _ = xdp.block_ip(ipv4);
            }
        }

        // Then fetch periodically every 24 hours
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(86400));
        loop {
            interval.tick().await;
            let ips = rules::threat_intel::fetch_threat_intel_ips().await;
            for ip in ips {
                threat_blocklist.insert(
                    ip,
                    std::time::Instant::now() + std::time::Duration::from_secs(86400),
                );
                if let std::net::IpAddr::V4(ipv4) = ip {
                    let mut xdp = crate::XDP_MANAGER.lock().await;
                    let _ = xdp.block_ip(ipv4);
                }
            }
        }
    });

    // Start periodic memory cleanup (clears global DashMaps every 30 min)
    proxy_engine::start_memory_cleanup();

    // Spawn metric push task if a push endpoint is configured
    if let Some(ref push_url) = cfg.global.metrics_push_url {
        let url = push_url.clone();
        let interval = cfg.global.metrics_push_interval_secs;
        tokio::spawn(async move {
            crate::metrics::start_metrics_pusher(url, interval).await;
        });
    }

    // Run Axum web server
    server::run_server(&cfg, state).await;
}

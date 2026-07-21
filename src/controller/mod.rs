pub mod auth;
pub mod handlers;
pub mod state;
pub mod websocket;

use crate::{config, logging};
use axum::{
    routing::{delete, get, post},
    Router,
};
pub use state::ControllerState;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

/// Command types pushed from Controller → Agent via WebSocket
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct BlockCommand {
    pub action: String, // "block" | "unblock" | "sync"
    pub ip: String,
    pub ttl: Option<u64>, // seconds, None = permanent
    pub reason: Option<String>,
}

pub async fn run_controller(port: u16, config_path: String) {
    // Ensure admin token is generated if not exists
    if let Ok(mut cfg) = config::load_config(&config_path) {
        let has_token = match &cfg.global.admin_token {
            Some(t) => !t.trim().is_empty(),
            None => false,
        };

        if !has_token {
            let generated = uuid::Uuid::new_v4().simple().to_string();
            cfg.global.admin_token = Some(generated.clone());
            if config::save_config(&config_path, &cfg).is_ok() {
                println!("\n\n");
                println!(
                    "========================================================================"
                );
                println!("                   jarsWAF - SECURITY INITIALIZATION                  ");
                println!(
                    "========================================================================"
                );
                println!("  A secure random administrator token has been generated for you:");
                println!("  ");
                println!("  Admin Token:  \x1b[1;33m{}\x1b[0m", generated);
                println!("  ");
                println!(
                    "  IMPORTANT: Please copy and save this key in a safe place (e.g., Notepad)."
                );
                println!("  It is used to access the dashboard and register agents.");
                println!("  This token will NOT be shown again.");
                println!(
                    "========================================================================"
                );
                println!("\n\n");
            }
        }
    }

    let cfg = config::load_config(&config_path).expect("Failed to load config");
    let db_path = cfg.logging.db_path.clone();
    logging::init_sqlite_db(&db_path).expect("Failed to initialize SQLite DB");
    handlers::start_threat_intel_scraper(db_path.clone());

    let grpc_token = cfg
        .global
        .grpc_token
        .clone()
        .unwrap_or_else(|| "default_token".to_string());
    tokio::spawn(async move {
        if let Err(e) = crate::grpc::server::run_manager_server(9000, grpc_token).await {
            tracing::error!("gRPC Manager Server error: {}", e);
        }
    });

    // Initialize broadcast channel for live logs
    let (tx, _rx) = broadcast::channel(10000);
    let (config_tx, _config_rx) = broadcast::channel(100);
    // Channel for real-time block commands pushed to agents
    let (block_tx, _block_rx) = broadcast::channel(1000);

    // App state
    let initial_stats = logging::sqlite_get_stats(&db_path, 24).unwrap_or(logging::Stats {
        total_requests: 0,
        blocked: 0,
        rate_limited: 0,
    });
    info!(
        "Loaded baseline stats from SQLite: total={}, blocked={}, rate_limited={}",
        initial_stats.total_requests, initial_stats.blocked, initial_stats.rate_limited
    );

    let state = ControllerState {
        tx,
        block_tx,
        db_path,
        logging_enabled: Arc::new(AtomicBool::new(true)),
        log_size_limit_mb: Arc::new(AtomicU64::new(500)), // default 500MB
        config_path,
        agent_registry: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        total_requests: Arc::new(AtomicU64::new(initial_stats.total_requests as u64)),
        blocked: Arc::new(AtomicU64::new(initial_stats.blocked as u64)),
        rate_limited: Arc::new(AtomicU64::new(initial_stats.rate_limited as u64)),
        config_tx,
        config_lock: Arc::new(tokio::sync::Mutex::new(())),
    };

    // CORS Configuration for local Svelte dashboard
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(Any);

    // Build Controller router
    let api_routes = Router::new()
        .route(
            "/api/v1/agents/register",
            post(handlers::register_agent_handler),
        )
        .route(
            "/api/v1/agents/metrics",
            post(handlers::receive_metrics_handler),
        )
        .route("/api/v1/agents/sync", post(handlers::sync_agent_handler))
        .route("/api/v1/agents", get(handlers::get_agents_handler))
        .route(
            "/api/v1/rate-limits",
            get(handlers::get_ratelimits_handler).post(handlers::post_ratelimits_handler),
        )
        .route("/api/v1/logs", post(handlers::receive_logs_handler))
        .route("/api/v1/logs/stream", get(handlers::sse_handler))
        .route("/api/v1/logs", get(handlers::get_logs_handler))
        .route("/api/v1/logs/db_size", get(handlers::get_db_size_handler))
        .route("/api/v1/logs/export", get(handlers::export_logs_handler))
        .route("/api/v1/logs/clear", post(handlers::clear_logs_handler))
        .route(
            "/api/v1/config",
            get(handlers::get_config_handler).post(handlers::post_config_handler),
        )
        .route(
            "/api/v1/config/poll",
            get(handlers::get_config_poll_handler),
        )
        .route(
            "/api/v1/config/history",
            get(handlers::get_config_history_handler),
        )
        .route("/api/v1/redteam", get(handlers::redteam_lab))
        .route(
            "/api/v1/config/rollback",
            post(handlers::post_config_rollback_handler),
        )
        .route(
            "/api/v1/vhosts",
            get(handlers::get_vhosts_handler).post(handlers::post_vhosts_handler),
        )
        .route(
            "/api/v1/custom-rules",
            get(handlers::get_custom_rules_handler).post(handlers::post_custom_rules_handler),
        )
        .route(
            "/api/v1/allowlists",
            get(handlers::get_allowlists_handler).post(handlers::post_allowlists_handler),
        )
        .route(
            "/api/v1/blacklists",
            get(handlers::get_blacklists_handler).post(handlers::post_blacklists_handler),
        )
        .route("/api/v1/stats", get(handlers::get_stats_handler))
        .route(
            "/api/v1/reputation/blocklist",
            get(handlers::get_blocklist_handler),
        )
        .route(
            "/api/v1/threat-intel/events",
            get(handlers::get_threat_intel_events_handler),
        )
        .route(
            "/api/v1/agent/block",
            post(handlers::post_agent_block_handler),
        )
        .route(
            "/api/v1/learning/retrain",
            post(handlers::post_retrain_handler),
        )
        .route(
            "/api/v1/rasp/telemetry",
            post(handlers::receive_rasp_telemetry_handler),
        )
        .route(
            "/api/v1/rasp/block",
            post(handlers::receive_rasp_block_handler),
        )
        .route(
            "/api/v1/compliance/report",
            get(handlers::get_compliance_report_handler),
        )
        .route(
            "/api/v1/ssl/certificates",
            get(handlers::get_ssl_certificates_handler)
                .post(handlers::post_ssl_certificate_handler),
        )
        .route(
            "/api/v1/ssl/certificates/:domain",
            delete(handlers::delete_ssl_certificate_handler),
        )
        .route("/api/v1/ssl/renew", post(handlers::post_ssl_renew_handler))
        .route("/ws/dashboard", get(websocket::ws_dashboard_handler))
        .route("/ws/agent", get(websocket::ws_agent_handler))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    let app = Router::new()
        .route("/install.sh", get(handlers::serve_install_script))
        .route("/metrics", get(handlers::get_metrics_handler))
        .merge(api_routes)
        .fallback_service(tower_http::services::ServeDir::new("dashboard/dist"))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Cannot bind Controller port");

    info!(
        "jarsWAF Controller API & Dashboard available at http://{}",
        addr
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

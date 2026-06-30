use super::super::state::ControllerState;
use crate::config;
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::atomic::Ordering;
use tracing::error;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ConfigPayload {
    pub logging_enabled: bool,
    pub log_limit_mb: u64,
    pub waf_enabled: bool,
}

pub async fn get_config_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };
    let payload = ConfigPayload {
        logging_enabled: state.logging_enabled.load(Ordering::Relaxed),
        log_limit_mb: state.log_size_limit_mb.load(Ordering::Relaxed),
        waf_enabled: cfg.global.waf_enabled,
    };
    (StatusCode::OK, Json(payload)).into_response()
}

pub async fn post_config_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<ConfigPayload>,
) -> impl IntoResponse {
    let _lock = state.config_lock.lock().await;

    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };

    cfg.global.waf_enabled = payload.waf_enabled;

    if let Err(e) = config::save_config(&state.config_path, &cfg) {
        error!("Failed to write updated config to disk: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to write config file",
        )
            .into_response();
    }

    // Update in-memory atomics
    state
        .logging_enabled
        .store(payload.logging_enabled, Ordering::Relaxed);
    state
        .log_size_limit_mb
        .store(payload.log_limit_mb, Ordering::Relaxed);

    // Broadcast updated config to all agents via config_tx
    let _ = state.config_tx.send(cfg);

    StatusCode::OK.into_response()
}

#[derive(serde::Serialize)]
pub struct BackupEntry {
    pub filename: String,
    pub timestamp: String,
    pub size: u64,
}

pub async fn get_config_history_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let parent = std::path::Path::new(&state.config_path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let backups_dir = parent.join("config_backups");

    let mut backups = Vec::new();
    if let Ok(entries) = std::fs::read_dir(backups_dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file() {
                let filename = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if filename.starts_with("config_") && filename.ends_with(".toml") {
                    let metadata = entry.metadata();
                    let size = metadata.map(|m| m.len()).unwrap_or(0);
                    let timestamp = filename
                        .trim_start_matches("config_")
                        .trim_end_matches(".toml")
                        .to_string();

                    backups.push(BackupEntry {
                        filename,
                        timestamp,
                        size,
                    });
                }
            }
        }
    }

    // Sort descending by timestamp (newest first)
    backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    (StatusCode::OK, Json(backups)).into_response()
}

#[derive(serde::Deserialize)]
pub struct RollbackPayload {
    pub filename: String,
}

pub async fn post_config_rollback_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<RollbackPayload>,
) -> impl IntoResponse {
    let _lock = state.config_lock.lock().await;

    let parent = std::path::Path::new(&state.config_path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let backup_path = parent.join("config_backups").join(&payload.filename);

    if !backup_path.exists() {
        return (StatusCode::NOT_FOUND, "Backup file not found").into_response();
    }

    // Copy backup back to config path
    if let Err(e) = std::fs::copy(&backup_path, &state.config_path) {
        error!("Failed to restore config from {:?}: {:?}", backup_path, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to restore config file",
        )
            .into_response();
    }

    // Reload configuration
    let cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to reload config after rollback: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load restored config",
            )
                .into_response();
        }
    };

    // Update in-memory atomics (derive from config fields)
    state
        .logging_enabled
        .store(cfg.logging.mode != "disabled", Ordering::Relaxed);
    state
        .log_size_limit_mb
        .store(cfg.logging.max_log_size_mb, Ordering::Relaxed);

    // Broadcast updated config to all agents via config_tx
    let _ = state.config_tx.send(cfg);

    StatusCode::OK.into_response()
}

pub async fn serve_install_script(
    State(_state): State<ControllerState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
) -> impl IntoResponse {
    let controller_ip =
        std::env::var("CONTROLLER_URL").unwrap_or_else(|_| format!("http://{}:8080", addr.ip()));

    let script = format!(
        r#"#!/bin/bash
set -e
echo "🛡️ Installing jarsWAF Agent..."
CONTROLLER_URL="${{CONTROLLER_IP:-{controller_ip}}}"
echo "Controller URL: $CONTROLLER_URL"
mkdir -p /etc/jarswaf /var/log/jarswaf
# systemd service definition
cat > /etc/systemd/system/jarswaf-agent.service <<EOF
[Unit]
Description=jarsWAF Agent
After=network.target

[Service]
ExecStart=/usr/local/bin/jarswaf-agent agent --controller $CONTROLLER_URL
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "✅ jarsWAF Agent installation script configuration completed."
"#
    );

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/x-shellscript")],
        script,
    )
}

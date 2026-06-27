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
    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };

    cfg.global.waf_enabled = payload.waf_enabled;

    // Serialize back to TOML and save
    let toml_str = match toml::to_string(&cfg) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to serialize updated config to TOML: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to serialize config",
            )
                .into_response();
        }
    };

    if let Err(e) = std::fs::write(&state.config_path, toml_str) {
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

pub async fn serve_install_script(
    State(_state): State<ControllerState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
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

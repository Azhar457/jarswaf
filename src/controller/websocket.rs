use super::state::ControllerState;
use crate::config;
use axum::{
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use std::sync::atomic::Ordering;
use tracing::info;

pub async fn ws_dashboard_handler(
    ws: WebSocketUpgrade,
    State(state): State<ControllerState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_dashboard_socket(socket, state))
}

pub async fn ws_agent_handler(
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

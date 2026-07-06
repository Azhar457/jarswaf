use super::state::ControllerState;
use crate::config;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tracing::{info, warn};

/// Max time without any message from an agent before we consider it dead.
const AGENT_HEARTBEAT_TIMEOUT_SECS: u64 = 120;

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

    let mut config_rx = state.config_tx.subscribe();
    let mut block_rx = state.block_tx.subscribe();

    // Heartbeat: if no message (including Ping) received in 120s, close the connection
    let heartbeat = Duration::from_secs(AGENT_HEARTBEAT_TIMEOUT_SECS);

    loop {
        tokio::select! {
            biased; // prefer data messages over timer

            Ok(new_cfg) = config_rx.recv() => {
                if let Ok(json) = serde_json::to_string(&new_cfg) {
                    if socket.send(axum::extract::ws::Message::Text(json)).await.is_err() {
                        break;
                    }
                }
            }
            Ok(block_cmd) = block_rx.recv() => {
                let payload = serde_json::json!({
                    "type": "block_command",
                    "data": block_cmd,
                });
                if socket.send(axum::extract::ws::Message::Text(payload.to_string())).await.is_err() {
                    break;
                }
            }
            msg = timeout_recv(&mut socket, heartbeat) => {
                match msg {
                    Some(Ok(msg)) => {
                        if let axum::extract::ws::Message::Close(_) = msg {
                            break;
                        }
                    }
                    Some(Err(_)) | None => {
                        // Connection error or heartbeat timeout
                        warn!("Agent connection closed or heartbeat expired");
                        break;
                    }
                }
            }
        }
    }
    info!("Agent client disconnected from WebSocket");

    // Note: agent_registry cleanup happens via the WebSocket drop handler
}

/// Receive a WS message with a timeout, returning `None` on timeout or close.
async fn timeout_recv(
    socket: &mut WebSocket,
    timeout: Duration,
) -> Option<Result<Message, axum::Error>> {
    tokio::time::timeout(timeout, socket.recv())
        .await
        .unwrap_or(None)
}

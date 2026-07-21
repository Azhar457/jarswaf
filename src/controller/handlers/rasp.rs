use super::super::state::ControllerState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tracing::{info, warn};

#[derive(serde::Deserialize, Debug)]
pub struct RaspTelemetryEvent {
    pub application_id: String,
    pub event_type: String, // e.g., "SQL_INJECTION", "FILE_READ"
    pub severity: String,
    pub details: String,
    pub client_ip: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
pub struct RaspBlockRequest {
    pub ip: String,
    pub reason: String,
    pub ttl: Option<u64>,
}

pub async fn receive_rasp_telemetry_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<RaspTelemetryEvent>,
) -> impl IntoResponse {
    info!("Received RASP Telemetry: {:?}", payload);

    let entry = crate::logging::WafLogEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        client_ip: payload.client_ip.unwrap_or_else(|| "0.0.0.0".to_string()),
        method: "RASP".to_string(),
        path: payload.application_id,
        action: "TELEMETRY".to_string(),
        rule_id: format!("RASP-{}", payload.event_type),
        reason: payload.details.clone(),
    };

    let _ = state.tx.send(entry);

    // In a full implementation, this might analyze the telemetry and automatically issue a block
    // if the severity is CRITICAL.

    StatusCode::ACCEPTED
}

pub async fn receive_rasp_block_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<RaspBlockRequest>,
) -> impl IntoResponse {
    warn!("Received RASP Block Request for IP: {}", payload.ip);

    let cmd = crate::controller::BlockCommand {
        action: "block".to_string(),
        ip: payload.ip.clone(),
        ttl: payload.ttl,
        reason: Some(format!("RASP Requested: {}", payload.reason)),
    };

    let _ = state.block_tx.send(cmd);

    let entry = crate::logging::WafLogEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        client_ip: payload.ip,
        method: "RASP".to_string(),
        path: "GLOBAL".to_string(),
        action: "BLOCK".to_string(),
        rule_id: "RASP-BLOCK".to_string(),
        reason: payload.reason,
    };
    let _ = state.tx.send(entry);

    StatusCode::ACCEPTED
}

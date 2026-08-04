use super::super::state::ControllerState;
use crate::config;
use crate::rules::RuleEngine;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SimulatePayload {
    pub payload: String,
    pub path: Option<String>,
    pub method: Option<String>,
}

#[derive(serde::Serialize)]
pub struct SimulateResponse {
    pub status: String,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
    pub engine: String,
}

/// POST /api/v1/redteam/simulate — Test a payload against the real rule engine (server-side)
pub async fn simulate_payload_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<SimulatePayload>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let cfg = config::load_config(&state.config_path)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed reading config"))?;

    let engine = RuleEngine::new(&cfg);
    let enabled_rules = vec!["*".to_string()];

    let path = payload.path.unwrap_or_else(|| "/".to_string());
    let method = payload.method.unwrap_or_else(|| "GET".to_string());
    let headers = ahash::AHashMap::<String, String>::new();

    let verdict = engine.check_request(
        &path,
        "",
        &headers,
        &payload.payload,
        None,
        &method,
        &enabled_rules,
    );

    match verdict {
        Some((rule_id, reason)) => Ok(Json(SimulateResponse {
            status: "triggered".to_string(),
            rule_id: Some(rule_id),
            reason: Some(reason),
            engine: "server".to_string(),
        })),
        None => Ok(Json(SimulateResponse {
            status: "passed".to_string(),
            rule_id: None,
            reason: None,
            engine: "server".to_string(),
        })),
    }
}

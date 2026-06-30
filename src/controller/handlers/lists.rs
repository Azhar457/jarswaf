use super::super::state::ControllerState;
use crate::config;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tracing::{error, info};

pub async fn get_allowlists_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };
    (StatusCode::OK, Json(cfg.allowlists)).into_response()
}

fn validate_allowlists(rules: &[config::AllowlistRule]) -> Result<(), &'static str> {
    for rule in rules {
        if rule.ip.trim().is_empty() {
            return Err("IP address cannot be empty");
        }
        if rule.ip.parse::<std::net::IpAddr>().is_err() && !rule.ip.contains('/') {
            return Err("Invalid IP address or CIDR format");
        }
    }
    Ok(())
}

pub async fn post_allowlists_handler(
    State(state): State<ControllerState>,
    Json(allowlists): Json<Vec<config::AllowlistRule>>,
) -> impl IntoResponse {
    if let Err(msg) = validate_allowlists(&allowlists) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": msg}))).into_response();
    }

    let _lock = state.config_lock.lock().await;

    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };

    cfg.allowlists = allowlists;

    match config::save_config(&state.config_path, &cfg) {
        Ok(_) => {
            info!(
                "Allowlists configuration updated successfully in {}",
                state.config_path
            );
            let _ = state.config_tx.send(cfg);
            StatusCode::OK.into_response()
        }
        Err(e) => {
            error!("Failed to write updated config to disk: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to write config file",
            )
                .into_response()
        }
    }
}

pub async fn get_blacklists_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };
    (StatusCode::OK, Json(cfg.blacklists)).into_response()
}

fn validate_blacklists(rules: &[config::BlacklistRule]) -> Result<(), &'static str> {
    for rule in rules {
        if rule.ip.trim().is_empty() {
            return Err("IP address cannot be empty");
        }
        if rule.ip.parse::<std::net::IpAddr>().is_err() && !rule.ip.contains('/') {
            return Err("Invalid IP address or CIDR format");
        }
    }
    Ok(())
}

pub async fn post_blacklists_handler(
    State(state): State<ControllerState>,
    Json(blacklists): Json<Vec<config::BlacklistRule>>,
) -> impl IntoResponse {
    if let Err(msg) = validate_blacklists(&blacklists) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": msg}))).into_response();
    }

    let _lock = state.config_lock.lock().await;

    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };

    cfg.blacklists = blacklists;

    match config::save_config(&state.config_path, &cfg) {
        Ok(_) => {
            info!(
                "Blacklists configuration updated successfully in {}",
                state.config_path
            );
            let _ = state.config_tx.send(cfg);
            StatusCode::OK.into_response()
        }
        Err(e) => {
            error!("Failed to write updated config to disk: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to write config file",
            )
                .into_response()
        }
    }
}

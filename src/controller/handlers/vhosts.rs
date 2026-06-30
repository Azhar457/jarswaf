use super::super::state::ControllerState;
use crate::config;
use axum::{extract::State, http::{StatusCode, HeaderMap}, response::IntoResponse, Json};
use tracing::{error, info};

pub async fn get_vhosts_handler(
    State(state): State<ControllerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };

    if let Some(tenant_id) = headers.get("X-Tenant-ID").and_then(|h| h.to_str().ok()) {
        let tenant_vhosts: Vec<config::VHost> = cfg
            .vhosts
            .into_iter()
            .filter(|v| v.tenant == tenant_id)
            .collect();
        (StatusCode::OK, Json(tenant_vhosts)).into_response()
    } else {
        (StatusCode::OK, Json(cfg.vhosts)).into_response()
    }
}

fn validate_vhosts(vhosts: &[config::VHost]) -> Result<(), &'static str> {
    for vhost in vhosts {
        if vhost.name.trim().is_empty() {
            return Err("Virtual host name cannot be empty");
        }
        if vhost.hosts.is_empty() {
            return Err("At least one host domain is required");
        }
        for host in &vhost.hosts {
            if host.trim().is_empty() {
                return Err("Host domain name cannot be empty");
            }
        }
        if vhost.backend.trim().is_empty() {
            return Err("Backend address cannot be empty");
        }
    }
    Ok(())
}

pub async fn post_vhosts_handler(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    Json(vhosts): Json<Vec<config::VHost>>,
) -> impl IntoResponse {
    if let Err(msg) = validate_vhosts(&vhosts) {
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

    if let Some(tenant_id) = headers.get("X-Tenant-ID").and_then(|h| h.to_str().ok()) {
        let mut new_vhosts: Vec<config::VHost> = cfg
            .vhosts
            .into_iter()
            .filter(|v| v.tenant != tenant_id)
            .collect();

        let mut validated_vhosts = vhosts;
        for v in &mut validated_vhosts {
            v.tenant = tenant_id.to_string();
        }

        new_vhosts.extend(validated_vhosts);
        cfg.vhosts = new_vhosts;
    } else {
        cfg.vhosts = vhosts;
    }

    match config::save_config(&state.config_path, &cfg) {
        Ok(_) => {
            info!(
                "Virtual hosts configuration updated successfully in {}",
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

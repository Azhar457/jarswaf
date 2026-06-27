use super::super::state::ControllerState;
use crate::config;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tracing::{error, info};

pub async fn get_vhosts_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };
    (StatusCode::OK, Json(cfg.vhosts)).into_response()
}

pub async fn post_vhosts_handler(
    State(state): State<ControllerState>,
    Json(vhosts): Json<Vec<config::VHost>>,
) -> impl IntoResponse {
    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };

    cfg.vhosts = vhosts;

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

    match std::fs::write(&state.config_path, toml_str) {
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

use super::super::state::ControllerState;
use crate::config;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tracing::{error, info};

pub async fn get_custom_rules_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };
    (StatusCode::OK, Json(cfg.custom_rules)).into_response()
}

pub async fn post_custom_rules_handler(
    State(state): State<ControllerState>,
    Json(custom_rules): Json<Vec<config::CustomRule>>,
) -> impl IntoResponse {
    let _lock = state.config_lock.lock().await;

    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };

    cfg.custom_rules = custom_rules;

    match config::save_config(&state.config_path, &cfg) {
        Ok(_) => {
            info!(
                "Custom rules configuration updated successfully in {}",
                state.config_path
            );
            let _ = state.config_tx.send(cfg.clone());

            let _ = crate::logging::write_audit_log(
                &state.db_path,
                "controller",
                "RULES_UPDATE",
                &format!("{} custom rules applied", cfg.custom_rules.len()),
            );

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

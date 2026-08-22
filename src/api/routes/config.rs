use crate::api::dto::responses::{ApiResponse, ConfigResponse, MessageResponse};
use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::control_bus::commands::ControlCommand;
use axum::{extract::State, Json};

pub async fn get_config(
    State(state): State<ApiState>,
) -> Result<Json<ApiResponse<ConfigResponse>>, ApiError> {
    let config = state.published_state.get_config();

    Ok(Json(ApiResponse::new(ConfigResponse {
        http_port: config.http_port,
        https_port: config.https_port,
        mode: config.mode.clone(),
        log_level: config.log_level.clone(),
        tls_mode: config.tls_mode.clone(),
        max_body_size: config.max_body_size,
        cleanup_interval_secs: config.cleanup_interval_secs,
    })))
}

pub async fn reload_config(
    State(state): State<ApiState>,
) -> Result<Json<ApiResponse<MessageResponse>>, ApiError> {
    state
        .cmd_tx
        .send(ControlCommand::ReloadConfig)
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    Ok(Json(ApiResponse::new(MessageResponse::new(
        "Config reload triggered",
    ))))
}

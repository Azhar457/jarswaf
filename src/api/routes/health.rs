use crate::api::dto::responses::{ApiResponse, HealthResponse};
use crate::api::state::ApiState;
use axum::{extract::State, Json};

pub async fn health_check(State(state): State<ApiState>) -> Json<ApiResponse<HealthResponse>> {
    Json(ApiResponse::new(HealthResponse {
        status: "ok".to_string(),
        version: state.version.clone(),
        uptime_secs: state.started_at.elapsed().as_secs(),
        // Since we are running in non-Linux or standalone, we can query kernel maps loaded state via global manager or return placeholder if missing
        kernel_loaded: crate::KERNEL_INTERFACE.is_some(),
        mode: state.published_state.get_config().mode.clone(),
    }))
}

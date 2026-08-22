use crate::api::dto::responses::{ApiResponse, DashboardSummary};
use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::control_bus::commands::ControlCommand;
use axum::{extract::State, Json};

pub async fn get_summary(
    State(state): State<ApiState>,
) -> Result<Json<ApiResponse<DashboardSummary>>, ApiError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    state
        .cmd_tx
        .send(ControlCommand::GetMetrics(reply_tx))
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    let metrics = reply_rx
        .await
        .map_err(|_| ApiError::internal("Control bus dropped response"))?;

    Ok(Json(ApiResponse::new(DashboardSummary::from(metrics))))
}

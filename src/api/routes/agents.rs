use crate::api::dto::responses::{AgentResponse, ApiResponse};
use crate::api::error::ApiError;
use crate::api::state::ApiState;
use axum::{
    extract::{Path, State},
    Json,
};

fn get_local_agent(state: &ApiState) -> AgentResponse {
    AgentResponse {
        hostname: "localhost".to_string(),
        ip: "127.0.0.1".to_string(),
        os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        cpu: 0.0,
        ram: 0.0,
        disk: 0.0,
        uptime: format!("{}", state.started_at.elapsed().as_secs()),
        status: "online".to_string(),
        region: Some("Local".to_string()),
        cloud_provider: Some("Bare Metal".to_string()),
        active_connections: Some(0),
        last_seen: chrono::Utc::now().to_rfc3339(),
    }
}

// In standalone mode, return only self
pub async fn list_agents(State(state): State<ApiState>) -> Json<ApiResponse<Vec<AgentResponse>>> {
    Json(ApiResponse::new(vec![get_local_agent(&state)]))
}

pub async fn get_agent(
    State(state): State<ApiState>,
    Path(_hostname): Path<String>,
) -> Result<Json<ApiResponse<AgentResponse>>, ApiError> {
    Ok(Json(ApiResponse::new(get_local_agent(&state))))
}

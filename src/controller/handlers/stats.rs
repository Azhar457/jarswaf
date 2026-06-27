use super::super::state::ControllerState;
use crate::logging;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use std::sync::atomic::Ordering;

#[derive(serde::Serialize)]
pub struct DbSizeResponse {
    pub size_bytes: u64,
    pub formatted: String,
}

pub async fn get_db_size_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let size_bytes = logging::sqlite_get_db_size(&state.db_path);

    let formatted = if size_bytes < 1024 {
        format!("{} B", size_bytes)
    } else if size_bytes < 1024 * 1024 {
        format!("{:.1} KB", size_bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", size_bytes as f64 / (1024.0 * 1024.0))
    };

    (
        StatusCode::OK,
        Json(DbSizeResponse {
            size_bytes,
            formatted,
        }),
    )
}

pub async fn get_stats_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let stats = logging::Stats {
        total_requests: state.total_requests.load(Ordering::Relaxed) as i64,
        blocked: state.blocked.load(Ordering::Relaxed) as i64,
        rate_limited: state.rate_limited.load(Ordering::Relaxed) as i64,
    };
    (StatusCode::OK, Json(stats)).into_response()
}

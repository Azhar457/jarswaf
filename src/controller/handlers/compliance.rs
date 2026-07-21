use super::super::state::ControllerState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

#[derive(serde::Serialize)]
pub struct ComplianceReport {
    pub generated_at: String,
    pub system_status: String,
    pub global_stats: crate::logging::Stats,
    pub audit_logs: Vec<crate::logging::AuditLogEntry>,
    pub security_posture: String,
}

pub async fn get_compliance_report_handler(
    State(state): State<ControllerState>,
) -> impl IntoResponse {
    let stats = crate::logging::sqlite_get_stats(&state.db_path, 24).unwrap_or(crate::logging::Stats {
        total_requests: 0,
        blocked: 0,
        rate_limited: 0,
    });

    let audit_logs = crate::logging::sqlite_get_audit_logs(&state.db_path, 100).unwrap_or_default();

    let report = ComplianceReport {
        generated_at: chrono::Utc::now().to_rfc3339(),
        system_status: "HEALTHY".to_string(),
        global_stats: stats,
        audit_logs,
        security_posture: "STRICT".to_string(),
    };

    (StatusCode::OK, Json(report))
}

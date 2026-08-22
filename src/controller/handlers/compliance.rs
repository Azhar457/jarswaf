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
    let stats =
        crate::logging::sqlite_get_stats(&state.db_path, 24).unwrap_or(crate::logging::Stats {
            total_requests: 0,
            blocked: 0,
            rate_limited: 0,
        });

    let audit_logs = crate::logging::sqlite_get_audit_logs(&state.db_path, 100).unwrap_or_default();

    let cfg = crate::config::load_config(&state.config_path).unwrap_or_default();

    let waf_active = cfg.global.waf_enabled;
    let must_change_pw = cfg.global.must_change_password.unwrap_or(false);
    let zero_trust_active =
        cfg.zero_trust.min_trust_score > 0.0 || !cfg.zero_trust.allowed_issuers.is_empty();

    let system_status = if waf_active {
        "HEALTHY".to_string()
    } else {
        "DEGRADED (WAF Disabled)".to_string()
    };

    let security_posture = if !waf_active {
        "VULNERABLE (Engine Disabled)".to_string()
    } else if must_change_pw {
        "WARNING (Default Admin Credentials Pending Change)".to_string()
    } else if zero_trust_active {
        "STRICT (Zero-Trust Active)".to_string()
    } else {
        "MODERATE (Basic Inspection Only)".to_string()
    };

    let report = ComplianceReport {
        generated_at: chrono::Utc::now().to_rfc3339(),
        system_status,
        global_stats: stats,
        audit_logs,
        security_posture,
    };

    (StatusCode::OK, Json(report))
}

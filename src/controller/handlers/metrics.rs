use crate::controller::state::ControllerState;
use axum::{extract::State, http::header, response::IntoResponse};
use std::sync::atomic::Ordering;

pub async fn get_metrics_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let total = state.total_requests.load(Ordering::Relaxed);
    let blocked = state.blocked.load(Ordering::Relaxed);
    let rate_limited = state.rate_limited.load(Ordering::Relaxed);

    let active_agents = if let Ok(registry) = state.agent_registry.read() {
        registry.len()
    } else {
        0
    };

    let metrics_data = format!(
        r#"# HELP jarswaf_total_requests Total number of HTTP requests processed by jarsWAF.
# TYPE jarswaf_total_requests counter
jarswaf_total_requests {}
 
# HELP jarswaf_blocked_requests Total number of requests blocked by WAF rules.
# TYPE jarswaf_blocked_requests counter
jarswaf_blocked_requests {}
 
# HELP jarswaf_rate_limited_requests Total number of requests rate limited.
# TYPE jarswaf_rate_limited_requests counter
jarswaf_rate_limited_requests {}
 
# HELP jarswaf_active_agents Total number of active WAF agents connected.
# TYPE jarswaf_active_agents gauge
jarswaf_active_agents {}
"#,
        total, blocked, rate_limited, active_agents
    );

    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics_data,
    )
}

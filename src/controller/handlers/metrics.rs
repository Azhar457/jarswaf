use crate::controller::state::ControllerState;
use crate::metrics;
use axum::{extract::State, http::header, response::IntoResponse};
use std::sync::atomic::Ordering;

pub async fn get_metrics_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    // Controller-level atomic counters
    let total = state.total_requests.load(Ordering::Relaxed);
    let blocked = state.blocked.load(Ordering::Relaxed);
    let rate_limited = state.rate_limited.load(Ordering::Relaxed);
    let active_agents = state.agent_registry.read().map(|r| r.len()).unwrap_or(0);

    // Sync our counters into prometheus metrics
    metrics::REQUESTS_TOTAL.inc_by(total as f64 - metrics::REQUESTS_TOTAL.get());
    metrics::BLOCKED_REQUESTS_TOTAL.inc_by(blocked as f64 - metrics::BLOCKED_REQUESTS_TOTAL.get());
    metrics::BLOCKED_IPS_GAUGE.set(blocked as f64);

    // Full prometheus registry dump
    let prom_output = metrics::gather_all();

    // Prepend the controller-only text metrics (some consumers scrape text/plain)
    let controller_metrics = format!(
        "# HELP jarswaf_total_requests Total requests processed by jarsWAF.\n\
         # TYPE jarswaf_total_requests counter\n\
         jarswaf_total_requests {}\n\n\
         # HELP jarswaf_blocked_requests Total blocked by WAF rules.\n\
         # TYPE jarswaf_blocked_requests counter\n\
         jarswaf_blocked_requests {}\n\n\
         # HELP jarswaf_rate_limited_requests Total rate limited requests.\n\
         # TYPE jarswaf_rate_limited_requests counter\n\
         jarswaf_rate_limited_requests {}\n\n\
         # HELP jarswaf_active_agents Active agents connected.\n\
         # TYPE jarswaf_active_agents gauge\n\
         jarswaf_active_agents {}\n",
        total, blocked, rate_limited, active_agents
    );

    let combined = format!("{}{}", controller_metrics, prom_output);

    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        combined,
    )
}

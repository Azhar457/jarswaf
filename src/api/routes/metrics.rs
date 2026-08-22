use crate::api::state::ApiState;
use crate::control_bus::commands::ControlCommand;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
};
use tracing::error;

/// Prometheus metrics endpoint
pub async fn prometheus_metrics(State(state): State<ApiState>) -> impl IntoResponse {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    match state
        .cmd_tx
        .send(ControlCommand::GetMetrics(reply_tx))
        .await
    {
        Ok(_) => match reply_rx.await {
            Ok(metrics) => {
                let body = format!(
                    r#"# HELP jarswaf_requests_total Total requests processed
# TYPE jarswaf_requests_total counter
jarswaf_requests_total {}

# HELP jarswaf_blocked_total Total blocked requests
# TYPE jarswaf_blocked_total counter
jarswaf_blocked_total {}

# HELP jarswaf_blocklist_size Current blocklist size
# TYPE jarswaf_blocklist_size gauge
jarswaf_blocklist_size {}

# HELP jarswaf_uptime_seconds Uptime in seconds
# TYPE jarswaf_uptime_seconds gauge
jarswaf_uptime_seconds {}
"#,
                    metrics.total_requests,
                    metrics.blocked_requests,
                    metrics.blocklist_size,
                    metrics.uptime_secs,
                );

                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
                    body,
                )
            }
            Err(e) => {
                error!("Failed to get metrics: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::CONTENT_TYPE, "text/plain")],
                    "metrics unavailable".to_string(),
                )
            }
        },
        Err(e) => {
            error!("Failed to send metrics command: {}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::CONTENT_TYPE, "text/plain")],
                "control bus unavailable".to_string(),
            )
        }
    }
}

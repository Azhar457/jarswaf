use crate::api::dto::requests::LogQueryParams;
use crate::api::dto::responses::{LogEntryResponse, PaginatedResponse};
use crate::api::state::ApiState;
use crate::storage;
use axum::{
    extract::{Query, State},
    Json,
};

pub async fn query_logs(
    State(state): State<ApiState>,
    Query(params): Query<LogQueryParams>,
) -> Result<Json<PaginatedResponse<LogEntryResponse>>, crate::api::error::ApiError> {
    let config = state.published_state.get_config();

    if config.log_mode != "sqlite" && config.log_mode != "clickhouse" {
        return Err(crate::api::error::ApiError::new(
            "INTERNAL_ERROR",
            "Log storage not enabled",
        ));
    }

    let page = params.page();
    let per_page = params.per_page();
    let offset = (page - 1) * per_page;

    // Query logs from storage
    let (entries, total) = storage::query_logs(
        &config.log_db_path,
        storage::LogFilter {
            action: params.action.clone(),
            client_ip: params.client_ip.clone(),
            vhost: params.vhost.clone(),
            rule_id: params.rule_id.clone(),
            since: params.since.clone(),
            until: params.until.clone(),
        },
        offset as i64,
        per_page as i64,
    )
    .await?;

    let responses: Vec<LogEntryResponse> = entries
        .into_iter()
        .map(|e| LogEntryResponse {
            timestamp: e.timestamp,
            request_id: e.request_id,
            client_ip: e.client_ip,
            method: e.method,
            path: e.path,
            action: e.action,
            rule_id: e.rule_id,
            score: e.score,
            latency_ms: e.latency_ms,
            vhost: e.vhost,
        })
        .collect();

    Ok(Json(PaginatedResponse::new(
        responses,
        page,
        per_page,
        total as u64,
    )))
}

pub async fn stream_logs(State(_state): State<ApiState>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let rx = crate::control_bus::ws_broadcaster::get().subscribe();

    let stream = async_stream::stream! {
        let mut rx = rx;
        while let Ok(event) = rx.recv().await {
            if let crate::control_bus::ws_broadcaster::WsEvent::Log {
                timestamp,
                request_id,
                client_ip,
                method,
                path,
                action,
                rule_id,
                score,
                latency_ms,
                vhost,
            } = event {
                yield Ok::<_, axum::Error>(
                    axum::response::sse::Event::default()
                        .data(serde_json::json!({
                            "timestamp": timestamp,
                            "request_id": request_id,
                            "client_ip": client_ip,
                            "method": method,
                            "path": path,
                            "action": action,
                            "rule_id": rule_id,
                            "score": score,
                            "latency_ms": latency_ms,
                            "vhost": vhost,
                        }).to_string())
                );
            }
        }
    };

    axum::response::Sse::new(stream).into_response()
}

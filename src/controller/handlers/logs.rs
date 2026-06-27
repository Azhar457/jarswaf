use super::super::state::ControllerState;
use crate::logging;
use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
    response::{
        sse::{Event, Sse},
        IntoResponse, Response,
    },
    Json,
};
use std::convert::Infallible;
use std::sync::atomic::Ordering;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

pub async fn receive_logs_handler(
    State(state): State<ControllerState>,
    Json(logs): Json<Vec<logging::WafLogEntry>>,
) -> impl IntoResponse {
    // Check if logging is enabled
    if !state.logging_enabled.load(Ordering::Relaxed) {
        return StatusCode::OK;
    }

    let logs_clone = logs.clone();
    let db_path = state.db_path.clone();

    // Broadcast logs to connected dashboards and update in-memory stats immediately (non-blocking)
    let mut new_total = 0;
    let mut new_blocked = 0;
    let mut new_rate_limited = 0;
    for log in logs {
        new_total += 1;
        if log.action == "BLOCK" {
            new_blocked += 1;
        } else if log.action == "RATE_LIMIT" {
            new_rate_limited += 1;
        }
        let _ = state.tx.send(log);
    }
    state.total_requests.fetch_add(new_total, Ordering::Relaxed);
    state.blocked.fetch_add(new_blocked, Ordering::Relaxed);
    state
        .rate_limited
        .fetch_add(new_rate_limited, Ordering::Relaxed);

    // Spawn background task to insert logs into SQLite asynchronously
    tokio::spawn(async move {
        let res = tokio::task::spawn_blocking(move || {
            let mut conn = rusqlite::Connection::open(&db_path)?;
            let tx = conn.transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO request_log (timestamp, client_ip, method, path, action, rule_id, reason)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
                )?;
                for entry in &logs_clone {
                    stmt.execute([
                        &entry.timestamp,
                        &entry.client_ip,
                        &entry.method,
                        &entry.path,
                        &entry.action,
                        &entry.rule_id,
                        &entry.reason,
                    ])?;
                }
            }
            tx.commit()?;
            Ok::<(), rusqlite::Error>(())
        }).await;

        if let Err(e) = res {
            tracing::error!("Blocking task panicked inserting logs to SQLite: {}", e);
        } else if let Ok(Err(e)) = res {
            tracing::error!("Failed to insert logs to SQLite: {}", e);
        }
    });

    StatusCode::OK
}

pub async fn get_logs_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let db_path = state.db_path.clone();
    let res = tokio::task::spawn_blocking(move || logging::sqlite_get_logs(&db_path, 100)).await;

    match res {
        Ok(Ok(logs)) => (StatusCode::OK, Json(logs)).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Vec::<logging::WafLogEntry>::new()),
        )
            .into_response(),
    }
}

pub async fn export_logs_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let db_path = state.db_path.clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&db_path)?;
        let mut stmt = conn.prepare(
            "SELECT timestamp, client_ip, method, path, action, rule_id, reason FROM request_log ORDER BY timestamp DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            let ts: String = row.get(0)?;
            let ip: String = row.get(1)?;
            let method: String = row.get(2)?;
            let path: String = row.get(3)?;
            let action: String = row.get(4)?;
            let rule_id: String = row.get(5)?;
            let reason: String = row.get(6)?;
            Ok(format!("{ts}\t{ip}\t{method}\t{path}\t{action}\t{rule_id}\t{reason}"))
        })?;
        let mut content = String::new();
        for line in rows.flatten() {
            content.push_str(&line);
            content.push('\n');
        }
        Ok::<String, rusqlite::Error>(content)
    }).await;

    match res {
        Ok(Ok(content)) => Response::builder()
            .header("Content-Type", "text/plain; charset=utf-8")
            .header("Content-Disposition", "attachment; filename=\"aegis.log\"")
            .body(Body::from(content))
            .unwrap()
            .into_response(),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to export logs").into_response(),
    }
}

pub async fn clear_logs_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let db_path = state.db_path.clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&db_path)?;
        conn.execute("DELETE FROM request_log", [])?;
        conn.execute("VACUUM", [])?;
        Ok::<(), rusqlite::Error>(())
    })
    .await;

    match res {
        Ok(Ok(())) => {
            state.total_requests.store(0, Ordering::Relaxed);
            state.blocked.store(0, Ordering::Relaxed);
            state.rate_limited.store(0, Ordering::Relaxed);
            StatusCode::OK
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub async fn sse_handler(
    State(state): State<ControllerState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.tx.subscribe();
    let stream = BroadcastStream::new(rx).map(|res| match res {
        Ok(log) => {
            let json = serde_json::to_string(&log).unwrap();
            Ok(Event::default().data(json))
        }
        Err(_) => Ok(Event::default().comment("lost message")),
    });
    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

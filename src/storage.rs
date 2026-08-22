use crate::api::error::ApiError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafLogEntry {
    pub timestamp: String,
    pub request_id: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub action: String,
    pub rule_id: String,
    pub score: f64,
    pub latency_ms: f64,
    pub vhost: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogFilter {
    pub action: Option<String>,
    pub client_ip: Option<String>,
    pub vhost: Option<String>,
    pub rule_id: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
}

pub async fn query_logs(
    db_path: &str,
    filter: LogFilter,
    offset: i64,
    limit: i64,
) -> Result<(Vec<WafLogEntry>, i64), ApiError> {
    let db_path = db_path.to_string();
    tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| ApiError::internal(&format!("Failed to open db: {e}")))?;

        let mut query = "SELECT timestamp, client_ip, method, path, action, rule_id, reason FROM request_log WHERE 1=1".to_string();
        let mut count_query = "SELECT COUNT(*) FROM request_log WHERE 1=1".to_string();

        // We will collect params as a list of Boxed trait objects
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(ref action) = filter.action {
            query.push_str(" AND action = ?");
            count_query.push_str(" AND action = ?");
            params.push(Box::new(action.clone()));
        }
        if let Some(ref client_ip) = filter.client_ip {
            query.push_str(" AND client_ip = ?");
            count_query.push_str(" AND client_ip = ?");
            params.push(Box::new(client_ip.clone()));
        }
        if let Some(ref rule_id) = filter.rule_id {
            query.push_str(" AND rule_id = ?");
            count_query.push_str(" AND rule_id = ?");
            params.push(Box::new(rule_id.clone()));
        }
        if let Some(ref since) = filter.since {
            query.push_str(" AND timestamp >= ?");
            count_query.push_str(" AND timestamp >= ?");
            params.push(Box::new(since.clone()));
        }
        if let Some(ref until) = filter.until {
            query.push_str(" AND timestamp <= ?");
            count_query.push_str(" AND timestamp <= ?");
            params.push(Box::new(until.clone()));
        }

        let total: i64 = {
            let mut count_stmt = conn.prepare(&count_query)
                .map_err(|e| ApiError::internal(&format!("Count query preparation failed: {e}")))?;
            let params_ref: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
            count_stmt.query_row(rusqlite::params_from_iter(params_ref), |r| r.get(0))
                .map_err(|e| ApiError::internal(&format!("Count query failed: {e}")))?
        };

        query.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
        let mut stmt = conn.prepare(&query)
            .map_err(|e| ApiError::internal(&format!("Query preparation failed: {e}")))?;

        params.push(Box::new(limit));
        params.push(Box::new(offset));

        let params_ref: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let log_iter = stmt.query_map(rusqlite::params_from_iter(params_ref), |row| {
            let timestamp: String = row.get(0)?;
            let client_ip: String = row.get(1)?;
            let method: String = row.get(2)?;
            let path: String = row.get(3)?;
            let action: String = row.get(4)?;
            let rule_id: String = row.get(5)?;
            let _reason: String = row.get(6)?;

            // Build pseudo request_id
            let request_id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, format!("{client_ip}{timestamp}").as_bytes()).to_string();
            let score = if action == "BLOCK" { 100.0 } else { 0.0 };

            Ok(WafLogEntry {
                timestamp,
                request_id,
                client_ip,
                method,
                path,
                action,
                rule_id,
                score,
                latency_ms: 0.0,
                vhost: "default".to_string(),
            })
        }).map_err(|e| ApiError::internal(&format!("Query map failed: {e}")))?;

        let mut entries = Vec::new();
        for entry in log_iter {
            entries.push(entry.map_err(|e| ApiError::internal(&format!("Row parsing failed: {e}")))?);
        }

        Ok((entries, total))
    })
    .await
    .map_err(|e| ApiError::internal(&format!("Spawn blocking failed: {e}")))?
}

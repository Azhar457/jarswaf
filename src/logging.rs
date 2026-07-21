use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::mpsc::Receiver;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WafLogEntry {
    pub timestamp: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub action: String,
    pub rule_id: String,
    pub reason: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Stats {
    pub total_requests: i64,
    pub blocked: i64,
    pub rate_limited: i64,
}

use reqwest::header::{HeaderMap, HeaderValue};

// Membuat HTTP Client dengan Header Autentikasi ClickHouse otomatis
pub fn build_client() -> reqwest::Client {
    let mut headers = HeaderMap::new();

    let user = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".to_string());
    if let Ok(val) = HeaderValue::from_str(&user) {
        headers.insert("X-ClickHouse-User", val);
    }

    let pass = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "jarswaf".to_string());
    if let Ok(val) = HeaderValue::from_str(&pass) {
        headers.insert("X-ClickHouse-Key", val);
    }

    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to build ClickHouse HTTP client ({}). Using default client — ClickHouse requests may fail auth.",
                e
            );
            reqwest::Client::new()
        })
}

// Inisialisasi SQLite Table
pub fn init_sqlite_db(db_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(parent) = std::path::Path::new(db_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let conn = rusqlite::Connection::open(db_path)?;

    // Enable WAL mode for concurrent read/write performance
    if let Err(e) = conn.execute("PRAGMA journal_mode=WAL;", []) {
        tracing::warn!("Failed to enable WAL mode: {}", e);
    }
    if let Err(e) = conn.execute("PRAGMA synchronous=NORMAL;", []) {
        tracing::warn!("Failed to set synchronous mode: {}", e);
    }

    conn.execute(
        "CREATE TABLE IF NOT EXISTS request_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            action TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            reason TEXT NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS reputation_feed (
            ip TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            added_at TEXT NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            admin_token TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL
        )",
        [],
    )?;

    // Create index on timestamp for fast queries
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_request_log_timestamp ON request_log (timestamp)",
        [],
    )?;

    tracing::info!("SQLite database initialized successfully at {}", db_path);
    Ok(())
}

// Mendapatkan statistik realtime dari SQLite
pub fn sqlite_get_stats(
    db_path: &str,
    hours: u32,
) -> Result<Stats, Box<dyn std::error::Error + Send + Sync>> {
    let conn = rusqlite::Connection::open(db_path)?;

    // Calculate the ISO timestamp for now() - hours
    let since = chrono::Utc::now() - chrono::Duration::hours(hours as i64);
    let since_str = since.to_rfc3339();

    let mut stmt = conn.prepare(
        "SELECT 
            count(), 
            count(CASE WHEN action = 'BLOCK' THEN 1 END), 
            count(CASE WHEN action = 'RATE_LIMIT' THEN 1 END) 
         FROM request_log 
         WHERE timestamp > ?1",
    )?;

    let mut rows = stmt.query([since_str])?;
    if let Some(row) = rows.next()? {
        Ok(Stats {
            total_requests: row.get(0).unwrap_or(0),
            blocked: row.get(1).unwrap_or(0),
            rate_limited: row.get(2).unwrap_or(0),
        })
    } else {
        Ok(Stats {
            total_requests: 0,
            blocked: 0,
            rate_limited: 0,
        })
    }
}

// Mendapatkan database size
pub fn sqlite_get_db_size(db_path: &str) -> u64 {
    std::fs::metadata(db_path).map(|m| m.len()).unwrap_or(0)
}

// Mendapatkan log terbaru dari SQLite
pub fn sqlite_get_logs(
    db_path: &str,
    limit: usize,
) -> Result<Vec<WafLogEntry>, Box<dyn std::error::Error + Send + Sync>> {
    let conn = rusqlite::Connection::open(db_path)?;
    let mut stmt = conn.prepare(
        "SELECT timestamp, client_ip, method, path, action, rule_id, reason 
         FROM request_log 
         ORDER BY timestamp DESC 
         LIMIT ?1",
    )?;

    let log_iter = stmt.query_map([limit], |row| {
        let timestamp_str: String = row.get(0)?;
        let client_ip_str: String = row.get(1)?;
        let method: String = row.get(2)?;
        let path: String = row.get(3)?;
        let action: String = row.get(4)?;
        let rule_id: String = row.get(5)?;
        let reason: String = row.get(6)?;

        Ok(WafLogEntry {
            timestamp: timestamp_str,
            client_ip: client_ip_str,
            method,
            path,
            action,
            rule_id,
            reason,
        })
    })?;

    let mut logs = Vec::new();
    for entry in log_iter.flatten() {
        logs.push(entry);
    }

    Ok(logs)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditLogEntry {
    pub timestamp: String,
    pub admin_token: String,
    pub action: String,
    pub details: String,
}

pub fn write_audit_log(
    db_path: &str,
    token: &str,
    action: &str,
    details: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = rusqlite::Connection::open(db_path)?;
    let timestamp = chrono::Utc::now().to_rfc3339();

    // Partially mask the token for security in DB
    let masked_token = if token.len() > 8 {
        format!("{}...{}", &token[..4], &token[token.len() - 4..])
    } else {
        "***".to_string()
    };

    conn.execute(
        "INSERT INTO audit_logs (timestamp, admin_token, action, details) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![timestamp, masked_token, action, details],
    )?;
    Ok(())
}

pub fn sqlite_get_audit_logs(
    db_path: &str,
    limit: usize,
) -> Result<Vec<AuditLogEntry>, Box<dyn std::error::Error + Send + Sync>> {
    let conn = rusqlite::Connection::open(db_path)?;
    let mut stmt = conn.prepare(
        "SELECT timestamp, admin_token, action, details 
         FROM audit_logs 
         ORDER BY timestamp DESC 
         LIMIT ?1",
    )?;

    let log_iter = stmt.query_map([limit], |row| {
        Ok(AuditLogEntry {
            timestamp: row.get(0)?,
            admin_token: row.get(1)?,
            action: row.get(2)?,
            details: row.get(3)?,
        })
    })?;

    let mut logs = Vec::new();
    for entry in log_iter.flatten() {
        logs.push(entry);
    }
    Ok(logs)
}

use std::fs::OpenOptions;
use std::io::Write;

/// Write a single log entry as a JSON line to a local file.
fn write_to_local_log(entry: &WafLogEntry, log_path: &str) {
    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(log_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        // Write as JSON line for machine-readability
        if let Ok(json) = serde_json::to_string(entry) {
            let _ = writeln!(file, "{}", json);
        }
    }

    // Also write compliance log in ECS format
    let compliance_path = format!("{}.ecs.json", log_path);
    if let Ok(mut compliance_file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&compliance_path)
    {
        let ecs_event = crate::compliance::map_to_compliance_event(entry);
        if let Ok(json) = serde_json::to_string(&ecs_event) {
            let _ = writeln!(compliance_file, "{}", json);
        }
    }
}

/// Rotate log files when the current file exceeds max_size_mb.
/// Renames: jarswaf.log -> jarswaf.log.1, jarswaf.log.1 -> jarswaf.log.2, etc.
/// Deletes the oldest file beyond max_files.
fn rotate_log_if_needed(log_path: &str, max_size_mb: u64, max_files: u32) {
    let path = std::path::Path::new(log_path);
    if let Ok(metadata) = std::fs::metadata(path) {
        let size_mb = metadata.len() / (1024 * 1024);
        if size_mb >= max_size_mb {
            // Rotate: delete oldest, shift down
            for i in (1..max_files).rev() {
                let from = format!("{}.{}", log_path, i);
                let to = format!("{}.{}", log_path, i + 1);
                let _ = std::fs::rename(&from, &to);
            }
            // Delete the max file if it exists
            let oldest = format!("{}.{}", log_path, max_files);
            let _ = std::fs::remove_file(&oldest);
            // Current -> .1
            let _ = std::fs::rename(log_path, format!("{}.1", log_path));
            tracing::info!(
                "Log file rotated: {} (exceeded {} MB)",
                log_path,
                max_size_mb
            );
        }
    }
}

// ─── Blocklist JSON File I/O ────────────────────────────────────────────────

/// Load blocked IPs from a local JSON file.
pub fn load_blocklist_from_file(path: &str) -> std::collections::HashSet<std::net::IpAddr> {
    let mut set = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        if let Ok(ips) = serde_json::from_str::<Vec<String>>(&content) {
            for ip_str in ips {
                if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                    set.insert(ip);
                }
            }
        }
    }
    set
}

/// Save blocked IPs to a local JSON file (atomic write via tmp + rename).
pub fn save_blocklist_to_file(path: &str, blocklist: &std::collections::HashSet<std::net::IpAddr>) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let ips: Vec<String> = blocklist.iter().map(|ip| ip.to_string()).collect();
    match serde_json::to_string_pretty(&ips) {
        Ok(json) => {
            let tmp_path = format!("{}.tmp.{}", path, std::process::id());
            match std::fs::write(&tmp_path, &json) {
                Ok(()) => {
                    if let Err(e) = std::fs::rename(&tmp_path, path) {
                        tracing::error!("Failed to atomically save blocklist: {}", e);
                        let _ = std::fs::remove_file(&tmp_path);
                    }
                }
                Err(e) => tracing::error!("Failed to write blocklist temp file: {}", e),
            }
        }
        Err(e) => tracing::error!("Failed to serialize blocklist: {}", e),
    }
}

/// Configuration passed to the log worker to control its behavior.
#[derive(Clone, Debug)]
pub struct LogWorkerConfig {
    pub mode: String,                   // "file", "remote", "clickhouse" / "sqlite"
    pub log_path: String,               // Local log file path
    pub max_log_size_mb: u64,           // Max size before rotation
    pub max_log_files: u32,             // Max rotated files
    pub db_path: String,                // SQLite database file path
    pub controller_url: Option<String>, // For agent mode (sends to controller)
    pub remote_url: Option<String>,     // For "remote" mode (push logs)
    pub push_interval_secs: u64,
    pub push_batch_size: usize,
    pub token: Option<String>,
}

/// Worker for reading channel logs and dispatching them based on configured mode.
pub async fn log_worker(rx: Receiver<WafLogEntry>, worker_cfg: LogWorkerConfig) {
    match worker_cfg.mode.as_str() {
        "file" => log_worker_file(rx, worker_cfg).await,
        "remote" => log_worker_remote(rx, worker_cfg).await,
        "clickhouse" | "sqlite" => log_worker_sqlite(rx, worker_cfg).await,
        other => {
            tracing::warn!("Unknown logging mode '{}', falling back to 'file'", other);
            log_worker_file(rx, worker_cfg).await;
        }
    }
}

/// FILE mode: Write logs to local JSON Lines file only.
/// Zero network dependencies. Ideal for small VPS.
async fn log_worker_file(mut rx: Receiver<WafLogEntry>, cfg: LogWorkerConfig) {
    let mut line_count: u64 = 0;
    tracing::info!("Log worker started in FILE mode → {}", cfg.log_path);

    while let Some(entry) = rx.recv().await {
        write_to_local_log(&entry, &cfg.log_path);
        line_count += 1;

        // Check rotation every 1000 lines
        if line_count.is_multiple_of(1000) {
            rotate_log_if_needed(&cfg.log_path, cfg.max_log_size_mb, cfg.max_log_files);
        }
    }
}

/// REMOTE mode: Write to local file + async batch push to remote Controller.
async fn log_worker_remote(mut rx: Receiver<WafLogEntry>, cfg: LogWorkerConfig) {
    let client = build_client();
    let push_interval = Duration::from_secs(cfg.push_interval_secs);
    let mut remote_batch: Vec<WafLogEntry> = Vec::new();
    let mut last_push = tokio::time::Instant::now();
    let mut line_count: u64 = 0;

    let remote_url = cfg
        .remote_url
        .clone()
        .or(cfg.controller_url.clone())
        .unwrap_or_default();

    tracing::info!(
        "Log worker started in REMOTE mode → {} + push to {}",
        cfg.log_path,
        remote_url
    );

    loop {
        let timeout = push_interval
            .checked_sub(last_push.elapsed())
            .unwrap_or(Duration::from_millis(100));

        tokio::select! {
            Some(entry) = rx.recv() => {
                // Always write to local file
                write_to_local_log(&entry, &cfg.log_path);
                line_count += 1;
                if line_count.is_multiple_of(1000) {
                    rotate_log_if_needed(&cfg.log_path, cfg.max_log_size_mb, cfg.max_log_files);
                }

                // Buffer for remote push
                remote_batch.push(entry);

                // Flush if batch size reached
                if remote_batch.len() >= cfg.push_batch_size {
                    push_logs_to_remote(&remote_batch, &remote_url, &client, &cfg.token).await;
                    remote_batch.clear();
                    last_push = tokio::time::Instant::now();
                }
            }
            _ = tokio::time::sleep(timeout) => {
                // Time-based flush
                if !remote_batch.is_empty() {
                    push_logs_to_remote(&remote_batch, &remote_url, &client, &cfg.token).await;
                    remote_batch.clear();
                }
                last_push = tokio::time::Instant::now();
            }
        }
    }
}

/// Push a batch of logs to a remote controller via HTTP POST.
async fn push_logs_to_remote(
    batch: &[WafLogEntry],
    remote_url: &str,
    client: &reqwest::Client,
    token: &Option<String>,
) {
    if batch.is_empty() || remote_url.is_empty() {
        return;
    }

    let url = format!("{}/api/v1/logs", remote_url.trim_end_matches('/'));
    let mut req = client.post(&url).json(batch);
    if let Some(ref t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    match req.send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                tracing::debug!("Pushed {} log entries to remote controller", batch.len());
            } else {
                tracing::warn!(
                    "Remote controller returned error: {} — logs are safe in local file",
                    resp.status()
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                "Failed to push logs to remote controller: {} — logs are safe in local file",
                e
            );
        }
    }
}

/// SQLITE mode: Batch insert logs to local SQLite + optional controller forwarding.
/// Holds a persistent connection — never open/close per flush.
struct SqliteLogWorker {
    controller_url: Option<String>,
    client: reqwest::Client,
    token: Option<String>,
    /// Shared connection, guarded by std Mutex, wrapped in Arc for spawn_blocking.
    conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>,
}

impl SqliteLogWorker {
    fn new(cfg: &LogWorkerConfig) -> Result<Self, rusqlite::Error> {
        let conn = rusqlite::Connection::open(&cfg.db_path)?;
        let _ = conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;");
        Ok(Self {
            controller_url: cfg.controller_url.clone(),
            client: build_client(),
            token: cfg.token.clone(),
            conn: std::sync::Arc::new(std::sync::Mutex::new(conn)),
        })
    }

    async fn flush(&self, batch: &[WafLogEntry]) {
        if batch.is_empty() {
            return;
        }
        let batch_len = batch.len();

        // Controller-forward mode (Agent → Controller)
        if let Some(ref ctrl_url) = self.controller_url {
            let url = format!("{}/api/v1/logs", ctrl_url.trim_end_matches('/'));
            let req = self.client.post(&url).json(batch);
            let req = if let Some(ref t) = self.token {
                req.header("Authorization", format!("Bearer {t}"))
            } else {
                req
            };
            // Fire-and-forget: error logged, never block proxy
            tokio::spawn(async move {
                if let Err(e) = req.send().await {
                    tracing::error!("Error posting logs to controller: {e}");
                }
            });
            return;
        }

        // Local SQLite insert inside spawn_blocking — never block async runtime
        let batch = batch.to_vec();
        let conn = self.conn.clone();
        let res = tokio::task::spawn_blocking(move || {
            let mut conn = match conn.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    tracing::error!("SQLite connection mutex poisoned, recovering");
                    poisoned.into_inner()
                }
            };
            let tx = conn.transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO request_log (timestamp, client_ip, method, path, action, rule_id, reason)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
                )?;
                for entry in &batch {
                    stmt.execute(rusqlite::params![
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
        })
        .await;

        match res {
            Ok(Ok(())) => tracing::debug!("Inserted {batch_len} logs into SQLite"),
            Ok(Err(e)) => tracing::error!("Failed SQLite insert ({batch_len}): {e}"),
            Err(_) => {
                tracing::error!("Blocking task panicked inserting {batch_len} logs into SQLite")
            }
        }
    }
}

async fn log_worker_sqlite(mut rx: Receiver<WafLogEntry>, cfg: LogWorkerConfig) {
    let writer = match SqliteLogWorker::new(&cfg) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(
                "Failed to open SQLite connection, falling back to file-only mode: {e}"
            );
            return log_worker_file(rx, cfg).await;
        }
    };

    let batch_interval = Duration::from_secs(1);
    let max_batch_size = 1000;
    let mut batch = Vec::new();
    let mut last_flush = tokio::time::Instant::now();

    tracing::info!(
        "Log worker started in SQLITE mode (persistent connection) → {}",
        cfg.db_path
    );

    loop {
        let timeout = batch_interval
            .checked_sub(last_flush.elapsed())
            .unwrap_or(Duration::from_millis(10));

        tokio::select! {
            Some(entry) = rx.recv() => {
                write_to_local_log(&entry, &cfg.log_path);

                batch.push(entry);
                if batch.len() >= max_batch_size {
                    writer.flush(&batch).await;
                    batch.clear();
                    last_flush = tokio::time::Instant::now();
                }
            }
            _ = tokio::time::sleep(timeout) => {
                if !batch.is_empty() {
                    writer.flush(&batch).await;
                    batch.clear();
                }
                last_flush = tokio::time::Instant::now();
            }
        }
    }
}

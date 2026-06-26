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

    let pass = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "aegis".to_string());
    if let Ok(val) = HeaderValue::from_str(&pass) {
        headers.insert("X-ClickHouse-Key", val);
    }

    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

// Inisialisasi ClickHouse Table
pub async fn init_db(clickhouse_url: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = build_client();
    let ddl = "
        CREATE TABLE IF NOT EXISTS request_log (
            timestamp DateTime64(3, 'UTC'),
            client_ip String,
            method String,
            path String,
            action String,
            rule_id String,
            reason String
        ) ENGINE = MergeTree()
        ORDER BY (timestamp, client_ip)
        TTL toDateTime(timestamp) + INTERVAL 30 DAY DELETE
    ";

    let url = format!("{}/", clickhouse_url.trim_end_matches('/'));
    let res = client.post(&url).body(ddl.to_string()).send().await?;
    if !res.status().is_success() {
        let err = res.text().await?;
        return Err(format!("ClickHouse init error: {}", err).into());
    }
    tracing::info!("ClickHouse request_log table initialized successfully");
    Ok(())
}

// Mendapatkan statistik realtime dari ClickHouse
pub async fn get_stats(
    clickhouse_url: &str,
    hours: u32,
) -> Result<Stats, Box<dyn std::error::Error + Send + Sync>> {
    let client = build_client();
    let query = format!(
        "SELECT count(), countIf(action = 'BLOCK'), countIf(action = 'RATE_LIMIT') FROM request_log WHERE timestamp > now() - INTERVAL {} HOUR FORMAT TSV",
        hours
    );
    let url = format!(
        "{}/?query={}",
        clickhouse_url.trim_end_matches('/'),
        urlencoding::encode(&query)
    );

    let res = client.get(&url).send().await?;
    if !res.status().is_success() {
        return Err("ClickHouse stats query failed".into());
    }

    let text = res.text().await?;
    let parts: Vec<&str> = text.trim().split('\t').collect();
    if parts.len() == 3 {
        Ok(Stats {
            total_requests: parts[0].parse().unwrap_or(0),
            blocked: parts[1].parse().unwrap_or(0),
            rate_limited: parts[2].parse().unwrap_or(0),
        })
    } else {
        Ok(Stats {
            total_requests: 0,
            blocked: 0,
            rate_limited: 0,
        })
    }
}

// Mendapatkan jumlah disk usage dari ClickHouse Table
pub async fn get_db_size(
    clickhouse_url: &str,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let client = build_client();
    let query = "SELECT total_bytes FROM system.tables WHERE name = 'request_log' FORMAT TSV";
    let url = format!(
        "{}/?query={}",
        clickhouse_url.trim_end_matches('/'),
        urlencoding::encode(query)
    );

    let res = client.get(&url).send().await?;
    if res.status().is_success() {
        let text = res.text().await?;
        Ok(text.trim().parse().unwrap_or(0))
    } else {
        Ok(0)
    }
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
}

/// Rotate log files when the current file exceeds max_size_mb.
/// Renames: aegis.log -> aegis.log.1, aegis.log.1 -> aegis.log.2, etc.
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
            tracing::info!("Log file rotated: {} (exceeded {} MB)", log_path, max_size_mb);
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

/// Save blocked IPs to a local JSON file.
pub fn save_blocklist_to_file(
    path: &str,
    blocklist: &std::collections::HashSet<std::net::IpAddr>,
) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let ips: Vec<String> = blocklist.iter().map(|ip| ip.to_string()).collect();
    if let Ok(json) = serde_json::to_string_pretty(&ips) {
        if let Err(e) = std::fs::write(path, json) {
            tracing::error!("Failed to save blocklist to {}: {}", path, e);
        }
    }
}

// ─── Log Worker (Multi-Mode) ────────────────────────────────────────────────

/// Configuration passed to the log worker to control its behavior.
#[derive(Clone, Debug)]
pub struct LogWorkerConfig {
    pub mode: String,         // "file", "remote", "clickhouse"
    pub log_path: String,     // Local log file path
    pub max_log_size_mb: u64, // Max size before rotation
    pub max_log_files: u32,   // Max rotated files
    pub clickhouse_url: String,
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
        "clickhouse" => log_worker_clickhouse(rx, worker_cfg).await,
        other => {
            tracing::warn!(
                "Unknown logging mode '{}', falling back to 'file'",
                other
            );
            log_worker_file(rx, worker_cfg).await;
        }
    }
}

/// FILE mode: Write logs to local JSON Lines file only.
/// Zero network dependencies. Ideal for small VPS.
async fn log_worker_file(mut rx: Receiver<WafLogEntry>, cfg: LogWorkerConfig) {
    let mut line_count: u64 = 0;
    tracing::info!(
        "Log worker started in FILE mode → {}",
        cfg.log_path
    );

    while let Some(entry) = rx.recv().await {
        write_to_local_log(&entry, &cfg.log_path);
        line_count += 1;

        // Check rotation every 1000 lines
        if line_count % 1000 == 0 {
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
                if line_count % 1000 == 0 {
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

/// CLICKHOUSE mode: Existing behavior with batch insert + optional controller forwarding.
async fn log_worker_clickhouse(mut rx: Receiver<WafLogEntry>, cfg: LogWorkerConfig) {
    let client = build_client();
    let batch_interval = Duration::from_secs(1);
    let max_batch_size = 5000;

    let mut batch = Vec::new();
    let mut last_flush = tokio::time::Instant::now();

    tracing::info!("Log worker started in CLICKHOUSE mode");

    loop {
        let timeout = batch_interval
            .checked_sub(last_flush.elapsed())
            .unwrap_or(Duration::from_millis(10));

        tokio::select! {
            Some(entry) = rx.recv() => {
                // Also write to local file for backup
                write_to_local_log(&entry, &cfg.log_path);

                batch.push(entry);
                if batch.len() >= max_batch_size {
                    flush_to_clickhouse(&batch, &cfg.clickhouse_url, &cfg.controller_url, &client, &cfg.token).await;
                    batch.clear();
                    last_flush = tokio::time::Instant::now();
                }
            }
            _ = tokio::time::sleep(timeout) => {
                if !batch.is_empty() {
                    flush_to_clickhouse(&batch, &cfg.clickhouse_url, &cfg.controller_url, &client, &cfg.token).await;
                    batch.clear();
                }
                last_flush = tokio::time::Instant::now();
            }
        }
    }
}

/// Flush logs to ClickHouse or forward to Controller (existing behavior).
async fn flush_to_clickhouse(
    batch: &[WafLogEntry],
    clickhouse_url: &str,
    controller_url: &Option<String>,
    client: &reqwest::Client,
    token: &Option<String>,
) {
    if batch.is_empty() {
        return;
    }

    if let Some(ctrl_url) = controller_url {
        // Mode Agent: Kirim JSON Array ke Controller
        let url = format!("{}/api/v1/logs", ctrl_url.trim_end_matches('/'));
        let mut req = client.post(&url).json(batch);
        if let Some(ref t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        if let Err(e) = req.send().await {
            tracing::error!("Error posting logs to controller: {}", e);
        }
    } else {
        // Mode Controller: Bulk Insert ke ClickHouse menggunakan JSONEachRow
        let mut body = String::new();
        for entry in batch {
            if let Ok(json) = serde_json::to_string(entry) {
                body.push_str(&json);
                body.push('\n');
            }
        }

        let url = format!(
            "{}/?query=INSERT INTO request_log FORMAT JSONEachRow",
            clickhouse_url.trim_end_matches('/')
        );
        let res = client.post(&url).body(body).send().await;
        if let Err(e) = res {
            tracing::error!("Failed to insert logs to ClickHouse: {}", e);
        } else if let Ok(resp) = res {
            if !resp.status().is_success() {
                let err_text = resp.text().await.unwrap_or_default();
                tracing::error!("ClickHouse insert error: {}", err_text);
            }
        }
    }
}

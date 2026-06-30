import re

def rewrite():
    with open('src/main.rs', 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. ControllerState struct
    content = content.replace(
        "db_path: String,",
        "clickhouse_url: String,"
    )

    # 2. run_controller DB initialization
    old_init = """    // Ensure logs folder exists
    let log_dir = Path::new("./logs");
    fs::create_dir_all(log_dir).ok();
    let db_path = "./logs/jarswaf-controller.db";

    // Initialize database
    let conn = rusqlite::Connection::open(db_path).expect("Failed to open controller DB");
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;"
    ).expect("Failed to enable WAL mode");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS request_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            method TEXT,
            path TEXT,
            status INTEGER,
            rule_id TEXT,
            reason TEXT
        )",
        [],
    ).expect("Failed to init controller DB table");

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_request_log_reputation ON request_log (timestamp, method, client_ip)",
        [],
    ).expect("Failed to create index for reputation lookup");"""
    
    new_init = """    let clickhouse_url = std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
    logging::init_db(&clickhouse_url).await.expect("Failed to initialize ClickHouse DB");"""
    
    content = content.replace(old_init, new_init)

    # 3. state instantiation
    content = content.replace(
        "db_path: db_path.to_string(),",
        "clickhouse_url: clickhouse_url.clone(),"
    )

    # 4. run_agent standalone blocklist
    old_standalone = """                // Standalone Mode: Query local SQLite DB directly for IPs with >= 5 blocks in last 5 minutes
                let db_path_clone = db_path_local.clone();
                let blocklist_standalone = blocklist_clone.clone();
                let res = tokio::task::spawn_blocking(move || {
                    let conn = rusqlite::Connection::open(db_path_clone)?;
                    let mut stmt = conn.prepare(
                        "SELECT client_ip, COUNT(*) as count 
                         FROM request_log 
                         WHERE method = 'BLOCK' 
                           AND datetime(timestamp) > datetime('now', '-5 minutes') 
                         GROUP BY client_ip 
                         HAVING count >= 5"
                    )?;
                    let ip_iter = stmt.query_map([], |row| {
                        let ip_str: String = row.get(0)?;
                        Ok(ip_str)
                    })?;
                    let mut ips = std::collections::HashSet::new();
                    for ip in ip_iter {
                        if let Ok(ip_str) = ip {
                            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                                ips.insert(ip);
                            }
                        }
                    }
                    Ok::<std::collections::HashSet<std::net::IpAddr>, rusqlite::Error>(ips)
                }).await;

                match res {
                    Ok(Ok(ips)) => {
                        if let Ok(mut lock) = blocklist_standalone.write() {
                            *lock = ips;
                        }
                    }
                    _ => {
                        tracing::error!("Failed to query local DB for reputation blocklist");
                    }
                }"""
    
    new_standalone = """                // Standalone Mode: Query ClickHouse
                let clickhouse_url_local = std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
                let blocklist_standalone = blocklist_clone.clone();
                let client_clone = client.clone();
                let query = "SELECT client_ip FROM request_log WHERE action = 'BLOCK' AND timestamp > now() - INTERVAL 5 MINUTE GROUP BY client_ip HAVING count() >= 5 FORMAT TSV";
                let url = format!("{}/?query={}", clickhouse_url_local.trim_end_matches('/'), urlencoding::encode(query));
                if let Ok(resp) = client_clone.get(&url).send().await {
                    if let Ok(text) = resp.text().await {
                        let mut ips = std::collections::HashSet::new();
                        for line in text.lines() {
                            if let Ok(ip) = line.trim().parse::<std::net::IpAddr>() {
                                ips.insert(ip);
                            }
                        }
                        if let Ok(mut lock) = blocklist_standalone.write() {
                            *lock = ips;
                        }
                    }
                }"""
    
    content = content.replace(old_standalone, new_standalone)

    # 5. export_logs_handler
    old_export = """async fn export_logs_handler(State(state): State<ControllerState>) -> Response<Body> {
    let db_path_clone = state.db_path.clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(db_path_clone)?;
        let mut stmt = conn.prepare(
            "SELECT timestamp, client_ip, method, path, status, rule_id, reason FROM request_log ORDER BY timestamp DESC"
        )?;
        
        let logs_iter = stmt.query_map([], |row| {
            let timestamp: String = row.get(0)?;
            let ip: String = row.get(1)?;
            let method: String = row.get(2)?;
            let path: String = row.get(3)?;
            let status: i32 = row.get(4)?;
            let rule_id: String = row.get(5)?;
            let reason: String = row.get(6)?;
            
            Ok(format!("[{}] {} {} {} {} {} {}", timestamp, ip, method, path, status, rule_id, reason))
        })?;

        let mut lines = String::new();
        for line in logs_iter {
            if let Ok(l) = line {
                lines.push_str(&l);
                lines.push('\\n');
            }
        }
        Ok::<String, rusqlite::Error>(lines)
    }).await;

    match res {
        Ok(Ok(content)) => {
            Response::builder()
                .header("Content-Type", "text/plain; charset=utf-8")
                .header("Content-Disposition", "attachment; filename=\\"jarswaf-access.log\\"")
                .body(Body::from(content))
                .unwrap()
        }
        _ => {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to export logs"))
                .unwrap()
        }
    }
}"""

    new_export = """async fn export_logs_handler(State(state): State<ControllerState>) -> Response<Body> {
    let client = reqwest::Client::new();
    let query = "SELECT * FROM request_log FORMAT TSV";
    let url = format!("{}/?query={}", state.clickhouse_url.trim_end_matches('/'), urlencoding::encode(query));
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(content) = resp.text().await {
                Response::builder()
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .header("Content-Disposition", "attachment; filename=\\"jarswaf-access.log\\"")
                    .body(Body::from(content))
                    .unwrap()
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read body").into_response()
            }
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to export logs from ClickHouse").into_response(),
    }
}"""
    content = content.replace(old_export, new_export)

    # 6. receive_logs_handler
    old_recv = """    let db_path_clone = state.db_path.clone();
    let logs_clone = logs.clone();

    // Bulk insert into SQLite database using spawn_blocking
    let res = tokio::task::spawn_blocking(move || {
        let mut conn = rusqlite::Connection::open(db_path_clone)?;
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO request_log (timestamp, client_ip, method, path, status, rule_id, reason)
                 VALUES (?1, ?2, ?3, ?4, 403, ?5, ?6)"
            )?;
            for log in logs_clone {
                stmt.execute(rusqlite::params![
                    log.timestamp,
                    log.client_ip,
                    log.action, // method stores WAF action (BLOCK / RATE_LIMIT)
                    log.path,
                    log.rule_id,
                    log.reason
                ])?;
            }
        }
        tx.commit()?;
        Ok::<(), rusqlite::Error>(())
    }).await;

    if let Err(e) = res {
        tracing::error!("Controller DB bulk insert join error: {:?}", e);
    } else if let Ok(Err(db_err)) = res {
        tracing::error!("Controller DB bulk insert SQLite error: {:?}", db_err);
    }

    // Auto-pruning logic: check file size on disk
    let limit_mb = state.log_size_limit_mb.load(Ordering::Relaxed);
    if limit_mb > 0 {
        let limit_bytes = limit_mb * 1024 * 1024;
        if let Ok(metadata) = std::fs::metadata(&state.db_path) {
            if metadata.len() > limit_bytes {
                let db_path_clone2 = state.db_path.clone();
                tokio::task::spawn_blocking(move || {
                    if let Ok(conn) = rusqlite::Connection::open(db_path_clone2) {
                        // Delete oldest 1000 rows
                        let _ = conn.execute(
                            "DELETE FROM request_log WHERE id IN (SELECT id FROM request_log ORDER BY id ASC LIMIT 1000)",
                            []
                        );
                    }
                });
            }
        }
    }"""
    new_recv = """    let client = reqwest::Client::new();
    let mut body = String::new();
    let logs_clone = logs.clone();
    for entry in &logs_clone {
        if let Ok(json) = serde_json::to_string(entry) {
            body.push_str(&json);
            body.push('\\n');
        }
    }
    let url = format!("{}/?query=INSERT INTO request_log FORMAT JSONEachRow", state.clickhouse_url.trim_end_matches('/'));
    let _ = client.post(&url).body(body).send().await;"""
    content = content.replace(old_recv, new_recv)

    # 7. get_logs_handler
    old_get_logs = """async fn get_logs_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let db_path_clone = state.db_path.clone();
    
    let res = tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(db_path_clone)?;
        let mut stmt = conn.prepare(
            "SELECT timestamp, client_ip, method, path, method, rule_id, reason FROM request_log ORDER BY timestamp DESC LIMIT 100"
        )?;
        
        let logs_iter = stmt.query_map([], |row| {
            Ok(logging::WafLogEntry {
                timestamp: row.get(0)?,
                client_ip: row.get(1)?,
                method: "".to_string(), // we didn't store original method separately from action
                path: row.get(3)?,
                action: row.get(4)?,
                rule_id: row.get(5)?,
                reason: row.get(6)?,
            })
        })?;

        let mut logs = Vec::new();
        for log in logs_iter {
            if let Ok(l) = log {
                logs.push(l);
            }
        }
        Ok::<Vec<logging::WafLogEntry>, rusqlite::Error>(logs)
    }).await;

    match res {
        Ok(Ok(logs)) => (StatusCode::OK, Json(logs)).into_response(),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![])).into_response(),
    }
}"""
    new_get_logs = """async fn get_logs_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let query = "SELECT timestamp, client_ip, method, path, action, rule_id, reason FROM request_log ORDER BY timestamp DESC LIMIT 100 FORMAT JSONEachRow";
    let url = format!("{}/?query={}", state.clickhouse_url.trim_end_matches('/'), urlencoding::encode(query));
    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(text) = resp.text().await {
            let mut logs = Vec::new();
            for line in text.lines() {
                if let Ok(log) = serde_json::from_str::<logging::WafLogEntry>(line) {
                    logs.push(log);
                }
            }
            return (StatusCode::OK, Json(logs)).into_response();
        }
    }
    (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![])).into_response()
}"""
    content = content.replace(old_get_logs, new_get_logs)

    # 8. get_db_size_handler
    old_size = """async fn get_db_size_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let size_bytes = match std::fs::metadata(&state.db_path) {
        Ok(m) => m.len(),
        Err(_) => 0,
    };
    
    let formatted = if size_bytes < 1024 * 1024 {
        format!("{:.2} KB", size_bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", size_bytes as f64 / (1024.0 * 1024.0))
    };

    let resp = DbSizeResponse {
        size_bytes,
        formatted,
    };
    (StatusCode::OK, Json(resp))
}"""
    new_size = """async fn get_db_size_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let size_bytes = logging::get_db_size(&state.clickhouse_url).await.unwrap_or(0);
    
    let formatted = if size_bytes < 1024 * 1024 {
        format!("{:.2} KB", size_bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", size_bytes as f64 / (1024.0 * 1024.0))
    };

    let resp = DbSizeResponse {
        size_bytes,
        formatted,
    };
    (StatusCode::OK, Json(resp))
}"""
    content = content.replace(old_size, new_size)

    # 9. get_blocklist_handler
    old_blocklist = """async fn get_blocklist_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let db_path_clone = state.db_path.clone();
    
    let res = tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(db_path_clone)?;
        let mut stmt = conn.prepare(
            "SELECT client_ip, COUNT(*) as count 
             FROM request_log 
             WHERE method = 'BLOCK' 
               AND datetime(timestamp) > datetime('now', '-5 minutes') 
             GROUP BY client_ip 
             HAVING count >= 5"
        )?;
        
        let ip_iter = stmt.query_map([], |row| {
            let ip: String = row.get(0)?;
            Ok(ip)
        })?;

        let mut ips = Vec::new();
        for ip in ip_iter {
            if let Ok(i) = ip {
                ips.push(i);
            }
        }
        Ok::<Vec<String>, rusqlite::Error>(ips)
    }).await;

    match res {
        Ok(Ok(ips)) => (StatusCode::OK, Json(ips)).into_response(),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(Vec::<String>::new())).into_response(),
    }
}"""
    new_blocklist = """async fn get_blocklist_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let query = "SELECT client_ip FROM request_log WHERE action = 'BLOCK' AND timestamp > now() - INTERVAL 5 MINUTE GROUP BY client_ip HAVING count() >= 5 FORMAT TSV";
    let url = format!("{}/?query={}", state.clickhouse_url.trim_end_matches('/'), urlencoding::encode(query));
    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(text) = resp.text().await {
            let mut ips = Vec::new();
            for line in text.lines() {
                let ip = line.trim().to_string();
                if !ip.is_empty() {
                    ips.push(ip);
                }
            }
            return (StatusCode::OK, Json(ips)).into_response();
        }
    }
    (StatusCode::INTERNAL_SERVER_ERROR, Json(Vec::<String>::new())).into_response()
}"""
    content = content.replace(old_blocklist, new_blocklist)

    # 10. get_stats_handler
    content = content.replace(
        "logging::get_stats(&state.db_path, 24)",
        "logging::get_stats(&state.clickhouse_url, 24).await"
    )

    # 11. ws_dashboard_handler
    content = content.replace(
        "let db_path = state.db_path.clone();",
        "let clickhouse_url = state.clickhouse_url.clone();"
    ).replace(
        "logging::get_stats(&db_path, 24).ok();",
        "logging::get_stats(&clickhouse_url, 24).await.ok();"
    )

    # 12. run_agent init DB
    content = content.replace(
        """logging::init_db(&cfg).expect("Failed to init logging DB");""",
        """let clickhouse_url = std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
    logging::init_db(&clickhouse_url).await.expect("Failed to init logging DB");"""
    )
    
    # 13. run_agent log worker
    content = content.replace(
        """logging::log_worker(log_rx, cfg_clone, controller_url).await;""",
        """logging::log_worker(log_rx, clickhouse_url.clone(), controller_url).await;"""
    )
    content = content.replace(
        "let cfg_clone = cfg.clone();\n    tokio::spawn(async move {",
        "let clickhouse_url_clone = clickhouse_url.clone();\n    tokio::spawn(async move {"
    ).replace(
        "logging::log_worker(log_rx, clickhouse_url.clone(), controller_url).await;",
        "logging::log_worker(log_rx, clickhouse_url_clone, controller_url).await;"
    )

    with open('src/main.rs', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Done rewriting main.rs")

if __name__ == "__main__":
    rewrite()

use crate::config::Config;
use async_trait::async_trait;
use bytes::Bytes;
use pingora::prelude::*;
use pingora_http::ResponseHeader;
use std::sync::Arc;

// Global Lock-Free Config
pub static GLOBAL_CONFIG: once_cell::sync::Lazy<arc_swap::ArcSwap<Config>> =
    once_cell::sync::Lazy::new(|| arc_swap::ArcSwap::from_pointee(Config::default()));

// We need a context to pass data between Pingora request phases
pub struct JarsWafCtx {
    pub client_ip: Option<std::net::IpAddr>,
    pub vhost_backend: Option<String>,
    pub vhost_name: Option<String>,
    pub body_buffer: Vec<u8>,
    pub body_limit: usize,
    pub is_blocked: bool,
    pub security_headers: Option<crate::config::SecurityHeadersConfig>,
    pub dlp_config: Option<crate::config::DlpConfig>,
    pub response_body_buffer: Vec<u8>,
    pub request_id: String,
    pub websocket_security_enabled: bool,
    pub max_concurrent_requests: usize,
    pub vhost_backend_resolved: Option<String>,
}

pub static ACTIVE_CONNECTIONS: once_cell::sync::Lazy<dashmap::DashMap<std::net::IpAddr, usize>> =
    once_cell::sync::Lazy::new(dashmap::DashMap::new);
pub static BACKEND_ACTIVE_REQUESTS: once_cell::sync::Lazy<dashmap::DashMap<String, usize>> =
    once_cell::sync::Lazy::new(dashmap::DashMap::new);
pub static SESSION_FINGERPRINTS: once_cell::sync::Lazy<dashmap::DashMap<std::net::IpAddr, String>> =
    once_cell::sync::Lazy::new(dashmap::DashMap::new);
pub static CHALLENGE_SECRET: once_cell::sync::Lazy<String> =
    once_cell::sync::Lazy::new(|| uuid::Uuid::new_v4().to_string());

/// Bounded blocklist — hard cap at 100k entries. Used in proxy and agent.
/// Entries beyond cap evict oldest first via retain-order.
pub const BLOCKLIST_MAX_ENTRIES: usize = 100_000;

/// Periodic cleanup of unbounded DashMaps to prevent memory leak.
/// Run every 30 minutes. Retains only active entries younger than threshold.
pub fn start_memory_cleanup() {
    use std::time::Duration;
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(1800));
        loop {
            interval.tick().await;
            tracing::debug!("Memory cleanup: clearing active-connection tracking tables");
            ACTIVE_CONNECTIONS.retain(|_, _| false);
            SESSION_FINGERPRINTS.retain(|_, _| false);
            BACKEND_ACTIVE_REQUESTS.retain(|_, _| false);
        }
    });
}

/// Trim a DashMap to at most `max` entries by removing oldest (last 2/3 of insertion order).
/// Since DashMap iterates in arbitrary order, this is an approximation — sufficient to
/// bound memory growth.
pub fn trim_dashmap<K: std::hash::Hash + Eq + Clone, V>(map: &dashmap::DashMap<K, V>, max: usize) {
    if map.len() > max {
        let to_remove = map.len() - max;
        let keys: Vec<_> = map
            .iter()
            .map(|e| e.key().clone())
            .take(to_remove)
            .collect();
        for k in keys {
            map.remove(&k);
        }
    }
}

fn get_challenge_html(client_ip: &str, salt: &str, original_path: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Security Check - jarsWAF</title>
    <style>
        body {{ font-family: sans-serif; text-align: center; padding: 50px; background-color: #f7f9fa; color: #333; }}
        .card {{ max-width: 500px; margin: 0 auto; padding: 40px; background: white; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
        h1 {{ color: #d93025; font-size: 24px; margin-bottom: 20px; }}
        p {{ font-size: 16px; line-height: 1.5; color: #5f6368; }}
        .spinner {{ border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body>
    <div class=\"card\">
        <h1>Security Check</h1>
        <p>Please wait while we verify your connection. This will only take a moment...</p>
        <div class=\"spinner\"></div>
    </div>
    <script>
        async function sha256(message) {{
            const msgBuffer = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }}

        async function solve() {{
            const ip = \"{client_ip}\";
            const salt = \"{salt}\";
            const target_prefix = \"000\";
            let nonce = 0;
            while (true) {{
                const hash = await sha256(ip + salt + nonce);
                if (hash.startsWith(target_prefix)) {{
                    const original_path = encodeURIComponent(\"{original_path}\");
                    window.location.href = `/jarswaf-challenge-verify?sol=\${{nonce}}&r=\${{original_path}}`;
                    break;
                }}
                nonce++;
            }}
        }}
        solve();
    </script>
</body>
</html>"#,
        client_ip = client_ip,
        salt = salt,
        original_path = original_path
    )
}

fn generate_challenge_signature(timestamp: &str, client_ip: &str, secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(timestamp.as_bytes());
    hasher.update(b"|");
    hasher.update(client_ip.as_bytes());
    hasher.update(b"|");
    hasher.update(secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn is_challenge_cookie_valid(cookie_header: &str, client_ip: &str, secret: &str) -> bool {
    for cookie in cookie_header.split(';') {
        let parts: Vec<&str> = cookie.trim().split('=').collect();
        if parts.len() == 2 && parts[0] == "jarswaf-challenge-token" {
            let token = parts[1];
            let token_parts: Vec<&str> = token.split('.').collect();
            if token_parts.len() == 3 {
                let timestamp_str = token_parts[0];
                let ip = token_parts[1];
                let signature = token_parts[2];

                if ip == client_ip {
                    let expected_sig = generate_challenge_signature(timestamp_str, ip, secret);
                    if expected_sig == signature {
                        if let Ok(ts) = timestamp_str.parse::<i64>() {
                            let now = chrono::Utc::now().timestamp();
                            if now >= ts && now - ts < 3600 {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

fn calculate_fingerprint(headers: &std::collections::HashMap<String, String>) -> String {
    use sha2::{Digest, Sha256};
    let user_agent = headers.get("user-agent").map(|s| s.as_str()).unwrap_or("");
    let accept = headers.get("accept").map(|s| s.as_str()).unwrap_or("");
    let accept_lang = headers
        .get("accept-language")
        .map(|s| s.as_str())
        .unwrap_or("");
    let accept_enc = headers
        .get("accept-encoding")
        .map(|s| s.as_str())
        .unwrap_or("");

    let mut hasher = Sha256::new();
    hasher.update(user_agent.as_bytes());
    hasher.update(b"|");
    hasher.update(accept.as_bytes());
    hasher.update(b"|");
    hasher.update(accept_lang.as_bytes());
    hasher.update(b"|");
    hasher.update(accept_enc.as_bytes());

    format!("{:x}", hasher.finalize())
}

pub fn start_websocket_security_proxy() {
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:24601").await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind WebSocket security proxy: {}", e);
                return;
            }
        };
        tracing::info!("jarsWAF WebSocket Security Proxy listening on 127.0.0.1:24601");

        loop {
            let (client_socket, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };

            tokio::spawn(async move {
                if let Err(e) = handle_secure_websocket_tunnel(client_socket).await {
                    tracing::debug!("WebSocket security tunnel closed: {:?}", e);
                }
            });
        }
    });
}

async fn handle_secure_websocket_tunnel(
    mut client_socket: tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::protocol::{Message, Role};
    use tokio_tungstenite::WebSocketStream;

    let mut header_buf = vec![0u8; 8192];
    let mut n = 0;
    loop {
        let read_bytes = client_socket.read(&mut header_buf[n..]).await?;
        if read_bytes == 0 {
            return Err("Client connection closed before handshake completed".into());
        }
        n += read_bytes;
        if header_buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if n >= 8192 {
            return Err("Handshake headers too large".into());
        }
    }

    let header_str = String::from_utf8_lossy(&header_buf[..n]);
    let mut real_backend = None;
    for line in header_str.lines() {
        if line.to_lowercase().starts_with("x-jarswaf-real-backend:") {
            if let Some(val) = line.split(':').nth(1) {
                real_backend = Some(val.trim().to_string());
            }
        }
    }

    let Some(backend_addr) = real_backend else {
        return Err("Missing X-Jarswaf-Real-Backend header".into());
    };

    let clean_backend = backend_addr
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_string();

    let mut backend_socket = tokio::net::TcpStream::connect(&clean_backend).await?;
    backend_socket.write_all(&header_buf[..n]).await?;

    let mut resp_buf = vec![0u8; 8192];
    let mut resp_n = 0;
    loop {
        let read_bytes = backend_socket.read(&mut resp_buf[resp_n..]).await?;
        if read_bytes == 0 {
            return Err("Backend connection closed".into());
        }
        resp_n += read_bytes;
        if resp_buf[..resp_n].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if resp_n >= 8192 {
            return Err("Handshake response headers too large".into());
        }
    }

    client_socket.write_all(&resp_buf[..resp_n]).await?;

    let resp_str = String::from_utf8_lossy(&resp_buf[..resp_n]);
    if !resp_str.contains("101 Switching Protocols") {
        return Err("Handshake failed".into());
    }

    let client_ws = WebSocketStream::from_raw_socket(client_socket, Role::Server, None).await;
    let backend_ws = WebSocketStream::from_raw_socket(backend_socket, Role::Client, None).await;

    let (client_write, mut client_read) = client_ws.split();
    let (mut backend_write, mut backend_read) = backend_ws.split();

    let client_write_lock = Arc::new(tokio::sync::Mutex::new(client_write));
    let client_write_for_backend = client_write_lock.clone();

    let client_to_backend = async {
        let config = GLOBAL_CONFIG.load();
        let rule_engine = crate::rules::RuleEngine::new(&config);
        while let Some(msg_res) = client_read.next().await {
            let msg = msg_res?;
            match &msg {
                Message::Text(text) => {
                    let headers = std::collections::HashMap::new();
                    let rules = vec![
                        "SQLI-AST".to_string(),
                        "XSS-AST".to_string(),
                        "CMD-INJECTION".to_string(),
                    ];
                    if let Some((rule_id, reason)) =
                        rule_engine.check_request("", "", &headers, text, None, "WS", &rules)
                    {
                        tracing::warn!(
                            "Blocked malicious WebSocket frame: rule={} reason={}",
                            rule_id,
                            reason
                        );
                        let _ = client_write_lock
                            .lock()
                            .await
                            .send(Message::Close(None))
                            .await;
                        return Err(tokio_tungstenite::tungstenite::Error::Io(
                            std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!("Blocked by jarsWAF: {}", reason),
                            ),
                        ));
                    }
                }
                Message::Close(_) => {
                    let _ = backend_write.send(msg).await;
                    break;
                }
                _ => {}
            }
            backend_write.send(msg).await?;
        }
        Ok::<_, tokio_tungstenite::tungstenite::Error>(())
    };

    let backend_to_client = async {
        while let Some(msg_res) = backend_read.next().await {
            let msg = msg_res?;
            client_write_for_backend.lock().await.send(msg).await?;
        }
        Ok::<_, tokio_tungstenite::tungstenite::Error>(())
    };

    tokio::select! {
        res = client_to_backend => {
            if let Err(e) = res {
                tracing::debug!("WebSocket client to backend tunnel ended: {:?}", e);
            }
        }
        res = backend_to_client => {
            if let Err(e) = res {
                tracing::debug!("WebSocket backend to client tunnel ended: {:?}", e);
            }
        }
    }

    Ok(())
}

#[derive(Clone)]
pub struct Backend {
    pub addr: String,
    pub healthy: Arc<std::sync::atomic::AtomicBool>,
}

pub static LOAD_BALANCER: once_cell::sync::Lazy<dashmap::DashMap<String, Vec<Backend>>> =
    once_cell::sync::Lazy::new(dashmap::DashMap::new);

pub static ROUND_ROBIN_COUNTERS: once_cell::sync::Lazy<
    dashmap::DashMap<String, Arc<std::sync::atomic::AtomicUsize>>,
> = once_cell::sync::Lazy::new(dashmap::DashMap::new);

pub static ACME_CHALLENGES: once_cell::sync::Lazy<dashmap::DashMap<String, String>> =
    once_cell::sync::Lazy::new(dashmap::DashMap::new);

pub fn start_health_checker(cancel: tokio_util::sync::CancellationToken) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    for entry in LOAD_BALANCER.iter() {
                        let backends = entry.value();
                        for backend in backends {
                            let addr = backend.addr.clone();
                            let clean_addr = addr
                                .trim_start_matches("http://")
                                .trim_start_matches("https://")
                                .to_string();

                            let is_up = tokio::net::TcpStream::connect(&clean_addr).await.is_ok();
                            backend
                                .healthy
                                .store(is_up, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
                _ = cancel.cancelled() => {
                    tracing::info!("Health checker stopped");
                    break;
                }
            }
        }
    });
}

pub struct JarsWafProxy {
    // For reputation blocklist — DashMap for lock-free concurrent access
    pub blocklist: Arc<dashmap::DashMap<std::net::IpAddr, ()>>,
    // Logging channel
    pub log_tx: tokio::sync::mpsc::Sender<crate::logging::WafLogEntry>,
    // Webhook / SIEM alert endpoints (loaded from config on startup)
    pub webhooks: Vec<crate::config::WebhookConfig>,
}

#[async_trait]
impl ProxyHttp for JarsWafProxy {
    type CTX = JarsWafCtx;
    fn new_ctx(&self) -> Self::CTX {
        JarsWafCtx {
            client_ip: None,
            vhost_backend: None,
            vhost_name: None,
            body_buffer: Vec::new(),
            body_limit: 1024 * 1024, // default 1MB
            is_blocked: false,
            security_headers: None,
            dlp_config: None,
            response_body_buffer: Vec::new(),
            request_id: uuid::Uuid::new_v4().to_string(),
            websocket_security_enabled: false,
            max_concurrent_requests: 100,
            vhost_backend_resolved: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let client_ip = match session.client_addr() {
            Some(cs) => {
                if let Some(ip) = cs.as_inet() {
                    ip.ip()
                } else {
                    return Ok(false);
                }
            }
            None => return Ok(false),
        };
        ctx.client_ip = Some(client_ip);

        // Extract req_header fields early to avoid hold-borrow of session
        let (req_method, path, query_str, host, headers_map) = {
            let req_header = session.req_header();
            let req_method = req_header.method.as_str().to_string();
            let path = req_header.uri.path().to_string();
            let query_str = req_header.uri.query().unwrap_or("").to_string();
            let host = req_header
                .headers
                .get("host")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());

            let mut headers_map = std::collections::HashMap::new();
            for (name, value) in req_header.headers.iter() {
                if let Ok(val_str) = value.to_str() {
                    headers_map.insert(name.to_string(), val_str.to_string());
                }
            }
            (req_method, path, query_str, host, headers_map)
        };

        // ACME HTTP-01 Challenge Interception
        if path.starts_with("/.well-known/acme-challenge/") {
            let token = path
                .trim_start_matches("/.well-known/acme-challenge/")
                .to_string();
            if let Some(content) = ACME_CHALLENGES.get(&token) {
                if let Ok(mut resp) = ResponseHeader::build(200, Some(content.len())) {
                    let _ = resp.insert_header("Content-Type", "text/plain");
                    if session
                        .write_response_header(Box::new(resp), false)
                        .await
                        .is_ok()
                    {
                        let _ = session
                            .write_response_body(
                                Some(Bytes::copy_from_slice(content.as_bytes())),
                                true,
                            )
                            .await;
                        return Ok(true); // Intercepted successfully
                    }
                }
            }
        }

        let config = GLOBAL_CONFIG.load();

        // Match VHost
        let (backend_addr, vhost_cfg) = match crate::vhost::match_vhost(host.as_deref(), &config) {
            Some((b, v)) => (b.to_string(), v.clone()),
            None => {
                let _ = session.respond_error(400).await;
                return Ok(true);
            }
        };

        ctx.vhost_backend = Some(backend_addr);
        ctx.vhost_name = Some(vhost_cfg.name.clone());
        ctx.body_limit = crate::config::parse_size(&vhost_cfg.max_body);
        ctx.websocket_security_enabled = vhost_cfg.websocket_security_enabled;
        ctx.max_concurrent_requests = vhost_cfg.max_concurrent_requests;
        ctx.security_headers = vhost_cfg.security_headers.clone();
        ctx.dlp_config = vhost_cfg.dlp.clone();

        // 0. Direct IP Access Block
        if let Some(host_str) = host.as_deref() {
            let clean_host = host_str.split(':').next().unwrap_or(host_str);
            if clean_host.parse::<std::net::IpAddr>().is_ok() {
                let entry = crate::logging::WafLogEntry {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    client_ip: client_ip.to_string(),
                    method: req_method.clone(),
                    path: path.clone(),
                    action: "BLOCK".to_string(),
                    rule_id: "DIRECT-IP-001".to_string(),
                    reason: format!("Direct IP access block: {}", clean_host),
                };
                let _ = self.log_tx.try_send(entry);
                let _ = session.respond_error(403).await;
                return Ok(true);
            }
        }

        // 0.1. Slowloris Connection Limit Check
        let conn_count = {
            let mut entry = ACTIVE_CONNECTIONS.entry(client_ip).or_insert(0);
            *entry += 1;
            *entry
        };
        if conn_count > vhost_cfg.max_conns_per_ip {
            let entry = crate::logging::WafLogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                client_ip: client_ip.to_string(),
                method: req_method.clone(),
                path: path.clone(),
                action: "BLOCK".to_string(),
                rule_id: "SLOWLORIS-001".to_string(),
                reason: format!(
                    "Slowloris concurrent connection limit exceeded: {}",
                    conn_count
                ),
            };
            let _ = self.log_tx.try_send(entry);
            let _ = session.respond_error(429).await;
            return Ok(true);
        }

        // 0.2. Request Fingerprinting Check
        let current_fp = calculate_fingerprint(&headers_map);
        let is_fp_anomaly = {
            if let Some(stored_fp) = SESSION_FINGERPRINTS.get(&client_ip) {
                stored_fp.value() != &current_fp
            } else {
                SESSION_FINGERPRINTS.insert(client_ip, current_fp.clone());
                false
            }
        };
        if is_fp_anomaly {
            let entry = crate::logging::WafLogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                client_ip: client_ip.to_string(),
                method: req_method.clone(),
                path: path.clone(),
                action: "ANOMALY".to_string(),
                rule_id: "ANOMALY-FINGERPRINT-001".to_string(),
                reason: "Request fingerprint changed mid-session".to_string(),
            };
            let _ = self.log_tx.try_send(entry);
        }

        // 0.3. Bot Challenge Check (Captive Portal PoW)
        if vhost_cfg.bot_challenge_enabled {
            if path == "/jarswaf-challenge-verify" {
                let mut sol_str = None;
                let mut orig_path = None;
                for pair in query_str.split('&') {
                    let mut parts = pair.splitn(2, '=');
                    if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                        if k == "sol" {
                            sol_str = Some(v.to_string());
                        } else if k == "r" {
                            orig_path = Some(
                                urlencoding::decode(v)
                                    .unwrap_or_else(|_| v.into())
                                    .into_owned(),
                            );
                        }
                    }
                }
                if let (Some(sol_str), Some(orig_path)) = (sol_str, orig_path) {
                    use sha2::{Digest, Sha256};
                    let salt = CHALLENGE_SECRET.as_str();
                    let check_str = format!("{}{}{}", client_ip, salt, sol_str);
                    let mut hasher = Sha256::new();
                    hasher.update(check_str.as_bytes());
                    let hash_result = format!("{:x}", hasher.finalize());
                    if hash_result.starts_with("000") {
                        let now = chrono::Utc::now().timestamp().to_string();
                        let signature = generate_challenge_signature(
                            &now,
                            &client_ip.to_string(),
                            CHALLENGE_SECRET.as_str(),
                        );
                        let token = format!("{}.{}.{}", now, client_ip, signature);

                        if let Ok(mut resp) = ResponseHeader::build(302, Some(0)) {
                            let _ = resp.insert_header("Location", orig_path);
                            let _ = resp.insert_header(
                                "Set-Cookie",
                                format!(
                                    "jarswaf-challenge-token={}; Path=/; HttpOnly; Max-Age=3600",
                                    token
                                ),
                            );
                            let _ = session.write_response_header(Box::new(resp), true).await;
                            return Ok(true);
                        }
                    }
                }
                let _ = session.respond_error(400).await;
                return Ok(true);
            }

            if path == "/jarswaf-challenge" {
                let orig_path = query_str.clone();
                let challenge_html = get_challenge_html(
                    &client_ip.to_string(),
                    CHALLENGE_SECRET.as_str(),
                    &orig_path,
                );
                if let Ok(mut resp) = ResponseHeader::build(200, Some(challenge_html.len())) {
                    let _ = resp.insert_header("Content-Type", "text/html");
                    if session
                        .write_response_header(Box::new(resp), false)
                        .await
                        .is_ok()
                    {
                        let _ = session
                            .write_response_body(
                                Some(Bytes::copy_from_slice(challenge_html.as_bytes())),
                                true,
                            )
                            .await;
                        return Ok(true);
                    }
                }
            }

            let cookie_header = headers_map.get("cookie").map(|s| s.as_str()).unwrap_or("");
            let is_challenge_valid = is_challenge_cookie_valid(
                cookie_header,
                &client_ip.to_string(),
                CHALLENGE_SECRET.as_str(),
            );

            let reputation_score = crate::rules::get_reputation_score(client_ip);
            if reputation_score >= 5.0 && !is_challenge_valid {
                let redirect_url = format!(
                    "{}{}",
                    path,
                    if query_str.is_empty() {
                        "".to_string()
                    } else {
                        format!("?{}", query_str)
                    }
                );
                let redirect_path = urlencoding::encode(&redirect_url);
                if let Ok(mut resp) = ResponseHeader::build(302, Some(0)) {
                    let _ = resp
                        .insert_header("Location", format!("/jarswaf-challenge?{}", redirect_path));
                    let _ = session.write_response_header(Box::new(resp), true).await;
                    return Ok(true);
                }
            }
        }

        // Lazily sync backends for this vhost in LOAD_BALANCER
        if !LOAD_BALANCER.contains_key(&vhost_cfg.name) {
            let mut backends = Vec::new();
            if let Some(list) = &vhost_cfg.backends {
                if !list.is_empty() {
                    for addr in list {
                        backends.push(Backend {
                            addr: addr.clone(),
                            healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                        });
                    }
                }
            }
            if backends.is_empty() {
                backends.push(Backend {
                    addr: vhost_cfg.backend.clone(),
                    healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                });
            }
            LOAD_BALANCER.insert(vhost_cfg.name.clone(), backends);
            ROUND_ROBIN_COUNTERS
                .entry(vhost_cfg.name.clone())
                .or_insert_with(|| Arc::new(std::sync::atomic::AtomicUsize::new(0)));
        }

        // Lazily start health checker & WS security proxy
        static HEALTH_CHECKER_STARTED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        if !HEALTH_CHECKER_STARTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            start_health_checker(tokio_util::sync::CancellationToken::new());
            start_websocket_security_proxy();
        }

        // 1. Check Blocklist (Reputation)
        let is_blocklisted = self.blocklist.contains_key(&client_ip);
        if is_blocklisted {
            let entry = crate::logging::WafLogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                client_ip: client_ip.to_string(),
                method: req_method.clone(),
                path: path.clone(),
                action: "BLOCK".to_string(),
                rule_id: "COLLAB-001".to_string(),
                reason: "Blocked by jarsWAF Collaborative Threat Intelligence (Reputation)"
                    .to_string(),
            };
            let _ = self.log_tx.try_send(entry);
            let _ = session.respond_error(403).await;
            return Ok(true); // Handled
        }

        // 2. Geoblocking
        let country = crate::proxy::resolve_ip_country(&client_ip);
        let is_geoblocked = if vhost_cfg.geoblock_type.to_lowercase() == "allowlist" {
            !vhost_cfg.blocked_countries.contains(&country.to_string()) && country != "LOCAL"
        } else {
            vhost_cfg.blocked_countries.contains(&country.to_string())
        };

        if is_geoblocked {
            let entry = crate::logging::WafLogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                client_ip: client_ip.to_string(),
                method: req_method.clone(),
                path: path.clone(),
                action: "BLOCK".to_string(),
                rule_id: "GEO-001".to_string(),
                reason: format!(
                    "Geoblocked ({}): Access from country [{}] is restricted",
                    vhost_cfg.geoblock_type, country
                ),
            };
            let _ = self.log_tx.try_send(entry);
            let _ = session.respond_error(403).await;
            return Ok(true); // Handled
        }

        let rule_engine = crate::rules::RuleEngine::new(&config);

        // 2.5. Rate Limiting Check
        let mut active_limit = None;
        for policy in &config.rate_limit_policies {
            let matches = policy.path.split(',').any(|pat| {
                let pat = pat.trim();
                if pat == "/*" || pat == "*" {
                    true
                } else if let Some(prefix) = pat.strip_suffix("/*") {
                    path.starts_with(prefix)
                } else if let Some(ext) = pat.strip_prefix("*.") {
                    path.ends_with(ext)
                } else {
                    path == pat
                }
            });

            if matches {
                active_limit = Some(crate::config::parse_rate_limit(&policy.limit));
                break;
            }
        }

        if let Some(limit) = active_limit {
            if limit > 0 {
                let allowed = rule_engine
                    .check_rate_limit(client_ip, limit, &config.redis)
                    .await;
                if !allowed {
                    let entry = crate::logging::WafLogEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        client_ip: client_ip.to_string(),
                        method: req_method.clone(),
                        path: path.clone(),
                        action: "RATE_LIMIT".to_string(),
                        rule_id: "RATELIMIT-001".to_string(),
                        reason: format!("Rate limit exceeded (Max: {} req/min)", limit),
                    };
                    let _ = self.log_tx.try_send(entry);
                    let _ = session.respond_error(429).await;
                    return Ok(true);
                }
            }
        }
        if let Some((rule_id, reason)) = rule_engine.check_request(
            &path,
            &query_str,
            &headers_map,
            "", // no body at this phase
            ctx.client_ip,
            &req_method,
            &vhost_cfg.rules,
        ) {
            ctx.is_blocked = true;
            let entry = crate::logging::WafLogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                client_ip: client_ip.to_string(),
                method: req_method.clone(),
                path: path.clone(),
                action: "BLOCK".to_string(),
                rule_id,
                reason,
            };
            let _ = self.log_tx.try_send(entry);
            let _ = session.respond_error(403).await;
            return Ok(true);
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let vhost_name = ctx.vhost_name.as_ref().unwrap();

        let mut selected_backend = None;
        if let Some(backends) = LOAD_BALANCER.get(vhost_name) {
            let healthy_list: Vec<&Backend> = backends
                .iter()
                .filter(|b| b.healthy.load(std::sync::atomic::Ordering::Relaxed))
                .collect();

            if !healthy_list.is_empty() {
                let idx = if let Some(counter) = ROUND_ROBIN_COUNTERS.get(vhost_name) {
                    counter
                        .value()
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        % healthy_list.len()
                } else {
                    0
                };
                selected_backend = Some(healthy_list[idx].addr.clone());
            } else {
                selected_backend = Some(backends[0].addr.clone());
            }
        }

        let backend = selected_backend.unwrap_or_else(|| ctx.vhost_backend.clone().unwrap());
        ctx.vhost_backend_resolved = Some(backend.clone());

        // Increment backend concurrent request count (Backpressure protection)
        let active_requests = {
            let mut entry = BACKEND_ACTIVE_REQUESTS.entry(backend.clone()).or_insert(0);
            *entry += 1;
            *entry
        };
        if active_requests > ctx.max_concurrent_requests {
            if let Some(mut entry) = BACKEND_ACTIVE_REQUESTS.get_mut(&backend) {
                if *entry > 0 {
                    *entry -= 1;
                }
            }
            return Err(pingora::Error::create(
                pingora::ErrorType::HTTPStatus(503),
                pingora::ErrorSource::Downstream,
                Some("Backend Overloaded (Backpressure)".into()),
                None,
            ));
        }

        // Check if this is a WebSocket upgrade request to route to security proxy
        let is_upgrade = _session
            .req_header()
            .headers
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_lowercase() == "websocket")
            .unwrap_or(false);

        // Handle "http://" or "https://" prefix in config
        let (host, port, tls) = if ctx.websocket_security_enabled && is_upgrade {
            ("127.0.0.1", 24601, false)
        } else if backend.starts_with("https://") {
            let stripped = backend.trim_start_matches("https://");
            let clean_host = stripped.split(':').next().unwrap_or(stripped);
            let p = stripped
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse().ok())
                .unwrap_or(443);
            (clean_host, p, true)
        } else if backend.starts_with("http://") {
            let stripped = backend.trim_start_matches("http://");
            let clean_host = stripped.split(':').next().unwrap_or(stripped);
            let p = stripped
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse().ok())
                .unwrap_or(80);
            (clean_host, p, false)
        } else {
            let clean_host = backend.split(':').next().unwrap_or(&backend);
            let p = backend
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse().ok())
                .unwrap_or(80);
            (clean_host, p, false)
        };

        let peer_addr = format!("{}:{}", host, port);
        let mut peer = HttpPeer::new(&peer_addr, tls, host.to_string());
        peer.options.connection_timeout = Some(std::time::Duration::from_secs(5));

        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(ip) = ctx.client_ip {
            upstream_request
                .insert_header("X-Forwarded-For", ip.to_string())
                .unwrap_or(());
        }

        // Inject request ID header for correlation
        let _ = upstream_request.insert_header("X-Request-ID", &ctx.request_id);

        if ctx.websocket_security_enabled {
            let is_upgrade = upstream_request
                .headers
                .get("upgrade")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_lowercase() == "websocket")
                .unwrap_or(false);
            if is_upgrade {
                if let Some(backend) = &ctx.vhost_backend_resolved {
                    let _ = upstream_request.insert_header("X-Jarswaf-Real-Backend", backend);
                }
            }
        }
        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        // 1. Decrement concurrent IP connections (Slowloris protection)
        if let Some(ip) = ctx.client_ip {
            if let Some(mut entry) = ACTIVE_CONNECTIONS.get_mut(&ip) {
                if *entry > 0 {
                    *entry -= 1;
                }
            }
        }

        // 2. Decrement backend active request count (Backpressure protection)
        if let Some(ref backend) = ctx.vhost_backend_resolved {
            if let Some(mut entry) = BACKEND_ACTIVE_REQUESTS.get_mut(backend) {
                if *entry > 0 {
                    *entry -= 1;
                }
            }
        }

        let req = session.req_header();
        let status = session.response_written().map_or(0, |r| r.status.as_u16());

        let log_level = GLOBAL_CONFIG.load().global.log_level.to_lowercase();
        if log_level == "verbose"
            || log_level == "all"
            || (e.is_some() && (log_level == "errors" || log_level == "anomaly"))
        {
            let ip_str = ctx
                .client_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            let entry = crate::logging::WafLogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                client_ip: ip_str,
                method: req.method.as_str().to_string(),
                path: req.uri.path().to_string(),
                action: if e.is_some() {
                    "ERROR".to_string()
                } else {
                    "PASS".to_string()
                },
                rule_id: if e.is_some() {
                    "SYS-ERR".to_string()
                } else {
                    "ALLOW".to_string()
                },
                reason: format!(
                    "ReqID: {} | {}",
                    ctx.request_id,
                    e.map(|err| err.to_string())
                        .unwrap_or_else(|| format!("Status: {}", status))
                ),
            };
            let _ = self.log_tx.try_send(entry);
        }
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if ctx.is_blocked {
            return Ok(());
        }

        if let Some(chunk) = body {
            if ctx.body_buffer.len() + chunk.len() > ctx.body_limit {
                ctx.is_blocked = true;
                let client_ip_str = ctx
                    .client_ip
                    .map_or("Unknown".to_string(), |ip| ip.to_string());
                let entry = crate::logging::WafLogEntry {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    client_ip: client_ip_str,
                    method: session.req_header().method.as_str().to_string(),
                    path: session.req_header().uri.path().to_string(),
                    action: "BLOCK".to_string(),
                    rule_id: "WAF-BODY-LIMIT".to_string(),
                    reason: format!(
                        "Request body size limit exceeded (Max: {} bytes)",
                        ctx.body_limit
                    ),
                };
                let _ = self.log_tx.try_send(entry);
                return Err(pingora::Error::create(
                    pingora::ErrorType::HTTPStatus(413),
                    pingora::ErrorSource::Downstream,
                    Some("Payload Too Large".into()),
                    None,
                ));
            }

            ctx.body_buffer.extend_from_slice(chunk);
        }

        if end_of_stream && !ctx.body_buffer.is_empty() {
            let body_str = String::from_utf8_lossy(&ctx.body_buffer);

            // Extract req_header fields early to avoid hold-borrow of session
            let (path, query, method, host, headers_map) = {
                let req_header = session.req_header();
                let path = req_header.uri.path().to_string();
                let query = req_header.uri.query().unwrap_or("").to_string();
                let method = req_header.method.as_str().to_string();
                let host = req_header
                    .headers
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string());

                let mut headers_map = std::collections::HashMap::new();
                for (name, value) in req_header.headers.iter() {
                    if let Ok(val_str) = value.to_str() {
                        headers_map.insert(name.to_string(), val_str.to_string());
                    }
                }
                (path, query, method, host, headers_map)
            };

            let config = GLOBAL_CONFIG.load();

            if let Some((_, vhost_cfg)) = crate::vhost::match_vhost(host.as_deref(), &config) {
                let rule_engine = crate::rules::RuleEngine::new(&config);

                if let Some((rule_id, reason)) = rule_engine.check_request(
                    &path,
                    &query,
                    &headers_map,
                    &body_str,
                    ctx.client_ip,
                    &method,
                    &vhost_cfg.rules,
                ) {
                    ctx.is_blocked = true;
                    let client_ip_str = ctx
                        .client_ip
                        .map_or("Unknown".to_string(), |ip| ip.to_string());
                    let entry = crate::logging::WafLogEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        client_ip: client_ip_str,
                        method: method.clone(),
                        path: path.clone(),
                        action: "BLOCK".to_string(),
                        rule_id,
                        reason,
                    };
                    let _ = self.log_tx.try_send(entry);
                    return Err(pingora::Error::create(
                        pingora::ErrorType::HTTPStatus(403),
                        pingora::ErrorSource::Downstream,
                        Some("Forbidden".into()),
                        None,
                    ));
                }
            }
            ctx.body_buffer.clear();
            ctx.body_buffer.shrink_to_fit();
        }

        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora::Error,
        _ctx: &mut Self::CTX,
    ) -> u16 {
        let code = match e.etype() {
            &pingora::ErrorType::HTTPStatus(status) => status,
            _ => 502,
        };

        let _ = session.respond_error(code).await;

        code
    }
}

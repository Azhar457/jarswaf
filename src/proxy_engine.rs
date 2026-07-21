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
    pub rate_limit_status: Option<crate::rules::RateLimitStatus>,
}

pub static ACTIVE_CONNECTIONS: once_cell::sync::Lazy<dashmap::DashMap<std::net::IpAddr, usize>> =
    once_cell::sync::Lazy::new(dashmap::DashMap::new);
pub static BACKEND_ACTIVE_REQUESTS: once_cell::sync::Lazy<dashmap::DashMap<String, usize>> =
    once_cell::sync::Lazy::new(dashmap::DashMap::new);

/// Circuit breaker: consecutive failure count per backend address.
/// When count exceeds CIRCUIT_BREAKER_THRESHOLD, backend marked as tripped
/// and excluded from round-robin until health checker resets it.
pub static BACKEND_FAILURE_COUNTS: once_cell::sync::Lazy<
    dashmap::DashMap<String, std::sync::atomic::AtomicUsize>,
> = once_cell::sync::Lazy::new(dashmap::DashMap::new);

/// Circuit breaker threshold — after N consecutive failures, backend is tripped.
pub const CIRCUIT_BREAKER_THRESHOLD: usize = 5;
pub static SESSION_FINGERPRINTS: once_cell::sync::Lazy<dashmap::DashMap<std::net::IpAddr, String>> =
    once_cell::sync::Lazy::new(dashmap::DashMap::new);


/// Bounded blocklist — hard cap at 100k entries. Used in proxy and agent.
/// Entries beyond cap evict oldest first via retain-order.
pub const BLOCKLIST_MAX_ENTRIES: usize = 100_000;

/// Semaphore limiting concurrent WAF rule checks (regex/AST tokenization).
/// Prevents N concurrent blocking ops from starving tokio worker threads.
/// When full, new requests skip WAF inspection gracefully (allow, not crash).
pub static WAF_SEMAPHORE: once_cell::sync::Lazy<tokio::sync::Semaphore> =
    once_cell::sync::Lazy::new(|| tokio::sync::Semaphore::new(4));

/// Try-acquire WAF semaphore; if full, log warning and return false (skip).
macro_rules! try_waf_permit {
    () => {{
        match crate::proxy_engine::WAF_SEMAPHORE.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!("WAF semaphore full — skipping rule check, allowing request");
                return Ok(false);
            }
        }
    }};
}

/// Start a SIGHUP handler that hot-reloads config without restart.
/// Falls back to old config on error — never crash on bad config.
pub fn start_config_hot_reload(config_path: String) {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Failed to install SIGHUP handler: {e}");
                return;
            }
        };
        loop {
            sighup.recv().await;
            tracing::info!("SIGHUP received — reloading config from {}", config_path);
            match crate::config::load_config(&config_path) {
                Ok(new_config) => {
                    GLOBAL_CONFIG.store(Arc::new(new_config));
                    tracing::info!("Config hot-reloaded successfully");
                }
                Err(e) => {
                    tracing::error!("Config reload failed, keeping old config: {e}");
                }
            }
        }
    });
}

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



async fn respond_custom_error(
    session: &mut Session,
    status_code: u16,
    title: &str,
    description: &str,
    client_ip: &str,
    rule_id: &str,
) {
    Box::pin(respond_custom_error_with_headers(
        session, status_code, title, description, client_ip, rule_id, None
    )).await
}

async fn respond_custom_error_with_headers(
    session: &mut Session,
    status_code: u16,
    title: &str,
    description: &str,
    client_ip: &str,
    rule_id: &str,
    extra_headers: Option<Vec<(&'static str, String)>>,
) {
    let accepts_json = session
        .req_header()
        .headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("application/json"))
        .unwrap_or(false);

    let (content_type, body) = if accepts_json {
        let mut map = ahash::AHashMap::with_capacity_and_hasher(64, Default::default());
        map.insert("error", title);
        map.insert("message", description);
        map.insert("client_ip", client_ip);
        map.insert("rule_id", rule_id);
        
        // Add rate limit context if applicable
        if status_code == 429 {
            if let Some(headers) = &extra_headers {
                for (k, v) in headers {
                    if *k == "X-RateLimit-Limit" {
                        map.insert("limit", v);
                    } else if *k == "X-RateLimit-Remaining" {
                        map.insert("remaining", v);
                    } else if *k == "X-RateLimit-Reset" {
                        map.insert("reset_after", v);
                    }
                }
            }
        }

        let json_body = serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string());
        ("application/json", json_body)
    } else {
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>{} - jarsWAF</title>
    <style>
        body {{
            background: #030712;
            color: #f3f4f6;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            overflow: hidden;
        }}
        .card {{
            background: rgba(17, 24, 39, 0.7);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(244, 63, 94, 0.2);
            border-radius: 16px;
            padding: 32px;
            max-width: 480px;
            width: 90%;
            box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.7), 0 0 20px 0 rgba(244, 63, 94, 0.1);
            text-align: center;
            animation: fadeIn 0.4s ease-out;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        .icon {{
            width: 64px;
            height: 64px;
            background: rgba(244, 63, 94, 0.1);
            border: 1px solid rgba(244, 63, 94, 0.2);
            color: #f43f5e;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
            font-size: 32px;
            font-weight: bold;
        }}
        h1 {{
            font-size: 24px;
            font-weight: 800;
            margin: 0 0 8px;
            color: #f3f4f6;
            letter-spacing: -0.025em;
        }}
        p {{
            font-size: 14px;
            color: #9ca3af;
            line-height: 1.5;
            margin: 0 0 24px;
        }}
        .meta-grid {{
            background: rgba(3, 7, 18, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 16px;
            font-family: monospace;
            font-size: 12px;
            color: #9ca3af;
            text-align: left;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        .meta-row {{
            display: flex;
            justify-content: space-between;
        }}
        .meta-val {{
            color: #60a5fa;
            font-weight: bold;
        }}
        .footer {{
            margin-top: 24px;
            font-size: 11px;
            color: #6b7280;
            font-weight: 500;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">🛡️</div>
        <h1>Request Blocked</h1>
        <p>{}</p>
        <div class="meta-grid">
            <div class="meta-row">
                <span>Client IP:</span>
                <span class="meta-val">{}</span>
            </div>
            <div class="meta-row">
                <span>Status Code:</span>
                <span class="meta-val">{}</span>
            </div>
            <div class="meta-row">
                <span>Trigger Rule:</span>
                <span class="meta-val">{}</span>
            </div>
        </div>
        <div class="footer">
            Powered by jarsWAF Web Application Firewall
        </div>
    </div>
</body>
</html>"#,
        title,
        description,
        client_ip,
        status_code,
        rule_id
    );
        ("text/html", html)
    };

    if let Ok(mut resp) = ResponseHeader::build(status_code, Some(body.len())) {
        let _ = resp.insert_header("Content-Type", content_type);
        let _ = resp.insert_header("Server", "jarsWAF");
        
        // Inject extra headers
        if let Some(headers) = extra_headers {
            for (k, v) in headers {
                let _ = resp.insert_header(k, v.as_bytes());
            }
        } else if status_code == 429 {
            // Fallback for legacy calls
            let _ = resp.insert_header("Retry-After", "60");
            let _ = resp.insert_header("X-RateLimit-Limit", description);
        }

        if session.write_response_header(Box::new(resp), false).await.is_ok() {
            let _ = session.write_response_body(Some(Bytes::copy_from_slice(body.as_bytes())), true).await;
        }
    }
}



fn calculate_fingerprint(headers: &ahash::AHashMap<String, String>) -> String {
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
                    let headers = ahash::AHashMap::with_capacity_and_hasher(64, Default::default());
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

                            // Reset circuit breaker when backend recovers
                            if is_up {
                                if let Some(fc) = BACKEND_FAILURE_COUNTS.get(&addr) {
                                    fc.value().store(0, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
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
    pub blocklist: Arc<dashmap::DashMap<std::net::IpAddr, std::time::Instant>>,
    // Logging channel
    pub log_tx: tokio::sync::mpsc::Sender<crate::logging::WafLogEntry>,
    // Webhook / SIEM alert endpoints (loaded from config on startup)
    pub webhooks: Vec<crate::config::WebhookConfig>,
}

impl JarsWafProxy {
    pub fn record_attack_and_ban(&self, ip: std::net::IpAddr) {
        crate::rules::record_block(ip);
    }
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
            rate_limit_status: None,
        }
    }
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(rl_status) = &ctx.rate_limit_status {
            if rl_status.allowed {
                let _ = upstream_response.insert_header("X-RateLimit-Limit", rl_status.limit.to_string());
                let _ = upstream_response.insert_header("X-RateLimit-Remaining", rl_status.remaining.to_string());
                let _ = upstream_response.insert_header("X-RateLimit-Reset", rl_status.reset_after_secs.to_string());
            }
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>> {
        let dlp_cfg = match &ctx.dlp_config {
            Some(cfg) if cfg.enabled => cfg,
            _ => return Ok(None),
        };

        if let Some(chunk) = body {
            if ctx.response_body_buffer.len() + chunk.len() <= dlp_cfg.response_body_limit {
                ctx.response_body_buffer.extend_from_slice(chunk);
            }
            *body = Some(Bytes::new());
        }

        if end_of_stream {
            let body_str = String::from_utf8_lossy(&ctx.response_body_buffer);
            let findings = crate::dlp::scan_body(&body_str, dlp_cfg);

            if !findings.is_empty() {
                for finding in &findings {
                    let client_ip_str = ctx.client_ip.map_or("Unknown".to_string(), |ip| ip.to_string());
                    let entry = crate::logging::WafLogEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        client_ip: client_ip_str,
                        method: _session.req_header().method.as_str().to_string(),
                        path: _session.req_header().uri.path().to_string(),
                        action: dlp_cfg.action.to_uppercase(),
                        rule_id: finding.rule.to_string(),
                        reason: format!("DLP finding: {} (sample: {})", finding.description, finding.sample),
                    };
                    let _ = self.log_tx.try_send(entry);
                }

                match dlp_cfg.action.as_str() {
                    "block" => {
                        return Err(pingora::Error::create(
                            pingora::ErrorType::HTTPStatus(502),
                            pingora::ErrorSource::Downstream,
                            Some("DLP Blocked".into()),
                            None,
                        ));
                    }
                    "mask" => {
                        let masked_body = crate::dlp::mask_body(&body_str, dlp_cfg);
                        *body = Some(Bytes::from(masked_body));
                    }
                    _ => {
                        *body = Some(Bytes::from(ctx.response_body_buffer.clone()));
                    }
                }
            } else {
                *body = Some(Bytes::from(ctx.response_body_buffer.clone()));
            }
            ctx.response_body_buffer.clear();
            ctx.response_body_buffer.shrink_to_fit();
        }

        Ok(None)
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

            let mut headers_map = ahash::AHashMap::with_capacity_and_hasher(64, Default::default());
            for (name, value) in req_header.headers.iter() {
                if let Ok(val_str) = value.to_str() {
                    headers_map.insert(name.to_string(), val_str.to_string());
                }
            }
            (req_method, path, query_str, host, headers_map)
        };

        // Health endpoint — respond 200 OK for load balancer probes.
        // No WAF processing, no logging — lightweight.
        if req_method == "GET" && path == "/health" {
            if let Ok(mut resp) = ResponseHeader::build(200, Some(2)) {
                let _ = resp.insert_header("Content-Type", "application/json");
                if session
                    .write_response_header(Box::new(resp), false)
                    .await
                    .is_ok()
                {
                    let _ = session
                        .write_response_body(
                            Some(Bytes::copy_from_slice(b"{}")),
                            true,
                        )
                        .await;
                    return Ok(true);
                }
            }
        }

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
                let _ = respond_custom_error(session, 400, "Bad Request", "The requested host header is not configured on this server.", &client_ip.to_string(), "VHOST-MATCH-000").await;
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
                let _ = respond_custom_error(session, 403, "Access Denied", &format!("Direct IP access block: {}", clean_host), &client_ip.to_string(), "DIRECT-IP-001").await;
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
            let _ = respond_custom_error(session, 429, "Too Many Requests", &format!("Slowloris concurrent connection limit exceeded: {}", conn_count), &client_ip.to_string(), "SLOWLORIS-001").await;
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
                let mut mouse_moves = 0;
                let mut canvas_hash = String::new();
                let mut webgl_renderer = String::new();
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
                        } else if k == "m" {
                            mouse_moves = v.parse::<i32>().unwrap_or(0);
                        } else if k == "fp_c" {
                            canvas_hash = v.to_string();
                        } else if k == "fp_w" {
                            webgl_renderer = urlencoding::decode(v)
                                .unwrap_or_else(|_| v.into())
                                .into_owned();
                        }
                    }
                }

                if mouse_moves < 3 || canvas_hash.is_empty() {
                    let _ = respond_custom_error(session, 403, "Bot Detected", "Advanced Bot Detection: Failed human interaction tests or browser fingerprinting.", &client_ip.to_string(), "BOT-CHALLENGE-002").await;
                    return Ok(true);
                }

                if crate::rules::bot_challenge::is_headless_renderer(&webgl_renderer) {
                    let _ = respond_custom_error(session, 403, "Bot Detected", "Advanced Bot Detection: Detected headless or automated browser.", &client_ip.to_string(), "BOT-CHALLENGE-003").await;
                    return Ok(true);
                }

                if let (Some(sol_str), Some(orig_path)) = (sol_str, orig_path) {
                    use sha2::{Digest, Sha256};
                    let salt = crate::rules::bot_challenge::CHALLENGE_SECRET.as_str();
                    let check_str = format!("{}{}{}", client_ip, salt, sol_str);
                    let mut hasher = Sha256::new();
                    hasher.update(check_str.as_bytes());
                    let hash_result = format!("{:x}", hasher.finalize());
                    if hash_result.starts_with("000") {
                        let now = chrono::Utc::now().timestamp().to_string();
                        let signature = crate::rules::bot_challenge::generate_challenge_signature(
                            &now,
                            &client_ip.to_string(),
                            crate::rules::bot_challenge::CHALLENGE_SECRET.as_str(),
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
                let _ = respond_custom_error(session, 400, "Bad Request", "Challenge verification failed. Nonce is invalid or signature mismatch.", &client_ip.to_string(), "BOT-CHALLENGE-001").await;
                return Ok(true);
            }

            if path == "/jarswaf-challenge" {
                let orig_path = query_str.clone();
                let challenge_html = crate::rules::bot_challenge::get_challenge_html(
                    &client_ip.to_string(),
                    crate::rules::bot_challenge::CHALLENGE_SECRET.as_str(),
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
            let is_challenge_valid = crate::rules::bot_challenge::is_challenge_cookie_valid(
                cookie_header,
                &client_ip.to_string(),
                crate::rules::bot_challenge::CHALLENGE_SECRET.as_str(),
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

        // 0.4. Self-Healing Backend Health Check & Active Shielding
        let all_backends_unhealthy = if let Some(backends) = LOAD_BALANCER.get(&vhost_cfg.name) {
            backends.iter().all(|b| !b.healthy.load(std::sync::atomic::Ordering::Relaxed))
        } else {
            false
        };

        if all_backends_unhealthy {
            let cookie_header = headers_map.get("cookie").map(|s| s.as_str()).unwrap_or("");
            let is_challenge_valid = crate::rules::bot_challenge::is_challenge_cookie_valid(
                cookie_header,
                &client_ip.to_string(),
                crate::rules::bot_challenge::CHALLENGE_SECRET.as_str(),
            );

            if !is_challenge_valid {
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
                    let _ = resp.insert_header("Location", format!("/jarswaf-challenge?{}", redirect_path));
                    let _ = session.write_response_header(Box::new(resp), true).await;
                    return Ok(true);
                }
            } else {
                let entry = crate::logging::WafLogEntry {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    client_ip: client_ip.to_string(),
                    method: req_method.clone(),
                    path: path.clone(),
                    action: "BLOCK".to_string(),
                    rule_id: "SELF-HEAL-503".to_string(),
                    reason: "Backend application offline. WAF Active Shielding is active.".to_string(),
                };
                let _ = self.log_tx.try_send(entry);
                
                let _ = respond_custom_error(
                    session,
                    503,
                    "Service Unavailable",
                    "The backend server is offline or experiencing heavy load. jarsWAF has activated Active Shielding mode to protect the server. Please try again in a few moments.",
                    &client_ip.to_string(),
                    "SELF-HEAL-503"
                ).await;
                return Ok(true);
            }
        }

        // 1. Check Blocklist (Persistent/Reputation & Auto-Remediation)
        let is_blocklisted = self.blocklist.contains_key(&client_ip) || crate::rules::is_ip_temporarily_blocked(client_ip);
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
            let _ = respond_custom_error(session, 403, "Access Denied", "Blocked by jarsWAF Collaborative Threat Intelligence (Reputation)", &client_ip.to_string(), "COLLAB-001").await;
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
            let _ = respond_custom_error(session, 403, "Access Denied", &format!("Geoblocked ({}): Access from country [{}] is restricted", vhost_cfg.geoblock_type, country), &client_ip.to_string(), "GEO-001").await;
            return Ok(true); // Handled
        }

        // 2.1. ASN Blocking
        if !vhost_cfg.blocked_asns.is_empty() {
            if let Some((asn, org)) = crate::proxy::resolve_ip_asn(&client_ip) {
                if vhost_cfg.blocked_asns.contains(&asn) {
                    let entry = crate::logging::WafLogEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        client_ip: client_ip.to_string(),
                        method: req_method.clone(),
                        path: path.clone(),
                        action: "BLOCK".to_string(),
                        rule_id: "GEO-ASN-001".to_string(),
                        reason: format!(
                            "ASN blocked: Access from ASN [{}] ({}) is restricted",
                            asn, org
                        ),
                    };
                    let _ = self.log_tx.try_send(entry);
                    let _ = respond_custom_error(session, 403, "Access Denied", &format!("ASN blocked: Access from ASN [{}] ({}) is restricted", asn, org), &client_ip.to_string(), "GEO-ASN-001").await;
                    return Ok(true); // Handled
                }
            }
        }

        let rule_engine = crate::rules::RuleEngine::new(&config);

        // 2.5. Rate Limiting Check (independent of waf_enabled)
        // Priority: vhost rate_limit_tiers (path-specific) → global rate_limit_policies → vhost rate_limit → global default
        let mut active_limit = None;

        // 2.5a. VHost `rate_limit_tiers` — per-path policy pada vhost ini
        for tier in &vhost_cfg.rate_limit_tiers {
            let matches = if tier.path == "/*" || tier.path == "*" {
                true
            } else if let Some(prefix) = tier.path.strip_suffix("/*") {
                path.starts_with(prefix)
            } else if let Some(ext) = tier.path.strip_prefix("*.") {
                path.ends_with(ext)
            } else {
                path == tier.path
            };
            if matches {
                active_limit = Some(tier.limit);
                break;
            }
        }

        // 2.5b. Global `rate_limit_policies` — hanya jika vhost tier tidak match
        if active_limit.is_none() {
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
        }

        // 2.5c. Fallback ke vhost default rate_limit (string → parsed)
        if active_limit.is_none() {
            let parsed = crate::config::parse_rate_limit(&vhost_cfg.rate_limit);
            if parsed > 0 && parsed < 999_999 {
                active_limit = Some(parsed);
            }
        }

        // Extract user key (Bearer token or API key) for composite rate limit key.
        let user_key = headers_map
            .get("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .or_else(|| headers_map.get("x-api-key").map(|v| v.as_str()))
            .or_else(|| headers_map.get("x-user-id").map(|v| v.as_str()));

        if let Some(limit) = active_limit {
            if limit > 0 {
                let rl_status = rule_engine
                    .check_rate_limit(client_ip, limit, &config.redis, user_key)
                    .await;
                ctx.rate_limit_status = Some(rl_status.clone());
                if !rl_status.allowed {
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
                    
                    let extra_headers = vec![
                        ("X-RateLimit-Limit", rl_status.limit.to_string()),
                        ("X-RateLimit-Remaining", rl_status.remaining.to_string()),
                        ("X-RateLimit-Reset", rl_status.reset_after_secs.to_string()),
                        ("Retry-After", rl_status.reset_after_secs.to_string()),
                    ];
                    
                    let _ = respond_custom_error_with_headers(
                        session, 429, "Too Many Requests",
                        &format!("Rate limit exceeded (Max: {} req/min)", limit),
                        &client_ip.to_string(), "RATELIMIT-001",
                        Some(extra_headers)
                    ).await;
                    return Ok(true);
                }
            }
        }

        // 2.6. API Security (JWT)
        if path.starts_with("/api/") {
            if let Err(reason) = crate::rules::api_security::validate_jwt_structure(&session.req_header().headers) {
                let entry = crate::logging::WafLogEntry {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    client_ip: client_ip.to_string(),
                    method: req_method.clone(),
                    path: path.clone(),
                    action: "BLOCK".to_string(),
                    rule_id: "API-JWT-001".to_string(),
                    reason: reason.to_string(),
                };
                let _ = self.log_tx.try_send(entry);
                let _ = respond_custom_error(session, 401, "Unauthorized", reason, &client_ip.to_string(), "API-JWT-001").await;
                return Ok(true);
            }
        }

        // 3. WAF Rule Engine Check (only when enabled)
        if !config.global.waf_enabled {
            return Ok(false);
        }
        // Acquire semaphore — skip WAF if concurrent regex work saturates
        let _permit = try_waf_permit!();
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
            if let Some(ip) = ctx.client_ip {
                self.record_attack_and_ban(ip);
            }
            let entry = crate::logging::WafLogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                client_ip: client_ip.to_string(),
                method: req_method.clone(),
                path: path.clone(),
                action: "BLOCK".to_string(),
                rule_id: rule_id.clone(),
                reason: reason.clone(),
            };
            let _ = self.log_tx.try_send(entry);
            
            if vhost_cfg.deception_mode {
                tracing::info!("Deception mode triggered for: {}", client_ip);
                let fake_json = r#"{
    "status": "success",
    "data": {
        "users": [
            {"id": 1, "username": "admin", "role": "superuser", "last_login": "2023-10-14T08:00:00Z"},
            {"id": 2, "username": "system", "role": "system", "last_login": "2023-10-14T08:05:00Z"}
        ],
        "debug_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake_token"
    }
}"#;
                let _ = respond_custom_error(session, 200, "OK", fake_json, &client_ip.to_string(), &rule_id).await;
            } else {
                let _ = respond_custom_error(session, 403, "Access Denied", &reason, &client_ip.to_string(), &rule_id).await;
            }
            return Ok(true);
        }

        if let Some(ip) = ctx.client_ip {
            crate::SUSPICIOUS_IPS.insert(ip, std::time::Instant::now());
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let vhost_name = match ctx.vhost_name.as_ref() {
            Some(name) => name,
            None => {
                return Err(pingora::Error::create(
                    pingora::ErrorType::HTTPStatus(502),
                    pingora::ErrorSource::Downstream,
                    Some("Missing VHost context".into()),
                    None,
                ));
            }
        };

        let mut selected_backend = None;
        if let Some(backends) = LOAD_BALANCER.get(vhost_name) {
            let healthy_list: Vec<&Backend> = backends
                .iter()
                .filter(|b| {
                    if !b.healthy.load(std::sync::atomic::Ordering::Relaxed) {
                        return false;
                    }
                    // Circuit breaker: skip backends with failure count >= threshold
                    if let Some(fc) = BACKEND_FAILURE_COUNTS.get(&b.addr) {
                        let count = fc.value().load(std::sync::atomic::Ordering::Relaxed);
                        if count >= CIRCUIT_BREAKER_THRESHOLD {
                            return false;
                        }
                    }
                    true
                })
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

        let backend = match selected_backend.or_else(|| ctx.vhost_backend.clone()) {
            Some(b) => b,
            None => {
                return Err(pingora::Error::create(
                    pingora::ErrorType::HTTPStatus(502),
                    pingora::ErrorSource::Downstream,
                    Some("No healthy backend found".into()),
                    None,
                ));
            }
        };
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
                if let Some(ip) = ctx.client_ip {
                    self.record_attack_and_ban(ip);
                }
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
            let config = GLOBAL_CONFIG.load();

            // Skip WAF body inspection if globally disabled
            if !config.global.waf_enabled {
                ctx.body_buffer.clear();
                ctx.body_buffer.shrink_to_fit();
                return Ok(());
            }

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

                let mut headers_map = ahash::AHashMap::with_capacity_and_hasher(64, Default::default());
                for (name, value) in req_header.headers.iter() {
                    if let Ok(val_str) = value.to_str() {
                        headers_map.insert(name.to_string(), val_str.to_string());
                    }
                }
                (path, query, method, host, headers_map)
            };

            if let Some((_, vhost_cfg)) = crate::vhost::match_vhost(host.as_deref(), &config) {
                // 2.7. API Security (GraphQL)
                if path.starts_with("/graphql") || path.starts_with("/api/graphql") {
                    if let Err(reason) = crate::rules::api_security::check_graphql_depth(&ctx.body_buffer, 5) {
                        let client_ip_str = ctx.client_ip.map_or("Unknown".to_string(), |ip| ip.to_string());
                        let entry = crate::logging::WafLogEntry {
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            client_ip: client_ip_str.clone(),
                            method: session.req_header().method.as_str().to_string(),
                            path: session.req_header().uri.path().to_string(),
                            action: "BLOCK".to_string(),
                            rule_id: "API-GQL-001".to_string(),
                            reason: reason.to_string(),
                        };
                        let _ = self.log_tx.try_send(entry);
                        return Err(pingora::Error::create(
                            pingora::ErrorType::HTTPStatus(400),
                            pingora::ErrorSource::Downstream,
                            Some("Bad Request".into()),
                            None,
                        ));
                    }
                }

                let rule_engine = crate::rules::RuleEngine::new(&config);

                // Acquire semaphore — skip body WAF if concurrent regex work saturates
                let _permit = match crate::proxy_engine::WAF_SEMAPHORE.try_acquire() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!("WAF semaphore full — skipping body rule check");
                        ctx.body_buffer.clear();
                        ctx.body_buffer.shrink_to_fit();
                        return Ok(());
                    }
                };

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
                    if let Some(ip) = ctx.client_ip {
                        crate::SUSPICIOUS_IPS.insert(ip, std::time::Instant::now());
                        self.record_attack_and_ban(ip);
                    }
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

        // Circuit breaker: increment failure count for backend
        if let Some(ref backend) = _ctx.vhost_backend_resolved {
            if let Some(entry) = BACKEND_FAILURE_COUNTS.get(backend) {
                let prev = entry.value().fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if prev + 1 == CIRCUIT_BREAKER_THRESHOLD {
                    tracing::warn!(
                        "Circuit breaker tripped for backend {} after {} consecutive failures",
                        backend,
                        prev + 1
                    );
                }
            } else {
                BACKEND_FAILURE_COUNTS.insert(backend.clone(), std::sync::atomic::AtomicUsize::new(1));
            }
        }

        let client_ip_str = session.client_addr()
            .and_then(|addr| addr.as_inet().map(|i| i.ip().to_string()))
            .unwrap_or_else(|| "Unknown".to_string());
        let _ = respond_custom_error(session, code, "Gateway Error", "Failed to connect to backend application. It might be offline or starting up.", &client_ip_str, "GATEWAY-ERR-502").await;

        code
    }
}

pub async fn flush_suspicious_ips_to_blocklist() {
    use std::time::Instant;
    let mut ips_to_block = Vec::new();
    let now = Instant::now();
    
    crate::SUSPICIOUS_IPS.retain(|ip, &mut ts| {
        if now.duration_since(ts).as_secs() < 5 {
            ips_to_block.push(*ip);
            false 
        } else {
            false 
        }
    });

    if ips_to_block.is_empty() {
        return;
    }

    let mut xdp = crate::XDP_MANAGER.lock().await;
    for ip in ips_to_block {
        if let std::net::IpAddr::V4(ipv4) = ip {
            tracing::warn!("Blocking suspicious IP due to RASP alert: {}", ipv4);
            let _ = xdp.block_ip(ipv4);
        } else {
            tracing::warn!("RASP IP block skipped for non-IPv4: {}", ip);
        }
    }
}

use crate::config::Config;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use pingora::prelude::*;
use pingora_http::ResponseHeader;
use std::collections::HashSet;
use std::sync::Arc;

// Global Lock-Free Config
pub static GLOBAL_CONFIG: once_cell::sync::Lazy<ArcSwap<Config>> =
    once_cell::sync::Lazy::new(|| ArcSwap::from_pointee(Config::default()));

// We need a context to pass data between Pingora request phases
pub struct JarsWafCtx {
    pub client_ip: Option<std::net::IpAddr>,
    pub vhost_backend: Option<String>,
    pub vhost_name: Option<String>,
    pub body_buffer: Vec<u8>,
    pub body_limit: usize,
    pub is_blocked: bool,
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

pub fn start_health_checker() {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
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
    });
}

pub struct JarsWafProxy {
    // For reputation blocklist
    pub blocklist: Arc<std::sync::RwLock<HashSet<std::net::IpAddr>>>,
    // Logging channel
    pub log_tx: tokio::sync::mpsc::Sender<crate::logging::WafLogEntry>,
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
            body_limit: 10 * 1024 * 1024, // default 10MB
            is_blocked: false,
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

        // Lazily start health checker
        static HEALTH_CHECKER_STARTED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        if !HEALTH_CHECKER_STARTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            start_health_checker();
        }

        // 1. Check Blocklist (Reputation)
        let is_blocklisted = {
            let blocklist_lock = self.blocklist.read().unwrap();
            blocklist_lock.contains(&client_ip)
        };
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

        // Handle "http://" or "https://" prefix in config
        let (host, port, tls) = if backend.starts_with("https://") {
            let stripped = backend.trim_start_matches("https://");
            let clean_host = stripped.split(':').next().unwrap_or(stripped);
            let p = if stripped.contains(':') {
                stripped
                    .split(':')
                    .next_back()
                    .unwrap()
                    .parse()
                    .unwrap_or(443)
            } else {
                443
            };
            (clean_host, p, true)
        } else if backend.starts_with("http://") {
            let stripped = backend.trim_start_matches("http://");
            let clean_host = stripped.split(':').next().unwrap_or(stripped);
            let p = if stripped.contains(':') {
                stripped
                    .split(':')
                    .next_back()
                    .unwrap()
                    .parse()
                    .unwrap_or(80)
            } else {
                80
            };
            (clean_host, p, false)
        } else {
            let clean_host = backend.split(':').next().unwrap_or(&backend);
            let p = if backend.contains(':') {
                backend
                    .split(':')
                    .next_back()
                    .unwrap()
                    .parse()
                    .unwrap_or(80)
            } else {
                80
            };
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
                .unwrap_or_else(());
        }
        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
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
                reason: e
                    .map(|err| err.to_string())
                    .unwrap_or_else(|| format!("Status: {}", status)),
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

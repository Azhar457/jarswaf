use axum::{
    body::Body,
    extract::Host,
    http::{Request, Response, StatusCode},
    response::IntoResponse,
};
use std::net::SocketAddr;
use crate::{AppState, rules::RuleEngine, vhost};
use std::collections::HashMap;
use once_cell::sync::Lazy;

pub async fn forward_request(
    state: axum::extract::State<AppState>,
    peer_addr: SocketAddr,
    host: Option<Host>,
    req: Request<Body>,
) -> Response<Body> {
    let mut req = req;
    // Read config inside a block to ensure RwLockReadGuard does not cross await boundaries
    let (backend_addr, vhost_cfg, global_max_body_size, global_default_rate_limit, log_level, trusted_proxies, resolved_custom_rules, waf_enabled) = {
        let config_lock = state.config.read().unwrap();
        let (b, v) = vhost::match_vhost(host.as_ref(), &*config_lock);
        
        let resolved = v.custom_rules.iter()
            .filter_map(|id| config_lock.custom_rules.iter().find(|r| &r.id == id).cloned())
            .collect::<Vec<crate::config::CustomRule>>();
            
        (
            b.to_string(),
            v.clone(),
            config_lock.global.max_body_size,
            config_lock.global.default_rate_limit,
            config_lock.global.log_level.to_lowercase(),
            config_lock.global.trusted_proxies.clone(),
            resolved,
            config_lock.global.waf_enabled,
        )
    };

    // Extract real client IP (XFF only trusted from whitelisted/private proxies)
    let client_ip = {
        let peer_ip = peer_addr.ip();
        let is_trusted = if let Some(ref proxies) = trusted_proxies {
            proxies.iter().any(|p_str| {
                p_str.parse::<std::net::IpAddr>().map(|ip| ip == peer_ip).unwrap_or(false)
            })
        } else {
            crate::is_local_ip(&peer_ip)
        };

        if is_trusted {
            if let Some(xff) = req.headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
            {
                // Traverse right-to-left
                let parts: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();
                let mut resolved = peer_ip;
                for part in parts.iter().rev() {
                    if let Ok(parsed_ip) = part.parse::<std::net::IpAddr>() {
                        let is_part_trusted = if let Some(ref proxies) = trusted_proxies {
                            proxies.iter().any(|p_str| {
                                p_str.parse::<std::net::IpAddr>().map(|ip| ip == parsed_ip).unwrap_or(false)
                            })
                        } else {
                            crate::is_local_ip(&parsed_ip)
                        };
                        if !is_part_trusted {
                            resolved = parsed_ip;
                            break;
                        }
                        resolved = parsed_ip;
                    }
                }
                resolved
            } else {
                peer_ip
            }
        } else {
            peer_ip
        }
    };

    // Extract request data
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let path_and_query = req.uri().path_and_query().map(|x| x.as_str().to_string()).unwrap_or_else(|| "/".to_string());
    let headers_map: HashMap<String, String> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    if !waf_enabled {
        let (parts, body) = req.into_parts();
        let mut req = Request::from_parts(parts, Body::empty());
        
        let client = state.http_client.clone();
        let uri_str = if backend_addr.starts_with("http://") || backend_addr.starts_with("https://") {
            format!("{}{}", backend_addr, path_and_query)
        } else {
            format!("http://{}{}", backend_addr, path_and_query)
        };
        
        let uri = match uri_str.parse::<axum::http::Uri>() {
            Ok(u) => u,
            Err(e) => {
                tracing::error!("Invalid backend URI '{}': {}", uri_str, e);
                return (StatusCode::BAD_GATEWAY, "Invalid backend address configuration").into_response();
            }
        };
        
        let mut backend_req = Request::builder()
            .method(method.clone())
            .uri(uri);
        for (key, value) in &headers_map {
            backend_req = backend_req.header(key.as_str(), value.as_str());
        }
        let backend_req = backend_req.body(body).unwrap();
        
        let is_upgrade = req.headers().get(axum::http::header::UPGRADE).is_some();
        let client_upgrade = if is_upgrade {
            Some(hyper::upgrade::on(&mut req))
        } else {
            None
        };
        
        let backend_timeout = tokio::time::Duration::from_secs(30);
        match tokio::time::timeout(backend_timeout, client.request(backend_req)).await {
            Ok(Ok(mut resp)) => {
                if is_upgrade && resp.status() == StatusCode::SWITCHING_PROTOCOLS {
                    if let Some(c_upgrade) = client_upgrade {
                        let b_upgrade = hyper::upgrade::on(&mut resp);
                        tokio::spawn(async move {
                            match tokio::join!(c_upgrade, b_upgrade) {
                                (Ok(client_io), Ok(backend_io)) => {
                                    use hyper_util::rt::TokioIo;
                                    let mut client_io = TokioIo::new(client_io);
                                    let mut backend_io = TokioIo::new(backend_io);
                                    if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut backend_io).await {
                                        tracing::debug!("WebSocket proxy tunnel closed: {:?}", e);
                                    }
                                }
                                (Err(e1), _) => tracing::error!("Client WS upgrade failed: {:?}", e1),
                                (_, Err(e2)) => tracing::error!("Backend WS upgrade failed: {:?}", e2),
                            }
                        });
                    }
                }
                let (parts, body) = resp.into_parts();
                return Response::from_parts(parts, Body::new(body));
            }
            Ok(Err(e)) => {
                tracing::error!("Backend proxy request failed: {:?}", e);
                return (StatusCode::BAD_GATEWAY, "Backend service unavailable").into_response();
            }
            Err(_) => {
                tracing::error!("Backend proxy request timed out");
                return (StatusCode::GATEWAY_TIMEOUT, "Backend gateway timeout").into_response();
            }
        }
    }

    // Check Collaborative IP Threat Intelligence Blocklist
    let is_reputation_blocked = {
        let blocklist_lock = state.blocklist.read().unwrap();
        blocklist_lock.contains(&client_ip)
    };

    if is_reputation_blocked {
        let entry = crate::logging::WafLogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            client_ip: client_ip.to_string(),
            method: method.as_str().to_string(),
            path: path_and_query.clone(),
            action: "BLOCK".to_string(),
            rule_id: "COLLAB-001".to_string(),
            reason: "Blocked by Aegis WAF Collaborative Threat Intelligence (Reputation)".to_string(),
        };
        let _ = state.log_tx.try_send(entry);
        return (StatusCode::FORBIDDEN, "Blocked by Aegis WAF Collaborative Threat Intelligence").into_response();
    }

    // Check Geoblocking (Lock by Country)
    let country = resolve_ip_country(&client_ip);
    let is_geoblocked = if vhost_cfg.geoblock_type.to_lowercase() == "allowlist" {
        !vhost_cfg.blocked_countries.contains(&country.to_string()) && country != "LOCAL"
    } else {
        vhost_cfg.blocked_countries.contains(&country.to_string())
    };

    if is_geoblocked {
        let entry = crate::logging::WafLogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            client_ip: client_ip.to_string(),
            method: method.as_str().to_string(),
            path: path_and_query.clone(),
            action: "BLOCK".to_string(),
            rule_id: "GEO-001".to_string(),
            reason: format!(
                "Geoblocked ({}): Access from country [{}] is restricted",
                vhost_cfg.geoblock_type, country
            ),
        };
        let _ = state.log_tx.try_send(entry);
        return (StatusCode::FORBIDDEN, format!("Blocked by Aegis WAF Geoblock: Access restricted for {}", country)).into_response();
    }

    // Body inspect: baca hanya jika kecil dan path tidak dikecualikan
    // Parse max body size per vhost (e.g. "10MB"), falling back to global max_body_size if empty/invalid
    let max_body_size = {
        let parsed = crate::config::parse_size(&vhost_cfg.max_body);
        if parsed > 0 { parsed } else { global_max_body_size }
    };

    // Check Content-Length header upfront to prevent oversized bodies from being processed or forwarded
    if let Some(cl_header) = req.headers().get(axum::http::header::CONTENT_LENGTH) {
        if let Ok(cl_str) = cl_header.to_str() {
            if let Ok(cl_val) = cl_str.parse::<usize>() {
                if cl_val > max_body_size {
                    return (StatusCode::PAYLOAD_TOO_LARGE, "Request payload exceeds configured limit").into_response();
                }
            }
        }
    }

    let body_inspection = vhost_cfg
        .rate_limit_tiers
        .iter()
        .find(|t| path.starts_with(&t.path))
        .map(|t| t.body_inspection)
        .unwrap_or(true);

    let (parts, body) = req.into_parts();

    let (body_str, new_body) = if body_inspection {
        match axum::body::to_bytes(body, max_body_size).await {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).to_string();
                (text, Body::from(bytes))
            }
            Err(_) => {
                // If it fails (due to exceeding limit or connection issues), reject the request
                return (StatusCode::PAYLOAD_TOO_LARGE, "Payload too large or read error").into_response();
            }
        }
    } else {
        // Jangan inspeksi, langsung forward
        (String::new(), body)
    };

    let mut req = Request::from_parts(parts, Body::empty());

    // Check Custom Rules
    for rule in &resolved_custom_rules {
        if !rule.enabled {
            continue;
        }
        let match_val = match rule.condition_type.as_str() {
            "path" => Some(&path),
            "query" => Some(&query),
            "body" => Some(&body_str),
            _ => {
                if rule.condition_type.starts_with("header:") {
                    let header_key = rule.condition_type.trim_start_matches("header:").to_lowercase();
                    headers_map.get(&header_key)
                } else {
                    None
                }
            }
        };

        if let Some(val) = match_val {
            let is_matched = match rule.operator.as_str() {
                "equals" => val == &rule.condition_value,
                "contains" => val.contains(&rule.condition_value),
                "starts_with" => val.starts_with(&rule.condition_value),
                _ => false,
            };

            if is_matched {
                if rule.action.as_str() == "redirect" {
                    let entry = crate::logging::WafLogEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        client_ip: client_ip.to_string(),
                        method: method.as_str().to_string(),
                        path: path_and_query.clone(),
                        action: "REDIRECT".to_string(),
                        rule_id: rule.id.clone(),
                        reason: format!("Redirected by Custom Rule [{}]: to {}", rule.name, rule.action_value),
                    };
                    let _ = state.log_tx.try_send(entry);

                    return Response::builder()
                        .status(StatusCode::FOUND)
                        .header("Location", &rule.action_value)
                        .body(Body::empty())
                        .unwrap()
                        .into_response();
                } else {
                    let entry = crate::logging::WafLogEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        client_ip: client_ip.to_string(),
                        method: method.as_str().to_string(),
                        path: path_and_query.clone(),
                        action: "BLOCK".to_string(),
                        rule_id: rule.id.clone(),
                        reason: format!("Blocked by Custom Rule [{}]: {}", rule.name, rule.condition_value),
                    };
                    let _ = state.log_tx.try_send(entry);
                    return (StatusCode::FORBIDDEN, format!("Blocked by Aegis WAF Custom Rule: {}", rule.name)).into_response();
                }
            }
        }
    }

    // Rule engine check
    let rule_engine = RuleEngine::new(&*state.config.read().unwrap());
    if let Some((rule_id, msg)) = rule_engine.check_request(
        &path,
        &query,
        &headers_map,
        &body_str,
        Some(client_ip),
        method.as_str(),
        &vhost_cfg.rules,
    ) {
        // Log block via async channel
        let entry = crate::logging::WafLogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            client_ip: client_ip.to_string(),
            method: method.as_str().to_string(),
            path: path_and_query.clone(),
            action: "BLOCK".to_string(),
            rule_id,
            reason: msg.clone(),
        };
        // Record block in reputation counter
        if crate::rules::record_block(client_ip) {
            if let Ok(mut lock) = state.blocklist.write() {
                if lock.insert(client_ip) {
                    tracing::warn!("IP {} blocked multiple times, added to in-memory blocklist (Reputation)", client_ip);
                }
            }
        }
        
        let _ = state.log_tx.try_send(entry);
        return (StatusCode::FORBIDDEN, format!("Blocked by Aegis WAF: {msg}")).into_response();
    }

    // Rate limit check (pakai tier atau default vhost rate limit)
    let rate_limit = vhost_cfg
        .rate_limit_tiers
        .iter()
        .find(|t| path.starts_with(&t.path))
        .map(|t| t.limit)
        .unwrap_or_else(|| {
            let parsed = crate::config::parse_rate_limit(&vhost_cfg.rate_limit);
            if parsed > 0 { parsed } else { global_default_rate_limit }
        });
    if !rule_engine.check_rate_limit(client_ip, rate_limit) {
        // Log rate limit via async channel
        let entry = crate::logging::WafLogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            client_ip: client_ip.to_string(),
            method: method.as_str().to_string(),
            path: path_and_query.clone(),
            action: "RATE_LIMIT".to_string(),
            rule_id: "RL-001".to_string(),
            reason: "Rate limit exceeded".to_string(),
        };
        let _ = state.log_tx.try_send(entry);
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }

    // Forward ke backend
    let client = state.http_client.clone();
    let uri_str = if backend_addr.starts_with("http://") || backend_addr.starts_with("https://") {
        format!("{}{}", backend_addr, path_and_query)
    } else {
        format!("http://{}{}", backend_addr, path_and_query)
    };

    let uri = match uri_str.parse::<axum::http::Uri>() {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Invalid backend URI '{}': {}", uri_str, e);
            return (StatusCode::BAD_GATEWAY, "Invalid backend address configuration").into_response();
        }
    };

    let mut backend_req = Request::builder()
        .method(method.clone())
        .uri(uri);
    for (key, value) in &headers_map {
        backend_req = backend_req.header(key.as_str(), value.as_str());
    }
    let backend_req = backend_req.body(new_body).unwrap();

    let is_upgrade = req.headers().get(axum::http::header::UPGRADE).is_some();
    let client_upgrade = if is_upgrade {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let backend_timeout = tokio::time::Duration::from_secs(30);
    match tokio::time::timeout(backend_timeout, client.request(backend_req)).await {
        Ok(Ok(mut resp)) => {
            if log_level == "verbose" || log_level == "all" {
                let status = resp.status();
                let entry = crate::logging::WafLogEntry {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    client_ip: client_ip.to_string(),
                    method: method.as_str().to_string(),
                    path: path_and_query.clone(),
                    action: "PASS".to_string(),
                    rule_id: "ALLOW".to_string(),
                    reason: format!("Response status: {}", status.as_u16()),
                };
                let _ = state.log_tx.try_send(entry);
            }

            if is_upgrade && resp.status() == StatusCode::SWITCHING_PROTOCOLS {
                if let Some(c_upgrade) = client_upgrade {
                    let b_upgrade = hyper::upgrade::on(&mut resp);
                    tokio::spawn(async move {
                        match tokio::join!(c_upgrade, b_upgrade) {
                            (Ok(client_io), Ok(backend_io)) => {
                                use hyper_util::rt::TokioIo;
                                let mut client_io = TokioIo::new(client_io);
                                let mut backend_io = TokioIo::new(backend_io);
                                if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut backend_io).await {
                                    tracing::debug!("WebSocket proxy tunnel closed: {:?}", e);
                                }
                            }
                            (Err(e1), _) => tracing::error!("Client WS upgrade failed: {:?}", e1),
                            (_, Err(e2)) => tracing::error!("Backend WS upgrade failed: {:?}", e2),
                        }
                    });
                }
            }

            // Convert hyper response to axum response
            let (parts, body) = resp.into_parts();
            Response::from_parts(parts, Body::new(body))
        }
        Ok(Err(e)) => {
            if log_level == "verbose" || log_level == "all" || log_level == "anomaly" || log_level == "errors" {
                let entry = crate::logging::WafLogEntry {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    client_ip: client_ip.to_string(),
                    method: method.as_str().to_string(),
                    path: path_and_query.clone(),
                    action: "ERROR".to_string(),
                    rule_id: "SYS-502".to_string(),
                    reason: format!("Backend connection failed: {e}"),
                };
                let _ = state.log_tx.try_send(entry);
            }
            (StatusCode::BAD_GATEWAY, format!("Backend error: {}", e)).into_response()
        }
        Err(_) => {
            if log_level == "verbose" || log_level == "all" || log_level == "anomaly" || log_level == "errors" {
                let entry = crate::logging::WafLogEntry {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    client_ip: client_ip.to_string(),
                    method: method.as_str().to_string(),
                    path: path_and_query.clone(),
                    action: "ERROR".to_string(),
                    rule_id: "SYS-504".to_string(),
                    reason: "Backend request timed out after 30 seconds".to_string(),
                };
                let _ = state.log_tx.try_send(entry);
            }
            (StatusCode::GATEWAY_TIMEOUT, "Gateway Timeout: Backend did not respond in time".to_string()).into_response()
        }
    }
}

static GEOIP_READER: Lazy<Option<maxminddb::Reader<Vec<u8>>>> = Lazy::new(|| {
    maxminddb::Reader::open_readfile("GeoLite2-Country.mmdb").ok()
});

pub fn resolve_ip_country(ip: &std::net::IpAddr) -> String {
    if crate::is_local_ip(ip) {
        return "LOCAL".to_string();
    }
    
    if let Some(reader) = GEOIP_READER.as_ref() {
        if let Ok(record) = reader.lookup::<maxminddb::geoip2::Country>(*ip) {
            if let Some(country) = record.country.and_then(|c| c.iso_code) {
                return country.to_string();
            }
        }
    }
    
    "XX".to_string()
}
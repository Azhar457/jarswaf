pub mod body;
pub mod headers;
pub mod uri;

use dashmap::DashMap;
use std::collections::HashMap;
use std::net::IpAddr;
use unicode_normalization::UnicodeNormalization;

use crate::config::Config;
use once_cell::sync::Lazy;
use tokio::time::Instant;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum Phase {
    Headers,
    Uri,
    Body,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum Action {
    Block,
    Log,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[allow(dead_code)]
pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub phase: Phase,
    pub action: Action,
    pub severity: Severity,
    pub description: &'static str,
    pub check: fn(&RequestInfo) -> bool,
}

#[allow(dead_code)]
pub struct RequestInfo<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a HashMap<String, String>,
    pub body: &'a str,
    pub ip: Option<IpAddr>,
}

pub struct RuleEngine {}

struct TokenBucket {
    tokens: f64,
    last_check: Instant,
    last_access: Instant,
    rate: f64, // tokens per second
    capacity: f64,
}

static RATE_LIMITER: Lazy<DashMap<IpAddr, TokenBucket>> = Lazy::new(DashMap::new);
static BLOCKED_COUNTERS: Lazy<DashMap<IpAddr, (u32, Instant)>> = Lazy::new(DashMap::new);

pub fn record_block(ip: IpAddr) -> bool {
    let now = Instant::now();
    let mut entry = BLOCKED_COUNTERS.entry(ip).or_insert((0, now));
    let (count, first_seen) = entry.value_mut();

    if now.duration_since(*first_seen).as_secs() > 300 {
        *count = 1;
        *first_seen = now;
    } else {
        *count += 1;
    }

    if *count >= 5 {
        let ip_clone = ip;
        tokio::spawn(async move {
            let mut xdp = crate::XDP_MANAGER.lock().await;
            if let IpAddr::V4(v4) = ip_clone {
                let _ = xdp.block_ip(v4);
            }
        });
        true
    } else {
        false
    }
}

pub fn start_rate_limiter_cleanup() {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            let now = Instant::now();
            RATE_LIMITER.retain(|_, bucket| now.duration_since(bucket.last_access).as_secs() < 300);
            BLOCKED_COUNTERS
                .retain(|_, (_, first_seen)| now.duration_since(*first_seen).as_secs() < 300);
        }
    });
}

impl RuleEngine {
    pub fn new(_cfg: &Config) -> Self {
        Self {}
    }

    /// Jalankan semua rule terhadap request yang sudah diparse.
    /// Return Option<(rule_id, message)> jika diblokir.
    pub fn check_request(
        &self,
        path: &str,
        query: &str,
        headers: &HashMap<String, String>,
        body: &str,
        ip: Option<IpAddr>,
        method: &str,
        enabled_rules: &[String],
    ) -> Option<(String, String)> {
        let norm_path = normalize_string(path);
        let norm_query = normalize_string(query);
        let norm_body = normalize_string(body);

        let req_info = RequestInfo {
            method,
            path: &norm_path,
            query: &norm_query,
            headers,
            body: &norm_body,
            ip,
        };

        // Phase 1: Headers
        for rule in headers::HEADER_RULES {
            if is_rule_enabled(rule.id, enabled_rules) && (rule.check)(&req_info) {
                return Some((
                    rule.id.to_string(),
                    format!("{}: {}", rule.name, rule.description),
                ));
            }
        }

        // Phase 2: URI + Query
        for rule in uri::URI_RULES {
            if is_rule_enabled(rule.id, enabled_rules) && (rule.check)(&req_info) {
                return Some((
                    rule.id.to_string(),
                    format!("{}: {}", rule.name, rule.description),
                ));
            }
        }

        // Phase 3: Body
        for rule in body::BODY_RULES {
            if is_rule_enabled(rule.id, enabled_rules) && (rule.check)(&req_info) {
                return Some((
                    rule.id.to_string(),
                    format!("{}: {}", rule.name, rule.description),
                ));
            }
        }

        None
    }
}

pub fn normalize_string(input: &str) -> String {
    let mut normalized = input.to_string();

    // 1. URL Decode (Recursively up to 3 times for double encoding)
    for _ in 0..3 {
        if let Ok(decoded) = urlencoding::decode(&normalized) {
            if decoded == normalized {
                break;
            }
            normalized = decoded.into_owned();
        } else {
            break;
        }
    }

    // 2. HTML Entity Decode (&lt; -> <, &gt; -> >, etc.)
    normalized = htmlescape::decode_html(&normalized).unwrap_or(normalized);

    // 3. Unicode NFKC Normalization (prevents fullwidth and homoglyph bypasses)
    normalized = normalized.nfkc().collect::<String>();

    // 4. Lowercase for uniform signature matching
    normalized = normalized.to_lowercase();

    // Convert '+' to ' ' to handle form-urlencoded space encoding and prevent bypasses
    normalized = normalized.replace('+', " ");

    // 5. Strip Null Bytes & Collapse Whitespace
    normalized = normalized.replace('\0', "");
    normalized = normalized
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");

    normalized
}

fn is_rule_enabled(rule_id: &str, enabled_rules: &[String]) -> bool {
    if enabled_rules.is_empty() {
        return true;
    }
    let is_toggled_category = rule_id.starts_with("SQLI-")
        || rule_id.starts_with("XSS-")
        || rule_id.starts_with("LFI-")
        || rule_id.starts_with("RFI-")
        || rule_id.starts_with("CMDI-")
        || rule_id.starts_with("SSRF-")
        || rule_id.starts_with("BOT-");

    if !is_toggled_category {
        return true;
    }

    for pattern in enabled_rules {
        if pattern == "*" {
            return true;
        }
        if pattern.ends_with('*') {
            let prefix = pattern.trim_end_matches('*');
            if rule_id.starts_with(prefix) {
                return true;
            }
        } else if pattern.starts_with('*') {
            let suffix = pattern.trim_start_matches('*');
            if rule_id.ends_with(suffix) {
                return true;
            }
        } else if rule_id == pattern {
            return true;
        }
    }
    false
}

impl RuleEngine {
    /// Rate limiter check (token bucket). Return true jika diizinkan.
    pub fn check_rate_limit(&self, ip: IpAddr, limit: u32) -> bool {
        let rate = limit as f64 / 60.0; // req per detik
        let capacity = rate * 2.0; // burst 2x
        let mut bucket = RATE_LIMITER.entry(ip).or_insert_with(|| TokenBucket {
            tokens: capacity,
            last_check: Instant::now(),
            last_access: Instant::now(),
            rate,
            capacity,
        });

        // Sync parameters dynamically if configuration has changed
        if (bucket.rate - rate).abs() > f64::EPSILON
            || (bucket.capacity - capacity).abs() > f64::EPSILON
        {
            bucket.rate = rate;
            bucket.capacity = capacity;
            bucket.tokens = bucket.tokens.min(capacity);
        }

        let now = Instant::now();
        bucket.last_access = now;
        let elapsed = now.duration_since(bucket.last_check).as_secs_f64();
        bucket.last_check = now;

        // Refill token
        bucket.tokens = (bucket.tokens + elapsed * bucket.rate).min(bucket.capacity);

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GlobalConfig;
    use crate::config::TlsConfig;

    fn test_config() -> Config {
        Config {
            global: GlobalConfig {
                port_http: 80,
                port_https: 443,
                max_body_size: 1024,
                default_rate_limit: 100,
                log_dir: "./logs".to_string(),
                log_level: "security".to_string(),
                trusted_proxies: Some(vec![]),
            },
            tls: TlsConfig {
                mode: "local_ca".to_string(),
                cert_dir: "./certs".to_string(),
            },
            vhosts: vec![],
            rate_limit_policies: vec![],
            certificates: vec![],
        }
    }

    #[test]
    fn test_clean_request_passes() {
        let engine = RuleEngine::new(&test_config());
        let mut headers = HashMap::new();
        headers.insert(
            "user-agent".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
        );
        headers.insert("host".to_string(), "example.com".to_string());

        let result = engine.check_request(
            "/index.html",
            "id=123&name=alice",
            &headers,
            "hello world",
            None,
            "GET",
            &[],
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_bot_001_blocked() {
        let engine = RuleEngine::new(&test_config());
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "sqlmap/1.4.9".to_string());

        let result = engine.check_request("/", "", &headers, "", None, "GET", &[]);
        assert!(result.is_some());
        let (rule_id, msg) = result.unwrap();
        assert_eq!(rule_id, "BOT-001");
        assert!(msg.contains("Bad User-Agent"));
    }

    #[test]
    fn test_sqli_001_blocked() {
        let engine = RuleEngine::new(&test_config());
        let mut headers = HashMap::new();
        headers.insert(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        );

        let result = engine.check_request(
            "/login",
            "",
            &headers,
            "username=admin' OR 1=1 --",
            None,
            "POST",
            &[],
        );
        assert!(result.is_some());
        let (rule_id, msg) = result.unwrap();
        assert_eq!(rule_id, "SQLI-001");
        assert!(msg.contains("SQL Injection"));
    }

    #[test]
    fn test_sqli_001_query_blocked() {
        let engine = RuleEngine::new(&test_config());
        let headers = HashMap::new();

        // Testing SQLi in query string with '+' representation for spaces
        let result = engine.check_request(
            "/vulnerabilities/sqli/",
            "id=%27+OR+1%3D1--&Submit=Submit",
            &headers,
            "",
            None,
            "GET",
            &[],
        );
        assert!(result.is_some());
        let (rule_id, msg) = result.unwrap();
        assert_eq!(rule_id, "SQLI-001");
        assert!(msg.contains("SQL Injection"));
    }

    #[test]
    fn test_lfi_001_blocked() {
        let engine = RuleEngine::new(&test_config());
        let headers = HashMap::new();

        let result = engine.check_request("/../../etc/passwd", "", &headers, "", None, "GET", &[]);
        assert!(result.is_some());
        let (rule_id, msg) = result.unwrap();
        assert_eq!(rule_id, "LFI-001");
        assert!(msg.contains("Local File Inclusion"));
    }
}

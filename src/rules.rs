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
    #[allow(clippy::too_many_arguments)]
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

        // AST / Semantic WAF Engine checks
        if is_rule_enabled("SQLI-AST", enabled_rules) {
            if let Some(msg) = check_sql_injection_semantic(&norm_query) {
                return Some((
                    "SQLI-AST".to_string(),
                    format!("Semantic SQLi block: {}", msg),
                ));
            }
            if let Some(msg) = check_sql_injection_semantic(&norm_body) {
                return Some((
                    "SQLI-AST".to_string(),
                    format!("Semantic SQLi block: {}", msg),
                ));
            }
            if let Some(msg) = check_sql_injection_semantic(&norm_path) {
                return Some((
                    "SQLI-AST".to_string(),
                    format!("Semantic SQLi block: {}", msg),
                ));
            }
        }

        if is_rule_enabled("XSS-AST", enabled_rules) {
            if let Some(msg) = check_xss_injection_semantic(&norm_query) {
                return Some((
                    "XSS-AST".to_string(),
                    format!("Semantic XSS block: {}", msg),
                ));
            }
            if let Some(msg) = check_xss_injection_semantic(&norm_body) {
                return Some((
                    "XSS-AST".to_string(),
                    format!("Semantic XSS block: {}", msg),
                ));
            }
            if let Some(msg) = check_xss_injection_semantic(&norm_path) {
                return Some((
                    "XSS-AST".to_string(),
                    format!("Semantic XSS block: {}", msg),
                ));
            }
        }

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

// ==========================================
// AST & Tokenization Semantic WAF Core Engine
// ==========================================

#[derive(Debug, PartialEq, Clone)]
enum SqlToken {
    Keyword(String),
    Numeric(String),
    StringLiteral(String),
    Operator(String),
    Symbol(char),
    Comment,
    Other(String),
}

fn tokenize_sql(input: &str) -> Vec<SqlToken> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '-' && i + 1 < chars.len() && chars[i + 1] == '-' {
            tokens.push(SqlToken::Comment);
            break;
        }
        if c == '#' {
            tokens.push(SqlToken::Comment);
            break;
        }
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            tokens.push(SqlToken::Comment);
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            continue;
        }
        if c == '\'' || c == '"' {
            let quote = c;
            // Check if there is a matching closing quote in the remaining characters
            let mut has_closing = false;
            let mut j = i + 1;
            let mut escaped = false;
            while j < chars.len() {
                if escaped {
                    escaped = false;
                } else if chars[j] == '\\' {
                    escaped = true;
                } else if chars[j] == quote {
                    has_closing = true;
                    break;
                }
                j += 1;
            }

            if has_closing {
                let mut val = String::new();
                i += 1;
                let mut local_escaped = false;
                while i < chars.len() {
                    let next_c = chars[i];
                    if local_escaped {
                        val.push(next_c);
                        local_escaped = false;
                    } else if next_c == '\\' {
                        local_escaped = true;
                    } else if next_c == quote {
                        i += 1;
                        break;
                    } else {
                        val.push(next_c);
                    }
                    i += 1;
                }
                tokens.push(SqlToken::StringLiteral(val));
                continue;
            } else {
                tokens.push(SqlToken::Symbol(c));
                i += 1;
                continue;
            }
        }
        if c == '=' || c == '<' || c == '>' || c == '!' {
            let mut op = c.to_string();
            if i + 1 < chars.len() && (chars[i + 1] == '=' || chars[i + 1] == '>') {
                op.push(chars[i + 1]);
                i += 1;
            }
            tokens.push(SqlToken::Operator(op));
            i += 1;
            continue;
        }
        if c == '(' || c == ')' || c == ',' || c == ';' {
            tokens.push(SqlToken::Symbol(c));
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let mut num = String::new();
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                num.push(chars[i]);
                i += 1;
            }
            tokens.push(SqlToken::Numeric(num));
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let mut word = String::new();
            while i < chars.len()
                && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.')
            {
                word.push(chars[i]);
                i += 1;
            }
            let word_upper = word.to_uppercase();
            match word_upper.as_str() {
                "SELECT" | "UNION" | "OR" | "AND" | "INSERT" | "WHERE" | "FROM" | "DROP"
                | "DELETE" | "UPDATE" | "INTO" | "TABLE" | "LIKE" | "HAVING" => {
                    tokens.push(SqlToken::Keyword(word_upper));
                }
                _ => {
                    tokens.push(SqlToken::Other(word));
                }
            }
            continue;
        }
        tokens.push(SqlToken::Other(c.to_string()));
        i += 1;
    }
    tokens
}

fn check_sql_injection_semantic(input: &str) -> Option<String> {
    let tokens = tokenize_sql(input);
    if tokens.contains(&SqlToken::Comment) {
        let mut has_sql_indicator = false;
        for t in &tokens {
            match t {
                SqlToken::Keyword(k) => {
                    if k == "UNION"
                        || k == "SELECT"
                        || k == "OR"
                        || k == "AND"
                        || k == "DROP"
                        || k == "DELETE"
                    {
                        has_sql_indicator = true;
                    }
                }
                SqlToken::Operator(_) => {
                    has_sql_indicator = true;
                }
                _ => {}
            }
        }
        if has_sql_indicator {
            return Some("Comment token injection detected".to_string());
        }
    }
    for i in 0..tokens.len() {
        if let SqlToken::Keyword(ref k) = tokens[i] {
            if (k == "OR" || k == "AND") && i + 3 < tokens.len() {
                let val_a = &tokens[i + 1];
                let op = &tokens[i + 2];
                let val_b = &tokens[i + 3];
                if let SqlToken::Operator(ref o) = op {
                    if o == "=" {
                        let is_equal = match (val_a, val_b) {
                            (SqlToken::Numeric(a), SqlToken::Numeric(b)) => a == b,
                            (SqlToken::StringLiteral(a), SqlToken::StringLiteral(b)) => a == b,
                            (SqlToken::Other(a), SqlToken::Other(b)) => a == b,
                            _ => false,
                        };
                        if is_equal {
                            return Some(format!(
                                "Tautology bypass detected via {} {} = {}",
                                k,
                                format_token(val_a),
                                format_token(val_b)
                            ));
                        }
                    }
                }
            }
        }
    }
    let mut seen_union = false;
    for t in &tokens {
        if let SqlToken::Keyword(ref k) = t {
            if k == "UNION" {
                seen_union = true;
            } else if k == "SELECT" && seen_union {
                return Some("UNION SELECT injection detected".to_string());
            }
        }
    }
    None
}

fn format_token(t: &SqlToken) -> String {
    match t {
        SqlToken::Keyword(s) => s.to_string(),
        SqlToken::Numeric(s) => s.to_string(),
        SqlToken::StringLiteral(s) => format!("'{}'", s),
        SqlToken::Operator(s) => s.to_string(),
        SqlToken::Symbol(c) => c.to_string(),
        SqlToken::Comment => "--".to_string(),
        SqlToken::Other(s) => s.to_string(),
    }
}

#[derive(Debug, PartialEq, Clone)]
enum XssToken {
    TagStart(String),
    TagEnd,
    Attribute(String, String),
    JsProtocol,
    JsEvent(String),
    HtmlComment,
}

fn tokenize_xss(input: &str) -> Vec<XssToken> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '<'
            && i + 3 < chars.len()
            && chars[i + 1] == '!'
            && chars[i + 2] == '-'
            && chars[i + 3] == '-'
        {
            tokens.push(XssToken::HtmlComment);
            i += 4;
            continue;
        }
        if c == 'j' && i + 10 < chars.len() {
            let potential: String = chars[i..i + 11].iter().collect();
            if potential.to_lowercase().starts_with("javascript:") {
                tokens.push(XssToken::JsProtocol);
                i += 11;
                continue;
            }
        }
        if c == '<' && i + 1 < chars.len() && (chars[i + 1].is_alphabetic() || chars[i + 1] == '/')
        {
            i += 1;
            let mut tag_name = String::new();
            if chars[i] == '/' {
                tag_name.push('/');
                i += 1;
            }
            while i < chars.len() && chars[i].is_alphanumeric() {
                tag_name.push(chars[i]);
                i += 1;
            }
            tokens.push(XssToken::TagStart(tag_name.to_lowercase()));
            while i < chars.len() && chars[i] != '>' {
                let ac = chars[i];
                if ac.is_whitespace() {
                    i += 1;
                    continue;
                }
                if ac.is_alphabetic() {
                    let mut attr_name = String::new();
                    while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '-') {
                        attr_name.push(chars[i]);
                        i += 1;
                    }
                    let attr_name_lower = attr_name.to_lowercase();
                    if attr_name_lower.starts_with("on") {
                        tokens.push(XssToken::JsEvent(attr_name_lower.clone()));
                    }
                    while i < chars.len() && chars[i].is_whitespace() {
                        i += 1;
                    }
                    if i < chars.len() && chars[i] == '=' {
                        i += 1;
                        while i < chars.len() && chars[i].is_whitespace() {
                            i += 1;
                        }
                        if i < chars.len() {
                            let val_c = chars[i];
                            let mut val = String::new();
                            if val_c == '\'' || val_c == '"' {
                                i += 1;
                                while i < chars.len() && chars[i] != val_c {
                                    val.push(chars[i]);
                                    i += 1;
                                }
                                i += 1;
                            } else {
                                while i < chars.len()
                                    && !chars[i].is_whitespace()
                                    && chars[i] != '>'
                                {
                                    val.push(chars[i]);
                                    i += 1;
                                }
                            }
                            tokens.push(XssToken::Attribute(attr_name_lower, val));
                        }
                    } else {
                        tokens.push(XssToken::Attribute(attr_name_lower, String::new()));
                    }
                } else {
                    i += 1;
                }
            }
            if i < chars.len() && chars[i] == '>' {
                tokens.push(XssToken::TagEnd);
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    tokens
}

fn check_xss_injection_semantic(input: &str) -> Option<String> {
    let tokens = tokenize_xss(input);
    for t in &tokens {
        match t {
            XssToken::TagStart(name) => {
                if name == "script" || name == "iframe" || name == "object" || name == "embed" {
                    return Some(format!("Dangerous HTML tag '<{}' injection detected", name));
                }
            }
            XssToken::JsEvent(event_name) => {
                return Some(format!(
                    "HTML JS event handler '{}=' injection detected",
                    event_name
                ));
            }
            XssToken::JsProtocol => {
                return Some("JavaScript protocol 'javascript:' URI schema detected".to_string());
            }
            XssToken::Attribute(name, val) if name == "src" || name == "href" => {
                let val_lower = val.to_lowercase();
                if val_lower.starts_with("javascript:") || val_lower.starts_with("data:text/html") {
                    return Some(format!(
                        "Dangerous URL scheme in attribute {}='{}'",
                        name, val
                    ));
                }
            }
            _ => {}
        }
    }
    None
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
                admin_token: None,
                waf_enabled: true,
            },
            tls: TlsConfig {
                mode: "local_ca".to_string(),
                cert_dir: "./certs".to_string(),
            },
            logging: Default::default(),
            components: Default::default(),
            vhosts: vec![],
            rate_limit_policies: vec![],
            certificates: vec![],
            custom_rules: vec![],
            allowlists: vec![],
            blacklists: vec![],
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
            &["SQLI-001".to_string()],
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
            &["SQLI-001".to_string()],
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

    #[test]
    fn test_sqli_ast_semantic_blocked() {
        let engine = RuleEngine::new(&test_config());
        let headers = HashMap::new();

        // Test SQLi AST Tautology
        let result = engine.check_request(
            "/",
            "id=1%20OR%20'abc'='abc'",
            &headers,
            "",
            None,
            "GET",
            &["SQLI-AST".to_string()],
        );
        assert!(result.is_some());
        let (rule_id, msg) = result.unwrap();
        assert_eq!(rule_id, "SQLI-AST");
        assert!(msg.contains("Tautology bypass detected"));

        // Test SQLi AST Comment Injection
        let result = engine.check_request(
            "/",
            "q=admin'--",
            &headers,
            "",
            None,
            "GET",
            &["SQLI-AST".to_string()],
        );
        assert!(result.is_some());
        let (rule_id, _) = result.unwrap();
        assert_eq!(rule_id, "SQLI-AST");
    }

    #[test]
    fn test_xss_ast_semantic_blocked() {
        let engine = RuleEngine::new(&test_config());
        let headers = HashMap::new();

        // Test XSS tag injection
        let result = engine.check_request(
            "/",
            "input=<script>alert(1)</script>",
            &headers,
            "",
            None,
            "GET",
            &["XSS-AST".to_string()],
        );
        assert!(result.is_some());
        let (rule_id, msg) = result.unwrap();
        assert_eq!(rule_id, "XSS-AST");
        assert!(msg.contains("Dangerous HTML tag"));

        // Test XSS Event Handler
        let result = engine.check_request(
            "/",
            "input=<img%20src=x%20onerror=alert(1)>",
            &headers,
            "",
            None,
            "GET",
            &["XSS-AST".to_string()],
        );
        assert!(result.is_some());
        let (rule_id, msg) = result.unwrap();
        assert_eq!(rule_id, "XSS-AST");
        assert!(msg.contains("HTML JS event handler"));
    }
}

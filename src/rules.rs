pub mod body;
pub mod headers;
pub mod uri;

use dashmap::DashMap;
use std::collections::HashMap;
use std::net::IpAddr;
use unicode_normalization::UnicodeNormalization;

use crate::config::Config;
use once_cell::sync::Lazy;
use quick_cache::sync::Cache;
use regex::Regex;
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

#[derive(Debug, Clone)]
pub struct CompiledCustomRule {
    pub id: String,
    pub name: String,
    pub condition_type: String,
    pub operator: String,
    pub condition_value: String,
    pub action: String,
    pub action_value: String,
    pub enabled: bool,
    pub regex: Option<Regex>,
}

pub struct RuleEngine {
    pub custom_rules: Vec<CompiledCustomRule>,
}

struct TokenBucket {
    tokens: f64,
    last_check: Instant,
    last_access: Instant,
    rate: f64, // tokens per second
    capacity: f64,
}

static RATE_LIMITER: Lazy<DashMap<IpAddr, TokenBucket>> = Lazy::new(DashMap::new);
static TOKEN_RATE_LIMITER: Lazy<DashMap<String, TokenBucket>> = Lazy::new(DashMap::new);
static REDIS_CLIENT: Lazy<tokio::sync::RwLock<Option<redis::Client>>> =
    Lazy::new(|| tokio::sync::RwLock::new(None));

// ── Auto-remediation (step-down block durations) ────────────────────────────

/// Duration tiers for automatic temporary blocks.
const BLOCK_TIERS: &[u64] = &[60, 300, 1800, 86400]; // 1m, 5m, 30m, 24h

struct BlockRecord {
    count: u32,
    first_seen: Instant,
    block_until: Instant,
    tier: usize,
}

static BLOCKED_IPS: Lazy<DashMap<IpAddr, BlockRecord>> = Lazy::new(DashMap::new);

/// Record a block event for `ip`. Returns `true` if the IP should be
/// blocked at the kernel level (XDP) after repeated offences.
///
/// The IP is temporarily banned from the *application-level* (*not* XDP) for
/// progressively longer durations each time it is blocked within a
/// sliding 5-minute window.
pub fn record_block(ip: IpAddr) -> bool {
    let now = Instant::now();
    let mut entry = BLOCKED_IPS.entry(ip).or_insert_with(|| BlockRecord {
        count: 0,
        first_seen: now,
        block_until: now,
        tier: 0,
    });
    let rec = entry.value_mut();

    // Reset window if older than 5 minutes since first_seen
    if now.duration_since(rec.first_seen).as_secs() > 300 {
        rec.count = 1;
        rec.first_seen = now;
        rec.tier = 0;
    } else {
        rec.count += 1;
    }

    // Escalate tier every 5 offences
    if rec.count >= 5 && rec.count.is_multiple_of(5) {
        let tier = rec.tier.min(BLOCK_TIERS.len() - 1);
        let duration = BLOCK_TIERS[tier];
        rec.block_until = now + std::time::Duration::from_secs(duration);
        rec.tier = tier + 1;

        tracing::warn!(
            "Auto-remediation: {} blocked for {}s (tier {}, count={})",
            ip,
            duration,
            rec.tier,
            rec.count,
        );

        // On the first escalation (tier 0 → 1) also add to XDP
        if tier == 0 {
            let ip_clone = ip;
            tokio::spawn(async move {
                let mut xdp = crate::XDP_MANAGER.lock().await;
                if let IpAddr::V4(v4) = ip_clone {
                    let _ = xdp.block_ip(v4);
                }
            });
        }
        true
    } else {
        false
    }
}

/// Check whether `ip` is currently under a temporary auto-remediation block.
pub fn is_ip_temporarily_blocked(ip: IpAddr) -> bool {
    BLOCKED_IPS.get(&ip).is_some_and(|rec| {
        let now = Instant::now();
        now < rec.block_until
    })
}

/// Return the remaining block duration in seconds for `ip`, or 0 if not blocked.
#[allow(dead_code)]
pub fn remaining_block_secs(ip: IpAddr) -> u64 {
    BLOCKED_IPS.get(&ip).map_or(0, |rec| {
        let now = Instant::now();
        if now < rec.block_until {
            rec.block_until.duration_since(now).as_secs()
        } else {
            0
        }
    })
}

// ── Dynamic IP Reputation Scoring ───────────────────────────────────────────

#[derive(Clone)]
struct IpReputation {
    score: f64,
    last_decay: Instant,
}

impl IpReputation {
    fn decay(&mut self) {
        // Lose 1 point per minute, floor at 0
        let elapsed = self.last_decay.elapsed().as_secs_f64();
        let decay = (elapsed / 60.0).min(self.score);
        self.score = (self.score - decay).max(0.0);
        self.last_decay = Instant::now();
    }
}

/// Global reputation table: IP → score. LRU cache bounded at 10k entries.
static IP_REPUTATION: Lazy<Cache<IpAddr, IpReputation>> = Lazy::new(|| Cache::new(10_000));

/// Score at which an IP is automatically added to the blocklist.
const REPUTATION_BLOCK_THRESHOLD: f64 = 50.0;

/// How many points to add for each type of event.
const REPUTATION_RATE_LIMIT_PENALTY: f64 = 5.0;
const REPUTATION_BLOCKED_ATTACK_PENALTY: f64 = 15.0;

/// Adjust `fn check_request` calls this whenever a rule triggers a block.
pub fn record_reputation_penalty(ip: IpAddr, is_rate_limit: bool) {
    let penalty = if is_rate_limit {
        REPUTATION_RATE_LIMIT_PENALTY
    } else {
        REPUTATION_BLOCKED_ATTACK_PENALTY
    };
    let mut rep = IP_REPUTATION.get(&ip).unwrap_or(IpReputation {
        score: 0.0,
        last_decay: Instant::now(),
    });
    rep.decay();
    rep.score = (rep.score + penalty).min(100.0);
    IP_REPUTATION.insert(ip, rep);
}

/// Returns `true` if this IP has crossed the reputation block threshold.
pub fn is_ip_reputation_blocked(ip: IpAddr) -> bool {
    if let Some(mut rep) = IP_REPUTATION.get(&ip) {
        rep.decay();
        let blocked = rep.score >= REPUTATION_BLOCK_THRESHOLD;
        // Write back updated last_decay so next check doesn't double-decay
        IP_REPUTATION.insert(ip, rep);
        blocked
    } else {
        false
    }
}

/// Get current reputation score (0.0–100.0) for an IP.
#[allow(dead_code)]
pub fn get_reputation_score(ip: IpAddr) -> f64 {
    if let Some(mut rep) = IP_REPUTATION.get(&ip) {
        rep.decay();
        let score = rep.score;
        IP_REPUTATION.insert(ip, rep);
        score
    } else {
        0.0
    }
}

pub fn start_rate_limiter_cleanup() {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = Instant::now();
            RATE_LIMITER.retain(|_, bucket| now.duration_since(bucket.last_access).as_secs() < 300);
            BLOCKED_IPS.retain(|ip, rec| {
                // Keep only if still in the active window or under an active block
                let window_ok = now.duration_since(rec.first_seen).as_secs() < 300;
                let blocked = now < rec.block_until;
                if !window_ok && !blocked {
                    tracing::debug!("Cleaning up auto-remediation record for {}", ip);
                }
                window_ok || blocked
            });
            // Reputation is LRU-bounded at 10k in quick_cache, auto-evicts — no retain needed.
        }
    });
}

impl RuleEngine {
    pub fn new(cfg: &Config) -> Self {
        let mut custom_rules: Vec<CompiledCustomRule> = Vec::new();

        // Compile custom rules from config with pre-compiled regex
        for rule in &cfg.custom_rules {
            let regex = if rule.operator == "regex" {
                let pattern = if rule.condition_type == "header" {
                    let parts: Vec<&str> = rule.condition_value.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        parts[1].trim()
                    } else {
                        ""
                    }
                } else {
                    rule.condition_value.as_str()
                };
                Regex::new(pattern).ok()
            } else {
                None
            };

            custom_rules.push(CompiledCustomRule {
                id: rule.id.clone(),
                name: rule.name.clone(),
                condition_type: rule.condition_type.clone(),
                operator: rule.operator.clone(),
                condition_value: rule.condition_value.clone(),
                action: rule.action.clone(),
                action_value: rule.action_value.clone(),
                enabled: rule.enabled,
                regex,
            });
        }

        // Dynamic rule loading from plugins directory
        let plugins_dir = std::path::Path::new("plugins");
        let _ = std::fs::create_dir_all(plugins_dir);
        if let Ok(entries) = std::fs::read_dir(plugins_dir) {
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if ext == "toml" {
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                if let Ok(plugin_rules) =
                                    toml::from_str::<Vec<crate::config::CustomRule>>(&content)
                                {
                                    for rule in plugin_rules {
                                        let regex = if rule.operator == "regex" {
                                            Regex::new(if rule.condition_type == "header" {
                                                let parts: Vec<&str> =
                                                    rule.condition_value.splitn(2, ':').collect();
                                                if parts.len() == 2 {
                                                    parts[1].trim()
                                                } else {
                                                    ""
                                                }
                                            } else {
                                                rule.condition_value.as_str()
                                            })
                                            .ok()
                                        } else {
                                            None
                                        };
                                        custom_rules.push(CompiledCustomRule {
                                            id: rule.id.clone(),
                                            name: rule.name.clone(),
                                            condition_type: rule.condition_type.clone(),
                                            operator: rule.operator.clone(),
                                            condition_value: rule.condition_value.clone(),
                                            action: rule.action.clone(),
                                            action_value: rule.action_value.clone(),
                                            enabled: rule.enabled,
                                            regex,
                                        });
                                    }
                                } else if let Ok(single_rule) =
                                    toml::from_str::<crate::config::CustomRule>(&content)
                                {
                                    let regex = if single_rule.operator == "regex" {
                                        Regex::new(if single_rule.condition_type == "header" {
                                            let parts: Vec<&str> = single_rule
                                                .condition_value
                                                .splitn(2, ':')
                                                .collect();
                                            if parts.len() == 2 {
                                                parts[1].trim()
                                            } else {
                                                ""
                                            }
                                        } else {
                                            single_rule.condition_value.as_str()
                                        })
                                        .ok()
                                    } else {
                                        None
                                    };
                                    custom_rules.push(CompiledCustomRule {
                                        id: single_rule.id.clone(),
                                        name: single_rule.name.clone(),
                                        condition_type: single_rule.condition_type.clone(),
                                        operator: single_rule.operator.clone(),
                                        condition_value: single_rule.condition_value.clone(),
                                        action: single_rule.action.clone(),
                                        action_value: single_rule.action_value.clone(),
                                        enabled: single_rule.enabled,
                                        regex,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Self { custom_rules }
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

        // Shannon Entropy-based Behavioral Anomaly Detection
        if is_rule_enabled("ANOMALY-DETECTION", enabled_rules) {
            let query_entropy = calculate_entropy(&norm_query);
            if query_entropy > 5.5 {
                return Some((
                    "ANOMALY-DETECTION".to_string(),
                    format!(
                        "High query entropy anomaly detected: {:.2} bits",
                        query_entropy
                    ),
                ));
            }

            let body_entropy = calculate_entropy(&norm_body);
            if body_entropy > 5.8 {
                return Some((
                    "ANOMALY-DETECTION".to_string(),
                    format!(
                        "High body entropy anomaly detected: {:.2} bits",
                        body_entropy
                    ),
                ));
            }
        }

        // Evaluate Custom Rules & Plugins
        for rule in &self.custom_rules {
            if !rule.enabled {
                continue;
            }
            if !is_rule_enabled(&rule.id, enabled_rules) {
                continue;
            }

            let val_to_check = match rule.condition_type.as_str() {
                "path" => path,
                "query" => query,
                "body" => body,
                "method" => method,
                "header" => {
                    let parts: Vec<&str> = rule.condition_value.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        let header_name = parts[0].trim().to_lowercase();
                        headers.get(&header_name).map(|v| v.as_str()).unwrap_or("")
                    } else {
                        ""
                    }
                }
                _ => "",
            };

            let matched = match rule.operator.as_str() {
                "equals" => {
                    if rule.condition_type == "header" {
                        let parts: Vec<&str> = rule.condition_value.splitn(2, ':').collect();
                        if parts.len() == 2 {
                            val_to_check.to_lowercase() == parts[1].trim().to_lowercase()
                        } else {
                            false
                        }
                    } else {
                        val_to_check.to_lowercase() == rule.condition_value.to_lowercase()
                    }
                }
                "contains" => {
                    if rule.condition_type == "header" {
                        let parts: Vec<&str> = rule.condition_value.splitn(2, ':').collect();
                        if parts.len() == 2 {
                            val_to_check
                                .to_lowercase()
                                .contains(&parts[1].trim().to_lowercase())
                        } else {
                            false
                        }
                    } else {
                        val_to_check
                            .to_lowercase()
                            .contains(&rule.condition_value.to_lowercase())
                    }
                }
                "regex" => {
                    if let Some(ref re) = rule.regex {
                        re.is_match(val_to_check)
                    } else {
                        false
                    }
                }
                _ => false,
            };

            if matched && rule.action == "block" {
                return Some((rule.id.clone(), format!("Custom rule block: {}", rule.name)));
            }
        }

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

pub fn calculate_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &byte in input.as_bytes() {
        counts[byte as usize] += 1;
    }
    let len = input.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn normalize_string(input: &str) -> String {
    // Pre-allocate dengan capacity 2x (normalisasi bisa expand karena URL/HTML decode)
    let mut buf = String::with_capacity(input.len() * 2);

    // 1. URL Decode (Recursively up to 3 times for double encoding)
    let mut decoded = input.to_string();
    for _ in 0..3 {
        if let Ok(d) = urlencoding::decode(&decoded) {
            if d == decoded {
                break;
            }
            decoded = d.into_owned();
        } else {
            break;
        }
    }

    // 2. HTML Entity Decode (&lt; -> <, &gt; -> >, etc.)
    let decoded = htmlescape::decode_html(&decoded).unwrap_or(decoded);

    // 3. NFKC + lowercase + cleanup dalam single pass
    //    Hindari multiple allocations: to_lowercase(), replace(), split_whitespace()
    let mut prev_space = false;
    for ch in decoded.nfkc() {
        let ch_lower = ch.to_lowercase().next().unwrap_or(ch);
        if ch_lower == '\0' {
            continue;
        }
        if ch_lower == '+' || ch_lower.is_whitespace() {
            if !prev_space {
                buf.push(' ');
                prev_space = true;
            }
        } else {
            buf.push(ch_lower);
            prev_space = false;
        }
    }

    buf
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
    pub fn check_rate_limit_local(&self, ip: IpAddr, limit: u32) -> bool {
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

    /// Rate limiter check by API token/key.
    /// Uses a separate token bucket pool keyed on the token string.
    pub fn check_rate_limit_token(&self, token: &str, limit: u32) -> bool {
        let rate = limit as f64 / 60.0;
        let capacity = rate * 2.0;
        let key = token.to_string();
        let mut bucket = TOKEN_RATE_LIMITER
            .entry(key)
            .or_insert_with(|| TokenBucket {
                tokens: capacity,
                last_check: Instant::now(),
                last_access: Instant::now(),
                rate,
                capacity,
            });

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

        bucket.tokens = (bucket.tokens + elapsed * bucket.rate).min(bucket.capacity);

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Rate limiter check. Supports distributed Redis rate limiting with local fallback.
    pub async fn check_rate_limit(
        &self,
        ip: IpAddr,
        limit: u32,
        redis_config: &crate::config::RedisConfig,
    ) -> bool {
        if redis_config.enabled {
            let mut client_guard = REDIS_CLIENT.read().await;
            if client_guard.is_none() {
                drop(client_guard);
                let mut write_guard = REDIS_CLIENT.write().await;
                if write_guard.is_none() {
                    match redis::Client::open(redis_config.url.as_str()) {
                        Ok(client) => {
                            *write_guard = Some(client);
                        }
                        Err(e) => {
                            eprintln!(
                                "Failed to open Redis client at {}: {:?}",
                                redis_config.url, e
                            );
                        }
                    }
                }
                client_guard = REDIS_CLIENT.read().await;
            }

            if let Some(client) = &*client_guard {
                if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                    let now_bucket = chrono::Utc::now().timestamp() / 60;
                    let key = format!("ratelimit:{}:{}", ip, now_bucket);

                    let count_res: redis::RedisResult<u32> =
                        redis::cmd("INCR").arg(&key).query_async(&mut conn).await;

                    if let Ok(count) = count_res {
                        if count == 1 {
                            let _: redis::RedisResult<()> = redis::cmd("EXPIRE")
                                .arg(&key)
                                .arg(65)
                                .query_async(&mut conn)
                                .await;
                        }
                        return count <= limit;
                    }
                }
            }
        }

        // Fallback to local rate limiting
        self.check_rate_limit_local(ip, limit)
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
                webhooks: vec![],
                metrics_push_url: None,
                metrics_push_interval_secs: 60,
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
            redis: crate::config::RedisConfig {
                enabled: false,
                url: "redis://127.0.0.1:6379".to_string(),
            },
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

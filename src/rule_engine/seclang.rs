//! SecLang / OWASP CRS Rule Engine Parser & Evaluator
//!
//! Implementasi parser & evaluator untuk sintaks SecLang (ModSecurity / OWASP CRS).
//! Mendukung directive `SecRule`, `SecAction`, dan `SecRuleRemoveById`.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use tracing;

static WS_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());

/// Target variabel SecLang
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecVariable {
    RequestHeaders,
    RequestHeader(String),
    Args,
    Arg(String),
    RequestUri,
    RequestMethod,
    RequestBody,
    Tx(String),
    ClientIp,
}

/// Operator SecLang
#[derive(Debug, Clone)]
pub enum SecOperator {
    Rx(Regex),
    Pm(Vec<String>),
    Contains(String),
    Within(String),
    Eq(i64),
    Gt(i64),
    Ge(i64),
    Lt(i64),
    Le(i64),
    Unconditional,
}

/// Transformasi data SecLang (t:transform)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecTransform {
    None,
    Lowercase,
    UrlDecode,
    RemoveNulls,
    CompressWhitespace,
    HtmlEntityDecode,
    Base64Decode,
}

/// Action SecLang
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecActionType {
    Block,
    Deny,
    Pass,
    Allow,
    SetVar { key: String, value: String },
}

/// Compiled SecLang Rule
#[derive(Debug, Clone)]
pub struct SecLangRule {
    pub id: String,
    pub phase: u8, // 1-4
    pub variables: Vec<SecVariable>,
    pub operator: SecOperator,
    pub actions: Vec<SecActionType>,
    pub transforms: Vec<SecTransform>,
    pub msg: Option<String>,
    pub severity: String,
    pub anomaly_score: u32,
}

/// Store untuk mengelola rules SecLang
#[derive(Debug, Clone, Default)]
pub struct SecLangEngine {
    pub rules: Vec<SecLangRule>,
    pub disabled_rules: HashSet<String>,
}

impl SecLangEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load & parse string berisi SecLang rules
    pub fn parse_rules(&mut self, content: &str) -> Result<usize, String> {
        let mut count = 0;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed.starts_with("SecRuleRemoveById") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                for id in &parts[1..] {
                    self.disabled_rules.insert((*id).to_string());
                }
            } else if trimmed.starts_with("SecRule") {
                match parse_sec_rule(trimmed) {
                    Ok(rule) => {
                        self.rules.push(rule);
                        count += 1;
                    }
                    Err(e) => {
                        tracing::warn!("Failed parsing SecRule line: {} (Error: {})", trimmed, e)
                    }
                }
            } else if trimmed.starts_with("SecAction") {
                match parse_sec_action(trimmed) {
                    Ok(rule) => {
                        self.rules.push(rule);
                        count += 1;
                    }
                    Err(e) => {
                        tracing::warn!("Failed parsing SecAction line: {} (Error: {})", trimmed, e)
                    }
                }
            }
        }
        Ok(count)
    }

    /// Disable specific rule ID
    pub fn remove_rule(&mut self, id: &str) {
        self.disabled_rules.insert(id.to_string());
    }

    /// Evaluasi request terhadap SecLang rules di phase tertentu
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_phase(
        &self,
        phase: u8,
        method: &str,
        path: &str,
        query: &str,
        headers: &ahash::AHashMap<String, String>,
        body: &str,
        client_ip: &str,
    ) -> Option<&SecLangRule> {
        for rule in &self.rules {
            if rule.phase != phase {
                continue;
            }
            if self.disabled_rules.contains(&rule.id) {
                continue;
            }

            if self.evaluate_rule(rule, method, path, query, headers, body, client_ip) {
                return Some(rule);
            }
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_rule(
        &self,
        rule: &SecLangRule,
        method: &str,
        path: &str,
        query: &str,
        headers: &ahash::AHashMap<String, String>,
        body: &str,
        client_ip: &str,
    ) -> bool {
        // Unconditional (SecAction)
        if matches!(rule.operator, SecOperator::Unconditional) {
            return true;
        }

        // Kumpulkan nilai variabel
        let mut target_values = Vec::new();
        for var in &rule.variables {
            match var {
                SecVariable::RequestHeaders => {
                    for (k, v) in headers {
                        target_values.push(format!("{}: {}", k, v));
                    }
                }
                SecVariable::RequestHeader(name) => {
                    if let Some(v) = headers.get(&name.to_lowercase()) {
                        target_values.push(v.clone());
                    }
                }
                SecVariable::Args => {
                    if !query.is_empty() {
                        target_values.push(query.to_string());
                    }
                    if !body.is_empty() {
                        target_values.push(body.to_string());
                    }
                }
                SecVariable::Arg(name) => {
                    // Extract query/body arg
                    for pair in query.split('&').chain(body.split('&')) {
                        if let Some((k, v)) = pair.split_once('=') {
                            if k.eq_ignore_ascii_case(name) {
                                target_values.push(v.to_string());
                            }
                        }
                    }
                }
                SecVariable::RequestUri => {
                    if query.is_empty() {
                        target_values.push(path.to_string());
                    } else {
                        target_values.push(format!("{}?{}", path, query));
                    }
                }
                SecVariable::RequestMethod => {
                    target_values.push(method.to_string());
                }
                SecVariable::RequestBody => {
                    target_values.push(body.to_string());
                }
                SecVariable::ClientIp => {
                    target_values.push(client_ip.to_string());
                }
                SecVariable::Tx(_) => {}
            }
        }

        // Evaluasi terhadap target values dengan transformasi
        for val in target_values {
            let transformed = apply_transforms(&val, &rule.transforms);
            if match_operator(&rule.operator, &transformed) {
                return true;
            }
        }

        false
    }
}

fn apply_transforms(input: &str, transforms: &[SecTransform]) -> String {
    let mut current = input.to_string();
    for t in transforms {
        match t {
            SecTransform::None => {}
            SecTransform::Lowercase => {
                current = current.to_lowercase();
            }
            SecTransform::UrlDecode => {
                if let Ok(dec) = urlencoding::decode(&current) {
                    current = dec.into_owned();
                }
            }
            SecTransform::RemoveNulls => {
                current = current.replace('\0', "");
            }
            SecTransform::CompressWhitespace => {
                current = WS_REGEX.replace_all(&current, " ").to_string();
            }
            SecTransform::HtmlEntityDecode => {
                current = htmlescape::decode_html(&current).unwrap_or(current);
            }
            SecTransform::Base64Decode => {
                use base64::Engine;
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&current) {
                    if let Ok(s) = String::from_utf8(decoded) {
                        current = s;
                    }
                }
            }
        }
    }
    current
}

fn match_operator(op: &SecOperator, val: &str) -> bool {
    match op {
        SecOperator::Rx(re) => re.is_match(val),
        SecOperator::Pm(phrases) => {
            let val_lower = val.to_lowercase();
            phrases
                .iter()
                .any(|p| val_lower.contains(&p.to_lowercase()))
        }
        SecOperator::Contains(substr) => val.contains(substr),
        SecOperator::Within(set) => set.contains(val),
        SecOperator::Eq(num) => val.parse::<i64>().map(|n| n == *num).unwrap_or(false),
        SecOperator::Gt(num) => val.parse::<i64>().map(|n| n > *num).unwrap_or(false),
        SecOperator::Ge(num) => val.parse::<i64>().map(|n| n >= *num).unwrap_or(false),
        SecOperator::Lt(num) => val.parse::<i64>().map(|n| n < *num).unwrap_or(false),
        SecOperator::Le(num) => val.parse::<i64>().map(|n| n <= *num).unwrap_or(false),
        SecOperator::Unconditional => true,
    }
}

/// Parse SecRule syntax: `SecRule TARGETS "@operator arg" "actions"`
fn parse_sec_rule(line: &str) -> Result<SecLangRule, String> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut current = String::new();

    let text = line.trim_start_matches("SecRule").trim();
    for ch in text.chars() {
        match ch {
            '"' | '\'' => {
                in_quotes = !in_quotes;
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }

    if parts.len() < 3 {
        return Err("SecRule requires at least 3 parts: targets, operator, actions".into());
    }

    let targets_raw = &parts[0];
    let operator_raw = &parts[1];
    let actions_raw = &parts[2];

    let variables = parse_variables(targets_raw);
    let operator = parse_operator(operator_raw)?;
    let (id, phase, actions, transforms, msg, severity, anomaly_score) = parse_actions(actions_raw);

    Ok(SecLangRule {
        id,
        phase,
        variables,
        operator,
        actions,
        transforms,
        msg,
        severity,
        anomaly_score,
    })
}

/// Parse SecAction syntax: `SecAction "actions"`
fn parse_sec_action(line: &str) -> Result<SecLangRule, String> {
    let text = line.trim_start_matches("SecAction").trim();
    let actions_raw = text.trim_matches('"').trim_matches('\'');

    let (id, phase, actions, transforms, msg, severity, anomaly_score) = parse_actions(actions_raw);

    Ok(SecLangRule {
        id,
        phase,
        variables: vec![],
        operator: SecOperator::Unconditional,
        actions,
        transforms,
        msg,
        severity,
        anomaly_score,
    })
}

fn parse_variables(raw: &str) -> Vec<SecVariable> {
    let mut vars = Vec::new();
    for item in raw.split('|') {
        let item = item.trim();
        if item.eq_ignore_ascii_case("REQUEST_HEADERS") {
            vars.push(SecVariable::RequestHeaders);
        } else if let Some(h) = item.strip_prefix("REQUEST_HEADERS:") {
            vars.push(SecVariable::RequestHeader(h.to_string()));
        } else if item.eq_ignore_ascii_case("ARGS") {
            vars.push(SecVariable::Args);
        } else if let Some(a) = item.strip_prefix("ARGS:") {
            vars.push(SecVariable::Arg(a.to_string()));
        } else if item.eq_ignore_ascii_case("REQUEST_URI") {
            vars.push(SecVariable::RequestUri);
        } else if item.eq_ignore_ascii_case("REQUEST_METHOD") {
            vars.push(SecVariable::RequestMethod);
        } else if item.eq_ignore_ascii_case("REQUEST_BODY") {
            vars.push(SecVariable::RequestBody);
        } else if item.eq_ignore_ascii_case("REMOTE_ADDR") {
            vars.push(SecVariable::ClientIp);
        } else if let Some(t) = item.strip_prefix("TX:") {
            vars.push(SecVariable::Tx(t.to_string()));
        }
    }
    if vars.is_empty() {
        vars.push(SecVariable::Args);
    }
    vars
}

fn parse_operator(raw: &str) -> Result<SecOperator, String> {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("@rx") {
        let pat = rest.trim();
        Regex::new(&format!("(?i){}", pat))
            .map(SecOperator::Rx)
            .map_err(|e| format!("Invalid regex in @rx: {}", e))
    } else if let Some(rest) = trimmed.strip_prefix("@pm") {
        let phrases: Vec<String> = rest.split_whitespace().map(|s| s.to_string()).collect();
        Ok(SecOperator::Pm(phrases))
    } else if let Some(rest) = trimmed.strip_prefix("@contains") {
        Ok(SecOperator::Contains(rest.trim().to_string()))
    } else if let Some(rest) = trimmed.strip_prefix("@within") {
        Ok(SecOperator::Within(rest.trim().to_string()))
    } else if let Some(rest) = trimmed.strip_prefix("@eq") {
        let val = rest.trim().parse::<i64>().unwrap_or(0);
        Ok(SecOperator::Eq(val))
    } else if let Some(rest) = trimmed.strip_prefix("@gt") {
        let val = rest.trim().parse::<i64>().unwrap_or(0);
        Ok(SecOperator::Gt(val))
    } else {
        Regex::new(&format!("(?i){}", trimmed))
            .map(SecOperator::Rx)
            .map_err(|e| format!("Invalid fallback regex: {}", e))
    }
}

fn parse_actions(
    raw: &str,
) -> (
    String,
    u8,
    Vec<SecActionType>,
    Vec<SecTransform>,
    Option<String>,
    String,
    u32,
) {
    let mut id = "900000".to_string();
    let mut phase = 2;
    let mut actions = Vec::new();
    let mut transforms = Vec::new();
    let mut msg = None;
    let mut severity = "CRITICAL".to_string();
    let mut anomaly_score = 50;

    for part in raw.split(',') {
        let item = part.trim();
        if item.eq_ignore_ascii_case("block") || item.eq_ignore_ascii_case("deny") {
            actions.push(SecActionType::Block);
        } else if item.eq_ignore_ascii_case("pass") {
            actions.push(SecActionType::Pass);
        } else if item.eq_ignore_ascii_case("allow") {
            actions.push(SecActionType::Allow);
        } else if let Some(val) = item.strip_prefix("id:") {
            id = val.trim_matches('\'').trim_matches('"').to_string();
        } else if let Some(val) = item.strip_prefix("phase:") {
            phase = val.parse::<u8>().unwrap_or(2);
        } else if let Some(val) = item.strip_prefix("msg:") {
            msg = Some(val.trim_matches('\'').trim_matches('"').to_string());
        } else if let Some(val) = item.strip_prefix("severity:") {
            severity = val.trim_matches('\'').trim_matches('"').to_uppercase();
        } else if let Some(val) = item.strip_prefix("t:") {
            let t_name = val.trim_matches('\'').trim_matches('"').to_lowercase();
            match t_name.as_str() {
                "lowercase" => transforms.push(SecTransform::Lowercase),
                "urldecode" => transforms.push(SecTransform::UrlDecode),
                "removenulls" => transforms.push(SecTransform::RemoveNulls),
                "compresswhitespace" => transforms.push(SecTransform::CompressWhitespace),
                "htmlentitydecode" => transforms.push(SecTransform::HtmlEntityDecode),
                "base64decode" => transforms.push(SecTransform::Base64Decode),
                _ => {}
            }
        } else if let Some(val) = item.strip_prefix("setvar:") {
            let val_clean = val.trim_matches('\'').trim_matches('"');
            if let Some((k, v)) = val_clean.split_once('=') {
                actions.push(SecActionType::SetVar {
                    key: k.to_string(),
                    value: v.to_string(),
                });
                if k.contains("inbound_anomaly_score") || k.contains("anomaly_score") {
                    anomaly_score = v.parse::<u32>().unwrap_or(50);
                }
            }
        }
    }

    if actions.is_empty() {
        actions.push(SecActionType::Block);
    }

    (id, phase, actions, transforms, msg, severity, anomaly_score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_eval_sec_rule_sqli() {
        let mut engine = SecLangEngine::new();
        let rule_str = r#"SecRule REQUEST_HEADERS|ARGS "@rx (union.*select|select.*from)" "id:942100,phase:2,block,msg:'SQL Injection Detected',t:lowercase,t:urlDecode""#;
        let count = engine.parse_rules(rule_str).unwrap();
        assert_eq!(count, 1);

        let mut headers = ahash::AHashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());

        // Attack payload
        let match_rule = engine.evaluate_phase(
            2,
            "GET",
            "/search",
            "q=1%27%20UNION%20SELECT%201,2--",
            &headers,
            "",
            "127.0.0.1",
        );
        assert!(match_rule.is_some());
        let rule = match_rule.unwrap();
        assert_eq!(rule.id, "942100");
        assert_eq!(rule.severity, "CRITICAL");

        // Safe payload
        let safe_rule =
            engine.evaluate_phase(2, "GET", "/search", "q=rust+waf", &headers, "", "127.0.0.1");
        assert!(safe_rule.is_none());
    }

    #[test]
    fn test_sec_rule_remove_by_id() {
        let mut engine = SecLangEngine::new();
        let rules_str = r#"
SecRule ARGS "@rx (union.*select)" "id:942100,phase:2,block"
SecRuleRemoveById 942100
"#;
        engine.parse_rules(rules_str).unwrap();

        let headers = ahash::AHashMap::new();
        let result =
            engine.evaluate_phase(2, "GET", "/", "q=union select 1", &headers, "", "127.0.0.1");
        assert!(result.is_none()); // Removed rule should be ignored
    }
}

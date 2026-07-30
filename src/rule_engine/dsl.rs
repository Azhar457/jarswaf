//! DSL Parser untuk jarsWAF rule (.jwaf files)
//!
//! Hand-written recursive descent parser (no nom dependency).
//! Syntax:
//! ```jwaf
//! @id: "100001"
//! @name: "SQLi UNION SELECT"
//! @phase: request_body
//! @severity: critical
//! @action: block
//!
//! match any {
//!   body ~ "(?i)union\\s+select"
//!   args ~ "(?i)union\\s+select"
//! }
//! ```
//!
//! Separator `---` antar multiple rule dalam 1 file.

use crate::rule_engine::{
    CompiledCondition, CompiledRule, CompiledValue, MatchLogic, MatchOperator, Phase, RuleAction,
    Severity,
};

#[derive(Debug, Clone, PartialEq)]
enum DslOperator {
    Tilde,
    Contains,
    Equals,
    In,
}

struct DslCondition {
    field: String,
    op: DslOperator,
    str_val: String,
    list_val: Vec<String>,
}

struct DslRule {
    id: Option<String>,
    name: Option<String>,
    phase: Option<Phase>,
    severity: Option<Severity>,
    action: Option<RuleAction>,
    paranoia: Option<u32>,
    score: Option<u32>,
    tags: Vec<String>,
    logic: MatchLogic,
    conditions: Vec<DslCondition>,
}

fn trim(s: &str) -> &str {
    s.trim()
}

fn parse_quoted(s: &str) -> Option<(&str, &str)> {
    let s = trim(s);
    if let Some(stripped) = s.strip_prefix('"') {
        if let Some(end) = stripped.find('"') {
            let content = &stripped[..end];
            let rest = &stripped[end + 1..];
            Some((content, rest))
        } else {
            None
        }
    } else {
        None
    }
}

fn parse_bracket_list(s: &str) -> Option<(Vec<String>, &str)> {
    let s = trim(s);
    if !s.starts_with('[') {
        return None;
    }
    let mut items = Vec::new();
    let mut rest = &s[1..];
    loop {
        rest = trim(rest);
        if let Some(stripped) = rest.strip_prefix(']') {
            return Some((items, stripped));
        }
        if !rest.is_empty() && !rest.starts_with(',') {
            if let Some((item, after)) = parse_quoted(rest) {
                items.push(item.to_string());
                rest = after;
                rest = trim(rest);
                if rest.starts_with(',') {
                    rest = &rest[1..];
                    continue;
                }
                continue;
            }
        }
        // skip until ] or end
        break;
    }
    // fallback: scan until ]
    if let Some(end) = rest.find(']') {
        Some((items, &rest[end + 1..]))
    } else {
        None
    }
}

fn parse_value(s: &str) -> (&str, &str) {
    let s = trim(s);
    if s.starts_with('"') {
        // quoted value
        if let Some((val, rest)) = parse_quoted(s) {
            return (val, rest);
        }
    }
    // bare value until newline/space/brace/#
    let end = s.find(['\n', '\r', '#', '}', ' ']).unwrap_or(s.len());
    let val = &s[..end];
    let rest = &s[end..];
    (trim(val), rest)
}

fn parse_metadata(line: &str) -> Option<(&str, Vec<String>)> {
    // @key: value or @key: [list]
    // line already trimmed
    let line = trim(line);
    if !line.starts_with('@') {
        return None;
    }
    let rest = &line[1..]; // skip @
    let colon_pos = rest.find(':')?;
    let key = trim(&rest[..colon_pos]);
    let val_str = trim(&rest[colon_pos + 1..]);
    if val_str.starts_with('[') {
        let (list, _) = parse_bracket_list(val_str).unwrap_or_default();
        Some((key, list))
    } else {
        let (val, _) = parse_value(val_str);
        Some((key, vec![val.to_string()]))
    }
}

fn parse_condition_line(line: &str) -> Option<DslCondition> {
    // Format: field ~ "regex" | field contains "string" | field in ["a", "b"]
    let line = trim(line);
    if line.is_empty() || line.starts_with('}') || line.starts_with("match") {
        return None;
    }

    // Try ~ operator
    if let Some(tilde_pos) = line.find('~') {
        let field = trim(&line[..tilde_pos]);
        let val_str = trim(&line[tilde_pos + 1..]);
        let (val, _) = parse_value(val_str);
        return Some(DslCondition {
            field: field.to_string(),
            op: DslOperator::Tilde,
            str_val: val.to_string(),
            list_val: vec![],
        });
    }

    // Try "in" operator
    if let Some(in_pos) = line.find(" in ") {
        let field = trim(&line[..in_pos]);
        let val_str = trim(&line[in_pos + 3..]);
        if let Some((list, _)) = parse_bracket_list(val_str) {
            return Some(DslCondition {
                field: field.to_string(),
                op: DslOperator::In,
                str_val: String::new(),
                list_val: list,
            });
        }
    }

    // Try "contains" operator
    if let Some(cont_pos) = line.find(" contains ") {
        let field = trim(&line[..cont_pos]);
        let val_str = trim(&line[cont_pos + 10..]);
        let (val, _) = parse_value(val_str);
        return Some(DslCondition {
            field: field.to_string(),
            op: DslOperator::Contains,
            str_val: val.to_string(),
            list_val: vec![],
        });
    }

    // Try "equals" operator
    if let Some(eq_pos) = line.find(" equals ") {
        let field = trim(&line[..eq_pos]);
        let val_str = trim(&line[eq_pos + 8..]);
        let (val, _) = parse_value(val_str);
        return Some(DslCondition {
            field: field.to_string(),
            op: DslOperator::Equals,
            str_val: val.to_string(),
            list_val: vec![],
        });
    }

    None
}

pub fn parse_jwaf_rules(input: &str) -> Result<Vec<CompiledRule>, String> {
    let mut rules = Vec::new();
    let mut current_rule = DslRule {
        id: None,
        name: None,
        phase: None,
        severity: None,
        action: None,
        paranoia: None,
        score: None,
        tags: vec![],
        logic: MatchLogic::Any,
        conditions: vec![],
    };
    let mut in_match_block = false;
    let mut has_current_data = false;

    let lines: Vec<&str> = input.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let raw = lines[i];
        let line = trim(raw);

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            i += 1;
            continue;
        }

        // Separator between rules
        if line == "---" {
            if has_current_data {
                rules.push(compile_dsl_rule(&current_rule, rules.len())?);
                current_rule = DslRule {
                    id: None,
                    name: None,
                    phase: None,
                    severity: None,
                    action: None,
                    paranoia: None,
                    score: None,
                    tags: vec![],
                    logic: MatchLogic::Any,
                    conditions: vec![],
                };
                has_current_data = false;
                in_match_block = false;
            }
            i += 1;
            continue;
        }

        // Metadata line
        if line.starts_with('@') {
            if let Some((key, values)) = parse_metadata(line) {
                match key {
                    "id" => {
                        if let Some(v) = values.first() {
                            current_rule.id = Some(v.clone());
                            has_current_data = true;
                        }
                    }
                    "name" => {
                        if let Some(v) = values.first() {
                            current_rule.name = Some(v.clone());
                            has_current_data = true;
                        }
                    }
                    "phase" => {
                        if let Some(v) = values.first() {
                            current_rule.phase = match v.as_str() {
                                "request_headers" => Some(Phase::RequestHeaders),
                                "request_body" => Some(Phase::RequestBody),
                                "response_headers" => Some(Phase::ResponseHeaders),
                                "response_body" => Some(Phase::ResponseBody),
                                _ => None,
                            };
                            has_current_data = true;
                        }
                    }
                    "severity" => {
                        if let Some(v) = values.first() {
                            current_rule.severity = match v.as_str() {
                                "low" => Some(Severity::Low),
                                "medium" => Some(Severity::Medium),
                                "high" => Some(Severity::High),
                                "critical" => Some(Severity::Critical),
                                _ => None,
                            };
                            has_current_data = true;
                        }
                    }
                    "action" => {
                        if let Some(v) = values.first() {
                            current_rule.action = match v.as_str() {
                                "block" => Some(RuleAction::Block),
                                "log" => Some(RuleAction::Log),
                                "anomaly" => Some(RuleAction::Anomaly),
                                "pass" => Some(RuleAction::Pass),
                                _ => None,
                            };
                            has_current_data = true;
                        }
                    }
                    "paranoia" => {
                        if let Some(v) = values.first() {
                            current_rule.paranoia = v.parse::<u32>().ok();
                            has_current_data = true;
                        }
                    }
                    "score" => {
                        if let Some(v) = values.first() {
                            current_rule.score = v.parse::<u32>().ok();
                            has_current_data = true;
                        }
                    }
                    "tags" => {
                        current_rule.tags = values.clone();
                        has_current_data = true;
                    }
                    _ => {}
                }
            }
            i += 1;
            continue;
        }

        // Match block start
        if let Some(rest_stripped) = line.strip_prefix("match") {
            let rest = trim(rest_stripped);
            if rest.starts_with("any") {
                current_rule.logic = MatchLogic::Any;
            } else if rest.starts_with("all") {
                current_rule.logic = MatchLogic::All;
            }
            in_match_block = true;
            // Check if opening brace is on same line
            if let Some(brace_pos) = rest.find('{') {
                // Conditions may follow on same line or next lines
                let after_brace = &rest[brace_pos + 1..];
                let after_brace = trim(after_brace);
                if !after_brace.is_empty() && after_brace != "}" {
                    if let Some(cond) = parse_condition_line(after_brace) {
                        current_rule.conditions.push(cond);
                    }
                }
            }
            i += 1;
            continue;
        }

        // Inside match block — condition line
        if in_match_block {
            if line == "}" || line.starts_with("}") {
                in_match_block = false;
                i += 1;
                continue;
            }
            if let Some(cond) = parse_condition_line(line) {
                current_rule.conditions.push(cond);
            }
            i += 1;
            continue;
        }

        // Unknown line — skip
        i += 1;
    }

    // Last rule
    if has_current_data || !current_rule.conditions.is_empty() {
        rules.push(compile_dsl_rule(&current_rule, rules.len())?);
    }

    Ok(rules)
}

fn compile_dsl_rule(dsl: &DslRule, index: usize) -> Result<CompiledRule, String> {
    let id = dsl
        .id
        .clone()
        .unwrap_or_else(|| format!("dsl-{:04}", index + 1));
    let name = dsl.name.clone().unwrap_or_else(|| format!("Rule {}", id));
    let phase = dsl.phase.unwrap_or(Phase::RequestBody);
    let severity = dsl.severity.unwrap_or(Severity::Medium);
    let action = dsl.action.unwrap_or(RuleAction::Block);
    let score = dsl.score.unwrap_or(0);

    let mut conditions = Vec::new();
    for cond in &dsl.conditions {
        let operator = match cond.op {
            DslOperator::Tilde => MatchOperator::Rx,
            DslOperator::Contains => MatchOperator::Contains,
            DslOperator::Equals => MatchOperator::Equals,
            DslOperator::In => MatchOperator::Pm,
        };
        let compiled_value = match cond.op {
            DslOperator::Tilde => {
                let re = regex::Regex::new(&cond.str_val)
                    .map_err(|e| format!("invalid regex in rule '{}': {}", id, e))?;
                CompiledValue::Regex(re)
            }
            DslOperator::Contains => CompiledValue::String(cond.str_val.clone()),
            DslOperator::Equals => CompiledValue::String(cond.str_val.clone()),
            DslOperator::In => CompiledValue::StringList(cond.list_val.clone()),
        };
        conditions.push(CompiledCondition {
            field: cond.field.clone(),
            operator,
            compiled_value,
            negate: false,
        });
    }

    if conditions.is_empty() {
        return Err(format!("rule '{}' has zero conditions", id));
    }

    Ok(CompiledRule {
        id,
        name,
        phase,
        severity,
        paranoia: dsl.paranoia.unwrap_or(1),
        tags: dsl.tags.clone(),
        logic: dsl.logic,
        conditions,
        action,
        anomaly_score: score,
        enabled: true,
        transforms: vec![],
    })
}

// ────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_rule() {
        let input = r#"@id: "100001"
@name: "Test Rule"
@phase: request_body
@severity: critical
@action: block
@score: 50
@tags: ["sqli", "owasp"]

match any {
  body ~ "(?i)union.*select"
  args ~ "(?i)union.*select"
}
"#;
        let rules = parse_jwaf_rules(input).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "100001");
        assert_eq!(rules[0].conditions.len(), 2);
        assert_eq!(rules[0].action, RuleAction::Block);
        assert!(rules[0].tags.contains(&"sqli".to_string()));
    }

    #[test]
    fn test_parse_multiple_rules_separated() {
        let input = r#"@id: "2001"
@name: "SQLi"
@phase: request_body
@action: block

match any {
  body ~ "union"
}

---

@id: "2002"
@name: "XSS"
@phase: request_body
@action: block
@score: 50

match any {
  body ~ "<script>"
}
"#;
        let rules = parse_jwaf_rules(input).unwrap();
        assert_eq!(rules.len(), 2, "should parse 2 rules");
        assert_eq!(rules[0].id, "2001");
        assert_eq!(rules[1].id, "2002");
        assert_eq!(rules[1].anomaly_score, 50);
    }

    #[test]
    fn test_parse_contains_operator() {
        let input = r#"@id: "3001"
@name: "Contains test"
@phase: request_body
@action: block

match any {
  path contains "/etc/passwd"
}
"#;
        let rules = parse_jwaf_rules(input).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].conditions.len(), 1);
        if let CompiledValue::String(s) = &rules[0].conditions[0].compiled_value {
            assert_eq!(s, "/etc/passwd");
        } else {
            panic!("expected String value");
        }
    }

    #[test]
    fn test_parse_in_operator() {
        let input = r#"@id: "4001"
@name: "Scanner UA"
@phase: request_headers
@action: anomaly
@score: 10
@paranoia: 2

match any {
  headers.user-agent in ["sqlmap", "nikto", "nmap"]
}
"#;
        let rules = parse_jwaf_rules(input).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].phase, Phase::RequestHeaders);
        assert_eq!(rules[0].action, RuleAction::Anomaly);
        assert_eq!(rules[0].anomaly_score, 10);
        assert_eq!(rules[0].paranoia, 2);

        if let CompiledValue::StringList(list) = &rules[0].conditions[0].compiled_value {
            assert_eq!(list.len(), 3);
            assert!(list.contains(&"sqlmap".to_string()));
        } else {
            panic!("expected StringList");
        }
    }

    #[test]
    fn test_parse_without_id() {
        let input = r#"@name: "No ID"
@phase: request_body

match any {
  body ~ "test"
}
"#;
        let rules = parse_jwaf_rules(input).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].id.starts_with("dsl-"));
        assert_eq!(rules[0].name, "No ID");
    }

    #[test]
    fn test_compile_to_compiled_rule_matches_payload() {
        let input = r#"@id: "9001"
@name: "SQLi UNION"
@phase: request_body
@action: block
@score: 50

match any {
  body ~ "(?i)union.*select"
}
"#;
        let rules = parse_jwaf_rules(input).unwrap();
        let rule = &rules[0];

        use crate::rule_engine::RequestData;

        let req = RequestData {
            method: "POST".to_string(),
            path: "/".to_string(),
            query: "".to_string(),
            headers: ahash::AHashMap::new(),
            body: "1 UNION SELECT * FROM users".to_string(),
            cookies: ahash::AHashMap::new(),
            args: ahash::AHashMap::new(),
        };

        assert!(
            crate::rule_engine::evaluate_rule(rule, &req),
            "DSL rule should match UNION SELECT"
        );
    }

    #[test]
    fn test_dsl_rule_without_match_block() {
        // Rule without match block should fail (no conditions)
        let input = r#"@id: "9999"
@name: "No Match"
@phase: request_body
@action: block
"#;
        let result = parse_jwaf_rules(input);
        assert!(result.is_err(), "rule without conditions should fail");
    }
}

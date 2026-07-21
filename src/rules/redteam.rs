//! Red Team Testing Suite — Built-in OWASP Top 10 payload validation.
//!
//! Provides a comprehensive set of attack payloads that can be run
//! against the RuleEngine at any time to validate detection coverage.
//! Each test category maps to an OWASP Top 10 attack class.

use ahash::AHashMap;

/// A single attack payload test case.
#[derive(Debug, Clone)]
pub struct AttackPayload {
    pub id: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub path: &'static str,
    pub query: &'static str,
    pub body: &'static str,
    pub method: &'static str,
    pub headers: Vec<(&'static str, &'static str)>,
    /// Whether the WAF should block this payload (true = expect block).
    pub expect_blocked: bool,
}

/// Generate the full OWASP Top 10 test suite.
pub fn owasp_test_suite() -> Vec<AttackPayload> {
    vec![
        // ─── A03:2021 — Injection (SQLi) ────────────────────────────
        AttackPayload {
            id: "SQLI-001",
            category: "SQL Injection",
            description: "Classic OR 1=1 bypass",
            path: "/api/users",
            query: "id=1' OR '1'='1",
            body: "",
            method: "GET",
            headers: vec![],
            expect_blocked: true,
        },
        AttackPayload {
            id: "SQLI-002",
            category: "SQL Injection",
            description: "UNION SELECT extraction",
            path: "/api/products",
            query: "id=1 UNION SELECT username,password FROM users--",
            body: "",
            method: "GET",
            headers: vec![],
            expect_blocked: true,
        },
        AttackPayload {
            id: "SQLI-003",
            category: "SQL Injection",
            description: "Blind SQLi with SLEEP",
            path: "/api/search",
            query: "q=test' AND SLEEP(5)--",
            body: "",
            method: "GET",
            headers: vec![],
            expect_blocked: true,
        },
        AttackPayload {
            id: "SQLI-004",
            category: "SQL Injection",
            description: "Body POST SQLi",
            path: "/api/login",
            query: "",
            body: r#"{"username":"admin' OR 1=1--","password":"x"}"#,
            method: "POST",
            headers: vec![("content-type", "application/json")],
            expect_blocked: true,
        },
        // ─── A03:2021 — Injection (XSS) ─────────────────────────────
        AttackPayload {
            id: "XSS-001",
            category: "Cross-Site Scripting",
            description: "Basic script tag",
            path: "/search",
            query: "q=<script>alert('xss')</script>",
            body: "",
            method: "GET",
            headers: vec![],
            expect_blocked: true,
        },
        AttackPayload {
            id: "XSS-002",
            category: "Cross-Site Scripting",
            description: "Event handler injection",
            path: "/profile",
            query: "name=<img src=x onerror=alert(1)>",
            body: "",
            method: "GET",
            headers: vec![],
            expect_blocked: true,
        },
        AttackPayload {
            id: "XSS-003",
            category: "Cross-Site Scripting",
            description: "SVG onload XSS",
            path: "/upload",
            query: "",
            body: "<svg onload=alert('xss')>",
            method: "POST",
            headers: vec![],
            expect_blocked: true,
        },
        // ─── A03:2021 — Injection (Command) ─────────────────────────
        AttackPayload {
            id: "CMDI-001",
            category: "Command Injection",
            description: "Semicolon command chain",
            path: "/api/ping",
            query: "host=127.0.0.1;cat /etc/passwd",
            body: "",
            method: "GET",
            headers: vec![],
            expect_blocked: true,
        },
        AttackPayload {
            id: "CMDI-002",
            category: "Command Injection",
            description: "Backtick execution",
            path: "/api/lookup",
            query: "domain=`id`",
            body: "",
            method: "GET",
            headers: vec![],
            expect_blocked: true,
        },
        // ─── A01:2021 — Broken Access Control (Path Traversal) ──────
        AttackPayload {
            id: "LFI-001",
            category: "Local File Inclusion",
            description: "Classic path traversal",
            path: "/download",
            query: "file=../../../etc/passwd",
            body: "",
            method: "GET",
            headers: vec![],
            expect_blocked: true,
        },
        AttackPayload {
            id: "LFI-002",
            category: "Local File Inclusion",
            description: "Null byte path traversal",
            path: "/static/../../etc/shadow%00.jpg",
            query: "",
            body: "",
            method: "GET",
            headers: vec![],
            expect_blocked: true,
        },
        // ─── A05:2021 — Security Misconfiguration (SSRF) ────────────
        AttackPayload {
            id: "SSRF-001",
            category: "Server-Side Request Forgery",
            description: "Internal IP access",
            path: "/api/fetch",
            query: "url=http://169.254.169.254/latest/meta-data/",
            body: "",
            method: "GET",
            headers: vec![],
            expect_blocked: true,
        },
        // ─── A08:2021 — Software and Data Integrity (XXE) ───────────
        AttackPayload {
            id: "XXE-001",
            category: "XML External Entity",
            description: "XXE file read",
            path: "/api/xml",
            query: "",
            body: r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"#,
            method: "POST",
            headers: vec![("content-type", "application/xml")],
            expect_blocked: true,
        },
        // ─── A04:2021 — Insecure Design (SSTI) ──────────────────────
        AttackPayload {
            id: "SSTI-001",
            category: "Server-Side Template Injection",
            description: "Jinja2/Twig template expression",
            path: "/render",
            query: "name={{7*7}}",
            body: "",
            method: "GET",
            headers: vec![],
            expect_blocked: true,
        },
        // ─── A07:2021 — Identification and Auth (Bot Detection) ─────
        AttackPayload {
            id: "BOT-001",
            category: "Bot Detection",
            description: "Python requests user-agent",
            path: "/api/data",
            query: "",
            body: "",
            method: "GET",
            headers: vec![("user-agent", "python-requests/2.28.0")],
            expect_blocked: true,
        },
        AttackPayload {
            id: "BOT-002",
            category: "Bot Detection",
            description: "curl user-agent",
            path: "/",
            query: "",
            body: "",
            method: "GET",
            headers: vec![("user-agent", "curl/7.88.1")],
            expect_blocked: true,
        },
        // ─── Clean traffic (should pass) ─────────────────────────────
        AttackPayload {
            id: "CLEAN-001",
            category: "Legitimate",
            description: "Normal API call",
            path: "/api/v1/products",
            query: "page=1&limit=20",
            body: "",
            method: "GET",
            headers: vec![("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")],
            expect_blocked: false,
        },
    ]
}

/// Run the full test suite against a RuleEngine and return a report.
pub fn run_red_team_suite(
    rule_engine: &crate::rules::RuleEngine,
    enabled_rules: &[String],
) -> RedTeamReport {
    let payloads = owasp_test_suite();
    let mut results = Vec::new();
    let mut passed = 0;
    let mut failed = 0;

    for payload in &payloads {
        let mut headers_map = AHashMap::new();
        for (k, v) in &payload.headers {
            headers_map.insert(k.to_string(), v.to_string());
        }

        let verdict = rule_engine.check_request(
            payload.path,
            payload.query,
            &headers_map,
            payload.body,
            None,
            payload.method,
            enabled_rules,
        );

        let was_blocked = verdict.is_some();
        let correct = was_blocked == payload.expect_blocked;

        if correct {
            passed += 1;
        } else {
            failed += 1;
        }

        results.push(TestResult {
            payload_id: payload.id.to_string(),
            category: payload.category.to_string(),
            description: payload.description.to_string(),
            expected_block: payload.expect_blocked,
            actual_block: was_blocked,
            rule_matched: verdict.map(|(id, _)| id),
            correct,
        });
    }

    RedTeamReport {
        total: payloads.len(),
        passed,
        failed,
        results,
    }
}

/// Report from running the red team test suite.
#[derive(Debug)]
pub struct RedTeamReport {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<TestResult>,
}

impl RedTeamReport {
    /// Format report as a human-readable string.
    pub fn to_string_report(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "=== Red Team Report ===\nTotal: {} | Passed: {} | Failed: {}\n\n",
            self.total, self.passed, self.failed
        ));

        for r in &self.results {
            let status = if r.correct { "✅ PASS" } else { "❌ FAIL" };
            let action = if r.actual_block { "BLOCKED" } else { "PASSED" };
            let expected = if r.expected_block { "block" } else { "pass" };
            out.push_str(&format!(
                "{} [{}] {} — {} (expected: {}, got: {}",
                status, r.payload_id, r.category, r.description, expected, action
            ));
            if let Some(ref rule) = r.rule_matched {
                out.push_str(&format!(", rule: {}", rule));
            }
            out.push_str(")\n");
        }

        out
    }
}

/// Result of a single test case.
#[derive(Debug)]
pub struct TestResult {
    pub payload_id: String,
    pub category: String,
    pub description: String,
    pub expected_block: bool,
    pub actual_block: bool,
    pub rule_matched: Option<String>,
    pub correct: bool,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owasp_suite_has_payloads() {
        let suite = owasp_test_suite();
        assert!(suite.len() >= 15, "Expected at least 15 payloads");
    }

    #[test]
    fn test_red_team_against_default_engine() {
        let config = crate::config::Config::default();
        let engine = crate::rules::RuleEngine::new(&config);
        // Enable all rules
        let enabled = vec!["*".to_string()];
        let report = run_red_team_suite(&engine, &enabled);

        // Most attack payloads should be caught
        let attack_results: Vec<_> = report.results.iter().filter(|r| r.expected_block).collect();
        let caught = attack_results.iter().filter(|r| r.correct).count();

        // At minimum, 50% of attacks should be caught by default rules
        assert!(
            caught as f64 / attack_results.len() as f64 >= 0.5,
            "Detection rate too low: {}/{} attacks caught",
            caught,
            attack_results.len()
        );

        // Clean traffic should always pass
        let clean_results: Vec<_> = report
            .results
            .iter()
            .filter(|r| !r.expected_block)
            .collect();
        for r in &clean_results {
            assert!(
                r.correct,
                "False positive on clean traffic: {} — {}. Rule: {:?}",
                r.payload_id, r.description, r.rule_matched
            );
        }
    }
}

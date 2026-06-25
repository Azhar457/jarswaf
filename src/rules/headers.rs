use super::{Action, Phase, RequestInfo, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

static BOT_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirb|wfuzz|nessus|openvas|w3af|arachni|skipfish|wapiti|vega|netsparker|acunetix|burpsuite|metasploit|nuclei)").unwrap()
});

static XFF_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.|^127\.|^0\.0\.0\.0|::1|::ffff:)",
    )
    .unwrap()
});

fn check_bot_001(req: &RequestInfo) -> bool {
    if let Some(ua) = req.headers.get("user-agent") {
        BOT_001_REGEX.is_match(ua)
    } else {
        false
    }
}

fn check_host_001(req: &RequestInfo) -> bool {
    if let Some(host) = req.headers.get("host") {
        let hostname = host.split(':').next().unwrap_or("");
        hostname.parse::<std::net::IpAddr>().is_ok()
            || hostname
                .chars()
                .any(|c| !c.is_alphanumeric() && c != '.' && c != '-')
    } else {
        false
    }
}

fn check_hpp_001(req: &RequestInfo) -> bool {
    let mut seen = std::collections::HashSet::new();
    for param in req.query.split('&') {
        if let Some(key) = param.split('=').next() {
            if !key.is_empty() && !seen.insert(key) {
                return true;
            }
        }
    }
    false
}

fn check_verb_001(req: &RequestInfo) -> bool {
    !matches!(
        req.method,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "PATCH" | "OPTIONS" | "TRACE"
    )
}

fn check_xff_001(req: &RequestInfo) -> bool {
    if let Some(xff) = req.headers.get("x-forwarded-for") {
        XFF_001_REGEX.is_match(xff)
    } else {
        false
    }
}

pub static HEADER_RULES: &[Rule] = &[
    Rule {
        id: "BOT-001",
        name: "Bad User-Agent",
        phase: Phase::Headers,
        action: Action::Block,
        severity: Severity::Medium,
        description: "Known security scanner or bot User-Agent",
        check: check_bot_001,
    },
    Rule {
        id: "HOST-001",
        name: "Host Header Injection",
        phase: Phase::Headers,
        action: Action::Block,
        severity: Severity::High,
        description: "Request with IP-based or malformed Host header",
        check: check_host_001,
    },
    Rule {
        id: "HPP-001",
        name: "HTTP Parameter Pollution",
        phase: Phase::Headers,
        action: Action::Block,
        severity: Severity::Medium,
        description: "Duplicate query parameters detected (HPP attack)",
        check: check_hpp_001,
    },
    Rule {
        id: "VERB-001",
        name: "HTTP Verb Tampering",
        phase: Phase::Headers,
        action: Action::Block,
        severity: Severity::Medium,
        description: "Uncommon or dangerous HTTP method",
        check: check_verb_001,
    },
    Rule {
        id: "XFF-001",
        name: "X-Forwarded-For Spoofing",
        phase: Phase::Headers,
        action: Action::Log,
        severity: Severity::Low,
        description: "X-Forwarded-For contains private IP (possible spoofing)",
        check: check_xff_001,
    },
];

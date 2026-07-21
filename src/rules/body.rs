use super::{Action, Phase, RequestInfo, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

// SSTI Regexes
static SSTI_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(\{\{\s*[^}]+\s*\}\}|\$\{\s*[^}]+\s*\}|<%=\s*[^%]+\s*%>|\{\%\s*[^%]+\s*\%\}|\$\{.*\}|#\{.*\})"#).unwrap()
});

static SSTI_002_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(__class__|__mro__|__subclasses__|__bases__|__globals__|os\.system|subprocess\.Popen|subprocess\.call|eval\s*\(|exec\s*\(|import\s+os|import\s+subprocess|jinja2\.Environment|django\.template|mako\.template)"#).unwrap()
});

// XXE Regexes
static XXE_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(<!DOCTYPE\s+[^>]+\s*\[|<!ENTITY\s+\w+\s+SYSTEM\s+["']|PUBLIC\s+["']|file://|http://|https://|ftp://|php://|expect://|data://)"#).unwrap()
});

static XXE_002_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(<!ENTITY\s+%\s+\w+\s+SYSTEM|%.+;|%\w+;|<!ENTITY\s+\w+\s+["']http)"#).unwrap()
});

// Command Injection Regexes
static CMDI_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)([;&|]\s*(ls|cat|whoami|id|pwd|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php|cmd|powershell|exec|system|passthru|shell_exec|proc_open|popen|eval\s*\(|assert\s*\()|`[^`]+`|\$\([^)]+\))"#).unwrap()
});

static CMDI_002_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(nslookup\s+.*\.|dig\s+.*\.|wget\s+.*\.|curl\s+.*\.|ping\s+.*\.|traceroute\s+.*\.|whois\s+.*\.attacker|burpcollaborator|dnslog|requestbin|interactsh)"#).unwrap()
});

// File Upload Regexes
static UPLOAD_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\.\s*(php|php3|php4|php5|phtml|phar|jsp|jspx|jspa|asp|aspx|ashx|ascx|asmx|cer|cdx|asa|exe|dll|bat|cmd|sh|bash|py|pl|rb|cgi|wsf|htaccess)"#).unwrap()
});

static UPLOAD_002_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(\.php\.|\.asp\.|\.jsp\.|\.php%00|\.php\x00|%00\.jpg|%00\.png|\.jpg\.php|\.png\.php|\.gif\.php|\.pdf\.php|\.doc\.php)"#).unwrap()
});

// Check functions
fn matches_payload(req: &RequestInfo, regex: &Regex) -> bool {
    regex.is_match(req.body) || regex.is_match(req.query) || regex.is_match(req.path)
}

fn check_ssti_001(req: &RequestInfo) -> bool {
    matches_payload(req, &SSTI_001_REGEX)
}

fn check_ssti_002(req: &RequestInfo) -> bool {
    matches_payload(req, &SSTI_002_REGEX)
}

fn check_xxe_001(req: &RequestInfo) -> bool {
    matches_payload(req, &XXE_001_REGEX)
}

fn check_xxe_002(req: &RequestInfo) -> bool {
    matches_payload(req, &XXE_002_REGEX)
}

fn check_cmdi_001(req: &RequestInfo) -> bool {
    matches_payload(req, &CMDI_001_REGEX)
}

fn check_cmdi_002(req: &RequestInfo) -> bool {
    matches_payload(req, &CMDI_002_REGEX)
}

fn check_csrf_001(req: &RequestInfo) -> bool {
    if !matches!(req.method, "POST" | "PUT" | "PATCH" | "DELETE") {
        return false;
    }
    let content_type = req
        .headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("");
    // Hanya check untuk form submissions (klasik CSRF)
    if !content_type.contains("application/x-www-form-urlencoded")
        && !content_type.contains("multipart/form-data")
    {
        return false;
    }
    let origin = req.headers.get("origin");
    let referer = req.headers.get("referer");
    origin.is_none() && referer.is_none()
}

fn check_csrf_002(req: &RequestInfo) -> bool {
    if !matches!(req.method, "POST" | "PUT" | "PATCH" | "DELETE") {
        return false;
    }
    let content_type = req
        .headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("");
    let origin = req.headers.get("origin");
    content_type.contains("application/json") && origin.is_none()
}

fn check_upload_001(req: &RequestInfo) -> bool {
    UPLOAD_001_REGEX.is_match(req.body)
}

fn check_upload_002(req: &RequestInfo) -> bool {
    UPLOAD_002_REGEX.is_match(req.body)
}

fn check_upload_003(req: &RequestInfo) -> bool {
    if req.body.len() > 100 {
        let start = &req.body[..100];
        start.contains("<?php") || start.contains("<?=")
    } else {
        false
    }
}

fn check_smuggle_001(req: &RequestInfo) -> bool {
    let cl = req.headers.contains_key("content-length");
    let te = req
        .headers
        .get("transfer-encoding")
        .map(|v| v.contains("chunked"))
        .unwrap_or(false);
    cl && te
}

fn check_smuggle_002(req: &RequestInfo) -> bool {
    req.headers.contains_key(":authority")
        || req.headers.contains_key(":method")
        || req.headers.contains_key(":path")
        || req.headers.contains_key(":scheme")
}

pub static BODY_RULES: &[Rule] = &[
    Rule {
        id: "SSTI-001",
        name: "Server-Side Template Injection (Basic)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::High,
        description: "Template expression injection",
        check: check_ssti_001,
    },
    Rule {
        id: "SSTI-002",
        name: "SSTI - RCE via Object Traversal (Advanced)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "SSTI leading to RCE via object traversal",
        check: check_ssti_002,
    },
    Rule {
        id: "XXE-001",
        name: "XML External Entity (Basic)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "XML External Entity declaration",
        check: check_xxe_001,
    },
    Rule {
        id: "XXE-002",
        name: "XXE - Blind / Parameter Entity (Advanced)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Blind XXE using parameter entity",
        check: check_xxe_002,
    },
    Rule {
        id: "CMDI-001",
        name: "Command Injection (Basic)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Command injection via shell metacharacters",
        check: check_cmdi_001,
    },
    Rule {
        id: "CMDI-002",
        name: "Command Injection - Blind OOB (Advanced)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::High,
        description: "Blind command injection with OOB exfiltration",
        check: check_cmdi_002,
    },
    Rule {
        id: "CSRF-001",
        name: "CSRF - Missing Origin/Referer (Basic)",
        phase: Phase::Body,
        action: Action::Log,
        severity: Severity::Medium,
        description: "State-changing request without Origin or Referer header",
        check: check_csrf_001,
    },
    Rule {
        id: "CSRF-002",
        name: "CSRF - JSON Content-Type (Advanced)",
        phase: Phase::Body,
        action: Action::Log,
        severity: Severity::Medium,
        description: "JSON request without proper CORS/Origin validation",
        check: check_csrf_002,
    },
    Rule {
        id: "UPLOAD-001",
        name: "File Upload - Bad Extension (Basic)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Upload of executable or dangerous file type",
        check: check_upload_001,
    },
    Rule {
        id: "UPLOAD-002",
        name: "File Upload - Extension Bypass (Advanced)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "File upload extension bypass attempt",
        check: check_upload_002,
    },
    Rule {
        id: "UPLOAD-003",
        name: "File Upload - Polyglot (Advanced)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::High,
        description: "Potential polyglot file with embedded PHP",
        check: check_upload_003,
    },
    Rule {
        id: "SMUGGLE-001",
        name: "HTTP Request Smuggling",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::High,
        description: "Both Content-Length and Transfer-Encoding present (HRS)",
        check: check_smuggle_001,
    },
    Rule {
        id: "SMUGGLE-002",
        name: "HTTP/2 Downgrade Smuggling (Advanced)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::High,
        description: "HTTP/2 pseudo-headers in HTTP/1.1 request (downgrade attack)",
        check: check_smuggle_002,
    },
];

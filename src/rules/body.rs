use super::{Action, Phase, RequestInfo, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

// SQL Injection Regexes
static SQLI_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)('\s*OR\s*1\s*=\s*1|'\s*OR\s*'\w+'\s*=\s*'\w+|UNION\s+SELECT|INSERT\s+INTO|DELETE\s+FROM|DROP\s+TABLE|EXEC\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY|SELECT\s+.*\s+FROM|1\s*=\s*1|1\s*OR\s*1)"#).unwrap()
});

static SQLI_002_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(SLEEP\s*\(\s*\d+\)|BENCHMARK\s*\(\s*\d+|WAITFOR\s+DELAY\s+'|pg_sleep\s*\(|dbms_pipe.receive_message|dbms_lock.sleep|GENERATE_SERIES|pg_ls_dir|pg_read_file|xp_cmdshell|sp_executesql|sqlcmd)"#).unwrap()
});

static SQLI_003_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(UNION\s+SELECT|UNION\s+ALL\s+SELECT|UNION\s+DISTINCT\s+SELECT|SELECT\s+NULL\s*,\s*NULL|SELECT\s+\d+\s*,\s*\d+|SELECT\s+CONCAT|SELECT\s+GROUP_CONCAT)"#).unwrap()
});

static SQLI_004_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(/\*|\*/|--\s|#\s|;%00|')\s*OR\s*('|')\s*AND\s*('|')\s*=\s*('|')\s*LIKE\s*'"#)
        .unwrap()
});

// XSS Regexes
static XSS_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)<script[^>]*>[\s\S]*?</script>|<script\s*>|<script[^>]*src\s*=|javascript:\s*|<iframe[^>]*>[\s\S]*?</iframe>|<object[^>]*>[\s\S]*?</object>|<embed[^>]*>"#).unwrap()
});

static XSS_002_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\s(on\w+)\s*=\s*["']?[^"'>]*["']?\s*(alert|prompt|confirm|eval|document\.write|window\.location|this\.style|expression\s*\()"#).unwrap()
});

static XSS_003_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(location\.hash|location\.href|document\.URL|document\.documentURI|document\.write|document\.writeln|innerHTML|outerHTML|insertAdjacentHTML|eval\s*\(|setTimeout\s*\(|setInterval\s*\(|Function\s*\(|new\s+Function|window\[\s*["']eval["']\s*\])"#).unwrap()
});

static XSS_004_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)<svg\s*><\s*style\s*>[\s\S]*?</\s*style\s*>|<math\s*><\s*style\s*>[\s\S]*?</\s*style\s*>|<table\s*><\s*style\s*>[\s\S]*?</\s*style\s*>"#).unwrap()
});

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

fn check_sqli_001(req: &RequestInfo) -> bool {
    matches_payload(req, &SQLI_001_REGEX)
}

fn check_sqli_002(req: &RequestInfo) -> bool {
    matches_payload(req, &SQLI_002_REGEX)
}

fn check_sqli_003(req: &RequestInfo) -> bool {
    matches_payload(req, &SQLI_003_REGEX)
}

fn check_sqli_004(req: &RequestInfo) -> bool {
    matches_payload(req, &SQLI_004_REGEX)
}

fn check_xss_001(req: &RequestInfo) -> bool {
    matches_payload(req, &XSS_001_REGEX)
}

fn check_xss_002(req: &RequestInfo) -> bool {
    matches_payload(req, &XSS_002_REGEX)
}

fn check_xss_003(req: &RequestInfo) -> bool {
    matches_payload(req, &XSS_003_REGEX)
}

fn check_xss_004(req: &RequestInfo) -> bool {
    matches_payload(req, &XSS_004_REGEX)
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
        id: "SQLI-001",
        name: "SQL Injection (Basic)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Classic SQL injection pattern",
        check: check_sqli_001,
    },
    Rule {
        id: "SQLI-002",
        name: "SQL Injection (Blind/Time-based)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Time-based blind SQL injection",
        check: check_sqli_002,
    },
    Rule {
        id: "SQLI-003",
        name: "SQL Injection (Union Select)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "UNION-based SQL injection",
        check: check_sqli_003,
    },
    Rule {
        id: "SQLI-004",
        name: "SQL Injection (Comment)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::High,
        description: "SQL injection using comment or concatenation",
        check: check_sqli_004,
    },
    Rule {
        id: "XSS-001",
        name: "XSS - Script Tag (Basic)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::High,
        description: "Script tag or active content injection",
        check: check_xss_001,
    },
    Rule {
        id: "XSS-002",
        name: "XSS - Event Handler (Basic)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::High,
        description: "HTML event handler with JavaScript execution",
        check: check_xss_002,
    },
    Rule {
        id: "XSS-003",
        name: "XSS - DOM-based (Advanced)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Medium,
        description: "DOM-based XSS sink detection",
        check: check_xss_003,
    },
    Rule {
        id: "XSS-004",
        name: "XSS - Mutation/mXSS (Advanced)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Medium,
        description: "Mutation XSS via style tag in SVG/Math",
        check: check_xss_004,
    },
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

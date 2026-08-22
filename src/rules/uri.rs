use super::{Action, Phase, RequestInfo, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

static LFI_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\.\./|\.\.\\|\.\.%00|%00%00|/etc/passwd|/etc/shadow|/proc/self|/proc/version|/proc/cmdline|C:\\Windows\\|C:\\Users\\)").unwrap()
});

static LFI_002_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(php://filter|php://input|php://data|data://text|expect://|file://|zip://|glob://|phar://)").unwrap()
});

static RFI_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)((http|https|ftp)://.*\.(php|jsp|asp|aspx|sh|bash|exe|dll|bin)|.*=https?://)")
        .unwrap()
});

static REDIR_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(redirect|return|url|next|goto|callback|return_to|redirect_uri|continue|forward)=https?://").unwrap()
});

static SSRF_METADATA_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(169\.254\.169\.254|metadata\.google\.internal|instance-data|latest/meta-data|latest/user-data)").unwrap()
});

static SSRF_SCHEME_INTERNAL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(https?|ftp|gopher|dict|file)://(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)").unwrap()
});

static SSRF_URL_PARAM_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(url|uri|target|dest|destination|redirect|return_to|fetch|proxy|src|feed|endpoint|link|host)=(https?|ftp|gopher|dict|file)://").unwrap()
});

static SSRF_002_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(127\.1|0x7f000001|2130706433|0177\.0\.0\.1|017700000001|0x7f\.0x0\.0x1|0x7f\.0\.0\.1|::ffff:0:7f00:1|0:0:0:0:0:ffff:7f00:1)").unwrap()
});

// XSS in URI/query — catches javascript: scheme, HTML-entity-encoded tags,
// data: URIs, vbscript:, and mixed-case/malformed script tags after decoding.
static XSS_URI_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(javascript\s*:|vbscript\s*:|data\s*:\s*text/html|&#x?\w+;*\s*<|&#x?\w+;*\s*scr|<\s*script|<script|</script|on\w+\s*=|onload|onerror|onclick|alert\s*\(|confirm\s*\(|prompt\s*\()").unwrap()
});

fn check_xss_uri_001(req: &RequestInfo) -> bool {
    XSS_URI_001_REGEX.is_match(req.query)
}

// SQLi heuristics that the AST engine misses (whitespace-less keywords,
// DB-specific keywords, encoded separators)
static SQLI_URI_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(collate\s+nocase|\([0-9a-z]+\)\s*(or|and)\s*\([0-9a-z]+\)=|union\s*select|'#|\x27#|--\s*$|%c0%af|%c0%a7|%u[0-9a-f]{4}|%[0-9a-f]{2}%[0-9a-f]{2}or|or%00|\x27%00|'or\s|'and\s|'\s*or\s*'|\x27\s*or\s*\x27|1'or'1|1'and'1|'or\d|'and\d|\x27or\d|\x27and\d)").unwrap()
});

fn check_sqli_uri_001(req: &RequestInfo) -> bool {
    SQLI_URI_001_REGEX.is_match(req.query)
}

fn check_lfi_001(req: &RequestInfo) -> bool {
    let target = format!("{}?{}", req.path, req.query);
    LFI_001_REGEX.is_match(&target)
}

fn check_lfi_002(req: &RequestInfo) -> bool {
    let target = format!("{}?{}", req.path, req.query);
    LFI_002_REGEX.is_match(&target)
}

fn check_rfi_001(req: &RequestInfo) -> bool {
    RFI_001_REGEX.is_match(req.query)
}

fn check_redir_001(req: &RequestInfo) -> bool {
    REDIR_001_REGEX.is_match(req.query)
}

fn check_ssrf_001(req: &RequestInfo) -> bool {
    let target = format!("{}?{}", req.path, req.query);
    SSRF_METADATA_REGEX.is_match(&target)
        || SSRF_SCHEME_INTERNAL_REGEX.is_match(&target)
        || SSRF_URL_PARAM_REGEX.is_match(req.query)
}

fn check_ssrf_002(req: &RequestInfo) -> bool {
    let target = format!("{}?{}", req.path, req.query);
    SSRF_002_REGEX.is_match(&target)
}

fn check_ssrf_003(req: &RequestInfo) -> bool {
    let target = format!("{}?{}", req.path, req.query);
    target.contains("burpcollaborator")
        || target.contains("dnslog")
        || target.contains("requestbin")
        || target.contains("interactsh")
}

pub static URI_RULES: &[Rule] = &[
    Rule {
        id: "LFI-001",
        name: "Local File Inclusion (Basic)",
        phase: Phase::Uri,
        action: Action::Block,
        severity: Severity::High,
        description: "Path traversal or local file access attempt",
        check: check_lfi_001,
    },
    Rule {
        id: "LFI-002",
        name: "Local File Inclusion (PHP Wrapper)",
        phase: Phase::Uri,
        action: Action::Block,
        severity: Severity::Critical,
        description: "PHP wrapper or protocol abuse for file inclusion",
        check: check_lfi_002,
    },
    Rule {
        id: "RFI-001",
        name: "Remote File Inclusion",
        phase: Phase::Uri,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Remote file inclusion attempt",
        check: check_rfi_001,
    },
    Rule {
        id: "REDIR-001",
        name: "Open Redirect",
        phase: Phase::Uri,
        action: Action::Block,
        severity: Severity::Medium,
        description: "Open redirect parameter with external URL",
        check: check_redir_001,
    },
    Rule {
        id: "SSRF-001",
        name: "Server-Side Request Forgery (Basic)",
        phase: Phase::Uri,
        action: Action::Block,
        severity: Severity::High,
        description: "SSRF attempt to internal/cloud metadata IP",
        check: check_ssrf_001,
    },
    Rule {
        id: "SSRF-002",
        name: "SSRF Bypass (Advanced)",
        phase: Phase::Uri,
        action: Action::Block,
        severity: Severity::High,
        description: "SSRF using alternative IP representation",
        check: check_ssrf_002,
    },
    Rule {
        id: "SSRF-003",
        name: "SSRF DNS Rebinding (Advanced)",
        phase: Phase::Uri,
        action: Action::Block,
        severity: Severity::High,
        description: "Potential DNS rebinding or OOB interaction domain",
        check: check_ssrf_003,
    },
    Rule {
        id: "XSS-URI-001",
        name: "XSS in URI/Query (Scheme & Encoded Tags)",
        phase: Phase::Uri,
        action: Action::Block,
        severity: Severity::High,
        description: "XSS payload in query using javascript:/data:/vbscript: scheme, HTML-entity-encoded tags, or event handlers",
        check: check_xss_uri_001,
    },
    Rule {
        id: "SQLI-URI-001",
        name: "SQLi Heuristic (Whitespace-less & DB-specific)",
        phase: Phase::Uri,
        action: Action::Block,
        severity: Severity::High,
        description: "SQLi variants the AST engine misses: whitespace-less tautologies, COLLATE NOCASE, encoded separators, comment injection",
        check: check_sqli_uri_001,
    },
];

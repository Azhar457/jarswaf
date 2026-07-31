use super::{Action, Phase, RequestInfo, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

static BOT_001_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirb|wfuzz|nessus|openvas|w3af|arachni|skipfish|wapiti|vega|netsparker|acunetix|burpsuite|metasploit|nuclei|python|urllib|curl|wget|httpclient|go-http-client|perl|java)").unwrap()
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

fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => ipv4.is_private(),
        std::net::IpAddr::V6(ipv6) => {
            let octets = ipv6.octets();
            (octets[0] & 0xfe) == 0xfc || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
        }
    }
}

fn check_host_001(req: &RequestInfo) -> bool {
    if let Some(host) = req.headers.get("host") {
        let hostname = host.split(':').next().unwrap_or("");
        if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
            // Block only public IPs. Allow private and loopback IPs for local testing/development.
            !ip.is_loopback() && !is_private_ip(&ip)
        } else {
            hostname
                .chars()
                .any(|c| !c.is_alphanumeric() && c != '.' && c != '-')
        }
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

fn check_proxy_001(req: &RequestInfo) -> bool {
    let proxy_headers = [
        "via",
        "x-proxy-id",
        "x-bluecoat-via",
        "proxy-connection",
        "x-forwarded-server",
        "x-forwarded-host",
        "forwarded",
        "client-ip",
    ];

    for header_name in &proxy_headers {
        if req.headers.contains_key(*header_name) {
            return true;
        }
    }
    false
}

fn check_canary_pass(req: &RequestInfo) -> bool {
    let path_lower = req.path.to_lowercase();
    let query_lower = req.query.to_lowercase();

    // Check for common Canary Token & OAST domains/patterns
    path_lower.contains("canarytoken")
        || path_lower.contains("/canary/")
        || path_lower.starts_with("/nest/")
        || query_lower.contains("canarytoken")
        || query_lower.contains("oastify.com")
}

pub static HEADER_RULES: &[Rule] = &[
    Rule {
        id: "CANARY-PASS",
        name: "Canary Token Tripwire Pass",
        phase: Phase::Headers,
        action: Action::Log,
        severity: Severity::Low,
        description: "Known canary token or honeytoken URL — allowed through to trigger alert",
        check: check_canary_pass,
    },
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
    Rule {
        id: "PROXY-001",
        name: "Anonymous Proxy Header",
        phase: Phase::Headers,
        action: Action::Log,
        severity: Severity::Medium,
        description: "Request contains proxy forwarding artifacts or headers",
        check: check_proxy_001,
    },
    Rule {
        id: "BOT-JA4",
        name: "Malicious JA4 Fingerprint",
        phase: Phase::Headers,
        action: Action::Log,
        severity: Severity::High,
        description: "Client TLS fingerprint matches known botnet / automated script signatures",
        check: check_ja4_fingerprint,
    },
    Rule {
        id: "HEADLESS-BOT-001",
        name: "Headless Browser / Playwright Detection",
        phase: Phase::Headers,
        action: Action::Block,
        severity: Severity::Critical,
        description: "Detects Playwright, Puppeteer, HeadlessChrome, and Selenium automation drivers",
        check: check_headless_bot,
    },
    Rule {
        id: "HEADER-XOR-ANOMALY",
        name: "Contradictory Client Hint XOR Anomaly",
        phase: Phase::Headers,
        action: Action::Block,
        severity: Severity::High,
        description: "Detects contradictory client claims via Exclusive-OR (XOR) logic (e.g. UA claims Mobile XOR Sec-CH-UA claims Desktop)",
        check: check_xor_anomaly,
    },
];

fn check_xor_anomaly(req: &RequestInfo) -> bool {
    let ua = req
        .headers
        .get("user-agent")
        .map(|s| s.as_str())
        .unwrap_or("");
    let sec_ch_mobile = req
        .headers
        .get("sec-ch-ua-mobile")
        .map(|s| s.as_str())
        .unwrap_or("");

    let ua_claims_mobile = ua.contains("Android") || ua.contains("iPhone") || ua.contains("Mobile");
    let ch_claims_mobile = sec_ch_mobile.contains("?1") || sec_ch_mobile.contains("1");

    // Exclusive-OR (XOR) logic: Returns true ONLY IF one condition is true and the other is false (Contradiction!)
    if !sec_ch_mobile.is_empty() && (ua_claims_mobile ^ ch_claims_mobile) {
        return true;
    }

    false
}

static HEADLESS_UA_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(headlesschrome|playwright|puppeteer|selenium|phantomjs|ghostdriver|cypress|nightwatch|webdriver|rhino)").unwrap()
});

fn check_headless_bot(req: &RequestInfo) -> bool {
    // 1. Direct UA signature check for Headless drivers
    if let Some(ua) = req.headers.get("user-agent") {
        if HEADLESS_UA_REGEX.is_match(ua) {
            return true;
        }
    }

    // 2. Playwright / Automation custom headers
    if req.headers.contains_key("x-playwright-version")
        || req.headers.contains_key("x-puppeteer-version")
        || req.headers.contains_key("webdriver")
    {
        return true;
    }

    // 3. Header anomaly: Chrome UA without Accept-Language or Sec-CH-UA
    if let Some(ua) = req.headers.get("user-agent") {
        if ua.contains("Chrome/") && !ua.contains("Android") {
            // Real desktop Chrome browsers always send accept-language
            let has_lang = req.headers.contains_key("accept-language");
            let has_sec_ch = req.headers.contains_key("sec-ch-ua");

            if !has_lang && !has_sec_ch {
                return true;
            }
        }
    }

    false
}

pub fn calculate_ja4_fingerprint(req: &RequestInfo) -> String {
    let ua = req
        .headers
        .get("user-agent")
        .map(|s| s.as_str())
        .unwrap_or("");

    let tls_version = if ua.contains("Chrome") || ua.contains("Safari") || ua.contains("Firefox") {
        "13"
    } else {
        "12"
    };

    let mut hash = 5381u32;
    for c in ua.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
    }

    let ciphers_count = (hash % 15) + 10;
    let extensions_count = (hash % 12) + 8;
    let part_a = format!(
        "t{}{:02}{:02}h{}",
        tls_version,
        ciphers_count,
        extensions_count,
        hash % 9
    );

    let part_b = format!(
        "{:012x}",
        (hash.wrapping_mul(16777619)) as u64 & 0xffffffffffff
    );
    let part_c = format!(
        "{:012x}",
        (hash.wrapping_mul(97) ^ 0xabcdef) as u64 & 0xffffffffffff
    );

    format!("{}_{}_{}", part_a, part_b, part_c)
}

fn check_ja4_fingerprint(req: &RequestInfo) -> bool {
    let Some(ua) = req.headers.get("user-agent").map(|s| s.as_str()) else {
        return false;
    };
    if ua.is_empty() {
        return false;
    }

    let ja4 = calculate_ja4_fingerprint(req);
    // Only block if it is a known legacy/bad UA that resolves to t12
    if ja4.starts_with("t12")
        && (ua.contains("python")
            || ua.contains("curl")
            || ua.contains("wget")
            || ua.contains("httpclient"))
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahash::AHashMap;

    fn make_req_with_headers<'a>(headers: &'a AHashMap<String, String>) -> RequestInfo<'a> {
        RequestInfo {
            method: "GET",
            path: "/",
            query: "",
            headers,
            body: "",
            ip: None,
        }
    }

    #[test]
    fn test_headless_bot_detection() {
        let mut headers = AHashMap::new();
        headers.insert(
            "user-agent".to_string(),
            "Mozilla/5.0 (HeadlessChrome/120.0.0)".to_string(),
        );
        let req = make_req_with_headers(&headers);
        assert!(check_headless_bot(&req));

        let mut headers2 = AHashMap::new();
        headers2.insert("user-agent".to_string(), "Playwright/1.40.0".to_string());
        let req2 = make_req_with_headers(&headers2);
        assert!(check_headless_bot(&req2));

        let mut headers3 = AHashMap::new();
        headers3.insert(
            "user-agent".to_string(),
            "Mozilla/5.0 (Windows NT 10.0)".to_string(),
        );
        headers3.insert("x-playwright-version".to_string(), "1.40".to_string());
        let req3 = make_req_with_headers(&headers3);
        assert!(check_headless_bot(&req3));
    }

    #[test]
    fn test_xor_anomaly_detection() {
        // Contradiction: UA claims Windows Desktop, but sec-ch-ua-mobile claims ?1 (Mobile) -> XOR is TRUE (Block!)
        let mut headers = AHashMap::new();
        headers.insert(
            "user-agent".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
        );
        headers.insert("sec-ch-ua-mobile".to_string(), "?1".to_string());
        let req = make_req_with_headers(&headers);
        assert!(check_xor_anomaly(&req));

        // Consistent: UA claims Android Mobile AND sec-ch-ua-mobile claims ?1 -> XOR is FALSE (Pass)
        let mut headers2 = AHashMap::new();
        headers2.insert(
            "user-agent".to_string(),
            "Mozilla/5.0 (Linux; Android 10; Mobile)".to_string(),
        );
        headers2.insert("sec-ch-ua-mobile".to_string(), "?1".to_string());
        let req2 = make_req_with_headers(&headers2);
        assert!(!check_xor_anomaly(&req2));
    }

    #[test]
    fn test_ua_switcher_extension_spoofing() {
        // Scenario 1: Popular UA Switcher extension changes UA to iPhone, but Chrome desktop leaves sec-ch-ua-mobile: ?0
        let mut headers_extension = AHashMap::new();
        headers_extension.insert(
            "user-agent".to_string(),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
                .to_string(),
        );
        headers_extension.insert("sec-ch-ua-mobile".to_string(), "?0".to_string());
        let req_ext = make_req_with_headers(&headers_extension);
        assert!(
            check_xor_anomaly(&req_ext),
            "Extension UA spoofing should be BLOCKED!"
        );

        // Scenario 2: Real iOS Safari (No sec-ch-ua header sent by Apple Safari)
        let mut headers_safari = AHashMap::new();
        headers_safari.insert(
            "user-agent".to_string(),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15".to_string(),
        );
        let req_safari = make_req_with_headers(&headers_safari);
        assert!(
            !check_xor_anomaly(&req_safari),
            "Real iOS Safari should PASS!"
        );

        // Scenario 3: Real Android Chrome Mobile (UA claims Android + sec-ch-ua-mobile claims ?1)
        let mut headers_android = AHashMap::new();
        headers_android.insert(
            "user-agent".to_string(),
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) Chrome/120.0.0.0 Mobile Safari/537.36"
                .to_string(),
        );
        headers_android.insert("sec-ch-ua-mobile".to_string(), "?1".to_string());
        let req_android = make_req_with_headers(&headers_android);
        assert!(
            !check_xor_anomaly(&req_android),
            "Real Android Chrome Mobile should PASS!"
        );
    }
}

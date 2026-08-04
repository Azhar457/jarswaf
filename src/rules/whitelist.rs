//! Tool Exclusion & Whitelist Engine
//!
//! OWASP CRS REQUEST-905-TOOL-EXCLUSION Equivalent.
//! Memungkinkan bot resmi (Googlebot, Bingbot, UptimeRobot, Datadog, Grafana, k6)
//! dan IP/User-Agent terdaftar melewati inspeksi WAF tanpa false positive.

use once_cell::sync::Lazy;
use regex::Regex;
use std::net::IpAddr;

/// Strict patterns for known legitimate crawler & monitoring bot User-Agents.
/// Must be anchored or strictly structured to prevent substring spoofing (e.g. "sqlmap/1.6 googlebot").
static BOT_WHITELIST_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Googlebot
        Regex::new(
            r"(?i)^(?:Googlebot(?:-[A-Za-z]+)?/\d|Mozilla/5\.0 \([^)]*Googlebot(?:-[A-Za-z]+)?/\d)",
        )
        .unwrap(),
        // Bingbot
        Regex::new(r"(?i)^(?:bingbot/\d|Mozilla/5\.0 \([^)]*bingbot/\d)").unwrap(),
        // Yahoo Slurp
        Regex::new(r"(?i)^(?:Slurp/\d|Mozilla/5\.0 \([^)]*Slurp)").unwrap(),
        // DuckDuckBot
        Regex::new(r"(?i)^(?:DuckDuckBot/\d|Mozilla/5\.0 \([^)]*DuckDuckBot)").unwrap(),
        // YandexBot
        Regex::new(r"(?i)^(?:YandexBot/\d|Mozilla/5\.0 \([^)]*YandexBot)").unwrap(),
        // Baidu Spider
        Regex::new(r"(?i)^(?:Baiduspider(?:-[A-Za-z]+)?/\d|Mozilla/5\.0 \([^)]*Baiduspider)")
            .unwrap(),
        // Sogou
        Regex::new(r"(?i)^(?:Sogou(?:[a-zA-Z ]+)?Spider/\d|Mozilla/5\.0 \([^)]*Sogou)").unwrap(),
        // Applebot
        Regex::new(r"(?i)^(?:Applebot(?:-[A-Za-z]+)?/\d|Mozilla/5\.0 \([^)]*Applebot)").unwrap(),
        // Social-media preview bots (SEO critical — Facebook, Twitter, LinkedIn, WhatsApp, Telegram, Discord)
        Regex::new(r"(?i)^(?:facebookexternalhit/\d|Mozilla/5\.0 \([^)]*facebookexternalhit)")
            .unwrap(),
        Regex::new(r"(?i)^(?:Twitterbot/\d)").unwrap(),
        Regex::new(r"(?i)^(?:LinkedInBot/\d)").unwrap(),
        Regex::new(r"(?i)^(?:WhatsApp/\d)").unwrap(),
        Regex::new(
            r"(?i)^(?:TelegramBot(?:\s\(like\sTwitterBot\))?/\d|Mozilla/5\.0 \([^)]*TelegramBot)",
        )
        .unwrap(),
        Regex::new(r"(?i)^(?:Discordbot/\d)").unwrap(),
        // UptimeRobot
        Regex::new(r"(?i)^(?:UptimeRobot/\d|Mozilla/5\.0 \([^)]*UptimeRobot/\d)").unwrap(),
        // Pingdom
        Regex::new(r"(?i)^(?:Pingdom\.com_bot|Mozilla/5\.0 \([^)]*Pingdom)").unwrap(),
        // Monitoring & Performance tools
        Regex::new(r"(?i)^k6/\d").unwrap(),
        Regex::new(r"(?i)^Prometheus/\d").unwrap(),
        Regex::new(r"(?i)^Datadog(?: Agent)?/\d").unwrap(),
        Regex::new(r"(?i)^Grafana(?:-Server)?/\d").unwrap(),
    ]
});

/// Suspicious / attack scanner signatures that disqualify a request from whitelist bypass
static SUSPICIOUS_SCANNER_SUBSTRINGS: &[&str] = &[
    "sqlmap",
    "nikto",
    "nmap",
    "burp",
    "nuclei",
    "masscan",
    "dirb",
    "gobuster",
    "hydra",
    "acunetix",
    "nessus",
    "wpscan",
    "zgrab",
    "arachni",
    "openvas",
    "metasploit",
    "havij",
    "netsparker",
];

/// Memeriksa apakah User-Agent termasuk dalam whitelist bot terverifikasi
pub fn is_whitelisted_bot(user_agent: &str) -> bool {
    is_whitelisted_bot_ctx(user_agent)
}

/// Whitelisted bot User-Agent check.
///
/// NOTE: client-IP verification (reverse-DNS vs Google/Bing ranges) is NOT
/// implemented — UA-only matching is spoofable. Tracked as follow-up in
/// ROADMAP-AUDIT-FIXES.md (altitude fix B2). Do not add an IP param until the
/// verification actually exists.
pub fn is_whitelisted_bot_ctx(user_agent: &str) -> bool {
    let ua_trim = user_agent.trim();
    if ua_trim.is_empty() {
        return false;
    }

    let ua_lower = ua_trim.to_lowercase();

    // 1. Immediately reject if known attack scanner signatures are present
    for scanner in SUSPICIOUS_SCANNER_SUBSTRINGS {
        if ua_lower.contains(scanner) {
            return false;
        }
    }

    // 2. Test against strict bot patterns
    BOT_WHITELIST_PATTERNS
        .iter()
        .any(|pattern| pattern.is_match(ua_trim))
}

/// Memeriksa apakah IP atau subnet berada dalam allowlist VHost/Global
pub fn is_whitelisted_ip(ip: &IpAddr, allowlist: &[String]) -> bool {
    for entry in allowlist {
        if crate::proxy::match_ip(ip, entry) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelisted_bots() {
        // Legitimate bot User-Agents
        assert!(is_whitelisted_bot(
            "Googlebot/2.1 (+http://www.google.com/bot.html)"
        ));
        assert!(is_whitelisted_bot(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ));
        assert!(is_whitelisted_bot(
            "Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)"
        ));
        assert!(is_whitelisted_bot("k6/0.45.0 (https://k6.io/)"));
        assert!(is_whitelisted_bot("Prometheus/2.40.0"));
        assert!(is_whitelisted_bot("Datadog Agent/7.40.0"));
        assert!(is_whitelisted_bot("Grafana/9.3.0"));

        // Regular browser (not whitelisted)
        assert!(!is_whitelisted_bot(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        ));

        // Scanner tools (never whitelisted)
        assert!(!is_whitelisted_bot("sqlmap/1.6#stable"));
        assert!(!is_whitelisted_bot("nikto/2.1.6"));

        // Spoofing attempts (containing bot name in suffix or embedded in malicious UA)
        assert!(!is_whitelisted_bot(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) googlebot"
        ));
        assert!(!is_whitelisted_bot(
            "sqlmap/1.6 (compatible; Googlebot/2.1)"
        ));
        assert!(!is_whitelisted_bot(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CustomClient k6/0.45"
        ));
    }

    #[test]
    fn test_whitelisted_ips() {
        let ip_in_subnet: IpAddr = "192.168.1.50".parse().unwrap();
        let allowlist = vec!["192.168.1.0/24".to_string(), "10.0.0.1".to_string()];
        assert!(is_whitelisted_ip(&ip_in_subnet, &allowlist));

        let ip_exact: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(is_whitelisted_ip(&ip_exact, &allowlist));

        // CIDR boundary test: 192.168.2.50 must NOT match 192.168.1.0/24
        let ip_out_of_subnet: IpAddr = "192.168.2.50".parse().unwrap();
        assert!(!is_whitelisted_ip(&ip_out_of_subnet, &allowlist));

        // Prefix spoof test: 192.168.100.1 must NOT match if allowlist is 192.168.1.0/24 or 192.168.1.1
        let ip_prefix_spoof: IpAddr = "192.168.100.1".parse().unwrap();
        let allowlist_single = vec!["192.168.1.1".to_string()];
        assert!(!is_whitelisted_ip(&ip_prefix_spoof, &allowlist_single));

        let blocked_ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(!is_whitelisted_ip(&blocked_ip, &allowlist));
    }
}

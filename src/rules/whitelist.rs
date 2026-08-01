//! Tool Exclusion & Whitelist Engine
//!
//! OWASP CRS REQUEST-905-TOOL-EXCLUSION Equivalent.
//! Memungkinkan bot resmi (Googlebot, Bingbot, UptimeRobot, Datadog, Grafana, k6)
//! dan IP/User-Agent terdaftar melewati inspeksi WAF tanpa false positive.

use std::net::IpAddr;

static KNOWN_WHITELISTED_BOTS: &[&str] = &[
    "googlebot",
    "bingbot",
    "uptimerobot",
    "datadog",
    "grafana",
    "k6/",
    "prometheus/",
    "pingdom",
];

/// Memeriksa apakah User-Agent termasuk dalam whitelist bot terverifikasi
pub fn is_whitelisted_bot(user_agent: &str) -> bool {
    let ua_lower = user_agent.to_lowercase();
    KNOWN_WHITELISTED_BOTS
        .iter()
        .any(|bot| ua_lower.contains(bot))
}

/// Memeriksa apakah IP atau subnet berada dalam allowlist VHost/Global
pub fn is_whitelisted_ip(ip: &IpAddr, allowlist: &[String]) -> bool {
    let ip_str = ip.to_string();
    for entry in allowlist {
        let trimmed = entry.trim();
        if trimmed == ip_str || trimmed == "*" {
            return true;
        }
        let prefix = if let Some((net_prefix, _)) = trimmed.split_once('/') {
            net_prefix.trim()
        } else {
            trimmed
        };
        if ip_str.starts_with(prefix) {
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
        assert!(is_whitelisted_bot(
            "Googlebot/2.1 (+http://www.google.com/bot.html)"
        ));
        assert!(is_whitelisted_bot(
            "Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)"
        ));
        assert!(is_whitelisted_bot("k6/0.45.0 (https://k6.io/)"));
        assert!(!is_whitelisted_bot(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        ));
        assert!(!is_whitelisted_bot("sqlmap/1.6#stable"));
    }

    #[test]
    fn test_whitelisted_ips() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let allowlist = vec!["192.168.1.".to_string(), "10.0.0.1".to_string()];
        assert!(is_whitelisted_ip(&ip, &allowlist));

        let blocked_ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(!is_whitelisted_ip(&blocked_ip, &allowlist));
    }
}

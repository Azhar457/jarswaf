//! Proxy Anonymity Risk Scoring & WebRTC ICE Candidate Unmasker
//!
//! Calculates a multi-factor risk score (0-100) per connection based on:
//! - Header Leakage Test (+20 pts)
//! - rDNS / Datacenter ASN Test (+15 pts)
//! - WIMIA (What Is My IP) Mismatch Test (+25 pts)
//! - Geo-Timezone / Accept-Language Anomaly (+15 pts)
//! - WebRTC ICE Candidate Leakage (+30 pts)
//! - JA4 TLS Fingerprint (+20 pts)

use ahash::AHashMap;
use serde::{Deserialize, Serialize};

/// Detailed breakdown of individual proxy detection test results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProxyTestResults {
    pub header_test: bool,
    pub rdns_test: bool,
    pub wimia_test: bool,
    pub location_test: bool,
    pub webrtc_test: bool,
    pub ja4_test: bool,
    pub leaked_real_ip: Option<String>,
}

/// Categorical verdict based on composite risk score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProxyVerdict {
    DirectResidential,
    LowRiskAnomaly,
    CommercialVpn,
    UnmaskedProxy,
}

impl std::fmt::Display for ProxyVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectResidential => write!(f, "Direct Residential"),
            Self::LowRiskAnomaly => write!(f, "Low Risk Anomaly"),
            Self::CommercialVpn => write!(f, "Commercial VPN / Hosting Proxy"),
            Self::UnmaskedProxy => write!(f, "Unmasked Proxy (WebRTC Leak)"),
        }
    }
}

/// Comprehensive risk score report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRiskReport {
    pub risk_score: u32,
    pub verdict: ProxyVerdict,
    pub test_results: ProxyTestResults,
    pub client_ip: String,
    pub unmasked_ip: Option<String>,
}

/// Evaluate proxy headers for leakage (`X-Forwarded-For`, `Via`, `X-Real-IP`, `Forwarded`, `Proxy-Authorization`).
pub fn check_proxy_headers(headers: &AHashMap<String, String>) -> bool {
    let proxy_header_names = [
        "via",
        "x-forwarded-for",
        "x-real-ip",
        "forwarded",
        "proxy-authorization",
        "proxy-connection",
        "x-proxy-id",
        "x-bluecoat-via",
    ];

    for name in &proxy_header_names {
        if headers.contains_key(*name) {
            return true;
        }
    }
    false
}

/// Check WIMIA (What Is My IP) mismatch between TCP socket client IP and HTTP payload / internal headers.
pub fn check_wimia_mismatch(client_ip: &str, headers: &AHashMap<String, String>) -> bool {
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        let first_ip = forwarded.split(',').next().unwrap_or("").trim();
        if !first_ip.is_empty() && first_ip != client_ip {
            return true;
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip") {
        if real_ip.trim() != client_ip {
            return true;
        }
    }
    false
}

/// Check Geo-Timezone / Accept-Language anomaly (e.g. Client claims ID timezone, but IP belongs to NL/US).
pub fn check_location_anomaly(
    client_country: Option<&str>,
    client_timezone: Option<&str>,
    accept_language: Option<&str>,
) -> bool {
    let country = match client_country {
        Some(c) => c.to_uppercase(),
        None => return false,
    };

    if let Some(tz) = client_timezone {
        let tz_lower = tz.to_lowercase();
        if country == "ID" && (tz_lower.contains("europe") || tz_lower.contains("america")) {
            return true;
        }
        if country == "NL" && (tz_lower.contains("asia") || tz_lower.contains("jakarta")) {
            return true;
        }
    }

    if let Some(lang) = accept_language {
        let lang_lower = lang.to_lowercase();
        if country == "DE" && lang_lower.starts_with("id") {
            return true;
        }
        if country == "NL" && lang_lower.starts_with("id") {
            return true;
        }
    }

    false
}

/// Calculate composite risk score (0 - 100) and generate a detailed report.
pub fn calculate_proxy_risk_score(client_ip: &str, results: &ProxyTestResults) -> ProxyRiskReport {
    let mut score: u32 = 0;

    if results.header_test {
        score += 20;
    }
    if results.rdns_test {
        score += 15;
    }
    if results.wimia_test {
        score += 25;
    }
    if results.location_test {
        score += 15;
    }
    if results.ja4_test {
        score += 20;
    }
    if results.webrtc_test {
        score += 30; // Decisive unmasking signal
    }

    if score > 100 {
        score = 100;
    }

    let verdict = match score {
        0..=20 => ProxyVerdict::DirectResidential,
        21..=50 => ProxyVerdict::LowRiskAnomaly,
        51..=75 => ProxyVerdict::CommercialVpn,
        _ => {
            if results.webrtc_test {
                ProxyVerdict::UnmaskedProxy
            } else {
                ProxyVerdict::CommercialVpn
            }
        }
    };

    ProxyRiskReport {
        risk_score: score,
        verdict,
        test_results: results.clone(),
        client_ip: client_ip.to_string(),
        unmasked_ip: results.leaked_real_ip.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_header_detection() {
        let mut headers = AHashMap::new();
        headers.insert("via".to_string(), "1.1 squid".to_string());
        assert!(check_proxy_headers(&headers));

        let mut clean_headers = AHashMap::new();
        clean_headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
        assert!(!check_proxy_headers(&clean_headers));
    }

    #[test]
    fn test_wimia_mismatch() {
        let mut headers = AHashMap::new();
        headers.insert("x-forwarded-for".to_string(), "180.252.14.88".to_string());
        assert!(check_wimia_mismatch("37.19.198.160", &headers));

        let mut clean_headers = AHashMap::new();
        clean_headers.insert("x-forwarded-for".to_string(), "37.19.198.160".to_string());
        assert!(!check_wimia_mismatch("37.19.198.160", &clean_headers));
    }

    #[test]
    fn test_location_anomaly() {
        assert!(check_location_anomaly(
            Some("NL"),
            Some("Asia/Jakarta"),
            Some("id-ID")
        ));
        assert!(!check_location_anomaly(
            Some("ID"),
            Some("Asia/Jakarta"),
            Some("id-ID")
        ));
    }

    #[test]
    fn test_composite_risk_score_calculation() {
        let results = ProxyTestResults {
            header_test: false,
            rdns_test: true,     // +15
            wimia_test: true,    // +25
            location_test: true, // +15
            webrtc_test: true,   // +30
            ja4_test: false,
            leaked_real_ip: Some("180.252.14.88".to_string()),
        };

        let report = calculate_proxy_risk_score("37.19.198.160", &results);
        assert_eq!(report.risk_score, 85);
        assert_eq!(report.verdict, ProxyVerdict::UnmaskedProxy);
        assert_eq!(report.unmasked_ip, Some("180.252.14.88".to_string()));
    }
}

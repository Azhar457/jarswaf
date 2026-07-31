//! Virtual Honeypot & Deception System (Tarpit + Deception Engine)
//!
//! When an attacker IP or request is flagged by WAF, instead of dropping or
//! returning a 403 Forbidden (which reveals WAF presence and triggers IP rotation),
//! jarsWAF transparently steers the traffic to an isolated Honeypot Deception Engine.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::info;

/// Configuration for Honeypot Deception System
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HoneypotConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_honeypot_upstream")]
    pub upstream_addr: String, // e.g. "127.0.0.1:9999"
    #[serde(default = "default_delay_ms")]
    pub min_delay_ms: u64, // e.g. 50ms artificial latency
    #[serde(default = "default_max_delay_ms")]
    pub max_delay_ms: u64, // e.g. 200ms artificial latency
    #[serde(default = "default_canary_tokens")]
    pub enable_canary_tokens: bool,
}

fn default_enabled() -> bool {
    false
}
fn default_honeypot_upstream() -> String {
    "127.0.0.1:9999".to_string()
}
fn default_delay_ms() -> u64 {
    50
}
fn default_max_delay_ms() -> u64 {
    200
}
fn default_canary_tokens() -> bool {
    true
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            upstream_addr: default_honeypot_upstream(),
            min_delay_ms: 50,
            max_delay_ms: 200,
            enable_canary_tokens: true,
        }
    }
}

/// Honeypot Threat Intel Event for logging and SIEM reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotEvent {
    pub timestamp: String,
    pub attacker_ip: IpAddr,
    pub service: String, // e.g. "http", "fake_admin", "fake_env"
    pub action: String,  // e.g. "honeypot_steered", "canary_accessed"
    pub path: String,
    pub user_agent: Option<String>,
    pub payload: String,
}

impl HoneypotEvent {
    pub fn new(
        attacker_ip: IpAddr,
        service: &str,
        action: &str,
        path: &str,
        user_agent: Option<&str>,
        payload: &str,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            attacker_ip,
            service: service.to_string(),
            action: action.to_string(),
            path: path.to_string(),
            user_agent: user_agent.map(|s| s.to_string()),
            payload: payload.to_string(),
        }
    }

    pub fn log(&self) {
        info!(
            "[HONEYPOT DECEPTION] IP: {} | Service: {} | Action: {} | Path: {} | UA: {:?}",
            self.attacker_ip, self.service, self.action, self.path, self.user_agent
        );
    }
}

/// Generates fake honeypot payloads (e.g. fake .env with canary keys or fake phpinfo)
pub fn generate_fake_env_honeydoc() -> String {
    "# Production Environment File (CONFIDENTIAL)\n\
     APP_NAME=EnterpriseCore\n\
     APP_ENV=production\n\
     APP_KEY=base64:9J3vKw8XF1zB4mL7pQ2rT5yU8iO0aS1dF4gG7hJ0kL=\n\
     DB_HOST=127.0.0.1\n\
     DB_USER=admin_db_user\n\
     DB_PASS=P@ssw0rd2026!Secured\n\
     AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
     AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\
     CANARY_TOKEN=http://canarytokens.com/feedback/tags/jarswaf-honeypot/index.html\n"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_honeypot_event_logging() {
        let event = HoneypotEvent::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "http",
            "honeypot_steered",
            "/.env",
            Some("curl/7.68.0"),
            "attempted_env_read",
        );
        assert_eq!(event.service, "http");
        assert_eq!(event.action, "honeypot_steered");
        assert!(generate_fake_env_honeydoc().contains("CANARY_TOKEN"));
    }
}

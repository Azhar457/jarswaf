//! Virtual Honeypot & Deception System (Tarpit + Deception Engine)
//!
//! When an attacker IP or request is flagged by WAF, instead of dropping or
//! returning a 403 Forbidden (which reveals WAF presence and triggers IP rotation),
//! jarsWAF transparently steers the traffic to an isolated Honeypot Deception Engine.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tokio::io::AsyncWriteExt;
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
    #[serde(default = "default_block_ttl")]
    pub block_ttl_seconds: u64, // Default: 3600 (1 hour IP block TTL)
    #[serde(default = "default_escalate_strikes")]
    pub escalate_after_strikes: u32, // Default: 3 strikes before permanent ban
    #[serde(default)]
    pub canary_callback_url: Option<String>,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16, // Default: 22
    #[serde(default = "default_mysql_port")]
    pub mysql_port: u16, // Default: 3306
    #[serde(default = "default_postgres_port")]
    pub postgres_port: u16, // Default: 5432
    #[serde(default = "default_redis_port")]
    pub redis_port: u16, // Default: 6379
}

fn default_enabled() -> bool {
    false
}
pub fn default_honeypot_upstream() -> String {
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
fn default_block_ttl() -> u64 {
    3600
}
fn default_escalate_strikes() -> u32 {
    3
}
fn default_ssh_port() -> u16 {
    22
}
fn default_mysql_port() -> u16 {
    3306
}
fn default_postgres_port() -> u16 {
    5432
}
fn default_redis_port() -> u16 {
    6379
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            upstream_addr: default_honeypot_upstream(),
            min_delay_ms: 50,
            max_delay_ms: 200,
            enable_canary_tokens: true,
            block_ttl_seconds: default_block_ttl(),
            escalate_after_strikes: default_escalate_strikes(),
            canary_callback_url: None,
            ssh_port: default_ssh_port(),
            mysql_port: default_mysql_port(),
            postgres_port: default_postgres_port(),
            redis_port: default_redis_port(),
        }
    }
}

/// Honeypot Threat Intel Event for logging and SIEM reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotEvent {
    pub timestamp: String,
    pub attacker_ip: IpAddr,
    pub service: String, // e.g. "http", "ssh", "mysql", "postgres", "redis"
    pub action: String,  // e.g. "honeypot_steered", "canary_accessed", "port_probe"
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

/// Generates fake honeypot HTTP payloads (e.g. fake .env with canary keys)
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

/// Protocol-Aware Deception Payload Generators
pub fn generate_fake_ssh_banner() -> &'static str {
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
}

pub fn generate_fake_mysql_handshake() -> &'static [u8] {
    b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x35\x00\x01\x00\x00\x00\x41\x42\x43\x44\x45\x46\x47\x48\x00\xff\xf7\x21\x02\x00\xff\xc7\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x49\x50\x51\x52\x53\x54\x55\x56\x57\x58\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
}

pub fn generate_fake_postgres_auth() -> &'static str {
    "N" // SSL refused, prompt for MD5 password
}

pub fn generate_fake_redis_resp() -> &'static str {
    "-NOAUTH Authentication required.\r\n"
}

/// Spawn TCP listeners for protocol-aware honeypot services.
///
/// Each listener accepts connections, sends the corresponding fake
/// handshake (SSH banner / MySQL native handshake / Postgres auth /
/// Redis NOAUTH), applies tarpit-style delay, then closes. Every
/// connection is logged as a HoneypotEvent for SIEM correlation.
///
/// This wires the previously-dead payload generators in this module to
/// real sockets — see FEATURE-ANALYSIS gap "Protocol-Aware Honeypot".
pub async fn start_honeypot_listeners(cfg: &HoneypotConfig) {
    if !cfg.enabled {
        return;
    }
    let mut tasks = Vec::new();

    // SSH — send banner immediately (nmap service detection trigger)
    tasks.push(tokio::spawn(honeypot_listener(
        cfg.ssh_port,
        "ssh",
        generate_fake_ssh_banner().as_bytes().to_vec(),
        cfg.min_delay_ms,
        cfg.max_delay_ms,
    )));

    // MySQL — send fake native handshake packet
    tasks.push(tokio::spawn(honeypot_listener(
        cfg.mysql_port,
        "mysql",
        generate_fake_mysql_handshake().to_vec(),
        cfg.min_delay_ms,
        cfg.max_delay_ms,
    )));

    // Postgres — send "N" (SSL refused → MD5 auth prompt follows)
    tasks.push(tokio::spawn(honeypot_listener(
        cfg.postgres_port,
        "postgres",
        generate_fake_postgres_auth().as_bytes().to_vec(),
        cfg.min_delay_ms,
        cfg.max_delay_ms,
    )));

    // Redis — send NOAUTH error (classic unauthenticated Redis probe reply)
    tasks.push(tokio::spawn(honeypot_listener(
        cfg.redis_port,
        "redis",
        generate_fake_redis_resp().as_bytes().to_vec(),
        cfg.min_delay_ms,
        cfg.max_delay_ms,
    )));

    for t in tasks {
        let _ = t.await;
    }
}

async fn honeypot_listener(
    port: u16,
    service: &'static str,
    banner: Vec<u8>,
    min_delay_ms: u64,
    max_delay_ms: u64,
) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(
                "Honeypot {} listener failed to bind {}: {}",
                service,
                addr,
                e
            );
            return;
        }
    };
    tracing::info!("Honeypot {} listening on {}", service, addr);
    loop {
        let (mut sock, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        let banner = banner.clone();
        tokio::spawn(async move {
            // Tarpit: random delay between min and max to slow scanners
            let delay = if max_delay_ms > min_delay_ms {
                min_delay_ms + (rand::random::<u64>() % (max_delay_ms - min_delay_ms))
            } else {
                min_delay_ms
            };
            tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
            let _ = sock.write_all(&banner).await;
            // Brief pause then close — mimics a real service that drops
            // connections after sending its banner.
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            let event = HoneypotEvent::new(
                peer.ip(),
                service,
                "port_probe",
                &format!("/{}", service),
                None,
                "probe_handshake_sent",
            );
            event.log();
        });
    }
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

    #[test]
    fn test_protocol_aware_payloads() {
        assert!(generate_fake_ssh_banner().starts_with("SSH-2.0"));
        assert!(!generate_fake_mysql_handshake().is_empty());
        assert_eq!(generate_fake_postgres_auth(), "N");
        assert_eq!(
            generate_fake_redis_resp(),
            "-NOAUTH Authentication required.\r\n"
        );
    }
}

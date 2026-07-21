use crate::config::{Config, VHost};

/// Helper to match host against a pattern (supports wildcard '*')
/// Uses `eq_ignore_ascii_case` to avoid allocations from `to_lowercase()`.
fn match_pattern(host: &str, pattern: &str) -> bool {
    if pattern == "_" {
        return true;
    }

    let host = host.trim();
    let pattern = pattern.trim();

    if pattern.contains('*') {
        if let Some(suffix) = pattern.strip_prefix('*') {
            // E.g., *.domainsaya.my.id -> matches sub.domainsaya.my.id
            host.len() >= suffix.len()
                && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            // E.g., admin.* -> matches admin.domainsaya.my.id
            host.len() >= prefix.len() && host[..prefix.len()].eq_ignore_ascii_case(prefix)
        } else {
            // Middle wildcard, e.g., api.*.example.com
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                host.len() >= parts[0].len() + parts[1].len()
                    && host[..parts[0].len()].eq_ignore_ascii_case(parts[0])
                    && host[host.len() - parts[1].len()..].eq_ignore_ascii_case(parts[1])
            } else {
                host.eq_ignore_ascii_case(pattern)
            }
        }
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

/// Mencari vhost berdasarkan Host header.
/// Return backend address & matched vhost config.
pub fn match_vhost<'a>(
    host_header: Option<&str>,
    config: &'a Config,
) -> Option<(&'a str, &'a VHost)> {
    let host_str = host_header.unwrap_or_default().to_string();

    // Strip port if exists (e.g. localhost:80 -> localhost)
    let host_name = host_str.split(':').next().unwrap_or("").trim();

    // Cari vhost yang host-nya match
    for vhost in &config.vhosts {
        for pattern in &vhost.hosts {
            if match_pattern(host_name, pattern) {
                return Some((&vhost.backend, vhost));
            }
        }
    }

    // Cari vhost default (fallback / general proxy)
    for vhost in &config.vhosts {
        if vhost.is_default {
            return Some((&vhost.backend, vhost));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vhost_config() -> Config {
        Config {
            global: crate::config::GlobalConfig {
                port_http: 80,
                port_https: 443,
                max_body_size: 1024,
                default_rate_limit: 100,
                log_dir: "./logs".to_string(),
                log_level: "security".to_string(),
                trusted_proxies: None,
                mode: "standalone".to_string(),
                manager_url: None,
                grpc_token: None,
                admin_token: None,
                waf_enabled: true,
                webhooks: vec![],
                metrics_push_url: None,
                metrics_push_interval_secs: 60,
                xdp_interface: None,
                scoring_mode: "immediate".to_string(),
                anomaly_threshold: 5,
            },
            tls: crate::config::TlsConfig {
                mode: "local_ca".to_string(),
                cert_dir: "./certs".to_string(),
            },
            logging: Default::default(),
            components: Default::default(),
            rate_limit_policies: vec![],
            vhosts: vec![
                VHost {
                    name: "example".to_string(),
                    hosts: vec!["example.com".to_string(), "*.example.com".to_string()],
                    backend: "10.0.0.1:8080".to_string(),
                    is_default: false,
                    ..Default::default()
                },
                VHost {
                    name: "default".to_string(),
                    hosts: vec![],
                    backend: "10.0.0.2:8080".to_string(),
                    is_default: true,
                    ..Default::default()
                },
                VHost {
                    name: "wild-admin".to_string(),
                    hosts: vec!["admin.*".to_string()],
                    backend: "10.0.0.3:8080".to_string(),
                    is_default: false,
                    ..Default::default()
                },
            ],
            certificates: vec![],
            custom_rules: vec![],
            allowlists: vec![],
            blacklists: vec![],
            redis: crate::config::RedisConfig {
                enabled: false,
                url: "redis://127.0.0.1:6379".to_string(),
            },
            gossip: crate::config::GossipConfig::default(),
            api_schemas: vec![],
            zero_trust: crate::config::ZeroTrustConfig::default(),
        }
    }

    #[test]
    fn test_match_vhost_exact() {
        let cfg = test_vhost_config();
        let (backend, _) = match_vhost(Some("example.com"), &cfg).unwrap();
        assert_eq!(backend, "10.0.0.1:8080");
    }

    #[test]
    fn test_match_vhost_wildcard_prefix() {
        let cfg = test_vhost_config();
        let (backend, _) = match_vhost(Some("sub.example.com"), &cfg).unwrap();
        assert_eq!(backend, "10.0.0.1:8080");
    }

    #[test]
    fn test_match_vhost_wildcard_suffix() {
        let cfg = test_vhost_config();
        let (backend, _) = match_vhost(Some("admin.test.local"), &cfg).unwrap();
        assert_eq!(backend, "10.0.0.3:8080");
    }

    #[test]
    fn test_match_vhost_strips_port() {
        let cfg = test_vhost_config();
        let (backend, _) = match_vhost(Some("example.com:443"), &cfg).unwrap();
        assert_eq!(backend, "10.0.0.1:8080");
    }

    #[test]
    fn test_match_vhost_default_fallback() {
        let cfg = test_vhost_config();
        let (backend, _) = match_vhost(Some("unknown.host"), &cfg).unwrap();
        assert_eq!(backend, "10.0.0.2:8080");
    }

    #[test]
    fn test_match_vhost_none() {
        let cfg = Config {
            vhosts: vec![],
            ..Default::default()
        };
        assert!(match_vhost(Some("test.com"), &cfg).is_none());
    }

    #[test]
    fn test_match_vhost_no_default() {
        let cfg = Config {
            vhosts: vec![VHost {
                name: "only".to_string(),
                hosts: vec!["only.com".to_string()],
                backend: "10.0.0.1:8080".to_string(),
                is_default: false,
                ..Default::default()
            }],
            ..Default::default()
        };
        // Non-matching host → no default → None
        assert!(match_vhost(Some("other.com"), &cfg).is_none());
    }
}

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
        if pattern.starts_with('*') {
            // E.g., *.domainsaya.my.id -> matches sub.domainsaya.my.id
            let suffix = &pattern[1..];
            host.len() >= suffix.len()
                && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        } else if pattern.ends_with('*') {
            // E.g., admin.* -> matches admin.domainsaya.my.id
            let prefix = &pattern[..pattern.len() - 1];
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

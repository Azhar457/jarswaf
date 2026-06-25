use crate::config::{Config, VHost};
use axum::extract::Host;

/// Helper to match host against a pattern (supports wildcard '*')
fn match_pattern(host: &str, pattern: &str) -> bool {
    if pattern == "_" {
        return true;
    }

    let host = host.trim().to_lowercase();
    let pattern = pattern.trim().to_lowercase();

    if pattern.contains('*') {
        if pattern.starts_with('*') {
            // E.g., *.domainsaya.my.id -> matches sub.domainsaya.my.id
            let suffix = pattern.trim_start_matches('*');
            host.ends_with(suffix)
        } else if pattern.ends_with('*') {
            // E.g., admin.* -> matches admin.domainsaya.my.id
            let prefix = pattern.trim_end_matches('*');
            host.starts_with(prefix)
        } else {
            // Middle wildcard, e.g., api.*.example.com
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                host.starts_with(parts[0]) && host.ends_with(parts[1])
            } else {
                host == pattern
            }
        }
    } else {
        host == pattern
    }
}

/// Mencari vhost berdasarkan Host header.
/// Return backend address & matched vhost config.
pub fn match_vhost<'a>(host_header: Option<&Host>, config: &'a Config) -> (&'a str, &'a VHost) {
    let host_str = host_header.map(|h| h.0.clone()).unwrap_or_default();

    // Strip port if exists (e.g. localhost:80 -> localhost)
    let host_name = host_str.split(':').next().unwrap_or("").trim();

    // Cari vhost yang host-nya match
    for vhost in &config.vhosts {
        for pattern in &vhost.hosts {
            if match_pattern(host_name, pattern) {
                return (&vhost.backend, vhost);
            }
        }
    }

    // fallback ke vhost pertama
    let first = config.vhosts.first().expect("No vhost configured");
    (&first.backend, first)
}

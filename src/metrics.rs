// jarsWAF — Prometheus metrics endpoint
// Provides /metrics in Prometheus-native format for Grafana scraping.
// Also exports jemalloc / process stats.

use once_cell::sync::Lazy;
use prometheus::{
    register_counter, register_gauge, register_gauge_vec, register_histogram_vec, Counter, Gauge,
    GaugeVec, HistogramVec,
};

// ─── Counters ───────────────────────────────────────────────────────────────

pub static REQUESTS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "jarswaf_requests_total",
        "Total number of HTTP requests processed"
    )
    .unwrap()
});

pub static BLOCKED_REQUESTS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "jarswaf_blocked_requests_total",
        "Total number of requests blocked by WAF rules / IP reputation / rate limit"
    )
    .unwrap()
});

pub static BLOCKED_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "jarswaf_blocked_total",
        "Deprecated — use jarswaf_blocked_requests_total instead"
    )
    .unwrap()
});

pub static PASSED_REQUESTS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "jarswaf_passed_requests_total",
        "Total number of requests that passed WAF inspection"
    )
    .unwrap()
});

// ─── Gauges ─────────────────────────────────────────────────────────────────

pub static ACTIVE_REQUEST_COUNT: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "jarswaf_active_requests",
        "Number of requests currently being processed"
    )
    .unwrap()
});

pub static BLOCKED_IPS_GAUGE: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "jarswaf_blocked_ips_count",
        "Current number of IPs in blocklist"
    )
    .unwrap()
});

pub static BLOCKLIST_SIZE: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "jarswaf_blocklist_size",
        "Current blocklist entry count (alias for dashboard)"
    )
    .unwrap()
});

pub static AGENTS_CONNECTED: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "jarswaf_agents_connected",
        "Number of connected agent nodes"
    )
    .unwrap()
});

pub static BLOCKED_IP_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "jarswaf_blocked_ip_total",
        "Total number of IP-block events (one per unique IP blocked)"
    )
    .unwrap()
});

pub static REPUTATION_CACHE_HITS: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "jarswaf_reputation_cache_hits",
        "Number of reputation cache lookups that hit"
    )
    .unwrap()
});

pub static REPUTATION_CACHE_MISSES: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "jarswaf_reputation_cache_misses",
        "Number of reputation cache lookups that missed"
    )
    .unwrap()
});

pub static CONNECTIONS_PER_IP: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "jarswaf_connections_per_ip",
        "Active connections per source IP",
        &["ip"]
    )
    .unwrap()
});

// ─── Histograms ─────────────────────────────────────────────────────────────

pub static REQUEST_DURATION_MS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "jarswaf_request_duration_ms",
        "Request latency in milliseconds",
        &["method", "status"]
    )
    .unwrap()
});

pub static REQUEST_BODY_SIZE_BYTES: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "jarswaf_request_body_bytes",
        "Request body size in bytes",
        &["method"]
    )
    .unwrap()
});

/// Gauge for log channel depth — how full the bounded mpsc channel is.
/// Updated by log worker. When near capacity (10000), system under pressure.
pub static LOG_CHANNEL_DEPTH: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "jarswaf_log_channel_depth",
        "Current depth of log message channel (near 10000 = backpressure)"
    )
    .unwrap()
});

/// Gauge for WAF semaphore availability — how many of 4 permits remain.
pub static WAF_SEMAPHORE_AVAILABLE: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "jarswaf_waf_semaphore_available",
        "Available WAF rule check permits (0 = all 4 in use, skipping)"
    )
    .unwrap()
});

/// Gauge for circuit breaker tripped backends count.
pub static CIRCUIT_BREAKER_TRIPPED: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "jarswaf_circuit_breaker_tripped",
        "Number of backends currently tripped by circuit breaker"
    )
    .unwrap()
});

// ─── Private: real-time blocked-IP gauge maintenance ───────────────────────

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Call this whenever the blocklist changes to keep BLOCKED_IPS_GAUGE in sync.
pub fn update_blocked_ip_count(blocklist: &Arc<DashMap<IpAddr, ()>>) {
    BLOCKED_IPS_GAUGE.set(blocklist.len() as f64);
}

/// Gather all registered prometheus metrics into a single `/metrics` response.
pub fn gather_all() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let mut buffer = Vec::new();
    let metric_families = prometheus::gather();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::warn!("Prometheus encode error: {e}");
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_default()
}

/// Push prometheus metrics to a remote Pushgateway / VictoriaMetrics endpoint.
pub async fn start_metrics_pusher(push_url: String, interval_secs: u64) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    loop {
        let body = gather_all();
        if !body.is_empty() {
            let resp = client
                .post(&push_url)
                .header("Content-Type", "text/plain; version=0.0.4")
                .body(body)
                .send()
                .await;
            match resp {
                Ok(r) => {
                    if !r.status().is_success() {
                        tracing::warn!("Metrics push returned {}", r.status());
                    }
                }
                Err(e) => tracing::debug!("Metrics push failed (likely transient): {e}"),
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
    }
}

//! Behavioral Detection & Anti-Proxy Rotation Module for jarsWAF
//!
//! Detects multi-IP endpoint rotation (9Proxy residential proxy attacks),
//! credential stuffing, and rapid User-Agent switching.

use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub struct BehavioralAnalyzer {
    // endpoint -> list of (timestamp, IpAddr)
    endpoint_hits: DashMap<String, Vec<(Instant, IpAddr)>>,
    // IP -> list of (timestamp, User-Agent)
    ip_ua_history: DashMap<IpAddr, Vec<(Instant, String)>>,
}

impl Default for BehavioralAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl BehavioralAnalyzer {
    pub fn new() -> Self {
        Self {
            endpoint_hits: DashMap::new(),
            ip_ua_history: DashMap::new(),
        }
    }

    /// Record a hit to an endpoint and check for 9Proxy IP rotation (BHV-001)
    /// Triggers if >50 unique IPs hit the same sensitive endpoint within 60 seconds.
    pub fn record_and_check_ip_rotation(&self, endpoint: &str, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(60);

        // Scope the lock to release it as fast as possible
        let ips_to_check = {
            let mut entry = self.endpoint_hits.entry(endpoint.to_string()).or_default();
            let hits = entry.value_mut();

            // Retain only entries within sliding window
            hits.retain(|(ts, _)| now.duration_since(*ts) < window);
            hits.push((now, ip));

            // Fast copy of IP addresses to avoid holding write locks during HashSet operations
            hits.iter().map(|(_, ip)| *ip).collect::<Vec<_>>()
        };

        // Count unique IPs in window outside the write lock
        let unique_ips: std::collections::HashSet<_> = ips_to_check.into_iter().collect();
        unique_ips.len() >= 50
    }

    /// Record a request from an IP and check for rapid User-Agent rotation (BHV-003)
    /// Triggers if a single IP rotates >10 different User-Agents within 120 seconds.
    pub fn record_and_check_ua_rotation(&self, ip: IpAddr, user_agent: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(120);

        // Scope the lock to release it as fast as possible
        let uas_to_check = {
            let mut entry = self.ip_ua_history.entry(ip).or_default();
            let uas = entry.value_mut();

            uas.retain(|(ts, _)| now.duration_since(*ts) < window);
            uas.push((now, user_agent.to_string()));

            // Fast copy of User Agents
            uas.iter().map(|(_, ua)| ua.clone()).collect::<Vec<_>>()
        };

        // Count unique User Agents outside the write lock
        let unique_uas: std::collections::HashSet<_> = uas_to_check.into_iter().collect();
        unique_uas.len() >= 10
    }

    /// ASYNC DAEMON: Garbage Collector that runs in the background.
    /// Safely clears expired entries and removes empty vectors from maps to save memory.
    pub async fn start_background_garbage_collector(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = Instant::now();
            let ip_window = Duration::from_secs(60);
            let ua_window = Duration::from_secs(120);

            // Clean endpoint_hits
            self.endpoint_hits.retain(|_, hits| {
                hits.retain(|(ts, _)| now.duration_since(*ts) < ip_window);
                !hits.is_empty()
            });

            // Clean ip_ua_history
            self.ip_ua_history.retain(|_, uas| {
                uas.retain(|(ts, _)| now.duration_since(*ts) < ua_window);
                !uas.is_empty()
            });

            tracing::debug!("Behavioral Analyzer Garbage Collection completed");
        }
    }
}

pub static BEHAVIORAL_ANALYZER: Lazy<BehavioralAnalyzer> = Lazy::new(BehavioralAnalyzer::new);

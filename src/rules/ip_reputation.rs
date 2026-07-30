//! IP Reputation & Anti-Proxy Engine for jarsWAF
//!
//! Provides caching and evaluation of IP reputation scores (AbuseIPDB, IPQS, Datacenter ASNs).

use once_cell::sync::Lazy;
use quick_cache::sync::Cache;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ReputationScore {
    pub abuse_confidence: f32, // 0.0 to 1.0
    pub proxy_score: f32,      // 0.0 to 1.0 (VPN/Proxy/Tor)
    pub is_datacenter: bool,
    pub cached_at: Instant,
}

pub struct IpReputationEngine {
    cache: Cache<IpAddr, ReputationScore>,
}

impl Default for IpReputationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl IpReputationEngine {
    pub fn new() -> Self {
        Self {
            cache: Cache::new(100_000),
        }
    }

    /// Check if IP reputation is cached and valid
    pub fn get_score(&self, ip: IpAddr) -> Option<ReputationScore> {
        if let Some(score) = self.cache.get(&ip) {
            // Check TTL (cache valid for 1 hour)
            if score.cached_at.elapsed() < Duration::from_secs(3600) {
                return Some(score.clone());
            }
        }
        None
    }

    /// Store an IP reputation score into the LRU cache
    pub fn set_score(&self, ip: IpAddr, score: ReputationScore) {
        self.cache.insert(ip, score);
    }
}

pub static REPUTATION_ENGINE: Lazy<IpReputationEngine> = Lazy::new(IpReputationEngine::new);

/// Heuristic check for known high-risk Datacenter ASNs (AWS, GCP, Azure, Hetzner, OVH, DigitalOcean)
pub fn is_known_datacenter_asn(asn: u32) -> bool {
    matches!(
        asn,
        16509 | 15169 | 8075 | 16276 | 14061 | 24940 | 63949 | 36351
    )
}

use arc_swap::ArcSwap;
use std::sync::Arc;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeConfig {
    pub http_port: u16,
    pub https_port: u16,
    pub mode: String,
    pub log_level: String,
    pub tls_mode: String,
    pub tls_cert_dir: String,
    pub log_mode: String,
    pub log_db_path: String,
    pub log_path: String,
    pub max_body_size: usize,
    pub cleanup_interval_secs: u64,
    pub rate_limiter_max_entries: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            http_port: 8000,
            https_port: 8443,
            mode: "standalone".to_string(),
            log_level: "info".to_string(),
            tls_mode: "local_ca".to_string(),
            tls_cert_dir: "./certs".to_string(),
            log_mode: "sqlite".to_string(),
            log_db_path: "/var/log/jarswaf/jarswaf.db".to_string(),
            log_path: "/var/log/jarswaf/jarswaf.log".to_string(),
            max_body_size: 10 * 1024 * 1024,
            cleanup_interval_secs: 300,
            rate_limiter_max_entries: 100_000,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomRuleDef {
    pub id: String,
    pub name: String,
    pub condition_type: String,
    pub operator: String,
    pub condition_value: String,
    pub action: String,
    pub action_value: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitPolicy {
    pub name: String,
    pub limit: u32,
    pub burst: u32,
    pub path: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct VhostConfig {
    pub name: String,
    pub hosts: Vec<String>,
    pub backend: String,
    pub tenant: Option<String>,
    pub rule_patterns: Vec<String>,
    pub blocked_countries: Vec<String>,
    pub geoblock_type: String,
    pub custom_rule_ids: Vec<String>,
    pub max_body: String,
    pub rate_limit: String,
    pub is_default: bool,
    pub max_conns_per_ip: u32,
    pub max_concurrent_requests: u32,
    pub bot_challenge_enabled: bool,
    pub websocket_security_enabled: bool,
    pub blocked_asns: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct RuleSet {
    pub custom_rules: Vec<CustomRuleDef>,
    pub rate_limit_policies: Vec<RateLimitPolicy>,
    pub vhosts: Vec<VhostConfig>,
}

impl RuleSet {
    pub fn get_custom_rule(&self, id: &str) -> Option<&CustomRuleDef> {
        self.custom_rules.iter().find(|r| r.id == id)
    }

    pub fn get_rate_limit_policy(&self, name: &str) -> Option<&RateLimitPolicy> {
        self.rate_limit_policies.iter().find(|p| p.name == name)
    }

    pub fn get_vhost(&self, host: &str) -> Option<&VhostConfig> {
        self.vhosts.iter().find(|v| {
            v.hosts.iter().any(|h| {
                if h == "*" || h == host {
                    true
                } else if h.starts_with("*.") {
                    let suffix = &h[1..];
                    host.ends_with(suffix)
                } else {
                    false
                }
            })
        }).or_else(|| self.vhosts.iter().find(|v| v.is_default))
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
pub enum BlockSource {
    Manual,
    RateLimit,
    ThreatIntel,
    Geoip,
    CustomRule,
    Anomaly,
}

#[derive(Debug, Clone)]
pub struct BlocklistEntry {
    pub ip: IpAddr,
    pub added_at: Instant,
    pub expires_at: Instant,
    pub reason: String,
    pub source: BlockSource,
}

#[derive(Debug, Clone, Default)]
pub struct BlocklistSnapshot {
    pub entries: HashMap<IpAddr, BlocklistEntry>,
}

#[derive(Clone)]
pub struct PublishedState {
    pub config: Arc<ArcSwap<RuntimeConfig>>,
    pub rules: Arc<ArcSwap<RuleSet>>,
    pub blocklist: Arc<ArcSwap<BlocklistSnapshot>>,
}

impl PublishedState {
    pub fn new(config: RuntimeConfig, rules: RuleSet, blocklist: BlocklistSnapshot) -> Self {
        Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            rules: Arc::new(ArcSwap::from_pointee(rules)),
            blocklist: Arc::new(ArcSwap::from_pointee(blocklist)),
        }
    }

    pub fn get_config(&self) -> arc_swap::Guard<Arc<RuntimeConfig>> {
        self.config.load()
    }
    
    pub fn get_rules(&self) -> arc_swap::Guard<Arc<RuleSet>> {
        self.rules.load()
    }
    
    pub fn get_blocklist(&self) -> arc_swap::Guard<Arc<BlocklistSnapshot>> {
        self.blocklist.load()
    }
    
    pub fn publish_config(&self, config: RuntimeConfig) {
        self.config.store(Arc::new(config));
    }
    
    pub fn publish_rules(&self, rules: RuleSet) {
        self.rules.store(Arc::new(rules));
    }
    
    pub fn publish_blocklist(&self, blocklist: BlocklistSnapshot) {
        self.blocklist.store(Arc::new(blocklist));
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DashboardMetrics {
    pub timestamp: String,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub allowed_requests: u64,
    pub requests_per_sec: f64,
    pub blocked_per_sec: f64,
    pub active_connections: u64,
    pub top_blocked_ips: Vec<IpBlockCount>,
    pub top_triggered_rules: Vec<RuleTriggerCount>,
    pub blocklist_size: usize,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IpBlockCount {
    pub ip: String,
    pub count: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleTriggerCount {
    pub rule_id: String,
    pub count: u64,
}

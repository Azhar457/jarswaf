use crate::control_bus::state::{CustomRuleDef, DashboardMetrics, RateLimitPolicy, VhostConfig};
use serde::Serialize;

// === GENERIC WRAPPER ===

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub data: T,
}

impl<T> ApiResponse<T> {
    pub fn new(data: T) -> Self {
        Self { data }
    }
}

// === PAGINATED WRAPPER ===

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub page: u32,
    pub per_page: u32,
    pub total: u64,
}

impl<T> PaginatedResponse<T> {
    pub fn new(data: Vec<T>, page: u32, per_page: u32, total: u64) -> Self {
        Self {
            data,
            page,
            per_page,
            total,
        }
    }
}

// === HEALTH ===

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
    pub kernel_loaded: bool,
    pub mode: String,
}

// === CONFIG ===

#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub http_port: u16,
    pub https_port: u16,
    pub mode: String,
    pub log_level: String,
    pub tls_mode: String,
    pub max_body_size: usize,
    pub cleanup_interval_secs: u64,
}

// === RULES ===

#[derive(Debug, Serialize)]
pub struct RuleResponse {
    pub id: String,
    pub name: String,
    pub condition_type: String,
    pub operator: String,
    pub condition_value: String,
    pub action: String,
    pub action_value: Option<String>,
    pub enabled: bool,
}

impl From<CustomRuleDef> for RuleResponse {
    fn from(r: CustomRuleDef) -> Self {
        Self {
            id: r.id,
            name: r.name,
            condition_type: r.condition_type,
            operator: r.operator,
            condition_value: r.condition_value,
            action: r.action,
            action_value: r.action_value,
            enabled: r.enabled,
        }
    }
}

// === RATE LIMITS ===

#[derive(Debug, Serialize)]
pub struct RateLimitResponse {
    pub name: String,
    pub limit: u32,
    pub burst: u32,
    pub path: String,
    pub description: Option<String>,
}

impl From<RateLimitPolicy> for RateLimitResponse {
    fn from(p: RateLimitPolicy) -> Self {
        Self {
            name: p.name,
            limit: p.limit,
            burst: p.burst,
            path: p.path,
            description: p.description,
        }
    }
}

// === VHOSTS ===

#[derive(Debug, Serialize)]
pub struct VhostResponse {
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

impl From<VhostConfig> for VhostResponse {
    fn from(v: VhostConfig) -> Self {
        Self {
            name: v.name,
            hosts: v.hosts,
            backend: v.backend,
            tenant: v.tenant,
            rule_patterns: v.rule_patterns,
            blocked_countries: v.blocked_countries,
            geoblock_type: v.geoblock_type,
            custom_rule_ids: v.custom_rule_ids,
            max_body: v.max_body,
            rate_limit: v.rate_limit,
            is_default: v.is_default,
            max_conns_per_ip: v.max_conns_per_ip,
            max_concurrent_requests: v.max_concurrent_requests,
            bot_challenge_enabled: v.bot_challenge_enabled,
            websocket_security_enabled: v.websocket_security_enabled,
            blocked_asns: v.blocked_asns,
        }
    }
}

// === LOGS ===

#[derive(Debug, Serialize)]
pub struct LogEntryResponse {
    pub timestamp: String,
    pub request_id: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub action: String,
    pub rule_id: String,
    pub score: f64,
    pub latency_ms: f64,
    pub vhost: String,
}

// === AGENTS ===

#[derive(Debug, Serialize)]
pub struct AgentResponse {
    pub hostname: String,
    pub ip: String,
    pub os: String,
    pub cpu: f32,
    pub ram: f32,
    pub disk: f32,
    pub uptime: String,
    pub status: String,
    pub region: Option<String>,
    pub cloud_provider: Option<String>,
    pub active_connections: Option<u64>,
    pub last_seen: String,
}

// === DASHBOARD ===

#[derive(Debug, Serialize)]
pub struct DashboardSummary {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub allowed_requests: u64,
    pub requests_per_sec: f64,
    pub blocked_per_sec: f64,
    pub active_connections: u64,
    pub blocklist_size: usize,
    pub uptime_secs: u64,
    pub top_blocked_ips: Vec<IpBlockCountResponse>,
    pub top_triggered_rules: Vec<RuleTriggerCountResponse>,
}

#[derive(Debug, Serialize)]
pub struct IpBlockCountResponse {
    pub ip: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct RuleTriggerCountResponse {
    pub rule_id: String,
    pub count: u64,
}

impl From<DashboardMetrics> for DashboardSummary {
    fn from(m: DashboardMetrics) -> Self {
        Self {
            total_requests: m.total_requests,
            blocked_requests: m.blocked_requests,
            allowed_requests: m.allowed_requests,
            requests_per_sec: m.requests_per_sec,
            blocked_per_sec: m.blocked_per_sec,
            active_connections: m.active_connections,
            blocklist_size: m.blocklist_size,
            uptime_secs: m.uptime_secs,
            top_blocked_ips: m
                .top_blocked_ips
                .into_iter()
                .map(|i| IpBlockCountResponse {
                    ip: i.ip,
                    count: i.count,
                })
                .collect(),
            top_triggered_rules: m
                .top_triggered_rules
                .into_iter()
                .map(|r| RuleTriggerCountResponse {
                    rule_id: r.rule_id,
                    count: r.count,
                })
                .collect(),
        }
    }
}

// === SIMPLE MESSAGE RESPONSE ===

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

impl MessageResponse {
    pub fn new(msg: &str) -> Self {
        Self {
            message: msg.to_string(),
        }
    }
}

// === BLOCKLIST ===

#[derive(Debug, Serialize)]
pub struct BlocklistEntryResponse {
    pub ip: String,
    pub reason: String,
    pub expires_at: String,
}

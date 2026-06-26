use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub global: GlobalConfig,
    pub tls: TlsConfig,
    #[serde(default)]
    pub logging: LoggingModeConfig,
    #[serde(default)]
    pub components: ComponentsConfig,
    #[serde(default)]
    pub rate_limit_policies: Vec<RateLimitPolicy>,
    pub vhosts: Vec<VHost>,
    #[serde(default)]
    pub certificates: Vec<CertificateConfig>,
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,
    #[serde(default)]
    pub allowlists: Vec<AllowlistRule>,
    #[serde(default)]
    pub blacklists: Vec<BlacklistRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CertificateConfig {
    pub domain: String,
    pub provider: String,
    pub email: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitPolicy {
    pub name: String,
    pub limit: String,
    pub burst: u32,
    pub path: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GlobalConfig {
    pub port_http: u16,
    pub port_https: u16,
    pub max_body_size: usize,
    pub default_rate_limit: u32,
    pub log_dir: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    pub trusted_proxies: Option<Vec<String>>,
    #[serde(default)]
    pub admin_token: Option<String>,
    #[serde(default = "default_waf_enabled")]
    pub waf_enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub mode: String,
    pub cert_dir: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    pub condition_type: String,
    pub operator: String,
    pub condition_value: String,
    pub action: String,
    pub action_value: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VHost {
    pub name: String,
    pub hosts: Vec<String>,
    pub backend: String,
    #[serde(default)]
    pub rate_limit_tiers: Vec<RateLimitTier>,
    #[serde(default)]
    pub logging: Option<LoggingConfig>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub blocked_countries: Vec<String>,
    #[serde(default = "default_geoblock_type")]
    pub geoblock_type: String,
    #[serde(default)]
    pub custom_rules: Vec<String>,
    #[serde(default = "default_ssl")]
    pub ssl: String,
    #[serde(default = "default_max_body")]
    pub max_body: String,
    #[serde(default = "default_rate_limit_str")]
    pub rate_limit: String,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default)]
    pub allowlists: Vec<AllowlistRule>,
    #[serde(default)]
    pub blacklists: Vec<BlacklistRule>,
}

fn default_geoblock_type() -> String {
    "Blocklist".to_string()
}

fn default_ssl() -> String {
    "Disabled".to_string()
}

fn default_max_body() -> String {
    "10MB".to_string()
}

fn default_rate_limit_str() -> String {
    "600 req/min".to_string()
}

fn default_log_level() -> String {
    "security".to_string()
}

fn default_waf_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitTier {
    pub path: String,
    pub limit: u32,
    #[serde(default = "default_body_inspection")]
    pub body_inspection: bool,
}

fn default_body_inspection() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub enabled: bool,
    pub db_path: String,
}

/// Configures how the Agent writes/ships security logs.
/// Modes:
///   - "file"       → JSON Lines to local file only (zero external deps, ideal for small VPS)
///   - "remote"     → JSON Lines to local file + async HTTP push to a remote Controller
///   - "clickhouse" → Direct batch insert to ClickHouse (existing behavior)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingModeConfig {
    #[serde(default = "default_logging_mode")]
    pub mode: String,
    #[serde(default = "default_log_path")]
    pub log_path: String,
    /// Max log file size in MB before rotation (default 50)
    #[serde(default = "default_max_log_size_mb")]
    pub max_log_size_mb: u64,
    /// Max number of rotated log files to keep (default 5)
    #[serde(default = "default_max_log_files")]
    pub max_log_files: u32,
    /// Remote Controller URL for "remote" mode
    #[serde(default)]
    pub remote_url: Option<String>,
    /// Push interval in seconds for "remote" mode (default 300 = 5 minutes)
    #[serde(default = "default_push_interval")]
    pub push_interval_secs: u64,
    /// Max batch size for remote push (default 100)
    #[serde(default = "default_push_batch_size")]
    pub push_batch_size: usize,
    /// Path to local JSON file for blocklist storage (default "blocklist.json")
    #[serde(default = "default_blocklist_path")]
    pub blocklist_path: String,
}

impl Default for LoggingModeConfig {
    fn default() -> Self {
        Self {
            mode: default_logging_mode(),
            log_path: default_log_path(),
            max_log_size_mb: default_max_log_size_mb(),
            max_log_files: default_max_log_files(),
            remote_url: None,
            push_interval_secs: default_push_interval(),
            push_batch_size: default_push_batch_size(),
            blocklist_path: default_blocklist_path(),
        }
    }
}

fn default_logging_mode() -> String {
    "clickhouse".to_string()
}
fn default_log_path() -> String {
    "./logs/aegis.log".to_string()
}
fn default_max_log_size_mb() -> u64 {
    50
}
fn default_max_log_files() -> u32 {
    5
}
fn default_push_interval() -> u64 {
    300
}
fn default_push_batch_size() -> usize {
    100
}
fn default_blocklist_path() -> String {
    "./blocklist.json".to_string()
}

/// Configures which system components are active.
/// Allows running a lightweight Agent without ClickHouse or Dashboard.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ComponentsConfig {
    /// Enable the Svelte Dashboard UI serving (only meaningful for Controller)
    #[serde(default = "default_true")]
    pub dashboard: bool,
    /// Enable ClickHouse database connection (disable for file-only logging)
    #[serde(default = "default_true")]
    pub clickhouse: bool,
    /// Enable service discovery (scanning Docker/system ports)
    #[serde(default = "default_true")]
    pub service_discovery: bool,
    /// Enable GeoIP-based country blocking
    #[serde(default = "default_true")]
    pub geoip: bool,
}

impl Default for ComponentsConfig {
    fn default() -> Self {
        Self {
            dashboard: true,
            clickhouse: true,
            service_discovery: true,
            geoip: true,
        }
    }
}

pub fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let cfg: Config = toml::from_str(&content)?;
    Ok(cfg)
}

pub fn parse_size(s: &str) -> usize {
    let s = s.trim().to_uppercase();
    if s.ends_with("MB") {
        s.trim_end_matches("MB")
            .trim()
            .parse::<usize>()
            .unwrap_or(10)
            * 1024
            * 1024
    } else if s.ends_with("KB") {
        s.trim_end_matches("KB")
            .trim()
            .parse::<usize>()
            .unwrap_or(10)
            * 1024
    } else if s.ends_with("GB") {
        s.trim_end_matches("GB")
            .trim()
            .parse::<usize>()
            .unwrap_or(1)
            * 1024
            * 1024
            * 1024
    } else {
        s.parse::<usize>().unwrap_or(10 * 1024 * 1024)
    }
}

pub fn parse_rate_limit(s: &str) -> u32 {
    let s = s.trim().to_lowercase();
    let number_str: String = s.chars().take_while(|c| c.is_numeric()).collect();
    number_str.parse::<u32>().unwrap_or(600)
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AllowlistRule {
    pub name: String,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub bypass_rules: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BlacklistRule {
    pub name: String,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

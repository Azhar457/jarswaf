use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub global: GlobalConfig,
    pub tls: TlsConfig,
    #[serde(default)]
    pub rate_limit_policies: Vec<RateLimitPolicy>,
    pub vhosts: Vec<VHost>,
    #[serde(default)]
    pub certificates: Vec<CertificateConfig>,
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,
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

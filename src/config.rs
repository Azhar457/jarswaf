use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    // NOTE: If you add fields with #[serde(default)],
    // ensure they implement Default.
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
    #[serde(default)]
    pub redis: RedisConfig,
    #[serde(default)]
    pub gossip: GossipConfig,
    #[serde(default)]
    pub api_schemas: Vec<RouteSchema>,
    #[serde(default)]
    pub zero_trust: ZeroTrustConfig,
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
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub manager_url: Option<String>,
    #[serde(default)]
    pub grpc_token: Option<String>,
    #[serde(default)]
    pub admin_token: Option<String>,
    #[serde(default = "default_waf_enabled")]
    pub waf_enabled: bool,
    /// Alert webhooks — fired on blocked requests or reputation events.
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
    /// URL for Prometheus Pushgateway / VictoriaMetrics push endpoint.
    /// Example: "http://pushgateway.example.com:9091/metrics/job/jarswaf"
    #[serde(default)]
    pub metrics_push_url: Option<String>,
    /// Interval in seconds between prometheus metric pushes (default 60)
    #[serde(default = "default_metrics_push_interval")]
    pub metrics_push_interval_secs: u64,
    /// XDP network interface to attach to (e.g., "eth0", "podman0")
    #[serde(default = "default_xdp_interface")]
    pub xdp_interface: Option<String>,
    #[serde(default = "default_scoring_mode")]
    pub scoring_mode: String,
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: u32,
}

fn default_mode() -> String {
    "standalone".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookConfig {
    /// Name / label for this webhook (e.g. "slack-security", "discord")
    pub name: String,
    /// URL to POST the JSON payload to
    pub url: String,
    /// Secret token to include as Bearer auth (optional)
    #[serde(default)]
    pub secret: Option<String>,
    /// Minimum event severity to trigger: "low" | "medium" | "high" | "critical"
    #[serde(default = "default_webhook_severity")]
    pub min_severity: String,
    /// Cooldown in seconds between alerts for the same rule (default 300)
    #[serde(default = "default_webhook_cooldown")]
    pub cooldown_secs: u64,
}

fn default_webhook_severity() -> String {
    "high".to_string()
}
fn default_webhook_cooldown() -> u64 {
    300
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
    pub backends: Option<Vec<String>>,
    #[serde(default = "default_tenant")]
    pub tenant: String,
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
    #[serde(default)]
    pub deception_mode: bool,
    /// Security headers to inject into every response.
    /// Default: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
    #[serde(default)]
    pub security_headers: Option<SecurityHeadersConfig>,
    /// DLP (Data Loss Prevention) — inspect response bodies for sensitive data.
    #[serde(default)]
    pub dlp: Option<DlpConfig>,
    #[serde(default = "default_max_conns_per_ip")]
    pub max_conns_per_ip: usize,
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
    #[serde(default = "default_bot_challenge_enabled")]
    pub bot_challenge_enabled: bool,
    #[serde(default = "default_websocket_security_enabled")]
    pub websocket_security_enabled: bool,
    #[serde(default)]
    pub blocked_asns: Vec<u32>,
}

impl Default for VHost {
    fn default() -> Self {
        Self {
            name: String::new(),
            hosts: Vec::new(),
            backend: String::new(),
            backends: None,
            tenant: default_tenant(),
            rate_limit_tiers: Vec::new(),
            logging: None,
            rules: Vec::new(),
            blocked_countries: Vec::new(),
            geoblock_type: default_geoblock_type(),
            custom_rules: Vec::new(),
            ssl: default_ssl(),
            max_body: default_max_body(),
            rate_limit: default_rate_limit_str(),
            is_default: false,
            allowlists: Vec::new(),
            blacklists: Vec::new(),
            deception_mode: false,
            security_headers: None,
            dlp: None,
            max_conns_per_ip: default_max_conns_per_ip(),
            max_concurrent_requests: default_max_concurrent_requests(),
            bot_challenge_enabled: default_bot_challenge_enabled(),
            websocket_security_enabled: default_websocket_security_enabled(),
            blocked_asns: Vec::new(),
        }
    }
}

fn default_max_conns_per_ip() -> usize {
    50
}

fn default_max_concurrent_requests() -> usize {
    100
}

fn default_bot_challenge_enabled() -> bool {
    false
}

fn default_websocket_security_enabled() -> bool {
    false
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

fn default_metrics_push_interval() -> u64 {
    60
}

fn default_xdp_interface() -> Option<String> {
    None
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
    /// Path to the SQLite database file
    #[serde(default = "default_db_path")]
    pub db_path: String,
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
            db_path: default_db_path(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            global: GlobalConfig {
                port_http: 80,
                port_https: 443,
                max_body_size: 10 * 1024 * 1024,
                default_rate_limit: 600,
                log_dir: "./logs".to_string(),
                log_level: "security".to_string(),
                trusted_proxies: None,
                mode: default_mode(),
                manager_url: None,
                grpc_token: None,
                admin_token: None,
                waf_enabled: true,
                metrics_push_url: None,
                metrics_push_interval_secs: 60,
                webhooks: Vec::new(),
                xdp_interface: None,
                scoring_mode: default_scoring_mode(),
                anomaly_threshold: default_anomaly_threshold(),
            },
            tls: TlsConfig {
                mode: "disabled".to_string(),
                cert_dir: "./certs".to_string(),
            },
            logging: LoggingModeConfig::default(),
            components: ComponentsConfig::default(),
            rate_limit_policies: Vec::new(),
            vhosts: Vec::new(),
            certificates: Vec::new(),
            custom_rules: Vec::new(),
            allowlists: Vec::new(),
            blacklists: Vec::new(),
            redis: RedisConfig::default(),
            gossip: GossipConfig::default(),
            api_schemas: Vec::new(),
            zero_trust: ZeroTrustConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GossipConfig {
    #[serde(default = "default_gossip_enabled")]
    pub enabled: bool,
    #[serde(default = "default_gossip_bind")]
    pub bind_addr: String,
    #[serde(default)]
    pub seeds: Vec<String>,
    /// Pre-shared key for ChaCha20Poly1305 encryption.
    /// MUST be exactly 32 bytes. If shorter, it will be zero-padded.
    /// If longer, it will be truncated to 32 bytes.
    #[serde(default)]
    pub psk: String,
    #[serde(default = "default_gossip_node_id")]
    pub node_id: String,
}

fn default_gossip_enabled() -> bool { false }
fn default_gossip_bind() -> String { "0.0.0.0:7946".to_string() }
fn default_gossip_node_id() -> String { "jarswaf-unknown".to_string() }

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: default_gossip_bind(),
            seeds: Vec::new(),
            psk: String::new(),
            node_id: default_gossip_node_id(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZeroTrustConfig {
    /// Minimum trust score (0.0 to 1.0). Requests below this are blocked.
    #[serde(default = "default_min_trust_score")]
    pub min_trust_score: f64,
    /// Allowed identity token issuers (e.g. "https://auth.jarswaf.local").
    /// Empty = trust all issuers.
    #[serde(default)]
    pub allowed_issuers: Vec<String>,
}

fn default_min_trust_score() -> f64 { 0.0 }

impl Default for ZeroTrustConfig {
    fn default() -> Self {
        Self {
            min_trust_score: default_min_trust_score(),
            allowed_issuers: Vec::new(),
        }
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: "redis://127.0.0.1:6379".to_string(),
        }
    }
}

fn default_logging_mode() -> String {
    "sqlite".to_string()
}
fn default_log_path() -> String {
    "./logs/jarswaf.log".to_string()
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
fn default_db_path() -> String {
    "/var/log/jarswaf/jarswaf.db".to_string()
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

pub fn save_config(path: &str, cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let toml_str = toml::to_string(cfg)?;
    let tmp_path = format!("{}.tmp", path);
    fs::write(&tmp_path, toml_str)?;

    // Create backup before renaming
    if std::path::Path::new(path).exists() {
        let parent = std::path::Path::new(path)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let backups_dir = parent.join("config_backups");
        let _ = fs::create_dir_all(&backups_dir);

        let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
        let backup_path = backups_dir.join(format!("config_{}.toml", timestamp));
        let _ = fs::copy(path, backup_path);

        // Keep only the last 15 backups
        if let Ok(entries) = fs::read_dir(&backups_dir) {
            let mut paths: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
            paths.sort();
            if paths.len() > 15 {
                for old_path in paths.iter().take(paths.len() - 15) {
                    let _ = fs::remove_file(old_path);
                }
            }
        }
    }

    fs::rename(&tmp_path, path)?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RedisConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_redis_url")]
    pub url: String,
}

fn default_false() -> bool {
    false
}

fn default_redis_url() -> String {
    "redis://127.0.0.1:6379".to_string()
}

fn default_tenant() -> String {
    "default".to_string()
}

// ─── DLP (Data Loss Prevention) Config ─────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DlpConfig {
    #[serde(default = "default_dlp_enabled")]
    pub enabled: bool,
    /// Action: "log" (default) or "block"
    #[serde(default = "default_dlp_action")]
    pub action: String,
    /// Regex: credit card (Luhn-validatable numbers)
    #[serde(default = "default_dlp_cc")]
    pub credit_card: bool,
    /// Regex: JWT / Bearer tokens
    #[serde(default = "default_dlp_jwt")]
    pub jwt_token: bool,
    /// Regex: AWS / Azure / GCP secret keys
    #[serde(default = "default_dlp_cloud_secrets")]
    pub cloud_secrets: bool,
    /// Regex: password/reset token patterns
    #[serde(default = "default_dlp_password")]
    pub password_in_body: bool,
    /// Regex: email addresses in response body
    #[serde(default = "default_dlp_email")]
    pub email: bool,
    /// Allow-list: response bodies matching any part of these strings are NOT flagged
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Custom regex patterns (key = pattern name, value = regex)
    #[serde(default)]
    pub custom_patterns: ahash::AHashMap<String, String>,
    /// Max response body size to inspect (default: 2MB)
    #[serde(default = "default_dlp_response_limit")]
    pub response_body_limit: usize,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: default_dlp_enabled(),
            action: default_dlp_action(),
            credit_card: default_dlp_cc(),
            jwt_token: default_dlp_jwt(),
            cloud_secrets: default_dlp_cloud_secrets(),
            password_in_body: default_dlp_password(),
            email: default_dlp_email(),
            allowlist: Vec::new(),
            custom_patterns: ahash::AHashMap::new(),
            response_body_limit: default_dlp_response_limit(),
        }
    }
}

fn default_dlp_enabled() -> bool {
    false
}
fn default_dlp_response_limit() -> usize {
    2 * 1024 * 1024
}
fn default_scoring_mode() -> String {
    "immediate".to_string()
}
fn default_anomaly_threshold() -> u32 {
    5
}
fn default_dlp_action() -> String {
    "log".to_string()
}
fn default_dlp_cc() -> bool {
    true
}
fn default_dlp_jwt() -> bool {
    true
}
fn default_dlp_cloud_secrets() -> bool {
    true
}
fn default_dlp_password() -> bool {
    true
}
fn default_dlp_email() -> bool {
    false
}

// ─── Security Headers Config ───────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityHeadersConfig {
    #[serde(default = "default_sh_enabled")]
    pub enabled: bool,
    /// Content-Security-Policy header value
    #[serde(default = "default_sh_csp")]
    pub content_security_policy: Option<String>,
    /// Strict-Transport-Security (only applied on HTTPS responses)
    #[serde(default = "default_sh_hsts")]
    pub strict_transport_security: Option<String>,
    /// X-Frame-Options
    #[serde(default = "default_sh_xfo")]
    pub x_frame_options: Option<String>,
    /// X-Content-Type-Options
    #[serde(default = "default_sh_xcto")]
    pub x_content_type_options: Option<String>,
    /// Referrer-Policy
    #[serde(default = "default_sh_referrer")]
    pub referrer_policy: Option<String>,
    /// Permissions-Policy
    #[serde(default = "default_sh_permissions")]
    pub permissions_policy: Option<String>,
    /// Cross-Origin-Resource-Policy
    #[serde(default = "default_sh_corp")]
    pub cross_origin_resource_policy: Option<String>,
    /// Custom extra headers (key=value pairs)
    #[serde(default)]
    pub extra_headers: ahash::AHashMap<String, String>,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            enabled: default_sh_enabled(),
            content_security_policy: default_sh_csp(),
            strict_transport_security: default_sh_hsts(),
            x_frame_options: default_sh_xfo(),
            x_content_type_options: default_sh_xcto(),
            referrer_policy: default_sh_referrer(),
            permissions_policy: default_sh_permissions(),
            cross_origin_resource_policy: default_sh_corp(),
            extra_headers: ahash::AHashMap::new(),
        }
    }
}

fn default_sh_enabled() -> bool {
    true
}
fn default_sh_csp() -> Option<String> {
    Some("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'".to_string())
}
fn default_sh_hsts() -> Option<String> {
    Some("max-age=63072000; includeSubDomains; preload".to_string())
}
fn default_sh_xfo() -> Option<String> {
    Some("DENY".to_string())
}
fn default_sh_xcto() -> Option<String> {
    Some("nosniff".to_string())
}
fn default_sh_referrer() -> Option<String> {
    Some("strict-origin-when-cross-origin".to_string())
}
fn default_sh_permissions() -> Option<String> {
    Some("camera=(), microphone=(), geolocation=(), interest-cohort=()".to_string())
}
fn default_sh_corp() -> Option<String> {
    Some("same-origin".to_string())
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
pub struct ParameterSchema {
    pub name: String,
    pub param_type: String, // "integer", "boolean", "string"
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
pub struct RouteSchema {
    pub path: String,
    pub method: String,
    pub parameters: Vec<ParameterSchema>,
}


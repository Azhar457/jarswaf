use crate::control_bus::state::{PublishedState, RuntimeConfig, RuleSet, VhostConfig, RateLimitPolicy, CustomRuleDef};
use crate::control_bus::commands::ControlCommand;
use crate::control_bus::ws_broadcaster::{get as get_ws, WsEvent};
use tracing::{info, error};

/// Manages configuration
pub struct ConfigManager {
    state: PublishedState,
    config_path: String,
    rules_dir: String,
}

impl ConfigManager {
    pub fn new(state: PublishedState, config_path: String, rules_dir: String) -> Self {
        Self {
            state,
            config_path,
            rules_dir,
        }
    }
    
    /// Load configuration from file
    pub fn load_config(&self) -> Result<LoadedConfig, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(&self.config_path)?;
        let config: crate::config::Config = toml::from_str(&content)?;
        
        Ok(LoadedConfig {
            runtime: RuntimeConfig {
                http_port: config.global.port_http,
                https_port: config.global.port_https,
                mode: config.global.mode.clone(),
                log_level: config.global.log_level.clone(),
                tls_mode: config.tls.mode.clone(),
                tls_cert_dir: config.tls.cert_dir.clone(),
                log_mode: config.logging.mode.clone(),
                log_db_path: config.logging.db_path.clone(),
                log_path: config.logging.log_path.clone(),
                max_body_size: config.global.max_body_size as usize,
                cleanup_interval_secs: 300,
                rate_limiter_max_entries: 100_000,
            },
            rules: RuleSet {
                custom_rules: config
                    .custom_rules
                    .into_iter()
                    .map(|r| CustomRuleDef {
                        id: r.id,
                        name: r.name,
                        condition_type: r.condition_type,
                        operator: r.operator,
                        condition_value: r.condition_value,
                        action: r.action,
                        action_value: Some(r.action_value),
                        enabled: r.enabled,
                    })
                    .collect(),
                rate_limit_policies: config
                    .rate_limit_policies
                    .into_iter()
                    .map(|p| RateLimitPolicy {
                        name: p.name,
                        limit: p.limit.parse::<u32>().unwrap_or(600),
                        burst: p.burst,
                        path: p.path,
                        description: Some(p.description),
                    })
                    .collect(),
                vhosts: config
                    .vhosts
                    .into_iter()
                    .map(|v| VhostConfig {
                        name: v.name,
                        hosts: v.hosts,
                        backend: v.backend,
                        tenant: Some(v.tenant),
                        rule_patterns: v.rules,
                        blocked_countries: v.blocked_countries,
                        geoblock_type: v.geoblock_type,
                        custom_rule_ids: v.custom_rules,
                        max_body: v.max_body,
                        rate_limit: v.rate_limit,
                        is_default: v.is_default,
                        max_conns_per_ip: v.max_conns_per_ip as u32,
                        max_concurrent_requests: v.max_concurrent_requests as u32,
                        bot_challenge_enabled: v.bot_challenge_enabled,
                        websocket_security_enabled: v.websocket_security_enabled,
                        blocked_asns: v.blocked_asns.iter().map(|n| n.to_string()).collect(),
                    })
                    .collect(),
            },
        })
    }
    
    /// Reload configuration from file
    pub async fn reload(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self.load_config() {
            Ok(loaded) => {
                self.state.publish_config(loaded.runtime);
                self.state.publish_rules(loaded.rules);
                
                get_ws().publish(WsEvent::ConfigReload {
                    success: true,
                    error: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
                
                info!("Configuration reloaded from {}", self.config_path);
                Ok(())
            }
            Err(e) => {
                error!("Failed to reload config: {}", e);
                
                get_ws().publish(WsEvent::ConfigReload {
                    success: false,
                    error: Some(e.to_string()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
                
                Err(e)
            }
        }
    }
    
    /// Start background config file watcher
    pub fn start_watcher(
        &self,
        cmd_tx: super::commands::CommandSender,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let config_path = self.config_path.clone();
        
        tokio::spawn(async move {
            let mut last_modified = std::fs::metadata(&config_path)
                .and_then(|m| m.modified())
                .unwrap_or_else(|_| std::time::SystemTime::now());
            
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Ok(metadata) = std::fs::metadata(&config_path) {
                            if let Ok(modified) = metadata.modified() {
                                if modified > last_modified {
                                    last_modified = modified;
                                    info!("Config file changed, triggering reload");
                                    let _ = cmd_tx.send(ControlCommand::ReloadConfig).await;
                                }
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        break;
                    }
                }
            }
        });
    }
}

/// Result of loading configuration
pub struct LoadedConfig {
    pub runtime: RuntimeConfig,
    pub rules: RuleSet,
}

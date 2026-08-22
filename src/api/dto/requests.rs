use crate::control_bus::state::{CustomRuleDef, VhostConfig};
use serde::Deserialize;

// === CUSTOM RULES ===

#[derive(Debug, Deserialize)]
pub struct CreateCustomRuleRequest {
    pub id: String,
    pub name: String,
    pub condition_type: String,
    pub operator: String,
    pub condition_value: String,
    pub action: String,
    pub action_value: Option<String>,
    pub enabled: bool,
}

impl CreateCustomRuleRequest {
    pub fn into_rule_def(self) -> CustomRuleDef {
        CustomRuleDef {
            id: self.id,
            name: self.name,
            condition_type: self.condition_type,
            operator: self.operator,
            condition_value: self.condition_value,
            action: self.action,
            action_value: self.action_value,
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateCustomRuleRequest {
    pub name: Option<String>,
    pub condition_type: Option<String>,
    pub operator: Option<String>,
    pub condition_value: Option<String>,
    pub action: Option<String>,
    pub action_value: Option<String>,
    pub enabled: Option<bool>,
}

impl UpdateCustomRuleRequest {
    pub fn into_rule_def(self, id: String, existing: &CustomRuleDef) -> CustomRuleDef {
        CustomRuleDef {
            id,
            name: self.name.unwrap_or_else(|| existing.name.clone()),
            condition_type: self
                .condition_type
                .unwrap_or_else(|| existing.condition_type.clone()),
            operator: self.operator.unwrap_or_else(|| existing.operator.clone()),
            condition_value: self
                .condition_value
                .unwrap_or_else(|| existing.condition_value.clone()),
            action: self.action.unwrap_or_else(|| existing.action.clone()),
            action_value: self.action_value.or(existing.action_value.clone()),
            enabled: self.enabled.unwrap_or(existing.enabled),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SetRuleEnabledRequest {
    pub enabled: bool,
}

// === VHOSTS ===

#[derive(Debug, Deserialize)]
pub struct CreateVhostRequest {
    pub name: String,
    pub hosts: Vec<String>,
    pub backend: String,
    pub tenant: Option<String>,
    pub rule_patterns: Option<Vec<String>>,
    pub blocked_countries: Option<Vec<String>>,
    pub geoblock_type: Option<String>,
    pub custom_rule_ids: Option<Vec<String>>,
    pub max_body: Option<String>,
    pub rate_limit: Option<String>,
    pub is_default: Option<bool>,
    pub max_conns_per_ip: Option<u32>,
    pub max_concurrent_requests: Option<u32>,
    pub bot_challenge_enabled: Option<bool>,
    pub websocket_security_enabled: Option<bool>,
    pub blocked_asns: Option<Vec<String>>,
}

impl CreateVhostRequest {
    pub fn into_vhost_config(self) -> VhostConfig {
        VhostConfig {
            name: self.name,
            hosts: self.hosts,
            backend: self.backend,
            tenant: self.tenant,
            rule_patterns: self.rule_patterns.unwrap_or_default(),
            blocked_countries: self.blocked_countries.unwrap_or_default(),
            geoblock_type: self
                .geoblock_type
                .unwrap_or_else(|| "Blocklist".to_string()),
            custom_rule_ids: self.custom_rule_ids.unwrap_or_default(),
            max_body: self.max_body.unwrap_or_else(|| "10MB".to_string()),
            rate_limit: self.rate_limit.unwrap_or_default(),
            is_default: self.is_default.unwrap_or(false),
            max_conns_per_ip: self.max_conns_per_ip.unwrap_or(0),
            max_concurrent_requests: self.max_concurrent_requests.unwrap_or(0),
            bot_challenge_enabled: self.bot_challenge_enabled.unwrap_or(false),
            websocket_security_enabled: self.websocket_security_enabled.unwrap_or(false),
            blocked_asns: self.blocked_asns.unwrap_or_default(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateVhostRequest {
    pub hosts: Option<Vec<String>>,
    pub backend: Option<String>,
    pub tenant: Option<String>,
    pub rule_patterns: Option<Vec<String>>,
    pub blocked_countries: Option<Vec<String>>,
    pub geoblock_type: Option<String>,
    pub custom_rule_ids: Option<Vec<String>>,
    pub max_body: Option<String>,
    pub rate_limit: Option<String>,
    pub is_default: Option<bool>,
    pub max_conns_per_ip: Option<u32>,
    pub max_concurrent_requests: Option<u32>,
    pub bot_challenge_enabled: Option<bool>,
    pub websocket_security_enabled: Option<bool>,
    pub blocked_asns: Option<Vec<String>>,
}

// === BLOCKLIST ===

#[derive(Debug, Deserialize)]
pub struct BlockIpRequest {
    pub ip: String,
    pub duration_secs: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncBlocklistRequest {
    pub ips: Vec<String>,
}

// === LOGS ===

#[derive(Debug, Deserialize)]
pub struct LogQueryParams {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub action: Option<String>,
    pub client_ip: Option<String>,
    pub vhost: Option<String>,
    pub rule_id: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
}

impl LogQueryParams {
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1).max(1)
    }

    pub fn per_page(&self) -> u32 {
        self.per_page.unwrap_or(50).clamp(1, 1000)
    }
}

// === AUTH ===

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

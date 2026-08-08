use crate::control_bus::state::{CustomRuleDef, PublishedState, RateLimitPolicy, VhostConfig};
use crate::control_bus::ws_broadcaster::{get as get_ws, WsEvent};
use tracing::info;

/// Manages the rule set
pub struct RuleEngine {
    state: PublishedState,
    /// Track rule trigger counts for dashboard
    trigger_counts: tokio::sync::Mutex<std::collections::HashMap<String, u64>>,
}

impl RuleEngine {
    pub fn new(state: PublishedState) -> Self {
        Self {
            state,
            trigger_counts: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
    
    /// Add a custom rule
    pub async fn add_custom_rule(&self, rule: CustomRuleDef) -> Result<String, super::commands::CommandError> {
        let mut rules = self.state.get_rules().as_ref().clone();
        
        // Check for duplicate ID
        if rules.get_custom_rule(&rule.id).is_some() {
            return Err(super::commands::CommandError::AlreadyExists(format!(
                "Rule '{}' already exists",
                rule.id
            )));
        }
        
        // Validate rule
        self.validate_custom_rule(&rule)?;
        
        let id = rule.id.clone();
        rules.custom_rules.push(rule);
        self.state.publish_rules(rules);
        
        get_ws().publish(WsEvent::RuleChange {
            rule_id: id.clone(),
            change: "added".to_string(),
        });
        
        info!("Custom rule '{}' added", id);
        Ok(id)
    }
    
    /// Remove a custom rule
    pub async fn remove_custom_rule(&self, id: &str) -> Result<(), super::commands::CommandError> {
        let mut rules = self.state.get_rules().as_ref().clone();
        
        let len_before = rules.custom_rules.len();
        rules.custom_rules.retain(|r| r.id != id);
        
        if rules.custom_rules.len() == len_before {
            return Err(super::commands::CommandError::NotFound(format!(
                "Rule '{}' not found",
                id
            )));
        }
        
        self.state.publish_rules(rules);
        
        get_ws().publish(WsEvent::RuleChange {
            rule_id: id.to_string(),
            change: "removed".to_string(),
        });
        
        info!("Custom rule '{}' removed", id);
        Ok(())
    }
    
    /// Update a custom rule
    pub async fn update_custom_rule(&self, id: &str, rule: CustomRuleDef) -> Result<(), super::commands::CommandError> {
        let mut rules = self.state.get_rules().as_ref().clone();
        
        let existing = rules
            .custom_rules
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| super::commands::CommandError::NotFound(format!("Rule '{}' not found", id)))?;
        
        self.validate_custom_rule(&rule)?;
        *existing = rule;
        
        self.state.publish_rules(rules);
        
        get_ws().publish(WsEvent::RuleChange {
            rule_id: id.to_string(),
            change: "updated".to_string(),
        });
        
        info!("Custom rule '{}' updated", id);
        Ok(())
    }
    
    /// Enable or disable a custom rule
    pub async fn set_rule_enabled(&self, id: &str, enabled: bool) -> Result<(), super::commands::CommandError> {
        let mut rules = self.state.get_rules().as_ref().clone();
        
        let rule = rules
            .custom_rules
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| super::commands::CommandError::NotFound(format!("Rule '{}' not found", id)))?;
        
        rule.enabled = enabled;
        
        self.state.publish_rules(rules);
        
        get_ws().publish(WsEvent::RuleChange {
            rule_id: id.to_string(),
            change: if enabled { "enabled" } else { "disabled" }.to_string(),
        });
        
        info!("Custom rule '{}' {}", id, if enabled { "enabled" } else { "disabled" });
        Ok(())
    }
    
    /// Add a rate limit policy
    pub async fn add_rate_limit_policy(&self, policy: RateLimitPolicy) -> Result<(), super::commands::CommandError> {
        let mut rules = self.state.get_rules().as_ref().clone();
        
        if rules.get_rate_limit_policy(&policy.name).is_some() {
            return Err(super::commands::CommandError::AlreadyExists(format!(
                "Rate limit policy '{}' already exists",
                policy.name
            )));
        }
        
        rules.rate_limit_policies.push(policy);
        self.state.publish_rules(rules);
        
        info!("Rate limit policy added");
        Ok(())
    }
    
    /// Remove a rate limit policy
    pub async fn remove_rate_limit_policy(&self, name: &str) -> Result<(), super::commands::CommandError> {
        let mut rules = self.state.get_rules().as_ref().clone();
        
        let len_before = rules.rate_limit_policies.len();
        rules.rate_limit_policies.retain(|p| p.name != name);
        
        if rules.rate_limit_policies.len() == len_before {
            return Err(super::commands::CommandError::NotFound(format!(
                "Rate limit policy '{}' not found",
                name
            )));
        }
        
        self.state.publish_rules(rules);
        info!("Rate limit policy '{}' removed", name);
        Ok(())
    }
    
    /// Add a vhost
    pub async fn add_vhost(&self, vhost: VhostConfig) -> Result<(), super::commands::CommandError> {
        let mut rules = self.state.get_rules().as_ref().clone();
        
        if rules.vhosts.iter().any(|v| v.name == vhost.name) {
            return Err(super::commands::CommandError::AlreadyExists(format!(
                "Vhost '{}' already exists",
                vhost.name
            )));
        }
        
        // Validate backend address
        if vhost.backend.parse::<std::net::SocketAddr>().is_err() {
            return Err(super::commands::CommandError::Validation(format!(
                "Invalid backend address: {}",
                vhost.backend
            )));
        }
        
        rules.vhosts.push(vhost);
        self.state.publish_rules(rules);
        
        info!("Vhost added");
        Ok(())
    }
    
    /// Update a vhost
    pub async fn update_vhost(&self, name: &str, vhost: VhostConfig) -> Result<(), super::commands::CommandError> {
        let mut rules = self.state.get_rules().as_ref().clone();
        
        let existing = rules
            .vhosts
            .iter_mut()
            .find(|v| v.name == name)
            .ok_or_else(|| super::commands::CommandError::NotFound(format!("Vhost '{}' not found", name)))?;
        
        *existing = vhost;
        self.state.publish_rules(rules);
        
        info!("Vhost '{}' updated", name);
        Ok(())
    }
    
    /// Remove a vhost
    pub async fn remove_vhost(&self, name: &str) -> Result<(), super::commands::CommandError> {
        let mut rules = self.state.get_rules().as_ref().clone();
        
        let len_before = rules.vhosts.len();
        rules.vhosts.retain(|v| v.name != name);
        
        if rules.vhosts.len() == len_before {
            return Err(super::commands::CommandError::NotFound(format!(
                "Vhost '{}' not found",
                name
            )));
        }
        
        self.state.publish_rules(rules);
        info!("Vhost '{}' removed", name);
        Ok(())
    }
    
    /// Record a rule trigger for metrics
    pub async fn record_trigger(&self, rule_id: &str) {
        let mut counts = self.trigger_counts.lock().await;
        *counts.entry(rule_id.to_string()).or_insert(0) += 1;
    }
    
    /// Get top triggered rules for dashboard
    pub async fn top_triggered_rules(&self, limit: usize) -> Vec<crate::control_bus::state::RuleTriggerCount> {
        let counts = self.trigger_counts.lock().await;
        let mut sorted: Vec<_> = counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.truncate(limit);
        sorted
            .into_iter()
            .map(|(id, count)| crate::control_bus::state::RuleTriggerCount {
                rule_id: id.clone(),
                count: *count,
            })
            .collect()
    }
    
    /// Load rules from YAML directory
    pub async fn load_from_directory(&self, dir: &std::path::Path) -> Result<usize, Box<dyn std::error::Error>> {
        let mut rules = self.state.get_rules().as_ref().clone();
        let mut count = 0;
        
        // Load custom rules from YAML files
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|e| e.to_str()) == Some("yaml")
                || path.extension().and_then(|e| e.to_str()) == Some("yml")
            {
                let content = std::fs::read_to_string(&path)?;
                let rule: CustomRuleDef = serde_yaml_ng::from_str(&content)?;
                rules.custom_rules.push(rule);
                count += 1;
            }
        }
        
        self.state.publish_rules(rules);
        info!("Loaded {} custom rules from {:?}", count, dir);
        Ok(count)
    }
    
    fn validate_custom_rule(&self, rule: &CustomRuleDef) -> Result<(), super::commands::CommandError> {
        if rule.id.is_empty() {
            return Err(super::commands::CommandError::Validation("Rule ID cannot be empty".to_string()));
        }
        if rule.name.is_empty() {
            return Err(super::commands::CommandError::Validation("Rule name cannot be empty".to_string()));
        }
        
        let valid_operators = ["contains", "equals", "starts_with", "ends_with", "regex", "not_contains"];
        if !valid_operators.contains(&rule.operator.as_str()) {
            return Err(super::commands::CommandError::Validation(format!(
                "Invalid operator '{}'. Valid: {:?}",
                rule.operator, valid_operators
            )));
        }
        
        let valid_actions = ["block", "redirect", "log", "challenge"];
        if !valid_actions.contains(&rule.action.as_str()) {
            return Err(super::commands::CommandError::Validation(format!(
                "Invalid action '{}'. Valid: {:?}",
                rule.action, valid_actions
            )));
        }
        
        Ok(())
    }
}

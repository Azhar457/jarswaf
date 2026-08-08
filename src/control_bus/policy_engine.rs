use crate::control_bus::state::PublishedState;
use crate::data_bus::events::DataEvent;

/// Policy engine — evaluates aggregate behavior and makes decisions
/// 
/// This is where cross-request analysis happens:
/// - Anomaly threshold evaluation
/// - Escalation decisions
/// - Automatic blocking based on score accumulation
pub struct PolicyEngine {
    state: PublishedState,
    anomaly_threshold: f64,
    scoring_mode: String,
}

impl PolicyEngine {
    pub fn new(state: PublishedState, anomaly_threshold: f64, scoring_mode: String) -> Self {
        Self {
            state,
            anomaly_threshold,
            scoring_mode,
        }
    }
    
    /// Process a data event and potentially take action
    /// Returns commands that should be executed
    pub async fn evaluate(&self, event: &DataEvent) -> Vec<crate::control_bus::commands::ControlCommand> {
        let mut commands = Vec::new();
        
        match event {
            DataEvent::RequestBlocked {
                client_ip,
                ..
            } => {
                if self.anomaly_threshold > 0.0 {
                    tracing::debug!(
                        "Blocked request from {} (auto-block policy applies)",
                        client_ip
                    );
                }
            }
            
            DataEvent::RateLimitExceeded {
                client_ip,
                ..
            } => {
                commands.push(crate::control_bus::commands::ControlCommand::BlockIp {
                    ip: *client_ip,
                    duration: std::time::Duration::from_secs(300), // 5 min auto-block
                    reason: "Rate limit exceeded — automatic block".to_string(),
                    source: crate::control_bus::state::BlockSource::RateLimit,
                });
            }
            
            _ => {}
        }
        
        commands
    }
}

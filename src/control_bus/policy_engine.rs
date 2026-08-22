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

    pub fn state(&self) -> &PublishedState {
        &self.state
    }

    pub fn scoring_mode(&self) -> &str {
        &self.scoring_mode
    }

    pub fn anomaly_threshold(&self) -> f64 {
        self.anomaly_threshold
    }

    /// Process a data event and potentially take action
    /// Returns commands that should be executed
    pub async fn evaluate(
        &self,
        event: &DataEvent,
    ) -> Vec<crate::control_bus::commands::ControlCommand> {
        let mut commands = Vec::new();

        match event {
            DataEvent::RequestBlocked { client_ip, .. } => {
                if self.anomaly_threshold > 0.0 {
                    tracing::debug!(
                        "Blocked request from {} (auto-block policy applies, mode={})",
                        client_ip,
                        self.scoring_mode
                    );
                    if self.scoring_mode == "immediate" && !self.state.is_ip_blocked(client_ip) {
                        commands.push(crate::control_bus::commands::ControlCommand::BlockIp {
                            ip: *client_ip,
                            duration: std::time::Duration::from_secs(600),
                            reason: "Immediate scoring block on attack".to_string(),
                            source: crate::control_bus::state::BlockSource::Manual,
                        });
                    }
                }
            }

            DataEvent::RateLimitExceeded { client_ip, .. } => {
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

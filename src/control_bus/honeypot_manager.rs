use tracing::info;

/// Manages honeypot listeners
pub struct HoneypotManager {
    enabled: bool,
    upstream_addr: String,
}

impl HoneypotManager {
    pub fn new(enabled: bool, upstream_addr: String) -> Self {
        Self {
            enabled,
            upstream_addr,
        }
    }

    /// Start honeypot listeners
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(());
        }

        info!(
            "Honeypot listeners starting (upstream: {})",
            self.upstream_addr
        );
        Ok(())
    }
}

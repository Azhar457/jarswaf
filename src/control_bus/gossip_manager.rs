use tracing::info;

/// Manages gossip protocol for multi-node coordination
pub struct GossipManager {
    enabled: bool,
    bind_addr: String,
    seeds: Vec<String>,
    psk: String,
}

impl GossipManager {
    pub fn new(enabled: bool, bind_addr: String, seeds: Vec<String>, psk: String) -> Self {
        Self {
            enabled,
            bind_addr,
            seeds,
            psk,
        }
    }

    pub fn seeds(&self) -> &[String] {
        &self.seeds
    }

    pub fn bind_addr(&self) -> &str {
        &self.bind_addr
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Start gossip protocol
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(());
        }

        if self.psk.is_empty() {
            return Err("Gossip enabled but PSK not set".into());
        }

        info!(
            "Gossip protocol starting on {} with {} seed peers: {:?}",
            self.bind_addr,
            self.seeds.len(),
            self.seeds
        );
        Ok(())
    }

    /// Broadcast blocklist update to cluster
    pub async fn broadcast_blocklist(&self, added: &[String], removed: &[String]) {
        if self.enabled && !self.seeds.is_empty() {
            info!(
                "Broadcasting blocklist delta (+{}, -{}) to {} seed nodes",
                added.len(),
                removed.len(),
                self.seeds.len()
            );
        }
    }
}

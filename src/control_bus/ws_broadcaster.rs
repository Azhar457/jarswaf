use serde::Serialize;
use tokio::sync::broadcast;
use tracing::debug;

/// WebSocket event types sent to frontend
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum WsEvent {
    Log {
        timestamp: String,
        request_id: String,
        client_ip: String,
        method: String,
        path: String,
        action: String,
        rule_id: Option<String>,
        score: f64,
        latency_ms: f64,
        vhost: String,
    },
    Metrics {
        timestamp: String,
        requests_per_sec: f64,
        blocked_per_sec: f64,
        active_connections: u64,
        cpu_percent: f32,
        ram_percent: f32,
        top_blocked_ips: Vec<IpBlockCount>,
        top_triggered_rules: Vec<RuleTriggerCount>,
    },
    BlocklistUpdate {
        added: Vec<String>,
        removed: Vec<String>,
    },
    RuleChange {
        rule_id: String,
        change: String,
    },
    Alert {
        level: String,
        message: String,
        timestamp: String,
        source: String,
    },
    ConfigReload {
        success: bool,
        error: Option<String>,
        timestamp: String,
    },
}

use crate::control_bus::state::{IpBlockCount, RuleTriggerCount};

/// Broadcaster that sends events to all connected WebSocket clients
pub struct WsBroadcaster {
    tx: broadcast::Sender<WsEvent>,
}

impl WsBroadcaster {
    pub fn new(buffer: usize) -> Self {
        let (tx, _) = broadcast::channel(buffer);
        Self { tx }
    }
    
    /// Subscribe to events (call this for each WebSocket connection)
    pub fn subscribe(&self) -> broadcast::Receiver<WsEvent> {
        self.tx.subscribe()
    }
    
    /// Publish an event to all subscribers
    pub fn publish(&self, event: WsEvent) {
        // Best-effort — if no subscribers or lagged, drop
        match self.tx.send(event) {
            Ok(subscribers) => debug!("WS event sent to {} subscribers", subscribers),
            Err(broadcast::error::SendError(_)) => {
                // No subscribers — normal when no dashboard connected
            }
        }
    }
    
    /// Number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

/// Global broadcaster instance
static BROADCASTER: std::sync::OnceLock<WsBroadcaster> = std::sync::OnceLock::new();

/// Initialize global broadcaster
pub fn init() -> &'static WsBroadcaster {
    BROADCASTER.get_or_init(|| WsBroadcaster::new(1000))
}

/// Get reference to global broadcaster
pub fn get() -> &'static WsBroadcaster {
    BROADCASTER.get().expect("WS broadcaster not initialized")
}

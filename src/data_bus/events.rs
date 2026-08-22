use crate::data_bus::context::{RuleMatch, Verdict};

/// Snapshot of a verdict for event serialization
#[derive(Debug, Clone, serde::Serialize)]
pub enum VerdictSnapshot {
    Undecided,
    Allow,
    Block { reason: String, action: String },
    Challenge { challenge_type: String },
    Redirect { url: String },
}

impl From<&Verdict> for VerdictSnapshot {
    fn from(v: &Verdict) -> Self {
        match v {
            Verdict::Undecided => VerdictSnapshot::Undecided,
            Verdict::Allow => VerdictSnapshot::Allow,
            Verdict::Block { reason, action } => VerdictSnapshot::Block {
                reason: format!("{:?}", reason),
                action: format!("{:?}", action),
            },
            Verdict::Challenge { challenge_type } => VerdictSnapshot::Challenge {
                challenge_type: challenge_type.clone(),
            },
            Verdict::Redirect { url } => VerdictSnapshot::Redirect { url: url.clone() },
        }
    }
}

/// Snapshot of a rule match for event serialization
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleMatchSnapshot {
    pub inspector_name: String,
    pub rule_id: String,
    pub score_delta: f64,
    pub details: String,
}

impl From<&RuleMatch> for RuleMatchSnapshot {
    fn from(r: &RuleMatch) -> Self {
        Self {
            inspector_name: r.inspector_name.clone(),
            rule_id: r.rule_id.clone(),
            score_delta: r.score_delta,
            details: r.details.clone(),
        }
    }
}

/// Events emitted by data bus, consumed by control bus
#[derive(Debug, Clone)]
pub enum DataEvent {
    RequestInspected {
        request_id: uuid::Uuid,
        client_ip: std::net::IpAddr,
        vhost: String,
        verdict: VerdictSnapshot,
        score: f64,
        matched_rules: Vec<RuleMatchSnapshot>,
        latency_us: u64,
    },
    RequestBlocked {
        request_id: uuid::Uuid,
        client_ip: std::net::IpAddr,
        reason: String,
        rule_id: String,
    },
    RequestForwarded {
        request_id: uuid::Uuid,
        client_ip: std::net::IpAddr,
        backend: String,
        status_code: u16,
        latency_us: u64,
    },
    BackendError {
        request_id: uuid::Uuid,
        backend: String,
        error: String,
    },
    RateLimitExceeded {
        client_ip: std::net::IpAddr,
        limit: u32,
        window_secs: u64,
    },
}

/// Channel for sending events from data bus to control bus
pub type EventSender = tokio::sync::mpsc::Sender<DataEvent>;
pub type EventReceiver = tokio::sync::mpsc::Receiver<DataEvent>;

/// Create a new event channel
pub fn event_channel(buffer: usize) -> (EventSender, EventReceiver) {
    tokio::sync::mpsc::channel(buffer)
}

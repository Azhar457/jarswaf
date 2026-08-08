use crate::data_bus::context::Verdict;

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: String,
    pub score: f64,
}

#[derive(Debug, Clone)]
pub enum DataEvent {
    RequestInspected {
        request_id: uuid::Uuid,
        client_ip: std::net::IpAddr,
        vhost: String,
        verdict: Verdict,
        score: f64,
        matched_rules: Vec<RuleMatch>,
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

pub type EventSender = tokio::sync::mpsc::Sender<DataEvent>;
pub type EventReceiver = tokio::sync::mpsc::Receiver<DataEvent>;

pub fn event_channel(buffer: usize) -> (EventSender, EventReceiver) {
    tokio::sync::mpsc::channel(buffer)
}

use std::collections::{HashMap, HashSet};
use std::time::Instant;
use bytes::Bytes;
use hyper::HeaderMap;

#[derive(Debug, Clone, Default)]
pub enum Verdict {
    #[default]
    Undecided,
    Allow,
    Block {
        reason: String,
        action: String,
    },
    Challenge,
    Redirect {
        url: String,
    },
}

pub struct InspectionContext {
    pub request_id: uuid::Uuid,
    pub client_ip: std::net::IpAddr,
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
    pub vhost: String,
    pub timestamp: Instant,
    
    // Inspection state
    pub verdict: Verdict,
    pub score: f64,
    pub matched_rules: Vec<String>,
    pub tags: HashSet<String>,
    pub metadata: HashMap<String, String>,
}

impl InspectionContext {
    pub fn new(
        client_ip: std::net::IpAddr,
        method: String,
        path: String,
        query: String,
        headers: HeaderMap,
        body: Option<Bytes>,
        vhost: String,
    ) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4(),
            client_ip,
            method,
            path,
            query,
            headers,
            body,
            vhost,
            timestamp: Instant::now(),
            verdict: Verdict::Undecided,
            score: 0.0,
            matched_rules: Vec::new(),
            tags: HashSet::new(),
            metadata: HashMap::new(),
        }
    }
}

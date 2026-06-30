use crate::{config, logging, types::AgentInfo};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct ControllerState {
    pub tx: broadcast::Sender<logging::WafLogEntry>,
    pub db_path: String,
    pub logging_enabled: Arc<AtomicBool>,
    pub log_size_limit_mb: Arc<AtomicU64>,
    pub config_path: String,
    pub agent_registry: Arc<std::sync::RwLock<std::collections::HashMap<String, AgentInfo>>>,
    pub total_requests: Arc<AtomicU64>,
    pub blocked: Arc<AtomicU64>,
    pub rate_limited: Arc<AtomicU64>,
    pub config_tx: broadcast::Sender<config::Config>,
    pub config_lock: Arc<tokio::sync::Mutex<()>>,
}

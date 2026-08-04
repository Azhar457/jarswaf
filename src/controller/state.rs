use crate::{config, logging, types::AgentInfo};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct ControllerState {
    pub tx: broadcast::Sender<logging::WafLogEntry>,
    pub block_tx: broadcast::Sender<crate::controller::BlockCommand>,
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
    /// Server-issued session tokens → Unix expiry timestamp. Logged-in clients receive a
    /// random session id (not the admin password); `auth_middleware` consults this store
    /// first and only falls back to the password-hash path for legacy clients/dashboard.
    /// A session is revoked by removing its entry (or by password change, which clears all).
    pub sessions: Arc<std::sync::RwLock<std::collections::HashMap<String, i64>>>,
}

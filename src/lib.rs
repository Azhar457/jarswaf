pub mod agent;
pub mod config;
pub mod controller;
pub mod logging;
pub mod pingora_proxy;
pub mod proxy;
pub mod rules;
pub mod tls;
pub mod types;
pub mod vhost;
pub mod xdp;

pub use types::is_local_ip;
use once_cell::sync::Lazy;
use std::sync::Arc;

// Global XDP Manager
pub static XDP_MANAGER: Lazy<Arc<tokio::sync::Mutex<xdp::XdpManager>>> =
    Lazy::new(|| Arc::new(tokio::sync::Mutex::new(xdp::XdpManager::new())));

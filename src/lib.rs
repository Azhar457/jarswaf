pub mod agent;
pub mod config;
pub mod controller;
pub mod logging;
pub mod proxy_engine;
pub mod proxy;
pub mod rules;
pub mod tls;
pub mod types;
pub mod vhost;
pub mod xdp;

use once_cell::sync::Lazy;
use std::sync::Arc;
pub use types::is_local_ip;

// Global XDP Manager
pub static XDP_MANAGER: Lazy<Arc<tokio::sync::Mutex<xdp::XdpManager>>> =
    Lazy::new(|| Arc::new(tokio::sync::Mutex::new(xdp::XdpManager::new())));

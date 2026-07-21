pub mod agent;
pub mod config;
pub mod controller;
pub mod dlp;
pub mod logging;
pub mod metrics;
pub mod proxy;
pub mod proxy_engine;
pub mod rules;
pub mod tls;
pub mod types;
pub mod vhost;
pub mod webhook;
pub mod xdp;
pub mod gossip;
pub mod wasm;
pub mod compliance;
pub mod rasp;
pub mod grpc;

use once_cell::sync::Lazy;
use std::sync::Arc;
use std::net::IpAddr;
use std::time::Instant;
use dashmap::DashMap;

pub use types::is_local_ip;

pub static SUSPICIOUS_IPS: Lazy<Arc<DashMap<IpAddr, Instant>>> =
    Lazy::new(|| Arc::new(DashMap::new()));

// Global XDP Manager
pub static XDP_MANAGER: Lazy<Arc<tokio::sync::Mutex<xdp::XdpManager>>> =
    Lazy::new(|| Arc::new(tokio::sync::Mutex::new(xdp::XdpManager::new())));

// Global Gossip Node
pub static GOSSIP_MANAGER: Lazy<Arc<tokio::sync::Mutex<Option<gossip::GossipNode>>>> =
    Lazy::new(|| Arc::new(tokio::sync::Mutex::new(None)));

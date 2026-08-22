pub mod agent;
pub mod api;
pub mod compliance;
pub mod config;
pub mod control_bus;
pub mod controller;
pub mod data_bus;
pub mod dlp;
pub mod gossip;
pub mod grpc;
pub mod honeypot;
pub mod kernel;
pub mod logging;
pub mod metrics;
pub mod proxy;
pub mod proxy_engine;
pub mod rasp;
pub mod rule_engine;
pub mod rules;
pub mod storage;
pub mod tls;
pub mod types;
pub mod utils;
pub mod vhost;
pub mod wasm;
pub mod webhook;
pub mod xdp;

use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

pub use types::is_local_ip;

pub static SUSPICIOUS_IPS: Lazy<Arc<DashMap<IpAddr, Instant>>> =
    Lazy::new(|| Arc::new(DashMap::new()));

// Global Kernel Abstraction Interface (Layer 1) — OPTIONAL: init by control bus.
// Unlike XDP_MANAGER (legacy, held in a lib-level static Mutex), this is only
// instantiated once control_bus::start_control_bus() runs, so non-Linux builds
// and pure-controller modes skip eBPF entirely. Set by kernel::init().
pub static KERNEL_INTERFACE: Lazy<Option<&'static kernel::KernelInterface>> =
    Lazy::new(kernel::init_if_present);

// Global XDP Manager
pub static XDP_MANAGER: Lazy<Arc<tokio::sync::Mutex<xdp::XdpManager>>> =
    Lazy::new(|| Arc::new(tokio::sync::Mutex::new(xdp::XdpManager::new())));

// Global Gossip Node
pub static GOSSIP_MANAGER: Lazy<Arc<tokio::sync::Mutex<Option<gossip::GossipNode>>>> =
    Lazy::new(|| Arc::new(tokio::sync::Mutex::new(None)));

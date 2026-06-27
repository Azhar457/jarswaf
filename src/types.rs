//! Shared types used by both the Agent and Controller modes of Aegis WAF.

/// A service discovered on the host via Docker or OS-level port scanning.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct DiscoveredService {
    pub name: String,
    pub port: u16,
    pub protocol: String,
    pub source: String, // "Docker" or "System"
}

/// System metrics payload sent by an Agent to the Controller.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AgentMetrics {
    pub hostname: String,
    pub ip: String,
    pub os: String,
    pub cpu: f32,
    pub ram: f32,
    pub disk: f32,
    pub uptime: u64,
    pub network_interfaces: Vec<String>,
    pub discovered_services: Vec<DiscoveredService>,
}

/// Information about a registered agent, maintained by the Controller.
#[derive(serde::Serialize, Clone, Debug)]
pub struct AgentInfo {
    pub hostname: String,
    pub ip: String,
    pub os: String,
    pub cpu: f32,
    pub ram: f32,
    pub disk: f32,
    pub uptime: String,
    pub status: String,
    pub network_interfaces: Vec<String>,
    pub discovered_services: Vec<DiscoveredService>,
    #[serde(skip)]
    pub last_seen: std::time::Instant,
}

/// Format an uptime value (in seconds) into a human-readable string.
pub fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    }
}

/// Check if an IP address is a local/private address.
pub fn is_local_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_private(),
        std::net::IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || (ipv6.segments()[0] & 0xff00) == 0xfd00
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

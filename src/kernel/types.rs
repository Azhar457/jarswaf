/// MUST match jarswaf-ebpf/src/main.rs ExecveEvent layout
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RaspEvent {
    pub pid: u32,
    pub uid: u32,
    pub command: [u8; 128],
}

impl Default for RaspEvent {
    fn default() -> Self {
        Self {
            pid: 0,
            uid: 0,
            command: [0u8; 128],
        }
    }
}

impl RaspEvent {
    pub fn command_str(&self) -> &str {
        let end = self.command.iter().position(|&b| b == 0).unwrap_or(128);
        std::str::from_utf8(&self.command[..end]).unwrap_or("<invalid utf8>")
    }
}

/// Result of a batch operation
#[derive(Debug, Clone)]
pub struct BatchResult {
    pub inserted: usize,
    pub failed: usize,
}

impl BatchResult {
    pub fn all_success(&self) -> bool {
        self.failed == 0
    }

    pub fn total(&self) -> usize {
        self.inserted + self.failed
    }
}

/// IP address wrapper that handles v4/v6 and byte order
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpKey {
    V4(u32), // Network byte order
    V6([u8; 16]),
}

impl From<std::net::Ipv4Addr> for IpKey {
    fn from(addr: std::net::Ipv4Addr) -> Self {
        IpKey::V4(u32::from(addr).to_be())
    }
}

impl From<std::net::Ipv6Addr> for IpKey {
    fn from(addr: std::net::Ipv6Addr) -> Self {
        IpKey::V6(addr.octets())
    }
}

impl From<std::net::IpAddr> for IpKey {
    fn from(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(v4) => IpKey::from(v4),
            std::net::IpAddr::V6(v6) => IpKey::from(v6),
        }
    }
}

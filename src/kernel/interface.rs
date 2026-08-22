use arc_swap::ArcSwap;
use std::collections::HashSet as StdHashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error};

use super::error::{KernelError, KernelResult};
use super::rasp::RaspSubsystem;
use super::tc::TcSubsystem;
use super::types::{BatchResult, IpKey, RaspEvent};
use super::xdp::XdpSubsystem;

#[derive(Debug, Clone, Default)]
pub struct BlocklistState {
    pub blocked_ips: StdHashSet<IpAddr>,
}

impl BlocklistState {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.contains(ip)
    }
}

#[derive(Debug, Default, Clone)]
struct PendingOps {
    blocks: StdHashSet<IpKey>,
    unblocks: StdHashSet<IpKey>,
}

pub struct BpfMapInterface {
    #[cfg(target_os = "linux")]
    pub(crate) bpf: Arc<tokio::sync::Mutex<Option<aya::Ebpf>>>,
    pub blocklist_state: ArcSwap<BlocklistState>,
    pending: Mutex<PendingOps>,
    total_blocks: std::sync::atomic::AtomicU64,
    total_unblocks: std::sync::atomic::AtomicU64,
    total_flushes: std::sync::atomic::AtomicU64,
}

impl BpfMapInterface {
    #[cfg(target_os = "linux")]
    pub fn new(bpf: Arc<tokio::sync::Mutex<Option<aya::Ebpf>>>) -> Self {
        Self {
            bpf,
            blocklist_state: ArcSwap::from_pointee(BlocklistState::default()),
            pending: Mutex::new(PendingOps::default()),
            total_blocks: std::sync::atomic::AtomicU64::new(0),
            total_unblocks: std::sync::atomic::AtomicU64::new(0),
            total_flushes: std::sync::atomic::AtomicU64::new(0),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Self {
        Self {
            blocklist_state: ArcSwap::from_pointee(BlocklistState::default()),
            pending: Mutex::new(PendingOps::default()),
            total_blocks: std::sync::atomic::AtomicU64::new(0),
            total_unblocks: std::sync::atomic::AtomicU64::new(0),
            total_flushes: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn is_loaded(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            if let Ok(lock) = self.bpf.try_lock() {
                lock.is_some()
            } else {
                false
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    pub async fn queue_block(&self, ip: IpAddr) {
        let key = IpKey::from(ip);
        let mut pending = self.pending.lock().await;
        pending.unblocks.remove(&key);
        pending.blocks.insert(key);
        debug!("Queued block for IP: {}", ip);
    }

    pub async fn queue_unblock(&self, ip: IpAddr) {
        let key = IpKey::from(ip);
        let mut pending = self.pending.lock().await;
        pending.blocks.remove(&key);
        pending.unblocks.insert(key);
        debug!("Queued unblock for IP: {}", ip);
    }

    pub async fn has_pending(&self) -> bool {
        let pending = self.pending.lock().await;
        !pending.blocks.is_empty() || !pending.unblocks.is_empty()
    }

    pub async fn flush(&self) -> KernelResult<BatchResult> {
        let mut pending = self.pending.lock().await;
        if pending.blocks.is_empty() && pending.unblocks.is_empty() {
            return Ok(BatchResult {
                inserted: 0,
                failed: 0,
            });
        }

        let ops = pending.clone();
        pending.blocks.clear();
        pending.unblocks.clear();
        drop(pending); // Release pending lock early

        let mut inserted = 0;
        let mut failed = 0;

        #[cfg(target_os = "linux")]
        {
            let mut lock = self.bpf.lock().await;
            if let Some(ref mut bpf) = *lock {
                for key in &ops.blocks {
                    match key {
                        IpKey::V4(be) => {
                            let blocklist_v4: Option<aya::maps::HashMap<_, u32, u8>> = bpf
                                .map_mut("BLOCKLIST")
                                .and_then(|m| aya::maps::HashMap::try_from(m).ok());
                            if let Some(mut map) = blocklist_v4 {
                                match map.insert(*be, 1, 0) {
                                    Ok(_) => inserted += 1,
                                    Err(e) => {
                                        error!("eBPF map insert v4 failed: {:?}", e);
                                        failed += 1;
                                    }
                                }
                            } else {
                                failed += 1;
                            }
                        }
                        IpKey::V6(octets) => {
                            let blocklist_v6: Option<aya::maps::HashMap<_, [u8; 16], u8>> = bpf
                                .map_mut("BLOCKLIST_V6")
                                .and_then(|m| aya::maps::HashMap::try_from(m).ok());
                            if let Some(mut map) = blocklist_v6 {
                                match map.insert(*octets, 1, 0) {
                                    Ok(_) => inserted += 1,
                                    Err(e) => {
                                        error!("eBPF map insert v6 failed: {:?}", e);
                                        failed += 1;
                                    }
                                }
                            } else {
                                failed += 1;
                            }
                        }
                    }
                }

                // Flush Unblocks
                for key in &ops.unblocks {
                    match key {
                        IpKey::V4(be) => {
                            let blocklist_v4: Option<aya::maps::HashMap<_, u32, u8>> = bpf
                                .map_mut("BLOCKLIST")
                                .and_then(|m| aya::maps::HashMap::try_from(m).ok());
                            if let Some(mut map) = blocklist_v4 {
                                let _ = map.remove(be);
                                inserted += 1;
                            } else {
                                failed += 1;
                            }
                        }
                        IpKey::V6(octets) => {
                            let blocklist_v6: Option<aya::maps::HashMap<_, [u8; 16], u8>> = bpf
                                .map_mut("BLOCKLIST_V6")
                                .and_then(|m| aya::maps::HashMap::try_from(m).ok());
                            if let Some(mut map) = blocklist_v6 {
                                let _ = map.remove(octets);
                                inserted += 1;
                            } else {
                                failed += 1;
                            }
                        }
                    }
                }
            } else {
                return Err(KernelError::NotLoaded);
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            inserted += ops.blocks.len() + ops.unblocks.len();
        }

        // Update published state for lock-free reads
        let mut current = self.blocklist_state.load().as_ref().clone();
        for ip_key in &ops.blocks {
            match ip_key {
                IpKey::V4(be) => {
                    let ip = IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(*be)));
                    current.blocked_ips.insert(ip);
                }
                IpKey::V6(octets) => {
                    current
                        .blocked_ips
                        .insert(IpAddr::V6(std::net::Ipv6Addr::from(*octets)));
                }
            }
        }
        for ip_key in &ops.unblocks {
            match ip_key {
                IpKey::V4(be) => {
                    let ip = IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(*be)));
                    current.blocked_ips.remove(&ip);
                }
                IpKey::V6(octets) => {
                    current
                        .blocked_ips
                        .remove(&IpAddr::V6(std::net::Ipv6Addr::from(*octets)));
                }
            }
        }
        self.blocklist_state.store(Arc::new(current));

        self.total_blocks.fetch_add(
            ops.blocks.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.total_unblocks.fetch_add(
            ops.unblocks.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.total_flushes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Ok(BatchResult { inserted, failed })
    }

    pub fn poll_rasp_events(&self, _buf: &mut [RaspEvent]) -> KernelResult<usize> {
        Ok(0)
    }

    pub fn stats(&self) -> KernelStats {
        KernelStats {
            total_blocks: self.total_blocks.load(std::sync::atomic::Ordering::Relaxed),
            total_unblocks: self
                .total_unblocks
                .load(std::sync::atomic::Ordering::Relaxed),
            total_flushes: self
                .total_flushes
                .load(std::sync::atomic::Ordering::Relaxed),
            pending_blocks: 0,
            pending_unblocks: 0,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KernelStats {
    pub total_blocks: u64,
    pub total_unblocks: u64,
    pub total_flushes: u64,
    pub pending_blocks: usize,
    pub pending_unblocks: usize,
}

pub struct KernelInterface {
    pub maps: BpfMapInterface,
    pub xdp: tokio::sync::Mutex<XdpSubsystem>,
    pub tc: tokio::sync::Mutex<TcSubsystem>,
    pub rasp: tokio::sync::Mutex<RaspSubsystem>,
}

impl KernelInterface {
    #[cfg(target_os = "linux")]
    pub fn new() -> Self {
        let bpf = Arc::new(tokio::sync::Mutex::new(None));
        Self {
            maps: BpfMapInterface::new(bpf.clone()),
            xdp: tokio::sync::Mutex::new(XdpSubsystem::new(bpf.clone())),
            tc: tokio::sync::Mutex::new(TcSubsystem::new(bpf.clone())),
            rasp: tokio::sync::Mutex::new(RaspSubsystem::new(bpf)),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Self {
        Self {
            maps: BpfMapInterface::new(),
            xdp: tokio::sync::Mutex::new(XdpSubsystem::new()),
            tc: tokio::sync::Mutex::new(TcSubsystem::new()),
            rasp: tokio::sync::Mutex::new(RaspSubsystem::new()),
        }
    }
}

impl Default for KernelInterface {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelInterface {
    pub async fn attach_xdp(&self, interface: &str) -> KernelResult<()> {
        let xdp = self.xdp.lock().await;
        xdp.attach(interface).await.map_err(KernelError::LoadFailed)
    }

    pub async fn attach_rasp(
        &self,
        rasp_tx: Option<tokio::sync::mpsc::Sender<()>>,
    ) -> KernelResult<()> {
        let rasp = self.rasp.lock().await;
        rasp.attach(rasp_tx).await.map_err(KernelError::LoadFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_key_from_ipv4() {
        let ip: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();
        let key = IpKey::from(ip);
        match key {
            IpKey::V4(be) => {
                assert_eq!(be, u32::from(ip).to_be());
            }
            _ => panic!("Expected V4"),
        }
    }

    #[test]
    fn test_ip_key_from_ipv6() {
        let ip: std::net::Ipv6Addr = "::1".parse().unwrap();
        let key = IpKey::from(ip);
        match key {
            IpKey::V6(octets) => {
                assert_eq!(octets[15], 1);
            }
            _ => panic!("Expected V6"),
        }
    }

    #[test]
    fn test_batch_result() {
        let result = BatchResult {
            inserted: 10,
            failed: 2,
        };
        assert!(!result.all_success());
        assert_eq!(result.total(), 12);
    }

    #[tokio::test]
    async fn test_queue_and_has_pending() {
        #[cfg(target_os = "linux")]
        let iface = BpfMapInterface::new(Arc::new(tokio::sync::Mutex::new(None)));
        #[cfg(not(target_os = "linux"))]
        let iface = BpfMapInterface::new();

        assert!(!iface.has_pending().await);

        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        iface.queue_block(ip).await;
        assert!(iface.has_pending().await);

        let _ = iface.flush().await;
        assert!(!iface.has_pending().await);
    }

    #[test]
    fn test_rasp_event_command_str() {
        let mut event = RaspEvent::default();
        let cmd = b"/bin/bash\0";
        event.command[..cmd.len()].copy_from_slice(cmd);
        assert_eq!(event.command_str(), "/bin/bash");
    }

    #[test]
    fn test_rasp_event_invalid_command() {
        let mut event = RaspEvent::default();
        event.command[0] = 0xC3;
        event.command[1] = 0x28; // Invalid UTF-8 sequence
        assert_eq!(event.command_str(), "<invalid utf8>");
    }
}

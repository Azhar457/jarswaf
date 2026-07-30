use std::net::Ipv4Addr;
use tracing::warn;

#[cfg(target_os = "linux")]
use tracing::info;

#[cfg(target_os = "linux")]
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpMode},
    Ebpf,
};

pub struct XdpManager {
    #[cfg(target_os = "linux")]
    bpf: Option<Ebpf>,
}

impl Default for XdpManager {
    fn default() -> Self {
        Self::new()
    }
}

impl XdpManager {
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            let candidate_paths = [
                "/app/jarswaf-ebpf",
                "jarswaf-ebpf/target/bpfel-unknown-none/release/jarswaf-ebpf",
                "target/bpfel-unknown-none/release/jarswaf-ebpf",
                "/opt/jarswaf/jarswaf-ebpf",
            ];

            let mut bpf = None;
            for path in &candidate_paths {
                if std::path::Path::new(path).exists() {
                    match Ebpf::load_file(path) {
                        Ok(b) => {
                            info!("Successfully loaded eBPF object from: {}", path);
                            bpf = Some(b);
                            break;
                        }
                        Err(e) => {
                            warn!("Failed loading eBPF object from {}: {:?}", path, e);
                        }
                    }
                }
            }

            if bpf.is_none() {
                warn!("Could not locate or load jarswaf-ebpf binary. eBPF packet drop will be disabled.");
            }

            Self { bpf }
        }

        #[cfg(not(target_os = "linux"))]
        {
            warn!("eBPF XDP is not supported on this OS. eBPF features will be disabled.");
            Self {}
        }
    }

    pub fn attach(&mut self, _interface: &str) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let bpf = match self.bpf.as_mut() {
                Some(b) => b,
                None => {
                    warn!("eBPF is disabled, skipping XDP program attach");
                    return Ok(());
                }
            };
            let program: &mut Xdp = bpf
                .program_mut("jarswaf_ebpf")
                .ok_or_else(|| {
                    "eBPF program 'jarswaf_ebpf' not found in loaded object".to_string()
                })?
                .try_into()
                .map_err(|e| format!("{}", e))?;
            program.load().map_err(|e| format!("{}", e))?;

            // Try Native Driver mode first; fall back to Generic (Skb) mode for WiFi/virtual interfaces
            match program.attach(_interface, XdpMode::Driver) {
                Ok(_) => {
                    info!(
                        "XDP program attached in Native Driver mode to interface: {}",
                        _interface
                    );
                }
                Err(e_drv) => {
                    warn!(
                        "Driver XDP mode failed on interface {} ({:?}), falling back to Generic (Skb) mode...",
                        _interface, e_drv
                    );
                    program.attach(_interface, XdpMode::Skb).map_err(|e| {
                        format!(
                            "Failed attaching XDP in both Driver and Generic mode: {}",
                            e
                        )
                    })?;
                    info!(
                        "XDP program attached in Generic (Skb) mode to interface: {}",
                        _interface
                    );
                }
            }
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            warn!("Cannot attach XDP: Not supported on this OS");
            Ok(())
        }
    }

    pub fn block_ip(&mut self, _ip: Ipv4Addr) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let bpf = match self.bpf.as_mut() {
                Some(b) => b,
                None => return Ok(()),
            };
            let mut blocklist: HashMap<_, u32, u8> = HashMap::try_from(
                bpf.map_mut("BLOCKLIST")
                    .ok_or_else(|| "eBPF map 'BLOCKLIST' not found".to_string())?,
            )
            .map_err(|e| format!("{}", e))?;
            let ip_u32 = u32::from(_ip).to_be(); // Ensure network byte order matching eBPF expectations
            blocklist
                .insert(ip_u32, 1, 0)
                .map_err(|e| format!("{}", e))?;
            info!("IP {} added to XDP blocklist", _ip);
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    }

    pub fn unblock_ip(&mut self, _ip: Ipv4Addr) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let bpf = match self.bpf.as_mut() {
                Some(b) => b,
                None => return Ok(()),
            };
            let mut blocklist: HashMap<_, u32, u8> = HashMap::try_from(
                bpf.map_mut("BLOCKLIST")
                    .ok_or_else(|| "eBPF map 'BLOCKLIST' not found".to_string())?,
            )
            .map_err(|e| format!("{}", e))?;
            let ip_u32 = u32::from(_ip).to_be();
            blocklist.remove(&ip_u32).map_err(|e| format!("{}", e))?;
            info!("IP {} removed from XDP blocklist", _ip);
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    }

    pub fn attach_rasp(
        &mut self,
        rasp_tx: Option<tokio::sync::mpsc::Sender<()>>,
    ) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            use aya::maps::perf::PerfEventArray;
            use aya::programs::KProbe;

            let bpf = match self.bpf.as_mut() {
                Some(b) => b,
                None => {
                    warn!("eBPF is disabled, skipping RASP attach");
                    return Ok(());
                }
            };

            let program: &mut KProbe = bpf
                .program_mut("jarswaf_rasp_exec")
                .ok_or_else(|| "eBPF program 'jarswaf_rasp_exec' not found".to_string())?
                .try_into()
                .map_err(|e| format!("{}", e))?;

            program.load().map_err(|e| format!("{}", e))?;

            program
                .attach("sys_execve", 0)
                .or_else(|_| program.attach("__x64_sys_execve", 0))
                .map_err(|e| format!("failed to attach the KProbe program: {}", e))?;

            info!("RASP KProbe successfully attached to sys_execve");

            let map = bpf
                .take_map("RASP_EVENTS")
                .ok_or_else(|| "eBPF map 'RASP_EVENTS' not found".to_string())?;
            let perf_array = PerfEventArray::try_from(map)
                .map_err(|e| format!("failed to get RASP_EVENTS map: {}", e))?;

            if let Some(tx) = rasp_tx {
                tokio::spawn(async move {
                    crate::rasp::start_rasp_monitor(perf_array, tx).await;
                });
            }

            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    }
}

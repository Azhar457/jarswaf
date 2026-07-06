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
            // Try loading from Docker path first, then fall back to local development build path
            let bpf = match Ebpf::load_file("/app/jarswaf-ebpf")
                .or_else(|_| Ebpf::load_file("target/bpfel-unknown-none/release/jarswaf-ebpf"))
            {
                Ok(b) => Some(b),
                Err(e) => {
                    warn!("Failed to load eBPF object (eBPF is likely not compiled or unsupported): {}. eBPF packet filtering is disabled.", e);
                    None
                }
            };
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
                .unwrap()
                .try_into()
                .map_err(|e| format!("{}", e))?;
            program.load().map_err(|e| format!("{}", e))?;
            program
                .attach(_interface, XdpMode::default())
                .map_err(|e| format!("failed to attach the XDP program: {}", e))?;
            info!(
                "XDP program successfully attached to interface: {}",
                _interface
            );
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
            let mut blocklist: HashMap<_, u32, u8> =
                HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())
                    .map_err(|e| format!("{}", e))?;
            let ip_u32 = u32::from(_ip); // Ensure network byte order matching eBPF expectations
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
}

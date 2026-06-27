use std::net::Ipv4Addr;
use tracing::warn;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use tracing::info;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpMode},
    Ebpf,
};

pub struct XdpManager {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    bpf: Option<Ebpf>,
}

impl Default for XdpManager {
    fn default() -> Self {
        Self::new()
    }
}

impl XdpManager {
    pub fn new() -> Self {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            // We use include_bytes! to embed the eBPF program directly inside the user-space binary.
            // This makes the binary fully self-contained and avoids the need to ship target/ files inside Docker.
            const EBPF_BYTES: &[u8] =
                include_bytes!("../target/bpfel-unknown-none/release/aegis-ebpf");
            let bpf = match Ebpf::load(EBPF_BYTES) {
                Ok(b) => Some(b),
                Err(e) => {
                    warn!("Failed to load embedded eBPF object: {}. eBPF packet filtering is disabled.", e);
                    None
                }
            };
            Self { bpf }
        }

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            warn!("eBPF XDP is not compiled or not supported on this OS. eBPF features will be disabled.");
            Self {}
        }
    }

    pub fn attach(&mut self, _interface: &str) -> Result<(), String> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let bpf = match self.bpf.as_mut() {
                Some(b) => b,
                None => {
                    warn!("eBPF is disabled, skipping XDP program attach");
                    return Ok(());
                }
            };
            let program: &mut Xdp = bpf
                .program_mut("aegis_ebpf")
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

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            warn!("Cannot attach XDP: eBPF is disabled or not supported on this OS");
            Ok(()) // Return Ok(()) so WAF initialization doesn't fail on non-eBPF systems
        }
    }

    pub fn block_ip(&mut self, _ip: Ipv4Addr) -> Result<(), String> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
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

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            Ok(())
        }
    }
}

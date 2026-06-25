use std::net::Ipv4Addr;
use tracing::warn; //info, and error TODO

#[cfg(target_os = "linux")]
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpMode},
    Ebpf,
};

pub struct XdpManager {
    #[cfg(target_os = "linux")]
    bpf: Ebpf,
}

impl XdpManager {
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            // Attempt to load the pre-compiled eBPF object
            // For now, we will return an empty instance if it fails, since we want the WAF to continue working without eBPF
            let bpf = match Ebpf::load_file("target/bpfel-unknown-none/release/aegis-ebpf") {
                Ok(b) => b,
                Err(e) => {
                    warn!("Failed to load eBPF object (eBPF is likely not compiled or unsupported): {}", e);
                    Ebpf::load(&[])
                        .unwrap_or_else(|_| panic!("Failed to create empty Ebpf instance"))
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
            let program: &mut Xdp = self
                .bpf
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

        #[cfg(not(target_os = "linux"))]
        {
            warn!("Cannot attach XDP: Not supported on this OS");
            Err("Not supported on this OS".to_string())
        }
    }

    pub fn block_ip(&mut self, _ip: Ipv4Addr) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let mut blocklist: HashMap<_, u32, u8> =
                HashMap::try_from(self.bpf.map_mut("BLOCKLIST").unwrap())
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

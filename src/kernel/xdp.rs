use std::sync::Arc;
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use aya::{
    programs::{Xdp, XdpMode},
    Ebpf,
};

pub struct XdpSubsystem {
    #[cfg(target_os = "linux")]
    bpf: Arc<tokio::sync::Mutex<Option<Ebpf>>>,
}

impl XdpSubsystem {
    pub fn new(#[cfg(target_os = "linux")] bpf: Arc<tokio::sync::Mutex<Option<Ebpf>>>) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            bpf,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Self {
        Self {}
    }

    pub async fn attach(&self, _interface: &str) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let mut lock = self.bpf.lock().await;
            let bpf = match lock.as_mut() {
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
}

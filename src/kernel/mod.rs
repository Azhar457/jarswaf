pub mod interface;
pub mod xdp;
pub mod tc;
pub mod rasp;
pub mod error;
pub mod types;

pub use interface::{KernelInterface, BpfMapInterface};
pub use error::{KernelError, KernelResult};
pub use types::{RaspEvent, BatchResult, IpKey};

use std::sync::OnceLock;

static KERNEL: OnceLock<KernelInterface> = OnceLock::new();

pub fn init() -> &'static KernelInterface {
    KERNEL.get_or_init(|| {
        KernelInterface::new()
    })
}

pub fn get() -> &'static KernelInterface {
    KERNEL.get().expect("Kernel interface not initialized. Call kernel::init() first.")
}

/// Returns the kernel interface if it has already been initialized (via
/// kernel::init()), otherwise None. Used by the global `KERNEL_INTERFACE`
/// lazy static so that pure-controller / non-Linux modes see None instead
/// of force-initializing eBPF at first access.
pub fn init_if_present() -> Option<&'static KernelInterface> {
    KERNEL.get()
}

/// Start background flush task for batched operations
pub fn start_flush_task(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        let kernel = get();
        
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if kernel.maps.has_pending().await {
                        match kernel.maps.flush().await {
                            Ok(result) if result.total() > 0 => {
                                tracing::debug!("Kernel flush: {:?}", result);
                            }
                            Err(e) => {
                                tracing::error!("Kernel flush failed: {}", e);
                            }
                            _ => {}
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if kernel.maps.has_pending().await {
                        let _ = kernel.maps.flush().await;
                    }
                    tracing::info!("Kernel flush task shutting down");
                    break;
                }
            }
        }
    });
}

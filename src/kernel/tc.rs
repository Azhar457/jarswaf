use std::sync::Arc;
use tracing::warn;

#[cfg(target_os = "linux")]
use aya::Ebpf;

pub struct TcSubsystem {
    #[cfg(target_os = "linux")]
    _bpf: Arc<tokio::sync::Mutex<Option<Ebpf>>>,
}

impl TcSubsystem {
    pub fn new(#[cfg(target_os = "linux")] _bpf: Arc<tokio::sync::Mutex<Option<Ebpf>>>) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            _bpf,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Self {
        Self {}
    }

    pub async fn attach(&self, _interface: &str) -> Result<(), String> {
        warn!("TC subsystem is currently a skeleton stub; TC not attached on {}", _interface);
        Ok(())
    }
}

use std::sync::Arc;
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use aya::{
    maps::perf::PerfEventArray,
    programs::KProbe,
    Ebpf,
};

pub struct RaspSubsystem {
    #[cfg(target_os = "linux")]
    bpf: Arc<tokio::sync::Mutex<Option<Ebpf>>>,
}

impl RaspSubsystem {
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

    pub async fn attach(
        &self,
        rasp_tx: Option<tokio::sync::mpsc::Sender<()>>,
    ) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let mut lock = self.bpf.lock().await;
            let bpf = match lock.as_mut() {
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

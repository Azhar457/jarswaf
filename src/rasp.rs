#[cfg(target_os = "linux")]
use aya::maps::perf::PerfEventArray;
#[cfg(target_os = "linux")]
use aya::util::online_cpus;
#[cfg(target_os = "linux")]
use tracing::warn;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveEvent {
    pub pid: u32,
    pub uid: u32,
    pub command: [u8; 128],
}

#[cfg(target_os = "linux")]
pub async fn start_rasp_monitor(
    mut perf_array: PerfEventArray<aya::maps::MapData>,
    tx: tokio::sync::mpsc::Sender<()>,
) {
    let cpus = match online_cpus() {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to get online CPUs for RASP: {:?}", e);
            return;
        }
    };

    for cpu_id in cpus {
        let mut buf = match perf_array.open(cpu_id, None) {
            Ok(b) => b,
            Err(e) => {
                warn!("Failed to open perf array buffer for CPU {}: {}", cpu_id, e);
                continue;
            }
        };

        let thread_tx = tx.clone();
        std::thread::spawn(move || {
            loop {
                // According to aya docs for read_events, it was replaced by for_each
                buf.for_each(|event| {
                    if let aya::maps::perf::PerfEvent::Sample { tail, .. } = event {
                        if let Some(e) = parse_execve_event(tail) {
                            analyze_rasp_event(&e, &thread_tx);
                        }
                    }
                });
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
    }
}

#[cfg(target_os = "linux")]
fn parse_execve_event(buf: &[u8]) -> Option<ExecveEvent> {
    if buf.len() < std::mem::size_of::<ExecveEvent>() {
        return None;
    }

    // Unsafe pointer read because it's coming from kernel perf buffer
    let event = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const ExecveEvent) };
    Some(event)
}

pub fn analyze_rasp_event(event: &ExecveEvent, tx: &tokio::sync::mpsc::Sender<()>) {
    let raw_cmd = &event.command;
    let end = raw_cmd
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(raw_cmd.len());
    let cmd = String::from_utf8_lossy(&raw_cmd[..end]).to_string();

    let is_malicious = cmd.contains("nc -e")
        || cmd.contains("/bin/sh")
        || cmd.contains("bash -i")
        || cmd.contains("wget ")
        || cmd.contains("curl ");

    if is_malicious {
        warn!(
            target: "jarswaf_rasp",
            "[RASP ALERT] Suspicious process execution detected! PID: {}, UID: {}, Command: {}",
            event.pid, event.uid, cmd
        );
        let _ = tx.blocking_send(());
    } else {
        // Only log for debugging
        // info!("[RASP] Execve PID: {}, UID: {}, Cmd: {}", event.pid, event.uid, cmd);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn analyze_rasp_event(_event: &ExecveEvent) {}

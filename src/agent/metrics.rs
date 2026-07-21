use super::discovery;
use crate::types::AgentMetrics;
use sysinfo::{Disks, System};
use tracing::{error, warn};

pub async fn start_metrics_collector(controller_url: String, token: Option<String>) {
    let client = crate::logging::build_client();
    let mut sys = System::new_all();
    sys.refresh_cpu();
    sys.refresh_memory();

    let hostname = discovery::get_hostname();
    let os = std::env::consts::OS.to_string();

    // Sleep briefly to let CPU metrics gather
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    loop {
        sys.refresh_cpu();
        sys.refresh_memory();
        let cpu = sys.global_cpu_info().cpu_usage();

        let total_mem = sys.total_memory();
        let used_mem = sys.used_memory();
        let ram = if total_mem > 0 {
            (used_mem as f32 / total_mem as f32) * 100.0
        } else {
            0.0
        };

        let disks = Disks::new_with_refreshed_list();
        let mut total_disk = 0u64;
        let mut available_disk = 0u64;
        for disk in &disks {
            total_disk += disk.total_space();
            available_disk += disk.available_space();
        }
        let disk = if total_disk > 0 {
            ((total_disk - available_disk) as f32 / total_disk as f32) * 100.0
        } else {
            0.0
        };

        let payload = AgentMetrics {
            hostname: hostname.clone(),
            ip: "127.0.0.1".to_string(), // will be overwritten by Controller with real remote IP
            os: os.clone(),
            cpu,
            ram,
            disk,
            uptime: sysinfo::System::uptime(),
            network_interfaces: discovery::get_network_interfaces(),
            discovered_services: {
                let mut srvs = discovery::get_docker_services();
                srvs.extend(discovery::get_system_services());
                srvs.sort_by_key(|s| s.port);
                srvs.dedup_by(|a, b| a.port == b.port);
                srvs
            },
            region: None, // Can be populated from ENV later
            cloud_provider: None,
            active_connections: None,
        };

        let url = format!(
            "{}/api/v1/agents/metrics",
            controller_url.trim_end_matches('/')
        );
        let mut req = client.post(&url).json(&payload);
        if let Some(ref t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        match req.send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    warn!(
                        "Controller metrics endpoint returned error: {}",
                        resp.status()
                    );
                }
            }
            Err(e) => {
                error!("Failed to send metrics to controller: {}", e);
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}

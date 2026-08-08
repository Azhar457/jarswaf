use sysinfo::Networks;

use crate::types::DiscoveredService;

/// Discover running Docker containers with exposed ports.
pub fn get_docker_services() -> Vec<DiscoveredService> {
    let mut services = Vec::new();
    match std::process::Command::new("docker")
        .args(["ps", "--format", "{{json .}}"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let out_str = String::from_utf8_lossy(&output.stdout);
            for line in out_str.lines() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    if let Some(name) = v.get("Names").and_then(|n| n.as_str()) {
                        if let Some(ports_str) = v.get("Ports").and_then(|p| p.as_str()) {
                            if ports_str.contains("->") {
                                let mut public_port = 0;
                                if let Some(idx) = ports_str.find("->") {
                                    let before_arrow = &ports_str[..idx];
                                    if let Some(colon_idx) = before_arrow.rfind(':') {
                                        if let Ok(p) = before_arrow[colon_idx + 1..].parse::<u16>()
                                        {
                                            public_port = p;
                                        }
                                    }
                                }
                                if public_port > 0 {
                                    services.push(DiscoveredService {
                                        name: name.to_string(),
                                        port: public_port,
                                        protocol: "tcp".to_string(),
                                        source: "Docker".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(output) => tracing::debug!(
            "docker ps failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(e) => tracing::debug!("docker not available: {}", e),
    }
    services
}

/// Discover system services listening on TCP ports (OS-specific).
pub fn get_system_services() -> Vec<DiscoveredService> {
    let mut services = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(tcp_services) = parse_proc_net_tcp("/proc/net/tcp", "TCP") {
            services.extend(tcp_services);
        }
        if let Ok(tcp6_services) = parse_proc_net_tcp("/proc/net/tcp6", "TCP") {
            services.extend(tcp6_services);
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(cmd_output) = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess | ConvertTo-Json -Compress"])
            .output()
        {
            if cmd_output.status.success() {
                let out_str = String::from_utf8_lossy(&cmd_output.stdout);
                if !out_str.trim().is_empty() {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&out_str) {
                        let mut sys = sysinfo::System::new();
                        sys.refresh_processes();

                        let parse_item = |item: &serde_json::Value| -> Option<DiscoveredService> {
                            let port = item.get("LocalPort")?.as_u64()? as u16;
                            if port == 8080 || port == 80 || port == 443 {
                                return None;
                            }
                            let pid = item.get("OwningProcess")?.as_u64()? as u32;
                            let proc_name = sys.process(sysinfo::Pid::from(pid as usize))
                                .map(|p| p.name().to_string())
                                .unwrap_or_else(|| format!("PID {pid}"));
                            Some(DiscoveredService {
                                name: proc_name,
                                port,
                                protocol: "TCP".to_string(),
                                source: "System".to_string(),
                            })
                        };

                        if let Some(arr) = val.as_array() {
                            for item in arr {
                                if let Some(srv) = parse_item(item) {
                                    services.push(srv);
                                }
                            }
                        } else if let Some(srv) = parse_item(&val) {
                            services.push(srv);
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(cmd_output) = std::process::Command::new("lsof")
            .args(["-iTCP", "-sTCP:LISTEN", "-P", "-n", "-F", "pN"])
            .output()
        {
            if cmd_output.status.success() {
                let out_str = String::from_utf8_lossy(&cmd_output.stdout);
                let mut current_pid = 0u32;
                let mut sys = sysinfo::System::new();
                sys.refresh_processes();

                for line in out_str.lines() {
                    if line.starts_with('p') {
                        if let Ok(pid) = line[1..].parse::<u32>() {
                            current_pid = pid;
                        }
                    } else if line.starts_with('N') {
                        if let Some(port_idx) = line.rfind(':') {
                            if let Ok(port) = line[port_idx + 1..].parse::<u16>() {
                                if port != 8080 && port != 80 && port != 443 {
                                    let proc_name = sys
                                        .process(sysinfo::Pid::from(current_pid as usize))
                                        .map(|p| p.name().to_string())
                                        .unwrap_or_else(|| format!("PID {current_pid}"));
                                    services.push(DiscoveredService {
                                        name: proc_name,
                                        port,
                                        protocol: "TCP".to_string(),
                                        source: "System".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    services.sort_by_key(|s| s.port);
    services.dedup_by(|a, b| a.port == b.port);
    services
}

#[cfg(target_os = "linux")]
fn parse_proc_net_tcp(
    file_path: &str,
    protocol: &str,
) -> Result<Vec<DiscoveredService>, std::io::Error> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::time::{Duration, Instant};

    const MAX_PID_SCAN: usize = 500;
    const SCAN_TIMEOUT: Duration = Duration::from_millis(500);

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut services = Vec::new();

    let scan_start = Instant::now();
    let mut pid_count = 0;

    let mut inode_map: Option<std::collections::HashMap<String, u32>> = None;
    let mut sys: Option<sysinfo::System> = None;

    for (idx, line) in reader.lines().enumerate() {
        if scan_start.elapsed() > SCAN_TIMEOUT {
            tracing::warn!(
                "Service discovery timeout in {} — scanned {} PIDs, aborting",
                file_path,
                pid_count
            );
            break;
        }

        if idx == 0 {
            continue;
        }
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        let state = parts[3];
        if state != "0A" {
            continue;
        }

        let local_addr = parts[1];
        let addr_parts: Vec<&str> = local_addr.split(':').collect();
        if addr_parts.len() != 2 {
            continue;
        }

        let port = u16::from_str_radix(addr_parts[1], 16).unwrap_or(0);
        if port == 8080 || port == 80 || port == 443 || port == 0 {
            continue;
        }

        let inode = parts[9];
        let mut process_name = "Unknown".to_string();

        if inode_map.is_none() && pid_count < MAX_PID_SCAN {
            inode_map = Some(get_linux_socket_inodes_limited(MAX_PID_SCAN));
            sys = Some(sysinfo::System::new());
            if let Some(ref mut s) = sys {
                s.refresh_processes();
            }
        }

        if let Some(ref map) = inode_map {
            if let Some(&pid) = map.get(inode) {
                pid_count += 1;
                if let Some(ref s) = sys {
                    if let Some(p) = s.process(sysinfo::Pid::from(pid as usize)) {
                        process_name = p.name().to_string();
                    } else if let Ok(cmd) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
                        process_name = cmd.trim().to_string();
                    }
                }
            }
        }

        services.push(DiscoveredService {
            name: process_name,
            port,
            protocol: protocol.to_string(),
            source: "System".to_string(),
        });
    }

    Ok(services)
}

#[cfg(target_os = "linux")]
fn get_linux_socket_inodes_limited(max_pids: usize) -> std::collections::HashMap<String, u32> {
    let mut map = std::collections::HashMap::new();
    let mut pid_count = 0;

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if pid_count >= max_pids {
                tracing::debug!("Socket inode scan hit PID limit ({}) — stopping", max_pids);
                break;
            }

            let path = entry.path();
            if let Some(name_str) = path.file_name().and_then(|s| s.to_str()) {
                if let Ok(pid) = name_str.parse::<u32>() {
                    let fd_path = format!("/proc/{}/fd", pid);
                    let fd_dir = match std::fs::read_dir(&fd_path) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };

                    for fd_entry in fd_dir.flatten() {
                        if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                            if let Some(link_str) = link.to_str() {
                                if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                                    let inode = &link_str[8..link_str.len() - 1];
                                    map.insert(inode.to_string(), pid);
                                }
                            }
                        }
                    }
                    pid_count += 1;
                }
            }
        }
    }

    tracing::debug!(
        "Socket inode scan: {} PIDs scanned, {} socket inodes found",
        pid_count,
        map.len()
    );

    map
}

/// Get the list of network interface names.
pub fn get_network_interfaces() -> Vec<String> {
    let networks = Networks::new_with_refreshed_list();
    networks.keys().map(|name| name.to_string()).collect()
}

/// Get the system hostname.
pub fn get_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "jarsWAF-Agent".to_string())
}

use crate::logging;
use crate::proxy_engine;
use crate::types::is_local_ip;
use std::sync::Arc;
use tracing::{debug, error};

pub async fn start_blocklist_sync(
    controller_url: Option<String>,
    token: Option<String>,
    blocklist: Arc<dashmap::DashMap<std::net::IpAddr, std::time::Instant>>,
    blocklist_file_path: String,
    use_sqlite: bool,
    db_path_local: String,
) {
    let client = crate::logging::build_client();
    loop {
        if let Some(ctrl_url) = &controller_url {
            // Agent Mode: Fetch blocklist from Controller
            let url = format!(
                "{}/api/v1/reputation/blocklist",
                ctrl_url.trim_end_matches('/')
            );
            let mut req = client.get(&url);
            if let Some(ref t) = token {
                req = req.header("Authorization", format!("Bearer {t}"));
            }
            match req.send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        if let Ok(ips) = resp.json::<Vec<String>>().await {
                            let mut new_blocklist = std::collections::HashSet::new();
                            for ip_str in ips {
                                if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                                    if !is_local_ip(&ip) {
                                        new_blocklist.insert(ip);
                                    }
                                }
                            }
                            // Save to local JSON file as backup
                            logging::save_blocklist_to_file(&blocklist_file_path, &new_blocklist);
                            blocklist.clear();
                            for ip in &new_blocklist {
                                blocklist.insert(*ip, std::time::Instant::now() + std::time::Duration::from_secs(31536000)); // Default 1 year for reputation sync
                            }
                            // Enforce max entries to cap memory usage
                            if blocklist.len() > proxy_engine::BLOCKLIST_MAX_ENTRIES {
                                proxy_engine::trim_dashmap(
                                    &blocklist,
                                    proxy_engine::BLOCKLIST_MAX_ENTRIES,
                                );
                                tracing::warn!(
                                    "Blocklist trimmed to {} entries (max={})",
                                    blocklist.len(),
                                    proxy_engine::BLOCKLIST_MAX_ENTRIES
                                );
                            }
                            debug!(
                                "Reputation blocklist synced. Active blocked IPs: {}",
                                blocklist.len()
                            );
                        }
                    }
                }
                Err(e) => {
                    error!("Error syncing reputation blocklist from controller: {}", e);
                }
            }
        } else if use_sqlite {
            // Standalone Mode with SQLite: Query SQLite for repeat offenders
            let db_path = db_path_local.clone();
            let blocklist_file_path_clone = blocklist_file_path.clone();
            let blocklist_clone = blocklist.clone();
            let res = tokio::task::spawn_blocking(move || {
                let conn = rusqlite::Connection::open(&db_path)?;
                let since = chrono::Utc::now() - chrono::Duration::minutes(5);
                let since_str = since.to_rfc3339();
                let mut stmt = conn.prepare(
                    "SELECT client_ip FROM request_log
                     WHERE action = 'BLOCK' AND timestamp > ?1
                     GROUP BY client_ip
                     HAVING count() >= 5",
                )?;
                let rows = stmt.query_map([since_str], |row| {
                    let ip_str: String = row.get(0)?;
                    Ok(ip_str)
                })?;
                let mut ips = std::collections::HashSet::new();
                for ip_str in rows.flatten() {
                    if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                        if !is_local_ip(&ip) {
                            ips.insert(ip);
                        }
                    }
                }
                Ok::<_, rusqlite::Error>(ips)
            })
            .await;

            if let Ok(Ok(ips)) = res {
                logging::save_blocklist_to_file(&blocklist_file_path_clone, &ips);
                blocklist_clone.clear();
                for ip in &ips {
                    blocklist_clone.insert(*ip, std::time::Instant::now() + std::time::Duration::from_secs(31536000));
                }
            }
        } else {
            // Standalone File/Remote mode: Load from local JSON file
            let loaded = logging::load_blocklist_from_file(&blocklist_file_path);
            blocklist.clear();
            for ip in &loaded {
                blocklist.insert(*ip, std::time::Instant::now() + std::time::Duration::from_secs(31536000));
            }
        }

        let sleep_secs = if controller_url.is_some() { 10 } else { 60 };
        tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;
    }
}

use reqwest::Client;
use std::net::IpAddr;
use std::time::Duration;
use tracing::{info, warn, error};

// List of public threat intel feeds.
// For the sake of this homelab WAF, we use Tor bulk exit list as a demo.
const TOR_EXIT_NODE_LIST: &str = "https://check.torproject.org/torbulkexitlist";

/// Fetches the latest threat intelligence IPs from public feeds.
pub async fn fetch_threat_intel_ips() -> Vec<IpAddr> {
    let mut blocked_ips = Vec::new();
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    info!("Fetching threat intelligence feed from {}", TOR_EXIT_NODE_LIST);
    
    match client.get(TOR_EXIT_NODE_LIST).send().await {
        Ok(response) => {
            if response.status().is_success() {
                if let Ok(body) = response.text().await {
                    let mut count = 0;
                    for line in body.lines() {
                        let line = line.trim();
                        if !line.is_empty() && !line.starts_with('#') {
                            if let Ok(ip) = line.parse::<IpAddr>() {
                                blocked_ips.push(ip);
                                count += 1;
                            }
                        }
                    }
                    info!("Successfully parsed {} IPs from threat intel feed.", count);
                }
            } else {
                warn!("Failed to fetch threat intel feed. Status: {}", response.status());
            }
        }
        Err(e) => {
            error!("Error fetching threat intel feed: {}", e);
        }
    }

    // In a real scenario, we could merge multiple feeds here.
    // e.g. AbuseIPDB, Spamhaus DROP list, etc.

    blocked_ips
}

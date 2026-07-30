use reqwest::Client;
use std::net::IpAddr;
use std::time::Duration;
use tracing::{error, info, warn};

// List of public threat intel feeds.
const TOR_EXIT_NODE_LIST: &str = "https://check.torproject.org/torbulkexitlist";
const SPAMHAUS_DROP_LIST: &str = "https://www.spamhaus.org/drop/drop.txt";
const SPAMHAUS_EDROP_LIST: &str = "https://www.spamhaus.org/drop/edrop.txt";
const FIREHOL_LEVEL1_LIST: &str =
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset";

/// Fetches the latest threat intelligence IPs from public feeds.
pub async fn fetch_threat_intel_ips() -> Vec<IpAddr> {
    let mut blocked_ips = Vec::new();
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let feeds = vec![
        ("Tor Exit Nodes", TOR_EXIT_NODE_LIST),
        ("Spamhaus DROP", SPAMHAUS_DROP_LIST),
        ("Spamhaus EDROP", SPAMHAUS_EDROP_LIST),
        ("FireHOL Level 1", FIREHOL_LEVEL1_LIST),
    ];

    for (name, feed_url) in feeds {
        info!("Fetching threat intelligence feed: {} ({})", name, feed_url);
        match client.get(feed_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(body) = response.text().await {
                        let mut count = 0;
                        for line in body.lines() {
                            let line = line.split(';').next().unwrap_or("").trim();
                            if line.is_empty() || line.starts_with('#') {
                                continue;
                            }

                            let ip_str = line.split('/').next().unwrap_or(line).trim();
                            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                blocked_ips.push(ip);
                                count += 1;
                            }
                        }
                        info!("Successfully parsed {} IPs/subnets from {}", count, name);
                    }
                } else {
                    warn!(
                        "Failed to fetch {} feed. Status: {}",
                        name,
                        response.status()
                    );
                }
            }
            Err(e) => {
                error!("Error fetching {} feed: {}", name, e);
            }
        }
    }

    blocked_ips
}

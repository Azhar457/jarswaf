use crate::control_bus::state::{
    BlockSource, BlocklistEntry, BlocklistSnapshot, IpBlockCount, PublishedState,
};
use crate::control_bus::ws_broadcaster::{get as get_ws, WsEvent};
use crate::kernel;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Manages the IP blocklist
pub struct BlocklistManager {
    pub(crate) state: PublishedState,
    /// Internal mutable state — not directly exposed
    entries: tokio::sync::RwLock<HashMap<IpAddr, BlocklistEntry>>,
    /// Statistics for dashboard
    block_counts: tokio::sync::Mutex<HashMap<IpAddr, u64>>,
}

impl BlocklistManager {
    pub fn new(state: PublishedState) -> Self {
        Self {
            state,
            entries: tokio::sync::RwLock::new(HashMap::new()),
            block_counts: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Block an IP address
    pub async fn block_ip(
        &self,
        ip: IpAddr,
        duration: Duration,
        reason: String,
        source: BlockSource,
    ) {
        let now = Instant::now();
        let entry = BlocklistEntry {
            ip,
            added_at: now,
            expires_at: now + duration,
            reason: reason.clone(),
            source,
        };

        let mut entries = self.entries.write().await;
        let is_new = !entries.contains_key(&ip);
        entries.insert(ip, entry);
        drop(entries);

        // Update kernel eBPF map
        kernel::get().maps.queue_block(ip).await;

        // Update published state
        self.publish_snapshot().await;

        // Update WS subscribers
        if is_new {
            get_ws().publish(WsEvent::BlocklistUpdate {
                added: vec![ip.to_string()],
                removed: vec![],
            });
        }

        info!(
            "IP {} blocked: {} (source: {:?}, duration: {:?})",
            ip, reason, source, duration
        );
    }

    /// Unblock an IP address
    pub async fn unblock_ip(&self, ip: IpAddr) {
        let mut entries = self.entries.write().await;
        if entries.remove(&ip).is_some() {
            drop(entries);

            // Update kernel eBPF map
            kernel::get().maps.queue_unblock(ip).await;

            // Update published state
            self.publish_snapshot().await;

            // Update WS subscribers
            get_ws().publish(WsEvent::BlocklistUpdate {
                added: vec![],
                removed: vec![ip.to_string()],
            });

            info!("IP {} unblocked", ip);
        }
    }

    /// Check if IP is blocked
    pub async fn is_blocked(&self, ip: &IpAddr) -> bool {
        let entries = self.entries.read().await;
        entries.contains_key(ip)
    }

    /// Get all blocked IPs
    pub async fn list_ips(&self) -> Vec<IpAddr> {
        let entries = self.entries.read().await;
        entries.keys().copied().collect()
    }

    /// Sync blocklist from external source (replaces entire list)
    pub async fn sync_blocklist(&self, ips: Vec<IpAddr>, source: BlockSource) {
        let now = Instant::now();
        let default_duration = Duration::from_secs(86400);

        let mut entries = self.entries.write().await;
        let old_ips: std::collections::HashSet<IpAddr> = entries.keys().copied().collect();
        let new_ips: std::collections::HashSet<IpAddr> = ips.into_iter().collect();

        // Remove IPs not in new list
        let removed: Vec<IpAddr> = old_ips.difference(&new_ips).copied().collect();
        for ip in &removed {
            entries.remove(ip);
            kernel::get().maps.queue_unblock(*ip).await;
        }

        // Add new IPs
        let added: Vec<IpAddr> = new_ips.difference(&old_ips).copied().collect();
        for ip in &added {
            entries.insert(
                *ip,
                BlocklistEntry {
                    ip: *ip,
                    added_at: now,
                    expires_at: now + default_duration,
                    reason: format!("sync from {:?}", source),
                    source,
                },
            );
            kernel::get().maps.queue_block(*ip).await;
        }

        drop(entries);
        self.publish_snapshot().await;

        if !removed.is_empty() || !added.is_empty() {
            get_ws().publish(WsEvent::BlocklistUpdate {
                added: added.iter().map(|i| i.to_string()).collect(),
                removed: removed.iter().map(|i| i.to_string()).collect(),
            });
        }

        info!(
            "Blocklist synced: +{} -{} (source: {:?})",
            added.len(),
            removed.len(),
            source
        );
    }

    /// Clear entire blocklist
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        let ips: Vec<IpAddr> = entries.keys().copied().collect();
        entries.clear();
        drop(entries);

        for ip in &ips {
            kernel::get().maps.queue_unblock(*ip).await;
        }

        self.publish_snapshot().await;
        info!("Blocklist cleared ({} IPs removed)", ips.len());
    }

    /// Record a block event for metrics
    pub async fn record_block(&self, ip: IpAddr) {
        let mut counts = self.block_counts.lock().await;
        *counts.entry(ip).or_insert(0) += 1;
    }

    /// Get top blocked IPs for dashboard
    pub async fn top_blocked_ips(&self, limit: usize) -> Vec<IpBlockCount> {
        let counts = self.block_counts.lock().await;
        let mut sorted: Vec<_> = counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.truncate(limit);
        sorted
            .into_iter()
            .map(|(ip, count)| IpBlockCount {
                ip: ip.to_string(),
                count: *count,
            })
            .collect()
    }

    /// Remove expired entries (called by cleanup task)
    pub async fn evict_expired(&self) {
        let now = Instant::now();
        let mut entries = self.entries.write().await;
        let expired: Vec<IpAddr> = entries
            .iter()
            .filter(|(_, entry)| now > entry.expires_at)
            .map(|(ip, _)| *ip)
            .collect();

        for ip in &expired {
            entries.remove(ip);
            kernel::get().maps.queue_unblock(*ip).await;
        }

        if !expired.is_empty() {
            drop(entries);
            self.publish_snapshot().await;
            debug!("Evicted {} expired blocklist entries", expired.len());
        }
    }

    /// Load initial blocklist from file
    pub async fn load_from_file(&self, path: &str) -> std::io::Result<usize> {
        let content = tokio::fs::read_to_string(path).await?;
        let ips: Vec<IpAddr> = content
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect();

        let count = ips.len();
        self.sync_blocklist(ips, BlockSource::Manual).await;
        Ok(count)
    }

    /// Publish current state to ArcSwap
    async fn publish_snapshot(&self) {
        let entries = self.entries.read().await;
        let snapshot = BlocklistSnapshot {
            entries: entries.clone(),
        };
        self.state.publish_blocklist(snapshot);
    }

    /// Get current blocklist size
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Check if blocklist is empty
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}

use crate::config::GossipConfig;
use async_trait::async_trait;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand::{thread_rng, RngCore};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

// ── Constants ───────────────────────────────────────────────────────────────

const GOSSIP_MULTICAST_ADDR: &str = "239.0.0.1:7946";
const MAGIC: &[u8; 4] = b"JWIF";
const NONCE_LEN: usize = 12;
const MAC_LEN: usize = 16;

// ── Payload ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatIntelMessage {
    pub ip: Ipv4Addr,
    pub score: f32,
    pub ttl_secs: u32,
    pub source_node: String,
}

// ── Handler trait ───────────────────────────────────────────────────────────

#[async_trait]
pub trait GossipHandler: Send + Sync {
    async fn on_threat_intel(&self, msg: &ThreatIntelMessage);
}

// ── Gossip Node ─────────────────────────────────────────────────────────────

pub struct GossipNode {
    config: GossipConfig,
    socket: Option<Arc<UdpSocket>>,
    handler: Option<Arc<dyn GossipHandler>>,
    running: Arc<Mutex<bool>>,
}

impl GossipNode {
    pub fn new(config: GossipConfig) -> Self {
        // NOTE: JARSWAF_GOSSIP_PSK env override lives ONLY in config.rs::load_config
        // (single source of truth). Do not re-apply here — SIGHUP reload would diverge.
        Self {
            config,
            socket: None,
            handler: None,
            running: Arc::new(Mutex::new(false)),
        }
    }

    pub fn set_handler(&mut self, handler: Arc<dyn GossipHandler>) {
        self.handler = Some(handler);
    }

    pub async fn start(&mut self) -> Result<(), String> {
        if !self.config.enabled {
            info!("Gossip disabled by config");
            return Ok(());
        }

        // Fail-closed on an empty PSK: a blank pre-shared key means the gossip key is
        // SHA256("") — a public constant — so ANY host on the multicast group can forge
        // threat-intel messages (poison blocklist) or decrypt/alloy them (CIA: integrity +
        // availability + confidentiality all break). Refusing to start is safer than running
        // with an open control channel. Operators must set gossip.psk or JARSWAF_GOSSIP_PSK.
        if self.config.psk.trim().is_empty() {
            return Err(
                "gossip.psk is empty but gossip is enabled — refusing to start. \
                 Set gossip.psk (or JARSWAF_GOSSIP_PSK) to a strong shared secret, \
                 or disable gossip."
                    .to_string(),
            );
        }

        let bind_addr = &self.config.bind_addr;
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind gossip UDP socket on {bind_addr}: {e}"))?;

        let multicast_ip: Ipv4Addr = "239.0.0.1"
            .parse()
            .map_err(|_| "Invalid multicast IP".to_string())?;

        if let Err(e) = socket.join_multicast_v4(multicast_ip, Ipv4Addr::UNSPECIFIED) {
            warn!("Failed to join multicast group (non-fatal): {e}");
        }

        let socket = Arc::new(socket);
        self.socket = Some(socket.clone());
        *self.running.lock().await = true;

        let running = self.running.clone();
        let handler = self.handler.clone();
        let psk = self.config.psk.clone().into_bytes();

        info!("Gossip node listening on {bind_addr} (multicast {GOSSIP_MULTICAST_ADDR})");

        tokio::spawn(async move {
            Self::receive_loop(socket, handler, psk, running).await;
        });

        Ok(())
    }

    fn derive_gossip_key(psk: &[u8]) -> Key {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(psk);
        let hash = hasher.finalize();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&hash);
        Key::from(key_bytes)
    }

    pub async fn broadcast_threat_intel(&self, msg: ThreatIntelMessage) {
        if !self.config.enabled {
            return;
        }
        let Some(ref socket) = self.socket else {
            warn!("Gossip socket not initialized, cannot broadcast");
            return;
        };

        let key = Self::derive_gossip_key(self.config.psk.as_bytes());
        let cipher = ChaCha20Poly1305::new(&key);

        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        match bincode::serialize(&msg) {
            Ok(payload) => {
                match cipher.encrypt(&nonce, payload.as_ref()) {
                    Ok(ciphertext) => {
                        let len = ciphertext.len() as u16;
                        let mut packet = Vec::with_capacity(4 + NONCE_LEN + 2 + ciphertext.len());
                        packet.extend_from_slice(MAGIC);
                        packet.extend_from_slice(&nonce_bytes);
                        packet.extend_from_slice(&len.to_le_bytes());
                        packet.extend_from_slice(&ciphertext);

                        let dest: SocketAddr = match GOSSIP_MULTICAST_ADDR.parse() {
                            Ok(a) => a,
                            Err(e) => {
                                error!("Invalid multicast address: {e}");
                                return;
                            }
                        };

                        match socket.send_to(&packet, dest).await {
                            Ok(n) => debug!("Gossip broadcast: {n} bytes to {dest}"),
                            Err(e) => warn!("Gossip broadcast failed: {e}"),
                        }

                        // Unicast to seeds for WAN / NAT environments
                        for seed in &self.config.seeds {
                            let dest: SocketAddr = match seed.parse() {
                                Ok(a) => a,
                                Err(e) => {
                                    warn!("Invalid seed address {seed}: {e}");
                                    continue;
                                }
                            };
                            match socket.send_to(&packet, dest).await {
                                Ok(n) => debug!("Gossip unicast: {n} bytes to {dest}"),
                                Err(e) => warn!("Gossip unicast failed: {e}"),
                            }
                        }
                    }
                    Err(e) => warn!("Gossip encryption failed: {:?}", e),
                }
            }
            Err(e) => warn!("Failed to serialize gossip message: {e}"),
        }
    }

    pub async fn shutdown(&mut self) {
        *self.running.lock().await = false;
        self.socket = None;
    }

    async fn receive_loop(
        socket: Arc<UdpSocket>,
        handler: Option<Arc<dyn GossipHandler>>,
        psk: Vec<u8>,
        running: Arc<Mutex<bool>>,
    ) {
        let mut buf = [0u8; 2048];
        let key = Self::derive_gossip_key(&psk);
        let cipher = ChaCha20Poly1305::new(&key);

        const MAX_SEEN_NONCES: usize = 10_000;
        let mut seen_nonces = std::collections::HashSet::with_capacity(MAX_SEEN_NONCES);
        let mut nonce_order = std::collections::VecDeque::with_capacity(MAX_SEEN_NONCES);

        loop {
            if !*running.lock().await {
                break;
            }

            match socket.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    let header_len = 4 + NONCE_LEN + 2;
                    if n < header_len + MAC_LEN {
                        debug!("Gossip: packet too short from {src}");
                        continue;
                    }

                    if &buf[..4] != MAGIC {
                        continue;
                    }

                    let mut nonce_bytes = [0u8; 12];
                    nonce_bytes.copy_from_slice(&buf[4..4 + NONCE_LEN]);

                    // Anti-replay: drop duplicate nonces
                    if seen_nonces.contains(&nonce_bytes) {
                        debug!("Gossip: replay detected (duplicate nonce) from {src}");
                        continue;
                    }

                    // Bounded FIFO eviction: evict only the oldest nonce when capacity is reached
                    if nonce_order.len() >= MAX_SEEN_NONCES {
                        if let Some(oldest) = nonce_order.pop_front() {
                            seen_nonces.remove(&oldest);
                        }
                    }

                    seen_nonces.insert(nonce_bytes);
                    nonce_order.push_back(nonce_bytes);

                    let nonce = Nonce::from(nonce_bytes);
                    let ciphertext_len =
                        u16::from_le_bytes([buf[4 + NONCE_LEN], buf[4 + NONCE_LEN + 1]]) as usize;
                    let expected_total = header_len + ciphertext_len;
                    if n < expected_total {
                        debug!("Gossip: truncated payload from {src}");
                        continue;
                    }

                    let ciphertext = &buf[header_len..header_len + ciphertext_len];
                    match cipher.decrypt(&nonce, ciphertext) {
                        Ok(plaintext) => {
                            match bincode::deserialize::<ThreatIntelMessage>(&plaintext) {
                                Ok(msg) => {
                                    // Validate TTL / expiry
                                    if msg.ttl_secs == 0 {
                                        debug!("Gossip: expired TTL from {src}, skipping");
                                        continue;
                                    }

                                    if let Some(ref h) = handler {
                                        h.on_threat_intel(&msg).await;
                                    }
                                }
                                Err(e) => debug!("Gossip: invalid payload from {src}: {e}"),
                            }
                        }
                        Err(_) => debug!(
                            "Gossip: decryption failed from {src} (possible forgery or wrong key)"
                        ),
                    }
                }
                Err(e) => {
                    error!("Gossip recv error: {e}");
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }

        debug!("Gossip receive loop ended");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gossip_key_derivation_deterministic() {
        let psk1 = b"my-super-secret-psk-123456789012";
        let key1 = GossipNode::derive_gossip_key(psk1);
        let key2 = GossipNode::derive_gossip_key(psk1);
        assert_eq!(key1, key2);

        let psk2 = b"different-psk-123456789012345678";
        let key3 = GossipNode::derive_gossip_key(psk2);
        assert_ne!(key1, key3);
    }

    #[tokio::test]
    async fn test_gossip_start_fails_closed_on_empty_psk() {
        // CIA (Integrity/Availability): with gossip enabled but an empty PSK, start() must
        // return Err BEFORE binding a socket — it must not run with the public key
        // SHA256("") that lets anyone on the multicast group forge threat-intel.
        let cfg = crate::config::GossipConfig {
            enabled: true,
            bind_addr: "127.0.0.1:0".to_string(),
            seeds: vec![],
            psk: "".to_string(),
            node_id: "test".to_string(),
        };
        let mut node = GossipNode::new(cfg);
        assert!(node.start().await.is_err());
    }

    #[test]
    fn test_gossip_anti_replay_fifo_eviction() {
        const MAX: usize = 100;
        let mut seen = std::collections::HashSet::with_capacity(MAX);
        let mut order = std::collections::VecDeque::with_capacity(MAX);

        for i in 0..MAX {
            let mut nonce = [0u8; 12];
            nonce[0] = (i & 0xff) as u8;
            nonce[1] = ((i >> 8) & 0xff) as u8;

            assert!(!seen.contains(&nonce));
            seen.insert(nonce);
            order.push_back(nonce);
        }

        // Verify duplicates are rejected
        let mut duplicate_nonce = [0u8; 12];
        duplicate_nonce[0] = 50;
        assert!(seen.contains(&duplicate_nonce));

        // Push 1 more beyond MAX
        let mut new_nonce = [0u8; 12];
        new_nonce[0] = 255;
        new_nonce[1] = 255;

        if order.len() >= MAX {
            if let Some(oldest) = order.pop_front() {
                seen.remove(&oldest);
            }
        }
        seen.insert(new_nonce);
        order.push_back(new_nonce);

        // Oldest nonce (i=0) was evicted
        let mut oldest_nonce = [0u8; 12];
        oldest_nonce[0] = 0;
        assert!(!seen.contains(&oldest_nonce));

        // Nonce i=50 is still retained!
        assert!(seen.contains(&duplicate_nonce));
        // New nonce is present
        assert!(seen.contains(&new_nonce));
    }
}

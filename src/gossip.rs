use crate::config::GossipConfig;
use async_trait::async_trait;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use rand::{RngCore, thread_rng};

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

    pub async fn broadcast_threat_intel(&self, msg: ThreatIntelMessage) {
        if !self.config.enabled {
            return;
        }
        let Some(ref socket) = self.socket else {
            warn!("Gossip socket not initialized, cannot broadcast");
            return;
        };

        let mut psk_bytes = [0u8; 32];
        let psk_len = self.config.psk.len().min(32);
        psk_bytes[..psk_len].copy_from_slice(&self.config.psk.as_bytes()[..psk_len]);
        let key = Key::from(psk_bytes);
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
        let mut psk_bytes = [0u8; 32];
        let psk_len = psk.len().min(32);
        psk_bytes[..psk_len].copy_from_slice(&psk[..psk_len]);
        let key = Key::from(psk_bytes);
        let cipher = ChaCha20Poly1305::new(&key);

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
                    let nonce = Nonce::from(nonce_bytes);
                    let ciphertext_len = u16::from_le_bytes([buf[4 + NONCE_LEN], buf[4 + NONCE_LEN + 1]]) as usize;
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
                                    if let Some(ref h) = handler {
                                        h.on_threat_intel(&msg).await;
                                    }
                                }
                                Err(e) => debug!("Gossip: invalid payload from {src}: {e}"),
                            }
                        }
                        Err(_) => debug!("Gossip: decryption failed from {src} (possible forgery or wrong key)"),
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

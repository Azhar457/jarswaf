pub mod blocklist_manager;
pub mod commands;
pub mod config_manager;
pub mod gossip_manager;
pub mod honeypot_manager;
pub mod policy_engine;
pub mod rule_engine;
pub mod state;
pub mod ws_broadcaster;
pub mod certificate_manager;

pub use commands::{CommandError, CommandSender, CommandReceiver, ControlCommand, command_channel};
pub use state::{PublishedState, RuntimeConfig, RuleSet, DashboardMetrics};
pub use ws_broadcaster::{WsBroadcaster, WsEvent};

use blocklist_manager::BlocklistManager;
use config_manager::ConfigManager;
use policy_engine::PolicyEngine;
use rule_engine::RuleEngine;
use crate::data_bus::events::{DataEvent, EventReceiver};
use tracing::{error, info, warn};

/// The control bus — central decision maker
pub struct ControlBus {
    // Sub-managers
    blocklist: BlocklistManager,
    rules: RuleEngine,
    config: ConfigManager,
    policy: PolicyEngine,
    
    // Channels
    event_rx: Option<EventReceiver>,
    cmd_rx: Option<CommandReceiver>,
    
    // Metrics
    start_time: std::time::Instant,
    total_requests: std::sync::atomic::AtomicU64,
    blocked_requests: std::sync::atomic::AtomicU64,
}

impl ControlBus {
    /// Create new control bus
    pub fn new(
        state: PublishedState,
        config_path: String,
        rules_dir: String,
        anomaly_threshold: f64,
        scoring_mode: String,
    ) -> Self {
        let blocklist = BlocklistManager::new(state.clone());
        let rules = RuleEngine::new(state.clone());
        let config = ConfigManager::new(state.clone(), config_path, rules_dir);
        let policy = PolicyEngine::new(state, anomaly_threshold, scoring_mode);
        
        Self {
            blocklist,
            rules,
            config,
            policy,
            event_rx: None,
            cmd_rx: None,
            start_time: std::time::Instant::now(),
            total_requests: std::sync::atomic::AtomicU64::new(0),
            blocked_requests: std::sync::atomic::AtomicU64::new(0),
        }
    }
    
    /// Set event receiver (from data bus)
    pub fn set_event_rx(&mut self, rx: EventReceiver) {
        self.event_rx = Some(rx);
    }
    
    /// Set command receiver (from API layer)
    pub fn set_command_rx(&mut self, rx: CommandReceiver) {
        self.cmd_rx = Some(rx);
    }
    
    /// Get published state reference (for data bus reads)
    pub fn state(&self) -> &PublishedState {
        &self.blocklist.state
    }
    
    /// Run the control bus event loop
    pub async fn run(mut self) {
        info!("Control bus starting");
        
        let mut event_rx = self.event_rx.take().expect("Event receiver not set");
        let mut cmd_rx = self.cmd_rx.take().expect("Command receiver not set");
        
        let self_ptr = std::sync::Arc::new(tokio::sync::Mutex::new(self));
        let self_clone = self_ptr.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                let bus = self_clone.lock().await;
                bus.publish_metrics().await;
            }
        });
        
        // Main event loop
        let bus = self_ptr.clone();
        loop {
            tokio::select! {
                // Process data events
                event = event_rx.recv() => {
                    match event {
                        Some(event) => {
                            let mut bus = bus.lock().await;
                            bus.process_event(event).await;
                        }
                        None => {
                            error!("Event channel closed — data bus disconnected");
                            break;
                        }
                    }
                }
                
                // Process commands
                command = cmd_rx.recv() => {
                    match command {
                        Some(cmd) => {
                            let mut bus = bus.lock().await;
                            bus.process_command(cmd).await;
                        }
                        None => {
                            info!("Command channel closed — API layer disconnected");
                            break;
                        }
                    }
                }
            }
        }
        
        info!("Control bus stopped");
    }
    
    /// Process a data event
    async fn process_event(&mut self, event: DataEvent) {
        self.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        match &event {
            DataEvent::RequestInspected { .. } => {
                // Request allowed — nothing to do
            }
            
            DataEvent::RequestBlocked {
                request_id,
                client_ip,
                reason: _,
                rule_id,
            } => {
                self.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.blocklist.record_block(*client_ip).await;
                self.rules.record_trigger(rule_id).await;
                
                // Publish to WebSocket
                ws_broadcaster::get().publish(ws_broadcaster::WsEvent::Log {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    request_id: request_id.to_string(),
                    client_ip: client_ip.to_string(),
                    method: String::new(),
                    path: String::new(),
                    action: "BLOCK".to_string(),
                    rule_id: Some(rule_id.clone()),
                    score: 0.0,
                    latency_ms: 0.0,
                    vhost: String::new(),
                });
            }
            
            DataEvent::RequestForwarded { .. } => {
                // Could track backend latency
            }
            
            DataEvent::BackendError { backend, error, .. } => {
                warn!("Backend error: {} — {}", backend, error);
                ws_broadcaster::get().publish(ws_broadcaster::WsEvent::Alert {
                    level: "warning".to_string(),
                    message: format!("Backend error: {} — {}", backend, error),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    source: "proxy".to_string(),
                });
            }
            
            DataEvent::RateLimitExceeded { client_ip, .. } => {
                ws_broadcaster::get().publish(ws_broadcaster::WsEvent::Alert {
                    level: "info".to_string(),
                    message: format!("Rate limit exceeded: {}", client_ip),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    source: "rate_limiter".to_string(),
                });
            }
        }
        
        // Run policy engine
        let policy_commands = self.policy.evaluate(&event).await;
        for cmd in policy_commands {
            self.process_command(cmd).await;
        }
    }
    
    /// Process a command
    async fn process_command(&mut self, cmd: ControlCommand) {
        match cmd {
            // Config
            ControlCommand::ReloadConfig => {
                if let Err(e) = self.config.reload().await {
                    error!("Config reload failed: {}", e);
                }
            }
            ControlCommand::GetConfig(reply) => {
                let _ = reply.send(self.state().get_config().as_ref().clone());
            }
            ControlCommand::UpdateConfig(config) => {
                self.state().publish_config(config);
            }
            
            // Rules
            ControlCommand::GetRuleSet(reply) => {
                let _ = reply.send(self.state().get_rules().as_ref().clone());
            }
            ControlCommand::AddCustomRule { rule, reply } => {
                let _ = reply.send(self.rules.add_custom_rule(rule).await);
            }
            ControlCommand::RemoveCustomRule { id, reply } => {
                let _ = reply.send(self.rules.remove_custom_rule(&id).await);
            }
            ControlCommand::UpdateCustomRule { id, rule, reply } => {
                let _ = reply.send(self.rules.update_custom_rule(&id, rule).await);
            }
            ControlCommand::SetRuleEnabled { id, enabled, reply } => {
                let _ = reply.send(self.rules.set_rule_enabled(&id, enabled).await);
            }
            
            // Rate limits
            ControlCommand::AddRateLimitPolicy { policy, reply } => {
                let _ = reply.send(self.rules.add_rate_limit_policy(policy).await);
            }
            ControlCommand::RemoveRateLimitPolicy { name, reply } => {
                let _ = reply.send(self.rules.remove_rate_limit_policy(&name).await);
            }
            
            // Vhosts
            ControlCommand::GetVhosts(reply) => {
                let vhosts = self.state().get_rules().vhosts.clone();
                let _ = reply.send(vhosts);
            }
            ControlCommand::AddVhost { vhost, reply } => {
                let _ = reply.send(self.rules.add_vhost(vhost).await);
            }
            ControlCommand::UpdateVhost { name, vhost, reply } => {
                let _ = reply.send(self.rules.update_vhost(&name, vhost).await);
            }
            ControlCommand::RemoveVhost { name, reply } => {
                let _ = reply.send(self.rules.remove_vhost(&name).await);
            }
            
            // Blocklist
            ControlCommand::GetBlocklist(reply) => {
                let _ = reply.send(self.blocklist.list_ips().await);
            }
            ControlCommand::BlockIp { ip, duration, reason, source } => {
                self.blocklist.block_ip(ip, duration, reason, source).await;
            }
            ControlCommand::UnblockIp { ip } => {
                self.blocklist.unblock_ip(ip).await;
            }
            ControlCommand::ClearBlocklist => {
                self.blocklist.clear().await;
            }
            ControlCommand::SyncBlocklist { ips, source } => {
                self.blocklist.sync_blocklist(ips, source).await;
            }
            ControlCommand::IsBlocked { ip, reply } => {
                let _ = reply.send(self.blocklist.is_blocked(&ip).await);
            }
            
            // Metrics
            ControlCommand::GetMetrics(reply) => {
                let metrics = self.build_metrics().await;
                let _ = reply.send(metrics);
            }
            
            // Lifecycle
            ControlCommand::Shutdown => {
                info!("Shutdown command received");
            }
        }
    }
    
    /// Build dashboard metrics
    async fn build_metrics(&self) -> DashboardMetrics {
        DashboardMetrics {
            timestamp: chrono::Utc::now().to_rfc3339(),
            total_requests: self.total_requests.load(std::sync::atomic::Ordering::Relaxed),
            blocked_requests: self.blocked_requests.load(std::sync::atomic::Ordering::Relaxed),
            allowed_requests: self.total_requests.load(std::sync::atomic::Ordering::Relaxed)
                - self.blocked_requests.load(std::sync::atomic::Ordering::Relaxed),
            requests_per_sec: 0.0,
            blocked_per_sec: 0.0,
            active_connections: 0,
            top_blocked_ips: self.blocklist.top_blocked_ips(10).await,
            top_triggered_rules: self.rules.top_triggered_rules(10).await,
            blocklist_size: self.blocklist.len().await,
            uptime_secs: self.start_time.elapsed().as_secs(),
        }
    }
    
    /// Publish metrics to WebSocket
    async fn publish_metrics(&self) {
        let metrics = self.build_metrics().await;
        ws_broadcaster::get().publish(ws_broadcaster::WsEvent::Metrics {
            timestamp: metrics.timestamp,
            requests_per_sec: metrics.requests_per_sec,
            blocked_per_sec: metrics.blocked_per_sec,
            active_connections: metrics.active_connections,
            cpu_percent: 0.0,
            ram_percent: 0.0,
            top_blocked_ips: metrics.top_blocked_ips,
            top_triggered_rules: metrics.top_triggered_rules,
        });
    }
}

/// Initialize and return control bus components
pub fn init(
    config_path: String,
    rules_dir: String,
    anomaly_threshold: f64,
    scoring_mode: String,
) -> (ControlBus, PublishedState, CommandSender) {
    ws_broadcaster::init();
    
    let state = PublishedState::new(
        RuntimeConfig::default(),
        RuleSet::default(),
        state::BlocklistSnapshot::default(),
    );
    
    let (cmd_tx, cmd_rx) = command_channel(100);
    
    let mut bus = ControlBus::new(
        state.clone(),
        config_path,
        rules_dir,
        anomaly_threshold,
        scoring_mode,
    );
    bus.set_command_rx(cmd_rx);
    
    (bus, state, cmd_tx)
}

/// Start the control bus + kernel interface (blocking run loop).
/// Returns the published state (L3 → L2 lock-free reads), a clone of the
/// L2 → L3 event SENDER (so the request path can emit events), and the
/// command sender (L4 → L3). The bus itself owns the event receiver.
pub fn start_control_bus(
    config_path: String,
    rules_dir: String,
    anomaly_threshold: f64,
    scoring_mode: String,
) -> (PublishedState, crate::data_bus::events::EventSender, CommandSender) {
    // Initialize kernel (Layer 1) — load eBPF object lazily. This is where
    // XDP/RASP/TC subsystems get their shared BpfMapInterface (see lib.rs).
    crate::kernel::init();
    crate::kernel::start_flush_task(tokio::sync::watch::channel(false).1);

    let (mut bus, state, cmd_tx) = init(config_path, rules_dir, anomaly_threshold, scoring_mode);
    let (event_tx, event_rx) = crate::data_bus::events::event_channel(1000);
    bus.set_event_rx(event_rx);
    tokio::spawn(async move {
        bus.run().await;
    });

    (state, event_tx, cmd_tx)
}

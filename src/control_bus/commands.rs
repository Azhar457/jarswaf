use crate::control_bus::state::{
    BlockSource, CustomRuleDef, RateLimitPolicy, RuleSet, RuntimeConfig, VhostConfig,
};
use std::net::IpAddr;
use std::time::Duration;

/// Commands that can be sent to the control bus
#[derive(Debug)]
pub enum ControlCommand {
    // === CONFIG ===
    ReloadConfig,
    GetConfig(tokio::sync::oneshot::Sender<RuntimeConfig>),
    UpdateConfig(RuntimeConfig),

    // === RULES ===
    GetRuleSet(tokio::sync::oneshot::Sender<RuleSet>),
    AddCustomRule {
        rule: CustomRuleDef,
        reply: tokio::sync::oneshot::Sender<Result<String, CommandError>>,
    },
    RemoveCustomRule {
        id: String,
        reply: tokio::sync::oneshot::Sender<Result<(), CommandError>>,
    },
    UpdateCustomRule {
        id: String,
        rule: CustomRuleDef,
        reply: tokio::sync::oneshot::Sender<Result<(), CommandError>>,
    },
    SetRuleEnabled {
        id: String,
        enabled: bool,
        reply: tokio::sync::oneshot::Sender<Result<(), CommandError>>,
    },

    // === RATE LIMITS ===
    AddRateLimitPolicy {
        policy: RateLimitPolicy,
        reply: tokio::sync::oneshot::Sender<Result<(), CommandError>>,
    },
    RemoveRateLimitPolicy {
        name: String,
        reply: tokio::sync::oneshot::Sender<Result<(), CommandError>>,
    },

    // === VHOSTS ===
    GetVhosts(tokio::sync::oneshot::Sender<Vec<VhostConfig>>),
    AddVhost {
        vhost: VhostConfig,
        reply: tokio::sync::oneshot::Sender<Result<(), CommandError>>,
    },
    UpdateVhost {
        name: String,
        vhost: VhostConfig,
        reply: tokio::sync::oneshot::Sender<Result<(), CommandError>>,
    },
    RemoveVhost {
        name: String,
        reply: tokio::sync::oneshot::Sender<Result<(), CommandError>>,
    },

    // === BLOCKLIST ===
    GetBlocklist(tokio::sync::oneshot::Sender<Vec<IpAddr>>),
    BlockIp {
        ip: IpAddr,
        duration: Duration,
        reason: String,
        source: BlockSource,
    },
    UnblockIp {
        ip: IpAddr,
    },
    ClearBlocklist,
    SyncBlocklist {
        ips: Vec<IpAddr>,
        source: BlockSource,
    },
    IsBlocked {
        ip: IpAddr,
        reply: tokio::sync::oneshot::Sender<bool>,
    },

    // === METRICS ===
    GetMetrics(tokio::sync::oneshot::Sender<crate::control_bus::state::DashboardMetrics>),

    // === LIFECYCLE ===
    Shutdown,
}

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type CommandSender = tokio::sync::mpsc::Sender<ControlCommand>;
pub type CommandReceiver = tokio::sync::mpsc::Receiver<ControlCommand>;

pub fn command_channel(buffer: usize) -> (CommandSender, CommandReceiver) {
    tokio::sync::mpsc::channel(buffer)
}

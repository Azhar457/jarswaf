use thiserror::Error;

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("eBPF program load failed: {0}")]
    LoadFailed(String),

    #[error("eBPF map operation failed: {0}")]
    MapOperation(String),

    #[error("eBPF program not loaded")]
    NotLoaded,

    #[error("interface '{0}' not found")]
    InterfaceNotFound(String),

    #[error("invalid IP address: {0}")]
    InvalidIp(String),

    #[error("batch operation partially failed: {inserted} inserted, {failed} failed")]
    PartialBatch { inserted: usize, failed: usize },

    #[error("RASP event poll failed: {0}")]
    RaspPoll(String),
}

pub type KernelResult<T> = Result<T, KernelError>;

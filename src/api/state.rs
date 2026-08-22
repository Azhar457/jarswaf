use crate::api::auth::AuthService;
use crate::control_bus::commands::CommandSender;
use crate::control_bus::state::PublishedState;
use crate::control_bus::ws_broadcaster::WsBroadcaster;
use std::sync::Arc;

/// Shared state for all API handlers
#[derive(Clone)]
pub struct ApiState {
    /// Channel to send commands to control bus
    pub cmd_tx: CommandSender,

    /// Published state for read-only access
    pub published_state: PublishedState,

    /// Auth service
    pub auth: Arc<AuthService>,

    /// WebSocket broadcaster
    pub ws_broadcaster: &'static WsBroadcaster,

    /// Application start time
    pub started_at: std::time::Instant,

    /// Version string
    pub version: String,
}

impl ApiState {
    pub fn new(
        cmd_tx: CommandSender,
        published_state: PublishedState,
        auth: AuthService,
        ws_broadcaster: &'static WsBroadcaster,
        version: String,
    ) -> Self {
        Self {
            cmd_tx,
            published_state,
            auth: Arc::new(auth),
            ws_broadcaster,
            started_at: std::time::Instant::now(),
            version,
        }
    }
}

//! Phase-Based Request Processing Pipeline
//!
//! Mengganti monolithic request_filter dengan phase pipeline:
//!   Phase 1: REQUEST_HEADERS — header validation, IP rep, rate limit
//!   Phase 2: REQUEST_BODY  — body deep inspection, AST, DLP
//!   Phase 3: RESPONSE_HEADERS — security headers, leak detection
//!   Phase 4: RESPONSE_BODY — data exfiltration prevention
//!
//! Setiap phase bisa early-reject (block sebelum backend dipanggil).
//! Cocok dengan OWASP CRS 4-phase model.

/// Result dari satu phase handler
#[derive(Debug)]
pub enum PhaseResult {
    /// Lanjut ke phase berikutnya
    Continue,
    /// Block request — return response immediately
    Reject {
        status: u16,
        title: String,
        description: String,
        rule_id: String,
    },
}

/// Sebuah handler untuk satu phase
#[async_trait::async_trait]
pub trait PhaseHandler: Send + Sync {
    fn phase_id(&self) -> u8; // 1-4
    fn name(&self) -> &'static str;
    async fn handle(&self, ctx: &PhaseContext) -> PhaseResult;
}

/// Context yang di-pass ke setiap phase handler
#[derive(Debug, Clone)]
pub struct PhaseContext {
    pub client_ip: std::net::IpAddr,
    pub method: String,
    pub path: String,
    pub query: String,
    pub host: Option<String>,
    pub headers: ahash::AHashMap<String, String>,
    pub body: String,
    pub vhost_name: String,
    pub request_id: String,
    pub max_body: String,
    pub max_conns_per_ip: usize,
    pub bot_challenge_enabled: bool,
}

impl PhaseContext {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|s| s.as_str())
    }
}

// ── Built-in Phase Handlers ─────────────────────────────────

/// Phase 1: Direct IP access block
pub struct DirectIpBlockHandler;

#[async_trait::async_trait]
impl PhaseHandler for DirectIpBlockHandler {
    fn phase_id(&self) -> u8 {
        1
    }
    fn name(&self) -> &'static str {
        "direct-ip-block"
    }
    async fn handle(&self, ctx: &PhaseContext) -> PhaseResult {
        if let Some(host_str) = ctx.host.as_ref() {
            let clean_host = host_str.split(':').next().unwrap_or(host_str);
            if clean_host.parse::<std::net::IpAddr>().is_ok() {
                return PhaseResult::Reject {
                    status: 403,
                    title: "Access Denied".into(),
                    description: format!("Direct IP access block: {}", clean_host),
                    rule_id: "DIRECT-IP-001".into(),
                };
            }
        }
        PhaseResult::Continue
    }
}

/// Pipeline yang menjalankan phase handler secara berurutan
pub struct PhasePipeline {
    pub phases: Vec<Box<dyn PhaseHandler>>,
}

impl PhasePipeline {
    pub fn new() -> Self {
        Self { phases: Vec::new() }
    }

    pub fn register(mut self, handler: Box<dyn PhaseHandler>) -> Self {
        self.phases.push(handler);
        self
    }

    pub fn add_handler(&mut self, handler: Box<dyn PhaseHandler>) {
        self.phases.push(handler);
    }

    /// Run semua phase sampai salah satu Reject atau semua Continue
    pub async fn execute(&self, ctx: &PhaseContext) -> PhaseResult {
        for phase in &self.phases {
            tracing::trace!("Phase {}: {} — running", phase.phase_id(), phase.name());
            match phase.handle(ctx).await {
                PhaseResult::Continue => {
                    tracing::trace!("Phase {}: {} — PASS", phase.phase_id(), phase.name());
                    continue;
                }
                reject @ PhaseResult::Reject { .. } => {
                    tracing::warn!(
                        "Phase {}: {} — REJECT ({})",
                        phase.phase_id(),
                        phase.name(),
                        match &reject {
                            PhaseResult::Reject { rule_id, .. } => rule_id.as_str(),
                            _ => "",
                        }
                    );
                    return reject;
                }
            }
        }
        PhaseResult::Continue
    }
}

impl Default for PhasePipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PassPhase;
    #[async_trait::async_trait]
    impl PhaseHandler for PassPhase {
        fn phase_id(&self) -> u8 {
            1
        }
        fn name(&self) -> &'static str {
            "PassPhase"
        }
        async fn handle(&self, _ctx: &PhaseContext) -> PhaseResult {
            PhaseResult::Continue
        }
    }

    struct RejectPhase;
    #[async_trait::async_trait]
    impl PhaseHandler for RejectPhase {
        fn phase_id(&self) -> u8 {
            2
        }
        fn name(&self) -> &'static str {
            "RejectPhase"
        }
        async fn handle(&self, _ctx: &PhaseContext) -> PhaseResult {
            PhaseResult::Reject {
                status: 403,
                title: "Blocked".into(),
                description: "Test reject".into(),
                rule_id: "TEST-001".into(),
            }
        }
    }

    fn test_ctx() -> PhaseContext {
        PhaseContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET".into(),
            path: "/".into(),
            query: "".into(),
            host: Some("test.local".into()),
            headers: ahash::AHashMap::new(),
            body: "".into(),
            vhost_name: "test".into(),
            request_id: "test".into(),
            max_body: "1MB".into(),
            max_conns_per_ip: 100,
            bot_challenge_enabled: false,
        }
    }

    #[tokio::test]
    async fn test_pipeline_all_pass() {
        let pipeline = PhasePipeline::new()
            .register(Box::new(PassPhase))
            .register(Box::new(PassPhase));
        let result = pipeline.execute(&test_ctx()).await;
        assert!(matches!(result, PhaseResult::Continue));
    }

    #[tokio::test]
    async fn test_pipeline_early_reject() {
        let pipeline = PhasePipeline::new()
            .register(Box::new(PassPhase))
            .register(Box::new(RejectPhase))
            .register(Box::new(PassPhase)); // should not run
        let result = pipeline.execute(&test_ctx()).await;
        match result {
            PhaseResult::Reject { rule_id, .. } => {
                assert_eq!(rule_id, "TEST-001");
            }
            _ => panic!("expected Reject"),
        }
    }

    #[tokio::test]
    async fn test_pipeline_no_phases_continues() {
        let pipeline = PhasePipeline::new();
        let result = pipeline.execute(&test_ctx()).await;
        assert!(matches!(result, PhaseResult::Continue));
    }

    #[tokio::test]
    async fn test_direct_ip_block_handler_rejects_ip_host() {
        let handler = DirectIpBlockHandler;
        let mut ctx = test_ctx();
        ctx.host = Some("192.168.1.1".into());
        let result = handler.handle(&ctx).await;
        match result {
            PhaseResult::Reject {
                rule_id, status, ..
            } => {
                assert_eq!(rule_id, "DIRECT-IP-001");
                assert_eq!(status, 403);
            }
            _ => panic!("expected Reject"),
        }
    }

    #[tokio::test]
    async fn test_direct_ip_block_handler_passes_domain_host() {
        let handler = DirectIpBlockHandler;
        let ctx = test_ctx();
        let result = handler.handle(&ctx).await;
        assert!(matches!(result, PhaseResult::Continue));
    }
}

use super::context::InspectionContext;
use super::events::{DataEvent, EventSender};
use super::inspectors::Inspector;
use tracing::{debug, warn};

/// Configuration for the inspection chain
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Skip inspection for static assets
    pub skip_static_assets: bool,
    /// Maximum score before auto-blocking
    pub score_threshold: f64,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            skip_static_assets: true,
            score_threshold: 50.0,
        }
    }
}

/// The inspection chain that runs inspectors in priority order
pub struct InspectionChain {
    inspectors: Vec<Box<dyn Inspector>>,
    config: ChainConfig,
    event_tx: EventSender,
}

impl InspectionChain {
    pub fn new(config: ChainConfig, event_tx: EventSender) -> Self {
        Self {
            inspectors: Vec::new(),
            config,
            event_tx,
        }
    }

    /// Add a single inspector (inserts in priority order)
    pub fn add_inspector(&mut self, inspector: Box<dyn Inspector>) {
        self.inspectors.push(inspector);
        self.inspectors.sort_by_key(|i| i.priority());
    }

    /// Add multiple inspectors at once
    pub fn add_inspectors(&mut self, inspectors: Vec<Box<dyn Inspector>>) {
        for inspector in inspectors {
            self.inspectors.push(inspector);
        }
        self.inspectors.sort_by_key(|i| i.priority());
    }

    /// Run the inspection chain on a request context
    pub async fn inspect(&self, mut ctx: InspectionContext) -> InspectionContext {
        // Skip static assets if configured
        if self.config.skip_static_assets && ctx.is_static_asset() {
            self.emit_event(&ctx).await;
            return ctx;
        }

        for inspector in &self.inspectors {
            // Stop if verdict is already decisive
            if ctx.verdict.is_decisive() {
                break;
            }

            // Check if inspector should run for this request
            if !inspector.should_run(&ctx) {
                continue;
            }

            let result = inspector.inspect(&mut ctx).await;

            // Apply verdict if set
            if let Some(verdict) = result.verdict {
                if !ctx.verdict.is_decisive() {
                    ctx.verdict = verdict;
                }
            }

            // Record match and accumulate score if something was detected
            if result.score_delta != 0.0 || !result.details.is_empty() {
                ctx.add_match(
                    inspector.name(),
                    inspector.name(),
                    result.score_delta,
                    result.details,
                );
            }

            // Auto-block if accumulated score exceeds threshold
            if ctx.score >= self.config.score_threshold && !ctx.verdict.is_decisive() {
                debug!(
                    score = ctx.score,
                    threshold = self.config.score_threshold,
                    "Score threshold exceeded — auto-blocking"
                );
                ctx.set_block(
                    super::context::BlockReason::BehavioralAnomaly,
                    super::context::BlockAction::Reject403,
                );
            }
        }

        // Emit event for control bus
        self.emit_event(&ctx).await;

        ctx
    }

    /// Emit a DataEvent for the processed request
    async fn emit_event(&self, ctx: &InspectionContext) {
        let event = if ctx.verdict.is_block() {
            DataEvent::RequestBlocked {
                request_id: ctx.request_id,
                client_ip: ctx.client_ip,
                reason: format!("{:?}", ctx.verdict),
                rule_id: ctx
                    .matched_rules
                    .last()
                    .map(|r| r.rule_id.clone())
                    .unwrap_or_else(|| "UNKNOWN".to_string()),
            }
        } else {
            DataEvent::RequestInspected {
                request_id: ctx.request_id,
                client_ip: ctx.client_ip,
                vhost: ctx.vhost.clone(),
                verdict: super::events::VerdictSnapshot::from(&ctx.verdict),
                score: ctx.score,
                matched_rules: ctx
                    .matched_rules
                    .iter()
                    .map(super::events::RuleMatchSnapshot::from)
                    .collect(),
                latency_us: ctx.timestamp.elapsed().as_micros() as u64,
            }
        };

        if let Err(e) = self.event_tx.try_send(event) {
            warn!("Failed to send data event (channel full or closed): {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_bus::inspectors::InspectionResult;
    use async_trait::async_trait;
    use hyper::Method;

    struct AlwaysBlockInspector;

    #[async_trait]
    impl Inspector for AlwaysBlockInspector {
        fn name(&self) -> &str {
            "always_block"
        }
        fn priority(&self) -> u32 {
            1
        }

        async fn inspect(&self, _ctx: &mut InspectionContext) -> InspectionResult {
            InspectionResult::block(
                super::super::context::BlockReason::CustomRule("test".to_string()),
                super::super::context::BlockAction::Reject403,
                100.0,
                "always blocks".to_string(),
            )
        }
    }

    struct NeverRunInspector;

    #[async_trait]
    impl Inspector for NeverRunInspector {
        fn name(&self) -> &str {
            "never_run"
        }
        fn priority(&self) -> u32 {
            2
        }

        fn should_run(&self, _ctx: &InspectionContext) -> bool {
            false
        }

        async fn inspect(&self, _ctx: &mut InspectionContext) -> InspectionResult {
            panic!("Should never run");
        }
    }

    #[tokio::test]
    async fn test_chain_short_circuits_on_block() {
        let (tx, _rx) = super::super::events::event_channel(100);
        let mut chain = InspectionChain::new(ChainConfig::default(), tx);
        chain.add_inspector(Box::new(AlwaysBlockInspector));
        chain.add_inspector(Box::new(NeverRunInspector));

        let ctx = InspectionContext::new(
            "10.0.0.1".parse().unwrap(),
            Method::GET,
            "/test".to_string(),
            String::new(),
            hyper::HeaderMap::new(),
            None,
            "test.local".to_string(),
            12345,
        );

        let result = chain.inspect(ctx).await;
        assert!(result.verdict.is_block());
        assert_eq!(result.score, 100.0);
    }

    #[tokio::test]
    async fn test_chain_skips_static_assets() {
        let (tx, _rx) = super::super::events::event_channel(100);
        let config = ChainConfig {
            skip_static_assets: true,
            ..Default::default()
        };
        let mut chain = InspectionChain::new(config, tx);
        chain.add_inspector(Box::new(AlwaysBlockInspector));

        let ctx = InspectionContext::new(
            "10.0.0.1".parse().unwrap(),
            Method::GET,
            "/style.css".to_string(),
            String::new(),
            hyper::HeaderMap::new(),
            None,
            "test.local".to_string(),
            12345,
        );

        let result = chain.inspect(ctx).await;
        assert!(!result.verdict.is_block());
    }
}

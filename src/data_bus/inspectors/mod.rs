pub mod behavioral;
pub mod bot_detection;
pub mod command_injection;
pub mod custom_rules;
pub mod geoip;
pub mod ip_reputation;
pub mod lfi_rfi;
pub mod rate_limit;
pub mod sql_injection;
pub mod ssrf;
pub mod xss;

use crate::data_bus::context::InspectionContext;
use crate::data_bus::context::Verdict;
use async_trait::async_trait;

/// Result returned by an inspector
#[derive(Debug, Clone)]
pub struct InspectionResult {
    /// If set, this verdict will be applied to the context
    pub verdict: Option<Verdict>,
    /// Score delta to add to context score
    pub score_delta: f64,
    /// Human-readable details about what was detected
    pub details: String,
}

impl InspectionResult {
    /// Create a "no match" result
    pub fn clean() -> Self {
        Self {
            verdict: None,
            score_delta: 0.0,
            details: String::new(),
        }
    }

    /// Create a suspicious result (score but no block)
    pub fn suspicious(score: f64, details: String) -> Self {
        Self {
            verdict: None,
            score_delta: score,
            details,
        }
    }

    /// Create a block result
    pub fn block(
        reason: crate::data_bus::context::BlockReason,
        action: crate::data_bus::context::BlockAction,
        score: f64,
        details: String,
    ) -> Self {
        Self {
            verdict: Some(Verdict::Block { reason, action }),
            score_delta: score,
            details,
        }
    }
}

/// Trait that all inspectors must implement
#[async_trait]
pub trait Inspector: Send + Sync + 'static {
    /// Unique name of this inspector
    fn name(&self) -> &str;

    /// Priority (lower = runs first)
    fn priority(&self) -> u32;

    /// Return false to skip this inspector for the given request
    fn should_run(&self, ctx: &InspectionContext) -> bool {
        !ctx.is_static_asset()
    }

    /// Inspect the request and return result
    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult;
}

/// Create all default inspectors
/// Returns them in priority order
pub fn create_default_inspectors() -> Vec<Box<dyn Inspector>> {
    vec![
        Box::new(ip_reputation::IpReputationInspector::new()),
        Box::new(rate_limit::RateLimitInspector::new()),
        Box::new(geoip::GeoipInspector::new()),
        Box::new(bot_detection::BotDetectionInspector::new()),
        Box::new(sql_injection::SqlInjectionInspector::new()),
        Box::new(xss::XssInspector::new()),
        Box::new(lfi_rfi::LfiRfiInspector::new()),
        Box::new(ssrf::SsrfInspector::new()),
        Box::new(command_injection::CommandInjectionInspector::new()),
        Box::new(behavioral::BehavioralInspector::new()),
        Box::new(custom_rules::CustomRuleInspector::new()),
    ]
}

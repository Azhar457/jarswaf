use super::{InspectionResult, Inspector};
use crate::data_bus::context::InspectionContext;
use async_trait::async_trait;

/// Behavioral analysis inspector
///
/// Tracks per-IP behavior patterns over time.
/// Full implementation in Phase 3 when control bus provides state.
/// For now, this is a placeholder that does minimal analysis.
pub struct BehavioralInspector {
    _anomaly_threshold: f64,
}

impl BehavioralInspector {
    pub fn new() -> Self {
        Self {
            _anomaly_threshold: 5.0,
        }
    }
}

impl Default for BehavioralInspector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Inspector for BehavioralInspector {
    fn name(&self) -> &str {
        "BEHAVIORAL"
    }
    fn priority(&self) -> u32 {
        200
    } // Run late — needs data from other inspectors

    fn should_run(&self, ctx: &InspectionContext) -> bool {
        !ctx.is_static_asset()
    }

    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult {
        // Phase 3 will add:
        // - Per-IP request frequency tracking
        // - Path diversity analysis
        // - Error rate tracking
        // - Session anomaly detection
        // - Scoring integration with other inspectors' tags

        // For now, use simple heuristic based on accumulated tags
        let suspicious_tags = ctx
            .tags
            .iter()
            .filter(|t| t.starts_with("suspicious-"))
            .count();

        if suspicious_tags >= 3 {
            InspectionResult::suspicious(
                suspicious_tags as f64,
                format!("Multiple suspicious tags: {:?}", ctx.tags),
            )
        } else {
            InspectionResult::clean()
        }
    }
}

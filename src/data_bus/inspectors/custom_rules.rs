use super::{InspectionResult, Inspector};
use crate::data_bus::context::InspectionContext;
use async_trait::async_trait;

/// Custom rule inspector
///
/// Loads rules from YAML files and evaluates them.
/// Full implementation in Phase 3 when control bus manages rule loading.
pub struct CustomRuleInspector;

impl CustomRuleInspector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CustomRuleInspector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Inspector for CustomRuleInspector {
    fn name(&self) -> &str {
        "CUSTOM_RULES"
    }
    fn priority(&self) -> u32 {
        250
    } // Run last

    fn should_run(&self, ctx: &InspectionContext) -> bool {
        !ctx.is_static_asset()
    }

    async fn inspect(&self, _ctx: &mut InspectionContext) -> InspectionResult {
        // Phase 3 will add:
        // - Load rules from YAML
        // - Evaluate path/header/body conditions
        // - Apply match/action (block/redirect/log)

        InspectionResult::clean()
    }
}

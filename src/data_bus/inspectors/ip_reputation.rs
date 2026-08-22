use super::{InspectionResult, Inspector};
use crate::data_bus::context::{BlockAction, BlockReason, InspectionContext};
use async_trait::async_trait;

/// IP reputation inspector — checks if IP is in blocklist.
///
/// This is the cheapest check (priority 10 — runs first).
/// Reads blocklist state from control bus via ArcSwap (lock-free).
#[derive(Default)]
pub struct IpReputationInspector;

impl IpReputationInspector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Inspector for IpReputationInspector {
    fn name(&self) -> &str {
        "IP_REPUTATION"
    }
    fn priority(&self) -> u32 {
        10
    } // Run first — cheapest check

    fn should_run(&self, _ctx: &InspectionContext) -> bool {
        true // Always run — even for static assets
    }

    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult {
        // Check against kernel blocklist state (ArcSwap lock-free read).
        // In Phase 3, this will read from control bus published state.
        // For now, check against the kernel::BpfMapInterface blocklist_state
        // if kernel is initialized.
        let blocked = if let Some(ki) = crate::KERNEL_INTERFACE.as_ref() {
            let blocklist = ki.maps.blocklist_state.load();
            blocklist.contains(&ctx.client_ip)
        } else {
            false
        };

        if blocked {
            InspectionResult::block(
                BlockReason::IpBlocked,
                BlockAction::Reject403,
                0.0,
                format!("IP {} is in blocklist", ctx.client_ip),
            )
        } else {
            InspectionResult::clean()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_is_first() {
        let inspector = IpReputationInspector::new();
        assert_eq!(inspector.priority(), 10);
    }

    #[test]
    fn test_always_runs() {
        let inspector = IpReputationInspector::new();
        let ctx = InspectionContext::new(
            "10.0.0.1".parse().unwrap(),
            hyper::Method::GET,
            "/style.css".to_string(),
            String::new(),
            hyper::HeaderMap::new(),
            None,
            "test.local".to_string(),
            12345,
        );
        assert!(inspector.should_run(&ctx));
    }
}

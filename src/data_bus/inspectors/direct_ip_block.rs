use async_trait::async_trait;
use crate::data_bus::chain::{Inspector, InspectionResult};
use crate::data_bus::context::{InspectionContext, Verdict};

/// Blocks requests that target the WAF by its raw IP (e.g. `http://1.2.3.4/`) instead of a
/// configured hostname — a classic bypass / direct-access vector.
///
/// Equivalent to the legacy `rule_engine::phase::DirectIpBlockHandler`, ported to the
/// InspectionChain pipeline (Phase 1 of the old phase pipeline).
pub struct DirectIpBlockInspector;

#[async_trait]
impl Inspector for DirectIpBlockInspector {
    fn name(&self) -> &str {
        "DIRECT_IP_BLOCK"
    }

    fn priority(&self) -> u32 {
        // Run first — cheapest check, highest priority to block early.
        10
    }

    fn should_run(&self, ctx: &InspectionContext) -> bool {
        !matches!(ctx.verdict, Verdict::Block { .. } | Verdict::Redirect { .. })
    }

    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult {
        // The Host header (or ":authority") carries the authority the client requested.
        let host = ctx
            .headers
            .get("host")
            .or_else(|| ctx.headers.get(":authority"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if let Some(host_str) = host {
            let clean_host = host_str.split(':').next().unwrap_or(&host_str);
            if clean_host.parse::<std::net::IpAddr>().is_ok() {
                return InspectionResult {
                    verdict: Some(Verdict::Block {
                        reason: format!("Direct IP access block: {clean_host}"),
                        action: "Reject 403".to_string(),
                    }),
                    score_delta: 5.0,
                    rule_name: "DIRECT-IP-001".to_string(),
                };
            }
        }

        InspectionResult {
            verdict: None,
            score_delta: 0.0,
            rule_name: "DIRECT_IP_CLEAN".to_string(),
        }
    }
}
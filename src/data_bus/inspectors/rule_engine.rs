use async_trait::async_trait;
use crate::data_bus::chain::{Inspector, InspectionResult};
use crate::data_bus::context::{InspectionContext, Verdict};

/// Wrapper Inspector that runs the existing `RuleEngine::check_request` pipeline.
///
/// This is the compatibility bridge for the full InspectionChain migration: instead of
/// re-implementing every rule (SQLi, XSS, LFI, etc.) as a bespoke Inspector, we keep the
/// mature, production-tested rule evaluation behind one Inspector. Request inspection now
/// flows through the InspectionChain (data_bus), while the actual rule logic stays put.
///
/// `ponytail:` once this is stable, individual rules can be split out into dedicated
/// Inspectors (like SqlInjectionInspector) for finer per-rule scoring; until then this
/// preserves exact behavior for the 166+ existing tests.
pub struct RuleEngineInspector {
    pub engine: std::sync::Arc<crate::rules::RuleEngine>,
    pub enabled_rules: Vec<String>,
}

impl RuleEngineInspector {
    pub fn new(engine: std::sync::Arc<crate::rules::RuleEngine>, enabled_rules: Vec<String>) -> Self {
        Self {
            engine,
            enabled_rules,
        }
    }
}

#[async_trait]
impl Inspector for RuleEngineInspector {
    fn name(&self) -> &str {
        "RULE_ENGINE"
    }

    fn priority(&self) -> u32 {
        // Run after the cheap static inspectors, before expensive deep analysis.
        500
    }

    fn should_run(&self, ctx: &InspectionContext) -> bool {
        // Nothing to inspect if a prior inspector already blocked.
        !matches!(ctx.verdict, Verdict::Block { .. } | Verdict::Redirect { .. })
    }

    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult {
        // Reuse the existing request body decoding path: InspectionContext stores body as
        // Option<Bytes>; RuleEngine expects a &str.
        let body_str = ctx
            .body
            .as_ref()
            .map(|b| String::from_utf8_lossy(b.as_ref()).into_owned())
            .unwrap_or_default();

        // Convert hyper HeaderMap -> AHashMap<String,String> (the interface RuleEngine uses).
        let mut headers = ahash::AHashMap::with_capacity_and_hasher(16, Default::default());
        for (name, value) in ctx.headers.iter() {
            if let Ok(v) = value.to_str() {
                headers.insert(name.to_string(), v.to_string());
            }
        }

        let result = self.engine.check_request(
            &ctx.path,
            &ctx.query,
            &headers,
            &body_str,
            Some(ctx.client_ip),
            &ctx.method,
            &self.enabled_rules,
        );

        match result {
            Some((rule_id, reason)) => InspectionResult {
                verdict: Some(Verdict::Block {
                    reason,
                    action: format!("Reject 403 - {rule_id}"),
                }),
                score_delta: crate::rules::Severity::High.score() as f64,
                rule_name: rule_id,
            },
            None => InspectionResult {
                verdict: None,
                score_delta: 0.0,
                rule_name: "RULE_ENGINE_CLEAN".to_string(),
            },
        }
    }
}
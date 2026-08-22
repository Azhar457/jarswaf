pub mod direct_ip_block;
pub mod rule_engine;
pub mod sql_injection;

use std::sync::Arc;

use crate::data_bus::chain::Inspector;

/// Build the default inspector set for the WAF request pipeline.
///
/// Order matters (InspectionChain sorts by `priority()` during register, so pass any order):
/// - `RuleEngineInspector` (priority 500) runs the full existing rule set (SQLi, XSS, LFI,
///   etc.) — this is the compatibility bridge that keeps production coverage.
/// - `SqlInjectionInspector` (priority 100) is a cheap static pre-filter that can block very
///   obvious SQLi before the heavier rule engine runs.
pub fn default_inspectors(
    engine: Arc<crate::rules::RuleEngine>,
    enabled_rules: Vec<String>,
    sqli_patterns: Vec<String>,
    sqli_threshold: f64,
) -> Vec<Box<dyn Inspector>> {
    vec![
        Box::new(crate::data_bus::inspectors::sql_injection::SqlInjectionInspector::new(
            sqli_patterns,
            sqli_threshold,
        )),
        Box::new(crate::data_bus::inspectors::rule_engine::RuleEngineInspector::new(
            engine,
            enabled_rules,
        )),
    ]
}
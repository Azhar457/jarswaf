use axum::{extract::State, response::IntoResponse, Json};
use serde_json::json;

use crate::config;
use crate::controller::ControllerState;
use crate::rules::redteam::run_red_team_suite;
use crate::rules::RuleEngine;

pub async fn redteam_lab(State(state): State<ControllerState>) -> impl IntoResponse {
    let cfg = config::load_config(&state.config_path).unwrap_or_default();

    // Instantiate a temporary RuleEngine with current config to run tests
    let engine = RuleEngine::new(&cfg);

    // Run tests with all rules enabled
    let enabled_rules = vec!["*".to_string()];
    let report = run_red_team_suite(&engine, &enabled_rules);

    let mut results = Vec::new();
    for r in report.results {
        results.push(json!({
            "id": r.payload_id,
            "category": r.category,
            "description": r.description,
            "expected_block": r.expected_block,
            "actual_block": r.actual_block,
            "rule_matched": r.rule_matched,
            "correct": r.correct,
        }));
    }

    let summary = json!({
        "total": report.total,
        "passed": report.passed,
        "failed": report.failed,
        "detection_rate": format!("{:.1}%", (report.passed as f64 / report.total as f64) * 100.0),
        "details": results
    });

    Json(summary)
}

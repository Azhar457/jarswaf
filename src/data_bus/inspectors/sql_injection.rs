use async_trait::async_trait;
use crate::data_bus::chain::{Inspector, InspectionResult};
use crate::data_bus::context::{InspectionContext, Verdict};

pub struct SqlInjectionInspector {
    pub patterns: Vec<regex::Regex>,
    pub threshold: f64,
}

impl SqlInjectionInspector {
    pub fn new(patterns: Vec<String>, threshold: f64) -> Self {
        let compiled = patterns.into_iter()
            .filter_map(|p| regex::Regex::new(&p).ok())
            .collect();
        Self {
            patterns: compiled,
            threshold,
        }
    }
}

#[async_trait]
impl Inspector for SqlInjectionInspector {
    fn name(&self) -> &str {
        "SQL_INJECTION"
    }

    fn priority(&self) -> u32 {
        100
    }

    fn should_run(&self, ctx: &InspectionContext) -> bool {
        !ctx.path.ends_with(".css")
            && !ctx.path.ends_with(".js")
            && !ctx.path.ends_with(".png")
    }

    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult {
        let mut score_delta = 0.0;
        let mut matched = false;

        let targets = [&ctx.path, &ctx.query];
        for target in &targets {
            for pattern in &self.patterns {
                if pattern.is_match(target) {
                    score_delta += 10.0;
                    matched = true;
                }
            }
        }

        let verdict = if score_delta >= self.threshold {
            Some(Verdict::Block {
                reason: "SQL Injection pattern match threshold exceeded".to_string(),
                action: "Reject 403".to_string(),
            })
        } else {
            None
        };

        InspectionResult {
            verdict,
            score_delta,
            rule_name: if matched { "SQL_INJECTION_MATCH".to_string() } else { "SQL_INJECTION_CLEAN".to_string() },
        }
    }
}

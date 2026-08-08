use async_trait::async_trait;
use super::context::InspectionContext;

#[derive(Debug, Clone)]
pub struct InspectionResult {
    pub verdict: Option<super::context::Verdict>,
    pub score_delta: f64,
    pub rule_name: String,
}

#[async_trait]
pub trait Inspector: Send + Sync {
    fn name(&self) -> &str;
    fn priority(&self) -> u32;
    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult;
    fn should_run(&self, _ctx: &InspectionContext) -> bool {
        true
    }
}

pub struct InspectionChain {
    pub inspectors: Vec<Box<dyn Inspector>>,
}

impl InspectionChain {
    pub fn new() -> Self {
        Self {
            inspectors: Vec::new(),
        }
    }

    pub fn register(&mut self, inspector: Box<dyn Inspector>) {
        self.inspectors.push(inspector);
        self.inspectors.sort_by_key(|i| i.priority());
    }

    pub async fn run(&self, mut ctx: InspectionContext) -> InspectionContext {
        for inspector in &self.inspectors {
            if !inspector.should_run(&ctx) {
                continue;
            }

            match ctx.verdict {
                super::context::Verdict::Block { .. } | super::context::Verdict::Redirect { .. } => break,
                _ => {}
            }

            let result = inspector.inspect(&mut ctx).await;
            if let Some(verdict) = result.verdict {
                ctx.verdict = verdict;
            }
            ctx.score += result.score_delta;
            ctx.matched_rules.push(result.rule_name);
        }

        ctx
    }
}
impl Default for InspectionChain {
    fn default() -> Self {
        Self::new()
    }
}

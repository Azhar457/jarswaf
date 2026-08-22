use super::{InspectionResult, Inspector};
use crate::data_bus::context::{BlockAction, BlockReason, InspectionContext};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;

static CMDI_PATTERNS: Lazy<Vec<(f64, Regex)>> = Lazy::new(|| {
    vec![
        // Command separators
        (
            25.0,
            r";\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php)",
        ),
        (
            25.0,
            r"\|\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|netcat|bash|sh)",
        ),
        (25.0, r"\|\|\s*(cat|ls|id|whoami|uname)"),
        (25.0, r"&&\s*(cat|ls|id|whoami|uname)"),
        // Backtick / $() execution
        (20.0, r"`[^`]+`"),
        (20.0, r"\$\([^)]+\)"),
        // Common commands
        (25.0, r"(?i)/bin/(sh|bash|dash|zsh|csh)"),
        (25.0, r"(?i)/usr/bin/(id|whoami|curl|wget|python)"),
        (20.0, r"(?i)\bping\s+-[cn]\s+\d+"),
        (20.0, r"(?i)\bnslookup\s+"),
        (20.0, r"(?i)\bdig\s+"),
        // Windows commands
        (25.0, r"(?i)\bcmd\.exe\b"),
        (25.0, r"(?i)\bpowershell\b"),
        (20.0, r"(?i)\bnet\s+user\b"),
        (20.0, r"(?i)\btype\s+[A-Za-z]:\\"),
        // Encoded variants
        (20.0, r"%0[aAdD]"),            // Newline injection
        (15.0, r"(?i)%2[fF]bin%2[fF]"), // /bin/ encoded
    ]
    .into_iter()
    .filter_map(|(score, pat)| Regex::new(pat).ok().map(|r| (score, r)))
    .collect()
});

pub struct CommandInjectionInspector {
    block_threshold: f64,
}

impl CommandInjectionInspector {
    pub fn new() -> Self {
        Self {
            block_threshold: 25.0,
        }
    }
}

impl Default for CommandInjectionInspector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Inspector for CommandInjectionInspector {
    fn name(&self) -> &str {
        "COMMAND_INJECTION"
    }
    fn priority(&self) -> u32 {
        140
    }

    fn should_run(&self, ctx: &InspectionContext) -> bool {
        !ctx.is_static_asset()
    }

    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult {
        let target = ctx.full_path();
        let mut total_score = 0.0;
        let mut matches = Vec::new();

        for (score, pattern) in CMDI_PATTERNS.iter() {
            if pattern.is_match(&target) {
                total_score += score;
                matches.push(pattern.as_str());
            }
        }

        // Check body for POST/PUT
        if matches!(
            ctx.method,
            hyper::Method::POST | hyper::Method::PUT | hyper::Method::PATCH
        ) {
            if let Some(body) = &ctx.body {
                if let Ok(body_str) = std::str::from_utf8(body) {
                    let sample = &body_str[..body_str.len().min(8192)];
                    for (score, pattern) in CMDI_PATTERNS.iter() {
                        if pattern.is_match(sample) {
                            total_score += score;
                            matches.push(pattern.as_str());
                        }
                    }
                }
            }
        }

        if total_score >= self.block_threshold {
            InspectionResult::block(
                BlockReason::CommandInjection,
                BlockAction::Reject403,
                total_score,
                format!("CMDI patterns: {:?}", &matches[..matches.len().min(3)]),
            )
        } else if total_score > 0.0 {
            InspectionResult::suspicious(total_score, matches.join(", "))
        } else {
            InspectionResult::clean()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(path: &str) -> InspectionContext {
        InspectionContext::new(
            "10.0.0.1".parse().unwrap(),
            hyper::Method::GET,
            path.to_string(),
            String::new(),
            hyper::HeaderMap::new(),
            None,
            "test.local".to_string(),
            12345,
        )
    }

    #[tokio::test]
    async fn test_blocks_semicolon_command() {
        let inspector = CommandInjectionInspector::new();
        let mut ctx = make_ctx("/ping?host=127.0.0.1;cat%20/etc/passwd");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_some());
    }

    #[tokio::test]
    async fn test_blocks_backticks() {
        let inspector = CommandInjectionInspector::new();
        let mut ctx = make_ctx("/lookup?name=`id`");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.score_delta > 0.0);
    }

    #[tokio::test]
    async fn test_clean_path() {
        let inspector = CommandInjectionInspector::new();
        let mut ctx = make_ctx("/api/ping?host=example.com");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_none());
    }
}

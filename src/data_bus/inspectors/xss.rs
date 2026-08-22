use super::{InspectionResult, Inspector};
use crate::data_bus::context::{BlockAction, BlockReason, InspectionContext};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;

static XSS_PATTERNS: Lazy<Vec<(f64, Regex)>> = Lazy::new(|| {
    vec![
        // High confidence
        (30.0, r"(?i)<script[\s>]"),
        (30.0, r"(?i)</script>"),
        (30.0, r"(?i)javascript\s*:"),
        (30.0, r"(?i)vbscript\s*:"),
        (30.0, r"(?i)\bon\w+\s*="), // onerror=, onload=, onclick=, etc.
        (30.0, r"(?i)<iframe[\s>]"),
        (30.0, r"(?i)<object[\s>]"),
        (30.0, r"(?i)<embed[\s>]"),
        (30.0, r"(?i)<svg[\s/].*\bon\w+\s*="),
        (30.0, r"(?i)expression\s*\("), // CSS expression
        // Medium confidence
        (15.0, r"(?i)<img\s[^>]*\bon\w+\s*="),
        (15.0, r"(?i)<body\s[^>]*\bon\w+\s*="),
        (15.0, r"(?i)<input\s[^>]*\bon\w+\s*="),
        (15.0, r"(?i)document\.(cookie|location|write)"),
        (15.0, r"(?i)window\.(location|open)"),
        (15.0, r"(?i)\.innerHTML\s*="),
        (10.0, r"(?i)eval\s*\("),
        (10.0, r"(?i)setTimeout\s*\("),
        (10.0, r"(?i)setInterval\s*\("),
        // Low confidence
        (5.0, r"(?i)<\w+\s"),   // Any HTML tag (very generic)
        (5.0, r"(?i)&#x?\d+;"), // HTML entities
    ]
    .into_iter()
    .filter_map(|(score, pat)| Regex::new(pat).ok().map(|r| (score, r)))
    .collect()
});

pub struct XssInspector {
    block_threshold: f64,
}

impl XssInspector {
    pub fn new() -> Self {
        Self {
            block_threshold: 30.0,
        }
    }
}

impl Default for XssInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl XssInspector {
    fn check_target(&self, target: &str) -> InspectionResult {
        let mut total_score = 0.0;
        let mut matches = Vec::new();

        for (score, pattern) in XSS_PATTERNS.iter() {
            if pattern.is_match(target) {
                total_score += score;
                matches.push(pattern.as_str());
            }
        }

        if total_score >= self.block_threshold {
            InspectionResult::block(
                BlockReason::Xss,
                BlockAction::Reject403,
                total_score,
                format!("XSS patterns: {:?}", &matches[..matches.len().min(3)]),
            )
        } else if total_score > 0.0 {
            InspectionResult::suspicious(total_score, matches.join(", "))
        } else {
            InspectionResult::clean()
        }
    }
}

#[async_trait]
impl Inspector for XssInspector {
    fn name(&self) -> &str {
        "XSS"
    }
    fn priority(&self) -> u32 {
        110
    }

    fn should_run(&self, ctx: &InspectionContext) -> bool {
        !ctx.is_static_asset()
    }

    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult {
        let target = ctx.full_path();
        let path_result = self.check_target(&target);
        if path_result.verdict.is_some() {
            return path_result;
        }

        // Check headers
        for header_name in &["referer", "x-forwarded-for"] {
            if let Some(value) = ctx.header_str(header_name) {
                let header_result = self.check_target(&value);
                if header_result.verdict.is_some() {
                    return header_result;
                }
            }
        }

        // Check body
        if matches!(
            ctx.method,
            hyper::Method::POST | hyper::Method::PUT | hyper::Method::PATCH
        ) {
            if let Some(body) = &ctx.body {
                if let Ok(body_str) = std::str::from_utf8(body) {
                    let sample = &body_str[..body_str.len().min(8192)];
                    let body_result = self.check_target(sample);
                    if body_result.verdict.is_some() {
                        return body_result;
                    }
                }
            }
        }

        path_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_xss_ctx(path: &str) -> InspectionContext {
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
    async fn test_blocks_script_tag() {
        let inspector = XssInspector::new();
        let mut ctx = make_xss_ctx("/search?q=<script>alert(1)</script>");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_some());
    }

    #[tokio::test]
    async fn test_blocks_javascript_protocol() {
        let inspector = XssInspector::new();
        let mut ctx = make_xss_ctx("/redirect?url=javascript:alert(1)");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_some());
    }

    #[tokio::test]
    async fn test_blocks_event_handler() {
        let inspector = XssInspector::new();
        let mut ctx = make_xss_ctx("/page?name=<img onerror=alert(1) src=x>");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_some());
    }

    #[tokio::test]
    async fn test_clean_path() {
        let inspector = XssInspector::new();
        let mut ctx = make_xss_ctx("/api/users");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_none());
    }
}

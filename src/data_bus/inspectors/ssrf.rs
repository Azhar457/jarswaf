use super::{InspectionResult, Inspector};
use crate::data_bus::context::{BlockAction, BlockReason, InspectionContext};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;

static SSRF_PATTERNS: Lazy<Vec<(f64, Regex)>> = Lazy::new(|| {
    vec![
        // Cloud metadata endpoints
        (30.0, r"(?i)169\.254\.169\.254"),
        (30.0, r"(?i)metadata\.google\.internal"),
        (30.0, r"(?i)100\.100\.100\.200"), // Alibaba Cloud
        // Localhost variants
        (30.0, r"(?i)(https?://)?localhost[:/]"),
        (30.0, r"(?i)(https?://)?127\.0\.0\.\d+"),
        (30.0, r"(?i)(https?://)?0\.0\.0\.0"),
        (30.0, r"(?i)(https?://)?0x7f"),
        (30.0, r"(?i)(https?://)?017700000001"), // Octal 127.0.0.1
        (30.0, r"(?i)(https?://)?2130706433"),   // Decimal 127.0.0.1
        (30.0, r"(?i)(https?://)\[::1?\]"),      // IPv6 loopback
        // Internal networks
        (25.0, r"(?i)(https?://)?10\.\d+\.\d+\.\d+"),
        (25.0, r"(?i)(https?://)?172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"),
        (25.0, r"(?i)(https?://)?192\.168\.\d+\.\d+"),
        // Dangerous protocols
        (30.0, r"(?i)gopher://"),
        (30.0, r"(?i)file:///"),
        (25.0, r"(?i)dict://"),
        (25.0, r"(?i)ldap://"),
        (25.0, r"(?i)tftp://"),
        // DNS rebinding indicators
        (20.0, r"(?i)\.internal[:/]"),
        (20.0, r"(?i)\.local[:/]"),
    ]
    .into_iter()
    .filter_map(|(score, pat)| Regex::new(pat).ok().map(|r| (score, r)))
    .collect()
});

pub struct SsrfInspector {
    block_threshold: f64,
}

impl SsrfInspector {
    pub fn new() -> Self {
        Self {
            block_threshold: 25.0,
        }
    }
}

impl Default for SsrfInspector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Inspector for SsrfInspector {
    fn name(&self) -> &str {
        "SSRF"
    }
    fn priority(&self) -> u32 {
        130
    }

    fn should_run(&self, ctx: &InspectionContext) -> bool {
        !ctx.is_static_asset()
    }

    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult {
        let target = ctx.full_path();
        let mut total_score = 0.0;
        let mut matches = Vec::new();

        for (score, pattern) in SSRF_PATTERNS.iter() {
            if pattern.is_match(&target) {
                total_score += score;
                matches.push(pattern.as_str());
            }
        }

        // Also check referer and any URL-like headers
        for header_name in &["referer", "x-forwarded-for", "x-original-url"] {
            if let Some(value) = ctx.header_str(header_name) {
                for (score, pattern) in SSRF_PATTERNS.iter() {
                    if pattern.is_match(&value) {
                        total_score += score;
                        matches.push(pattern.as_str());
                    }
                }
            }
        }

        if total_score >= self.block_threshold {
            InspectionResult::block(
                BlockReason::Ssrf,
                BlockAction::Reject403,
                total_score,
                format!("SSRF patterns: {:?}", &matches[..matches.len().min(3)]),
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
    async fn test_blocks_localhost() {
        let inspector = SsrfInspector::new();
        let mut ctx = make_ctx("/fetch?url=http://localhost/admin");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_some());
    }

    #[tokio::test]
    async fn test_blocks_cloud_metadata() {
        let inspector = SsrfInspector::new();
        let mut ctx = make_ctx("/proxy?url=http://169.254.169.254/latest/meta-data/");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_some());
    }

    #[tokio::test]
    async fn test_blocks_internal_ip() {
        let inspector = SsrfInspector::new();
        let mut ctx = make_ctx("/webhook?url=http://192.168.1.1:8080/admin");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_some());
    }

    #[tokio::test]
    async fn test_clean_external_url() {
        let inspector = SsrfInspector::new();
        let mut ctx = make_ctx("/fetch?url=https://api.example.com/data");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_none());
    }
}

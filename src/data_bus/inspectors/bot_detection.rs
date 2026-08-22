use super::{InspectionResult, Inspector};
use crate::data_bus::context::{BlockAction, BlockReason, InspectionContext};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;

static BOT_PATTERNS: Lazy<Vec<(f64, Regex)>> = Lazy::new(|| {
    vec![
        // Known bad bots / scanners (30 pts = instant block)
        (
            30.0,
            r"(?i)(masscan|nmap|nikto|sqlmap|dirbuster|gobuster|wfuzz|hydra|medusa|zgrab|zmap)",
        ),
        (
            30.0,
            r"(?i)(acunetix|nessus|openvas|qualys|burpsuite|owasp|zap)",
        ),
        // Suspicious user agents (10 pts each)
        (10.0, r"(?i)^curl/"),
        (10.0, r"(?i)^wget/"),
        (10.0, r"(?i)^python-requests/"),
        (10.0, r"(?i)^go-http-client/"),
        (8.0, r"(?i)^java/"),
        (8.0, r"(?i)^ruby"),
        (8.0, r"(?i)^perl"),
        // Empty user agent
        (5.0, r"^$"),
    ]
    .into_iter()
    .filter_map(|(score, pat)| Regex::new(pat).ok().map(|r| (score, r)))
    .collect()
});

pub struct BotDetectionInspector {
    block_threshold: f64,
    challenge_threshold: f64,
}

impl BotDetectionInspector {
    pub fn new() -> Self {
        Self {
            block_threshold: 30.0,
            challenge_threshold: 10.0,
        }
    }
}

impl Default for BotDetectionInspector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Inspector for BotDetectionInspector {
    fn name(&self) -> &str {
        "BOT_DETECTION"
    }
    fn priority(&self) -> u32 {
        70
    }

    fn should_run(&self, ctx: &InspectionContext) -> bool {
        !ctx.is_static_asset()
    }

    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult {
        let ua = ctx.user_agent().unwrap_or_default();
        let mut total_score = 0.0;
        let mut matches = Vec::new();

        for (score, pattern) in BOT_PATTERNS.iter() {
            if pattern.is_match(&ua) {
                total_score += score;
                matches.push(pattern.as_str());
            }
        }

        if total_score >= self.block_threshold {
            ctx.add_tag("bot");
            InspectionResult::block(
                BlockReason::BotDetected,
                BlockAction::Reject403,
                total_score,
                format!("Bot detected: {:?}", matches),
            )
        } else if total_score >= self.challenge_threshold {
            ctx.add_tag("suspicious-ua");
            InspectionResult::suspicious(total_score, format!("Suspicious UA: {:?}", matches))
        } else {
            InspectionResult::clean()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    fn make_ctx_with_ua(ua: &str) -> InspectionContext {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", ua.parse().unwrap());
        InspectionContext::new(
            "10.0.0.1".parse().unwrap(),
            hyper::Method::GET,
            "/".to_string(),
            String::new(),
            headers,
            None,
            "test.local".to_string(),
            12345,
        )
    }

    #[tokio::test]
    async fn test_blocks_sqlmap() {
        let inspector = BotDetectionInspector::new();
        let mut ctx = make_ctx_with_ua("sqlmap/1.7");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_some());
    }

    #[tokio::test]
    async fn test_suspicious_curl() {
        let inspector = BotDetectionInspector::new();
        let mut ctx = make_ctx_with_ua("curl/7.88");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.score_delta > 0.0);
        assert!(result.verdict.is_none()); // Below block threshold
    }

    #[tokio::test]
    async fn test_clean_browser() {
        let inspector = BotDetectionInspector::new();
        let mut ctx = make_ctx_with_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_none());
        assert_eq!(result.score_delta, 0.0);
    }
}

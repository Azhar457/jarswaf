use super::{InspectionResult, Inspector};
use crate::data_bus::context::{BlockAction, BlockReason, InspectionContext};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;

static LFI_PATTERNS: Lazy<Vec<(f64, Regex)>> = Lazy::new(|| {
    vec![
        // Path traversal
        (30.0, r"\.\./\.\./"),   // ../../
        (30.0, r"\.\.\\\.\.\\"), // ..\..\
        (25.0, r"%2e%2e[/\\%]"), // URL encoded
        (25.0, r"%252e%252e"),   // Double encoded
        // Sensitive files
        (30.0, r"(?i)/etc/(passwd|shadow|hosts|group)"),
        (30.0, r"(?i)/proc/(self|version|cmdline)"),
        (30.0, r"(?i)/(boot|win)\.ini"),
        (25.0, r"(?i)\.(htaccess|htpasswd|env)$"),
        (25.0, r"(?i)/wp-config\.php"),
        // PHP wrappers
        (30.0, r"(?i)php://(filter|input|data)"),
        (30.0, r"(?i)expect://"),
        (30.0, r"(?i)zip://"),
        (25.0, r"(?i)phar://"),
        // Null bytes
        (30.0, r"%00"),
    ]
    .into_iter()
    .filter_map(|(score, pat)| Regex::new(pat).ok().map(|r| (score, r)))
    .collect()
});

static RFI_PATTERNS: Lazy<Vec<(f64, Regex)>> = Lazy::new(|| {
    vec![
        (30.0, r"(?i)(https?|ftp)://[^/\s]+\.(php|asp|jsp|txt)"),
        (25.0, r"(?i)file=https?://"),
        (25.0, r"(?i)page=https?://"),
        (25.0, r"(?i)url=https?://"),
        (20.0, r"(?i)data://text/plain"),
    ]
    .into_iter()
    .filter_map(|(score, pat)| Regex::new(pat).ok().map(|r| (score, r)))
    .collect()
});

pub struct LfiRfiInspector {
    block_threshold: f64,
}

impl LfiRfiInspector {
    pub fn new() -> Self {
        Self {
            block_threshold: 25.0,
        }
    }
}

impl Default for LfiRfiInspector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Inspector for LfiRfiInspector {
    fn name(&self) -> &str {
        "LFI_RFI"
    }
    fn priority(&self) -> u32 {
        120
    }

    fn should_run(&self, ctx: &InspectionContext) -> bool {
        !ctx.is_static_asset()
    }

    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult {
        let target = ctx.full_path();
        let mut total_score = 0.0;
        let mut matches = Vec::new();

        for (score, pattern) in LFI_PATTERNS.iter() {
            if pattern.is_match(&target) {
                total_score += score;
                let pat_str = pattern.as_str();
                matches.push(format!("LFI:{}", &pat_str[..pat_str.len().min(20)]));
            }
        }

        for (score, pattern) in RFI_PATTERNS.iter() {
            if pattern.is_match(&target) {
                total_score += score;
                let pat_str = pattern.as_str();
                matches.push(format!("RFI:{}", &pat_str[..pat_str.len().min(20)]));
            }
        }

        if total_score >= self.block_threshold {
            let reason = if matches.iter().any(|m| m.starts_with("RFI")) {
                BlockReason::Rfi
            } else {
                BlockReason::Lfi
            };
            InspectionResult::block(
                reason,
                BlockAction::Reject403,
                total_score,
                matches.join(", "),
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
    async fn test_blocks_path_traversal() {
        let inspector = LfiRfiInspector::new();
        let mut ctx = make_ctx("/download?file=../../../etc/passwd");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_some());
    }

    #[tokio::test]
    async fn test_blocks_php_wrapper() {
        let inspector = LfiRfiInspector::new();
        let mut ctx = make_ctx("/page?file=php://filter/convert.base64-encode/resource=index.php");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_some());
    }

    #[tokio::test]
    async fn test_clean_path() {
        let inspector = LfiRfiInspector::new();
        let mut ctx = make_ctx("/api/users/123");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_none());
    }
}

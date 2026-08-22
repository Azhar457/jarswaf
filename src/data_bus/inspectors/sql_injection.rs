use super::{InspectionResult, Inspector};
use crate::data_bus::context::{BlockAction, BlockReason, InspectionContext};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;

static SQLI_PATTERNS: Lazy<Vec<(f64, Regex)>> = Lazy::new(|| {
    vec![
        // High confidence (30+ pts each — single match = block)
        (30.0, r"(?i)\bUNION\s+(ALL\s+)?SELECT\b"),
        (30.0, r"(?i)\bSELECT\s+.+\s+FROM\s+\w+"),
        (30.0, r"(?i)\bINSERT\s+INTO\b"),
        (30.0, r"(?i)\bDROP\s+(TABLE|DATABASE)\b"),
        (30.0, r"(?i)\bDELETE\s+FROM\b"),
        (30.0, r"(?i)\bUPDATE\s+\w+\s+SET\b"),
        (30.0, r"(?i);\s*EXEC(UTE)?\s"),
        (30.0, r"(?i)\bxp_cmdshell\b"),
        (30.0, r"(?i)\bLOAD_FILE\s*\("),
        (30.0, r"(?i)\bINTO\s+(OUT|DUMP)FILE\b"),
        // Medium confidence (10-20 pts)
        (20.0, r"(?i)\bOR\s+[\d']+\s*=\s*[\d']+"),
        (20.0, r"(?i)\bAND\s+[\d']+\s*=\s*[\d']+"),
        (15.0, r"(?i)\bSLEEP\s*\(\d+\)"),
        (15.0, r"(?i)\bBENCHMARK\s*\("),
        (15.0, r"(?i)\bWAITFOR\s+DELAY\b"),
        (10.0, r"(?i)\bHAVING\s+\d"),
        (10.0, r"(?i)\bGROUP\s+BY\s+\d"),
        (10.0, r"(?i)\bORDER\s+BY\s+\d"),
        // Low confidence (5 pts — need accumulation)
        (10.0, r"--\s*$"),
        (5.0, r"(?i)\bCONCAT\s*\("),
        (5.0, r"(?i)\bCHAR\s*\(\d"),
        (5.0, r"(?i)\bCONVERT\s*\("),
        (5.0, r"'%27"),
    ]
    .into_iter()
    .filter_map(|(score, pat)| Regex::new(pat).ok().map(|r| (score, r)))
    .collect()
});

pub struct SqlInjectionInspector {
    block_threshold: f64,
}

impl SqlInjectionInspector {
    pub fn new() -> Self {
        Self {
            block_threshold: 30.0,
        }
    }
}

impl Default for SqlInjectionInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlInjectionInspector {
    fn check_target(&self, target: &str) -> InspectionResult {
        let mut total_score = 0.0;
        let mut matches = Vec::new();

        for (score, pattern) in SQLI_PATTERNS.iter() {
            if pattern.is_match(target) {
                total_score += score;
                matches.push(pattern.as_str());
            }
        }

        if total_score >= self.block_threshold {
            InspectionResult::block(
                BlockReason::SqlInjection,
                BlockAction::Reject403,
                total_score,
                format!("SQLi patterns: {:?}", &matches[..matches.len().min(3)]),
            )
        } else if total_score > 0.0 {
            InspectionResult::suspicious(total_score, matches.join(", "))
        } else {
            InspectionResult::clean()
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
        !ctx.is_static_asset()
    }

    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult {
        // Check path + query
        let target = ctx.full_path();
        let path_result = self.check_target(&target);
        if path_result.verdict.is_some() {
            return path_result;
        }

        // Check common attack headers
        for header_name in &["referer", "x-forwarded-for", "x-original-url"] {
            if let Some(value) = ctx.header_str(header_name) {
                let header_result = self.check_target(&value);
                if header_result.verdict.is_some() {
                    return header_result;
                }
            }
        }

        // Check body for POST/PUT/PATCH
        if matches!(
            ctx.method,
            hyper::Method::POST | hyper::Method::PUT | hyper::Method::PATCH
        ) {
            if let Some(body) = &ctx.body {
                if let Ok(body_str) = std::str::from_utf8(body) {
                    // Only check first 8KB of body
                    let sample = &body_str[..body_str.len().min(8192)];
                    let body_result = self.check_target(sample);
                    if body_result.verdict.is_some() {
                        return body_result;
                    }
                }
            }
        }

        // Return accumulated suspicious score from path/headers even if no block
        path_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    fn make_sqli_ctx(path: &str) -> InspectionContext {
        InspectionContext::new(
            "10.0.0.1".parse().unwrap(),
            hyper::Method::GET,
            path.to_string(),
            String::new(),
            HeaderMap::new(),
            None,
            "test.local".to_string(),
            12345,
        )
    }

    #[tokio::test]
    async fn test_blocks_union_select() {
        let inspector = SqlInjectionInspector::new();
        let mut ctx = make_sqli_ctx("/user?id=1 UNION SELECT * FROM users--");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_some());
        assert!(matches!(
            result.verdict,
            Some(crate::data_bus::context::Verdict::Block { .. })
        ));
    }

    #[tokio::test]
    async fn test_blocks_or_1_equals_1() {
        let inspector = SqlInjectionInspector::new();
        let mut ctx = make_sqli_ctx("/login?user=admin' OR 1=1--");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_some());
    }

    #[tokio::test]
    async fn test_clean_path() {
        let inspector = SqlInjectionInspector::new();
        let mut ctx = make_sqli_ctx("/api/users?page=1");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_none());
        assert_eq!(result.score_delta, 0.0);
    }

    #[tokio::test]
    async fn test_skips_static_assets() {
        let inspector = SqlInjectionInspector::new();
        // Pure static asset without query should skip inspection
        let ctx = make_sqli_ctx("/style.css");
        assert!(!inspector.should_run(&ctx));

        // Static asset with query parameters must NOT skip inspection and must catch attacks
        let mut attack_ctx = make_sqli_ctx("/style.css?user=admin' OR 1=1--");
        assert!(inspector.should_run(&attack_ctx));
        let result = inspector.inspect(&mut attack_ctx).await;
        assert!(result.verdict.is_some());
    }
}

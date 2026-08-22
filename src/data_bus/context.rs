use bytes::Bytes;
use hyper::{HeaderMap, Method};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// Why a request was blocked
#[derive(Debug, Clone)]
pub enum BlockReason {
    SqlInjection,
    Xss,
    Lfi,
    Rfi,
    Ssrf,
    CommandInjection,
    IpBlocked,
    RateLimit,
    GeoBlock,
    BotDetected,
    BehavioralAnomaly,
    CustomRule(String),
    Unknown,
}

/// How to block a request
#[derive(Debug, Clone)]
pub enum BlockAction {
    Reject403,
    Reject401,
    Reject429,
    Drop,
    CustomStatus(u16),
}

/// Request verdict — starts Undecided, becomes decisive once set
#[derive(Debug, Clone, Default)]
pub enum Verdict {
    #[default]
    Undecided,
    Allow,
    Block {
        reason: BlockReason,
        action: BlockAction,
    },
    Challenge {
        challenge_type: String,
    },
    Redirect {
        url: String,
    },
}

impl Verdict {
    /// Returns true if the verdict has been set to Block, Challenge, or Redirect
    pub fn is_decisive(&self) -> bool {
        matches!(
            self,
            Verdict::Block { .. } | Verdict::Challenge { .. } | Verdict::Redirect { .. }
        )
    }

    /// Returns true if the verdict is a Block
    pub fn is_block(&self) -> bool {
        matches!(self, Verdict::Block { .. })
    }
}

/// A single rule match recorded during inspection
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub inspector_name: String,
    pub rule_id: String,
    pub score_delta: f64,
    pub details: String,
}

/// Static asset extensions that skip inspection
const STATIC_EXTENSIONS: &[&str] = &[
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
    ".eot", ".map", ".webp", ".avif",
];

/// Request context that flows through the inspection chain
pub struct InspectionContext {
    pub request_id: uuid::Uuid,
    pub client_ip: std::net::IpAddr,
    pub method: Method,
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
    pub vhost: String,
    pub client_port: u16,
    pub timestamp: Instant,

    // Inspection state
    pub verdict: Verdict,
    pub score: f64,
    pub matched_rules: Vec<RuleMatch>,
    pub tags: HashSet<String>,
    pub metadata: HashMap<String, String>,
}

impl InspectionContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_ip: std::net::IpAddr,
        method: Method,
        mut path: String,
        mut query: String,
        headers: HeaderMap,
        body: Option<Bytes>,
        vhost: String,
        client_port: u16,
    ) -> Self {
        if query.is_empty() && path.contains('?') {
            if let Some(idx) = path.find('?') {
                query = path[idx + 1..].to_string();
                path.truncate(idx);
            }
        }
        Self {
            request_id: uuid::Uuid::new_v4(),
            client_ip,
            method,
            path,
            query,
            headers,
            body,
            vhost,
            client_port,
            timestamp: Instant::now(),
            verdict: Verdict::Undecided,
            score: 0.0,
            matched_rules: Vec::new(),
            tags: HashSet::new(),
            metadata: HashMap::new(),
        }
    }

    /// Returns true if the request is strictly for a static asset (read-only, no query/body/path params)
    pub fn is_static_asset(&self) -> bool {
        // Only safe read methods (GET / HEAD) can be static assets.
        // State-mutating methods (POST, PUT, DELETE, PATCH, etc.) must ALWAYS be inspected.
        if self.method != Method::GET && self.method != Method::HEAD {
            return false;
        }

        // If there is a request body, it is not a pure static file request.
        if self.body.as_ref().map(|b| !b.is_empty()).unwrap_or(false) {
            return false;
        }

        // If there are query parameters, dynamic handling is likely requested.
        if !self.query.is_empty() {
            return false;
        }

        // Sanitize path: strip path matrix parameters like /file.css;param=val or /file.php;.png
        let clean_path = if let Some(idx) = self.path.find(';') {
            &self.path[..idx]
        } else {
            &self.path
        };

        // If path contains dot-dot traversal or path evasion markers, do not skip.
        if clean_path.contains("..") || clean_path.contains("%2e") || clean_path.contains("%2E") {
            return false;
        }

        let path_lower = clean_path.to_lowercase();
        // Check if the clean path strictly ends with an allowed static extension
        STATIC_EXTENSIONS
            .iter()
            .any(|ext| path_lower.ends_with(ext))
    }

    /// Returns the full path including query string
    pub fn full_path(&self) -> String {
        if self.query.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, self.query)
        }
    }

    /// Set the verdict to Block (only if not already decisive)
    pub fn set_block(&mut self, reason: BlockReason, action: BlockAction) {
        if !self.verdict.is_decisive() {
            self.verdict = Verdict::Block { reason, action };
        }
    }

    /// Record a rule match and accumulate score
    pub fn add_match(
        &mut self,
        inspector_name: &str,
        rule_id: &str,
        score_delta: f64,
        details: String,
    ) {
        self.score += score_delta;
        self.matched_rules.push(RuleMatch {
            inspector_name: inspector_name.to_string(),
            rule_id: rule_id.to_string(),
            score_delta,
            details,
        });
    }

    /// Get a header value as a string
    pub fn header_str(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Get the User-Agent header
    pub fn user_agent(&self) -> Option<String> {
        self.header_str("user-agent")
    }

    /// Add a tag to the request
    pub fn add_tag(&mut self, tag: &str) {
        self.tags.insert(tag.to_string());
    }

    /// Set a metadata key-value pair
    pub fn set_metadata(&mut self, key: &str, value: String) {
        self.metadata.insert(key.to_string(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(path: &str) -> InspectionContext {
        InspectionContext::new(
            "10.0.0.1".parse().unwrap(),
            Method::GET,
            path.to_string(),
            String::new(),
            HeaderMap::new(),
            None,
            "test.local".to_string(),
            12345,
        )
    }

    #[test]
    fn test_static_asset_detection() {
        assert!(make_ctx("/style.css").is_static_asset());
        assert!(make_ctx("/app.js").is_static_asset());
        assert!(make_ctx("/img.png").is_static_asset());
        assert!(!make_ctx("/api/users").is_static_asset());
        assert!(!make_ctx("/login").is_static_asset());

        // Hardening & bypass checks:
        // 1. POST method with static extension must NOT be static
        let mut post_ctx = make_ctx("/style.css");
        post_ctx.method = Method::POST;
        assert!(!post_ctx.is_static_asset());

        // 2. Query string on static file must NOT skip inspection
        let mut query_ctx = make_ctx("/style.css");
        query_ctx.query = "id=1' OR 1=1--".to_string();
        assert!(!query_ctx.is_static_asset());

        // 3. Matrix path parameter must NOT bypass inspection
        assert!(!make_ctx("/api/action.php;.css").is_static_asset());

        // 4. Dot-dot traversal must NOT bypass inspection
        assert!(!make_ctx("/images/../admin.php.png").is_static_asset());
    }

    #[test]
    fn test_full_path_with_query() {
        let ctx = InspectionContext::new(
            "10.0.0.1".parse().unwrap(),
            Method::GET,
            "/search".to_string(),
            "q=test&page=1".to_string(),
            HeaderMap::new(),
            None,
            "test.local".to_string(),
            12345,
        );
        assert_eq!(ctx.full_path(), "/search?q=test&page=1");
    }

    #[test]
    fn test_verdict_set_block() {
        let mut ctx = make_ctx("/");
        assert!(!ctx.verdict.is_decisive());
        ctx.set_block(BlockReason::SqlInjection, BlockAction::Reject403);
        assert!(ctx.verdict.is_decisive());
        assert!(ctx.verdict.is_block());
    }

    #[test]
    fn test_verdict_no_override() {
        let mut ctx = make_ctx("/");
        ctx.set_block(BlockReason::SqlInjection, BlockAction::Reject403);
        ctx.set_block(BlockReason::Xss, BlockAction::Reject403);
        assert!(matches!(
            ctx.verdict,
            Verdict::Block {
                reason: BlockReason::SqlInjection,
                ..
            }
        ));
    }

    #[test]
    fn test_add_match_accumulates_score() {
        let mut ctx = make_ctx("/");
        ctx.add_match("SQLI", "SQLI-001", 10.0, "pattern matched".to_string());
        ctx.add_match("XSS", "XSS-001", 5.0, "suspicious".to_string());
        assert_eq!(ctx.score, 15.0);
        assert_eq!(ctx.matched_rules.len(), 2);
    }
}

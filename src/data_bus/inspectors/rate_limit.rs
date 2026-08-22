use super::{InspectionResult, Inspector};
use crate::data_bus::context::{BlockAction, BlockReason, InspectionContext};
use async_trait::async_trait;
use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub limit: u32,
    pub window: Duration,
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            limit: 100,
            window: Duration::from_secs(60),
            burst: 20,
        }
    }
}

struct IpCounter {
    count: u32,
    window_start: Instant,
}

pub struct RateLimitInspector {
    config: RateLimitConfig,
    counters: DashMap<IpAddr, IpCounter>,
}

impl RateLimitInspector {
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            config,
            counters: DashMap::new(),
        }
    }
}

impl Default for RateLimitInspector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Inspector for RateLimitInspector {
    fn name(&self) -> &str {
        "RATE_LIMIT"
    }
    fn priority(&self) -> u32 {
        50
    }

    fn should_run(&self, _ctx: &InspectionContext) -> bool {
        true // Always run — even for static assets
    }

    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult {
        let ip = ctx.client_ip;
        let now = Instant::now();

        let mut entry = self.counters.entry(ip).or_insert_with(|| IpCounter {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start) > self.config.window {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;
        let count = entry.count;
        let effective_limit = self.config.limit + self.config.burst;

        if count > effective_limit {
            ctx.add_tag("rate-limited");
            InspectionResult::block(
                BlockReason::RateLimit,
                BlockAction::Reject429,
                0.0,
                format!(
                    "Rate limit exceeded: {} requests in window (limit: {})",
                    count, self.config.limit
                ),
            )
        } else if count > self.config.limit {
            // In burst zone — suspicious but not blocked
            ctx.add_tag("burst-zone");
            InspectionResult::suspicious(
                5.0,
                format!(
                    "In burst zone: {} requests (limit: {}, burst: {})",
                    count, self.config.limit, self.config.burst
                ),
            )
        } else {
            InspectionResult::clean()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(ip: &str) -> InspectionContext {
        InspectionContext::new(
            ip.parse().unwrap(),
            hyper::Method::GET,
            "/api/test".to_string(),
            String::new(),
            hyper::HeaderMap::new(),
            None,
            "test.local".to_string(),
            12345,
        )
    }

    #[tokio::test]
    async fn test_allows_under_limit() {
        let inspector = RateLimitInspector::with_config(RateLimitConfig {
            limit: 5,
            window: Duration::from_secs(60),
            burst: 0,
        });

        for _ in 0..5 {
            let mut ctx = make_ctx("10.0.0.1");
            let result = inspector.inspect(&mut ctx).await;
            assert!(result.verdict.is_none());
        }
    }

    #[tokio::test]
    async fn test_blocks_over_limit() {
        let inspector = RateLimitInspector::with_config(RateLimitConfig {
            limit: 3,
            window: Duration::from_secs(60),
            burst: 0,
        });

        for _ in 0..3 {
            let mut ctx = make_ctx("10.0.0.2");
            let _ = inspector.inspect(&mut ctx).await;
        }

        let mut ctx = make_ctx("10.0.0.2");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_some());
    }

    #[tokio::test]
    async fn test_separate_ips_independent() {
        let inspector = RateLimitInspector::with_config(RateLimitConfig {
            limit: 2,
            window: Duration::from_secs(60),
            burst: 0,
        });

        for _ in 0..2 {
            let mut ctx = make_ctx("10.0.0.3");
            let _ = inspector.inspect(&mut ctx).await;
        }

        // Different IP should still be allowed
        let mut ctx = make_ctx("10.0.0.4");
        let result = inspector.inspect(&mut ctx).await;
        assert!(result.verdict.is_none());
    }
}

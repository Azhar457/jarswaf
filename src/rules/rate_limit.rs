use std::net::IpAddr;
use std::time::Instant;
use dashmap::DashMap;


#[derive(Clone, Debug)]
pub struct RateLimitStatus {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_after_secs: u64,
}

pub struct TokenBucket {
    pub tokens: f64,
    pub last_check: Instant,
    pub last_access: Instant,
    pub rate: f64,
    pub capacity: f64,
}

#[async_trait::async_trait]
pub trait RateLimiterStore: Send + Sync {
    async fn check_and_increment(&self, ip: IpAddr, limit: u32, user_key: Option<&str>) -> RateLimitStatus;
}

pub struct LocalStore {
    limiter: DashMap<String, TokenBucket>,
}

impl Default for LocalStore {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalStore {
    pub fn new() -> Self {
        Self {
            limiter: DashMap::new(),
        }
    }

    fn rate_limit_key(ip: IpAddr, user_key: Option<&str>) -> String {
        match user_key {
            Some(k) if !k.is_empty() => format!("{}|{}", ip, k),
            _ => ip.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl RateLimiterStore for LocalStore {
    async fn check_and_increment(&self, ip: IpAddr, limit: u32, user_key: Option<&str>) -> RateLimitStatus {
        let rate = limit as f64 / 60.0;
        let capacity = rate * 2.0;
        let key = Self::rate_limit_key(ip, user_key);
        let mut bucket = self.limiter.entry(key).or_insert_with(|| TokenBucket {
            tokens: capacity,
            last_check: Instant::now(),
            last_access: Instant::now(),
            rate,
            capacity,
        });

        if (bucket.rate - rate).abs() > f64::EPSILON || (bucket.capacity - capacity).abs() > f64::EPSILON {
            bucket.rate = rate;
            bucket.capacity = capacity;
            bucket.tokens = bucket.tokens.min(capacity);
        }

        let now = Instant::now();
        bucket.last_access = now;
        let elapsed = now.duration_since(bucket.last_check).as_secs_f64();
        bucket.last_check = now;

        bucket.tokens = (bucket.tokens + elapsed * bucket.rate).min(bucket.capacity);

        let allowed = if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        };

        RateLimitStatus {
            allowed,
            limit,
            remaining: bucket.tokens as u32,
            reset_after_secs: 60,
        }
    }
}

pub struct RedisStore {
    client: redis::Client,
    local_fallback: LocalStore,
}

impl RedisStore {
    pub fn new(url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        Ok(Self {
            client,
            local_fallback: LocalStore::new(),
        })
    }
}

#[async_trait::async_trait]
impl RateLimiterStore for RedisStore {
    async fn check_and_increment(&self, ip: IpAddr, limit: u32, user_key: Option<&str>) -> RateLimitStatus {
        if let Ok(mut conn) = self.client.get_multiplexed_async_connection().await {
            let composite_key = LocalStore::rate_limit_key(ip, user_key);
            let key = format!("ratelimit:sliding:{}", composite_key);
            let window_secs: i64 = 60;
            let now_us: i64 = chrono::Utc::now().timestamp_micros();
            let cutoff_us = now_us - (window_secs * 1_000_000);

            let _: redis::RedisResult<()> = redis::cmd("ZREMRANGEBYSCORE")
                .arg(&key).arg("-inf").arg(cutoff_us).query_async(&mut conn).await;

            let count: redis::RedisResult<u32> = redis::cmd("ZCARD")
                .arg(&key).query_async(&mut conn).await;

            if let Ok(count_val) = count {
                if count_val >= limit {
                    return RateLimitStatus {
                        allowed: false,
                        limit,
                        remaining: 0,
                        reset_after_secs: 60,
                    };
                }

                let member = format!("{}:{}", now_us, uuid::Uuid::new_v4());
                let _: redis::RedisResult<()> = redis::cmd("ZADD")
                    .arg(&key).arg(now_us).arg(&member).query_async(&mut conn).await;

                let _: redis::RedisResult<()> = redis::cmd("EXPIRE")
                    .arg(&key).arg(window_secs * 2).query_async(&mut conn).await;

                return RateLimitStatus {
                    allowed: true,
                    limit,
                    remaining: limit - count_val - 1,
                    reset_after_secs: 60,
                };
            }
        }

        // Fallback to local
        self.local_fallback.check_and_increment(ip, limit, user_key).await
    }
}

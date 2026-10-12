//! Simple in-memory rate limiter for auth endpoints.
//!
//! For production deployments behind a load balancer, replace with Redis-backed
//! rate limiting. The in-memory version is sufficient for single-instance
//! deployments and correctly enforces limits per IP.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Rate limit bucket: tracks hits and the window start.
#[derive(Debug, Clone)]
struct Bucket {
    count: u32,
    window_start: Instant,
}

/// In-memory rate limiter with sliding window per key (IP).
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<IpAddr, Bucket>>>,
    max_requests: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Check if the request should be allowed. Returns `Ok(())` if allowed,
    /// `Err(retry_after_secs)` if rate limited.
    pub async fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let now = Instant::now();
        let mut buckets = self.buckets.write().await;

        let bucket = buckets.entry(ip).or_insert(Bucket {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(bucket.window_start) >= self.window {
            bucket.count = 0;
            bucket.window_start = now;
        }

        bucket.count += 1;

        if bucket.count > self.max_requests {
            let retry_after = self
                .window
                .saturating_sub(now.duration_since(bucket.window_start))
                .as_secs()
                .max(1);
            return Err(retry_after);
        }

        Ok(())
    }

    /// Reset the counter for a specific IP (e.g., after successful login).
    pub async fn reset(&self, ip: IpAddr) {
        self.buckets.write().await.remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn allows_requests_under_limit() {
        let limiter = RateLimiter::new(5, 60);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        for _ in 0..5 {
            assert!(limiter.check(ip).await.is_ok());
        }
    }

    #[tokio::test]
    async fn blocks_requests_over_limit() {
        let limiter = RateLimiter::new(3, 60);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        assert!(limiter.check(ip).await.is_ok());
        assert!(limiter.check(ip).await.is_ok());
        assert!(limiter.check(ip).await.is_ok());
        let err = limiter.check(ip).await.unwrap_err();
        assert!(err > 0);
    }

    #[tokio::test]
    async fn resets_after_window() {
        let limiter = RateLimiter::new(2, 1); // 1 second window
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        assert!(limiter.check(ip).await.is_ok());
        assert!(limiter.check(ip).await.is_ok());
        assert!(limiter.check(ip).await.is_err());

        tokio::time::sleep(Duration::from_secs(2)).await;

        assert!(limiter.check(ip).await.is_ok());
    }

    #[tokio::test]
    async fn reset_clears_bucket() {
        let limiter = RateLimiter::new(1, 60);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        assert!(limiter.check(ip).await.is_ok());
        assert!(limiter.check(ip).await.is_err());

        limiter.reset(ip).await;

        assert!(limiter.check(ip).await.is_ok());
    }
}

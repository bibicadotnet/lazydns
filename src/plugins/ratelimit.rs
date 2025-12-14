//! Rate limiting plugin for DNS queries
//!
//! Implements rate limiting to prevent DoS attacks and resource exhaustion.

use crate::dns::ResponseCode;
use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

/// Rate limiter entry tracking request history
#[derive(Debug)]
struct RateLimitEntry {
    /// Number of requests in current window
    count: u32,
    /// Window start time
    window_start: Instant,
}

/// Rate limiting plugin
///
/// Limits the number of queries from a single IP address within a time window.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::RateLimitPlugin;
///
/// // Allow 100 queries per 60 seconds per IP
/// let rate_limiter = RateLimitPlugin::new(100, 60);
/// ```
#[derive(Debug)]
pub struct RateLimitPlugin {
    /// Maximum queries per window
    max_queries: u32,
    /// Time window in seconds
    window_secs: u64,
    /// Storage for rate limit tracking
    limits: Arc<DashMap<IpAddr, RateLimitEntry>>,
}

impl RateLimitPlugin {
    /// Create a new rate limit plugin
    ///
    /// # Arguments
    ///
    /// * `max_queries` - Maximum number of queries allowed per window
    /// * `window_secs` - Time window in seconds
    pub fn new(max_queries: u32, window_secs: u64) -> Self {
        Self {
            max_queries,
            window_secs,
            limits: Arc::new(DashMap::new()),
        }
    }

    /// Check if a request should be rate limited
    fn should_limit(&self, client_ip: IpAddr) -> bool {
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.window_secs);

        let mut should_limit = false;

        self.limits
            .entry(client_ip)
            .and_modify(|entry| {
                // Check if we need to reset the window
                if now.duration_since(entry.window_start) >= window_duration {
                    entry.count = 1;
                    entry.window_start = now;
                } else {
                    entry.count += 1;
                    if entry.count > self.max_queries {
                        should_limit = true;
                    }
                }
            })
            .or_insert(RateLimitEntry {
                count: 1,
                window_start: now,
            });

        should_limit
    }

    /// Clean up old entries
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.window_secs);

        self.limits
            .retain(|_, entry| now.duration_since(entry.window_start) < window_duration * 2);
    }
}

#[async_trait]
impl Plugin for RateLimitPlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Try to get client IP from metadata (set by server)
        let client_ip: IpAddr = match ctx.get_metadata::<IpAddr>("client_ip") {
            Some(ip) => *ip,
            None => {
                // Default to localhost if no IP available
                "127.0.0.1".parse().unwrap()
            }
        };

        if self.should_limit(client_ip) {
            warn!("Rate limit exceeded for IP: {}", client_ip);

            // Create a REFUSED response
            let mut response = crate::dns::Message::new();
            response.set_id(ctx.request().id());
            response.set_response(true);
            response.set_response_code(ResponseCode::Refused);

            ctx.set_response(Some(response));
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "rate_limit"
    }

    fn priority(&self) -> i32 {
        // Should run early to block excessive requests
        1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[test]
    fn test_rate_limit_creation() {
        let limiter = RateLimitPlugin::new(10, 60);
        assert_eq!(limiter.max_queries, 10);
        assert_eq!(limiter.window_secs, 60);
    }

    #[test]
    fn test_rate_limit_allows_within_limit() {
        let limiter = RateLimitPlugin::new(5, 60);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..5 {
            assert!(!limiter.should_limit(ip));
        }
    }

    #[test]
    fn test_rate_limit_blocks_over_limit() {
        let limiter = RateLimitPlugin::new(3, 60);
        let ip: IpAddr = "192.168.1.2".parse().unwrap();

        // First 3 should pass
        for _ in 0..3 {
            assert!(!limiter.should_limit(ip));
        }

        // 4th should be blocked
        assert!(limiter.should_limit(ip));
    }

    #[test]
    fn test_rate_limit_different_ips() {
        let limiter = RateLimitPlugin::new(2, 60);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Each IP should have independent limits
        assert!(!limiter.should_limit(ip1));
        assert!(!limiter.should_limit(ip2));
        assert!(!limiter.should_limit(ip1));
        assert!(!limiter.should_limit(ip2));

        // Both should now be at limit
        assert!(limiter.should_limit(ip1));
        assert!(limiter.should_limit(ip2));
    }

    #[test]
    fn test_cleanup() {
        let limiter = RateLimitPlugin::new(10, 1);
        let ip: IpAddr = "192.168.1.3".parse().unwrap();

        limiter.should_limit(ip);
        assert_eq!(limiter.limits.len(), 1);

        limiter.cleanup();
        assert_eq!(limiter.limits.len(), 1); // Still there

        std::thread::sleep(std::time::Duration::from_secs(3));
        limiter.cleanup();
        assert_eq!(limiter.limits.len(), 0); // Cleaned up
    }

    #[tokio::test]
    async fn test_rate_limit_plugin_execute() {
        let limiter = RateLimitPlugin::new(2, 60);
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("client_ip", "192.168.1.1".parse::<IpAddr>().unwrap());

        // First two should pass
        limiter.execute(&mut ctx).await.unwrap();
        assert!(ctx.response().is_none());

        limiter.execute(&mut ctx).await.unwrap();
        assert!(ctx.response().is_none());

        // Third should be rate limited
        limiter.execute(&mut ctx).await.unwrap();
        assert!(ctx.response().is_some());
        assert_eq!(
            ctx.response().unwrap().response_code(),
            ResponseCode::Refused
        );
    }
}

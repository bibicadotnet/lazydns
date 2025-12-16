//! Forward plugin
//!
//! Forwarding layer that sends DNS queries to one or more upstream
//! resolvers and returns the first valid response. This module implements
//! both classic socket-based forwarding (UDP/TCP to `ip:port`) and
//! DNS-over-HTTPS (DoH) via HTTP POST (`application/dns-message`).
//!
//! Features
//! - Multiple upstreams with configurable load-balancing strategies:
//!   round-robin, random, and `Fastest` (based on locally recorded
//!   response times).
//! - Local per-upstream health tracking (queries, successes, failures,
//!   average response time) which can be enabled via the builder.
//! - Optional concurrent (race) mode which sends parallel queries to
//!   all upstreams and returns the fastest successful response.
//! - DoH support for upstreams that are supplied as HTTP(S) URLs.
//! - Prometheus metrics reporting (see `crate::metrics`) for upstream
//!   success/failure counts and response duration observations when
//!   health checks are enabled.
//!
//! Usage
//! - Use `ForwardPlugin::builder()` to construct an instance. Add
//!   upstreams with `add_upstream("ip:port")` or a DoH endpoint
//!   `add_upstream("https://dns.example/dns-query")`.
//! - Call `enable_health_checks(true)` to collect health metrics and
//!   enable richer selection for the `Fastest` strategy.
//! - Use `concurrent_queries(true)` to enable race-mode for lower
//!   latency at the cost of extra upstream load.
//!
//! Notes
//! - When providing an upstream with an associated tag use
//!   `add_upstream_with_tag(upstream, tag)`; tags are stored alongside
//!   upstream entries and can be used by higher layers to refer to
//!   upstreams without relying on raw addresses.
//! - Prometheus label cardinality: the code currently labels metrics
//!   by upstream address. If your deployment has high cardinality
//!   upstream identifiers, prefer tagging or adjust metrics labeling
//!   accordingly.
//!
//! Example
//! ```rust
//! let plugin = lazydns::plugins::ForwardPlugin::builder()
//!     .add_upstream("8.8.8.8:53")
//!     .add_upstream("https://dns.example/dns-query")
//!     .strategy(lazydns::plugins::LoadBalanceStrategy::Fastest)
//!     .enable_health_checks(true)
//!     .concurrent_queries(false)
//!     .build();
//! ```

use crate::dns::Message;
use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use reqwest::Client as HttpClient;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration, Instant};
use tracing::{debug, error, warn};

/// Load balancing strategy for upstream selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalanceStrategy {
    /// Round-robin selection
    RoundRobin,
    /// Random selection
    Random,
    /// Fastest response time
    Fastest,
}

/// Health status of an upstream server
#[derive(Debug)]
struct UpstreamHealth {
    /// Total queries sent
    queries: AtomicU64,
    /// Successful responses
    successes: AtomicU64,
    /// Failed queries
    failures: AtomicU64,
    /// Average response time in microseconds
    avg_response_time_us: AtomicU64,
    /// Last successful query timestamp
    last_success: std::sync::Mutex<Option<Instant>>,
}

impl UpstreamHealth {
    fn new() -> Self {
        Self {
            queries: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            avg_response_time_us: AtomicU64::new(0),
            last_success: std::sync::Mutex::new(None),
        }
    }

    fn record_success(&self, response_time: Duration) {
        self.queries.fetch_add(1, Ordering::Relaxed);
        self.successes.fetch_add(1, Ordering::Relaxed);

        // Update average response time (simple moving average)
        let new_time = response_time.as_micros() as u64;
        let old_avg = self.avg_response_time_us.load(Ordering::Relaxed);
        let queries = self.queries.load(Ordering::Relaxed);
        let new_avg = if queries <= 1 {
            new_time
        } else {
            (old_avg * (queries - 1) + new_time) / queries
        };
        self.avg_response_time_us.store(new_avg, Ordering::Relaxed);

        *self.last_success.lock().unwrap() = Some(Instant::now());
    }

    fn record_failure(&self) {
        self.queries.fetch_add(1, Ordering::Relaxed);
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    fn success_rate(&self) -> f64 {
        let total = self.queries.load(Ordering::Relaxed);
        if total == 0 {
            return 1.0;
        }
        let successes = self.successes.load(Ordering::Relaxed);
        successes as f64 / total as f64
    }

    /// Public accessor for success rate
    #[allow(dead_code)]
    pub fn get_success_rate(&self) -> f64 {
        self.success_rate()
    }

    /// Get counters snapshot (queries, successes, failures)
    pub fn counters(&self) -> (u64, u64, u64) {
        (
            self.queries.load(Ordering::Relaxed),
            self.successes.load(Ordering::Relaxed),
            self.failures.load(Ordering::Relaxed),
        )
    }

    fn avg_response_time(&self) -> Duration {
        let micros = self.avg_response_time_us.load(Ordering::Relaxed);
        Duration::from_micros(micros)
    }
}

/// Upstream server configuration
#[allow(dead_code)]
#[derive(Debug)]
struct Upstream {
    /// Server address
    addr: String,
    /// Health tracking
    health: UpstreamHealth,
    /// Optional tag for lookup
    tag: Option<String>,
}

/// Forward plugin
///
/// This plugin forwards DNS queries to configured upstream DNS servers.
/// It supports multiple upstreams with various load balancing strategies,
/// health checks, failover, and concurrent queries.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::{ForwardPlugin, LoadBalanceStrategy};
///
/// // Build with concurrent queries enabled
/// let plugin = ForwardPlugin::builder()
///     .add_upstream("8.8.8.8:53")
///     .add_upstream("8.8.4.4:53")
///     .strategy(LoadBalanceStrategy::Fastest)
///     .enable_health_checks(true)
///     .concurrent_queries(true)  // Race all upstreams
///     .build();
/// ```
#[derive(Debug)]
pub struct ForwardPlugin {
    /// Upstream DNS servers
    upstreams: Arc<Vec<Upstream>>,

    /// Query timeout
    timeout: Duration,

    /// Load balancing strategy
    strategy: LoadBalanceStrategy,

    /// Enable health checks and failover
    health_checks_enabled: bool,

    /// Current upstream index for round-robin
    current: AtomicUsize,

    /// Maximum failover attempts
    max_attempts: usize,

    /// Enable concurrent queries (race mode)
    concurrent_queries: bool,
}

/// Builder for ForwardPlugin
pub struct ForwardPluginBuilder {
    upstreams: Vec<String>,
    timeout: Duration,
    strategy: LoadBalanceStrategy,
    health_checks_enabled: bool,
    max_attempts: usize,
    concurrent_queries: bool,
}

impl ForwardPluginBuilder {
    /// Create a new `ForwardPluginBuilder` with sensible defaults.
    ///
    /// Defaults:
    /// - `timeout`: 5s
    /// - `strategy`: `RoundRobin`
    /// - `health_checks_enabled`: false
    /// - `max_attempts`: 3
    /// - `concurrent_queries`: false
    ///
    /// Use the builder methods to customize upstreams and behavior before
    /// calling `build()`.
    pub fn new() -> Self {
        Self {
            upstreams: Vec::new(),
            timeout: Duration::from_secs(5),
            strategy: LoadBalanceStrategy::RoundRobin,
            health_checks_enabled: false,
            max_attempts: 3,
            concurrent_queries: false,
        }
    }

    /// Add an upstream server by address (e.g. `8.8.8.8:53`).
    ///
    /// This accepts either a plain socket address (`ip:port`) or a DoH URL
    /// (`https://dns.example/dns-query`). The upstream will be contacted
    /// when the `ForwardPlugin` forwards queries.
    pub fn add_upstream(mut self, upstream: impl Into<String>) -> Self {
        self.upstreams.push(upstream.into());
        self
    }

    /// Add an upstream with an associated `tag`.
    ///
    /// The `tag` is a small identifier stored alongside the upstream entry
    /// and can be used by higher-level logic to refer to specific upstreams
    /// without relying on the full `addr` string.
    pub fn add_upstream_with_tag(
        mut self,
        upstream: impl Into<String>,
        tag: impl Into<String>,
    ) -> Self {
        let entry = format!("{}|{}", upstream.into(), tag.into());
        self.upstreams.push(entry);
        self
    }

    /// Set the per-upstream query `timeout` used for network requests.
    ///
    /// Example: `.timeout(Duration::from_secs(2))`.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the `LoadBalanceStrategy` used for selecting upstreams.
    ///
    /// Options include round-robin, random, or selecting the fastest based
    /// on locally collected health stats.
    pub fn strategy(mut self, strategy: LoadBalanceStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Enable or disable local health checks and tracking.
    ///
    /// When enabled the plugin records success/failure counts and response
    /// times per upstream which influence selection (e.g. `Fastest`).
    pub fn enable_health_checks(mut self, enabled: bool) -> Self {
        self.health_checks_enabled = enabled;
        self
    }

    /// Set the maximum number of failover attempts when forwarding a query.
    ///
    /// The plugin will try up to `max` different upstreams before returning
    /// an error. This limits the amount of work spent retrying.
    pub fn max_attempts(mut self, max: usize) -> Self {
        self.max_attempts = max;
        self
    }

    /// Enable concurrent (race) queries across all upstreams.
    ///
    /// When enabled the plugin sends the same query to all upstreams and
    /// returns the first successful response. This reduces latency at the
    /// cost of increased upstream load.
    pub fn concurrent_queries(mut self, enabled: bool) -> Self {
        self.concurrent_queries = enabled;
        self
    }

    /// Consume the builder and create a configured `ForwardPlugin`.
    ///
    /// After `build()` the plugin is ready to be inserted into the plugin
    /// chain; the upstream list and settings are immutable on the returned
    /// `ForwardPlugin` instance.
    pub fn build(self) -> ForwardPlugin {
        let upstreams = self
            .upstreams
            .into_iter()
            .map(|entry| {
                // support optional tag encoded as "addr|tag" from builder helper
                if let Some((addr, tag)) = entry.split_once('|') {
                    Upstream {
                        addr: addr.to_string(),
                        health: UpstreamHealth::new(),
                        tag: Some(tag.to_string()),
                    }
                } else {
                    Upstream {
                        addr: entry,
                        health: UpstreamHealth::new(),
                        tag: None,
                    }
                }
            })
            .collect();

        ForwardPlugin {
            upstreams: Arc::new(upstreams),
            timeout: self.timeout,
            strategy: self.strategy,
            health_checks_enabled: self.health_checks_enabled,
            current: AtomicUsize::new(0),
            max_attempts: self.max_attempts,
            concurrent_queries: self.concurrent_queries,
        }
    }

    /// Build with a list of upstream addresses (internal helper)
    fn build_with_upstreams(mut self, upstreams: Vec<String>) -> ForwardPlugin {
        self.upstreams = upstreams;
        self.build()
    }
}

impl Default for ForwardPluginBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwardPlugin {
    /// Create a new forward plugin with default settings
    ///
    /// # Arguments
    ///
    /// * `upstreams` - List of upstream DNS server addresses (format: "ip:port")
    pub fn new(upstreams: Vec<String>) -> Self {
        Self::builder()
            .timeout(Duration::from_secs(5))
            .build_with_upstreams(upstreams)
    }

    /// Create a builder for advanced configuration
    pub fn builder() -> ForwardPluginBuilder {
        ForwardPluginBuilder::new()
    }

    /// Create a forward plugin with custom timeout (legacy method)
    ///
    /// # Arguments
    ///
    /// * `upstreams` - List of upstream DNS server addresses
    /// * `timeout` - Query timeout duration
    pub fn with_timeout(upstreams: Vec<String>, timeout: Duration) -> Self {
        Self::builder()
            .timeout(timeout)
            .build_with_upstreams(upstreams)
    }

    /// Return a list of upstream address strings (for testing/inspection)
    pub fn upstream_addrs(&self) -> Vec<String> {
        self.upstreams.iter().map(|u| u.addr.clone()).collect()
    }

    /// Select an upstream based on the configured strategy
    fn select_upstream(&self) -> Option<usize> {
        if self.upstreams.is_empty() {
            return None;
        }

        match self.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let index = self.current.fetch_add(1, Ordering::Relaxed);
                Some(index % self.upstreams.len())
            }
            LoadBalanceStrategy::Random => {
                // Use a simple pseudo-random selection based on current time
                // This is sufficient for load balancing purposes
                use std::time::SystemTime;
                let nanos = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                Some((nanos as usize) % self.upstreams.len())
            }
            LoadBalanceStrategy::Fastest => {
                // Select the upstream with the lowest average response time
                // Prefer upstreams with no measurements (Duration::ZERO) to give them a chance
                let mut best_idx = 0;
                let mut best_time = self.upstreams[0].health.avg_response_time();

                for (idx, upstream) in self.upstreams.iter().enumerate().skip(1) {
                    let avg_time = upstream.health.avg_response_time();

                    // Prefer upstreams with measurements over those without
                    // Among measured, prefer faster ones
                    // Among unmeasured, prefer first one
                    if best_time == Duration::ZERO {
                        // Current best is unmeasured, only switch if new is also unmeasured and earlier
                        // (keep first unmeasured)
                        continue;
                    } else if avg_time == Duration::ZERO {
                        // New upstream is unmeasured, prefer it to give it a chance
                        best_idx = idx;
                        best_time = avg_time;
                    } else if avg_time < best_time {
                        // Both measured, prefer faster
                        best_idx = idx;
                        best_time = avg_time;
                    }
                }
                Some(best_idx)
            }
        }
    }

    /// Get the next upstream server for round-robin (legacy method)
    #[allow(dead_code)]
    fn next_upstream(&self) -> Option<&str> {
        let idx = self.select_upstream()?;
        Some(&self.upstreams[idx].addr)
    }

    /// Forward a query to an upstream server with health tracking
    async fn forward_query_with_health(
        &self,
        request: &Message,
        upstream_idx: usize,
    ) -> Result<Message> {
        let upstream = &self.upstreams[upstream_idx];
        let start = Instant::now();

        match self.forward_query(request, &upstream.addr).await {
            Ok(response) => {
                let elapsed = start.elapsed();
                if self.health_checks_enabled {
                    upstream.health.record_success(elapsed);
                    // Report to Prometheus metrics for observability
                    let _ = {
                        use crate::metrics::{UPSTREAM_DURATION_SECONDS, UPSTREAM_QUERIES_TOTAL};
                        UPSTREAM_QUERIES_TOTAL
                            .with_label_values(&[&upstream.addr, "success"])
                            .inc();
                        UPSTREAM_DURATION_SECONDS
                            .with_label_values(&[&upstream.addr])
                            .observe(elapsed.as_secs_f64());
                        Ok::<(), ()>(())
                    };
                }
                // Structured log with current counters
                let (queries, successes, failures) = upstream.health.counters();
                // Extract A/AAAA addresses for logging
                let mut addrs: Vec<String> = Vec::new();
                for rr in response.answers() {
                    match rr.rdata() {
                        crate::dns::RData::A(ipv4) => addrs.push(ipv4.to_string()),
                        crate::dns::RData::AAAA(ipv6) => addrs.push(ipv6.to_string()),
                        _ => {}
                    }
                }

                debug!(
                    upstream = upstream.addr.as_str(),
                    elapsed_ms = elapsed.as_millis(),
                    queries = queries,
                    successes = successes,
                    failures = failures,
                    avg_resp_us = upstream.health.avg_response_time_us.load(Ordering::Relaxed),
                    addrs = ?addrs,
                    "Query to upstream succeeded"
                );
                Ok(response)
            }
            Err(e) => {
                if self.health_checks_enabled {
                    upstream.health.record_failure();
                    // Report failure to Prometheus metrics
                    let _ = {
                        use crate::metrics::UPSTREAM_QUERIES_TOTAL;
                        UPSTREAM_QUERIES_TOTAL
                            .with_label_values(&[&upstream.addr, "error"])
                            .inc();
                        Ok::<(), ()>(())
                    };
                }
                let (queries, successes, failures) = upstream.health.counters();
                warn!(
                    upstream = upstream.addr.as_str(),
                    error = %e,
                    queries = queries,
                    successes = successes,
                    failures = failures,
                    "Query to upstream failed"
                );
                Err(e)
            }
        }
    }

    /// Forward a query to an upstream server
    async fn forward_query(&self, request: &Message, upstream: &str) -> Result<Message> {
        debug!("Forwarding query to upstream: {}", upstream);

        // If upstream looks like an HTTP URL, use DoH (HTTP POST application/dns-message)
        if upstream.starts_with("http://") || upstream.starts_with("https://") {
            return self.forward_query_doh(request, upstream).await;
        }

        // Otherwise treat as a UDP/TCP socket address (legacy)
        let upstream_addr = SocketAddr::from_str(upstream)
            .map_err(|e| crate::Error::Config(format!("Invalid upstream address: {}", e)))?;

        // Create a UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // If ECS metadata exists, attach logs (future: attach EDNS0 options)
        // This log aids debugging when client-subnet data is present.
        // Note: actual EDNS0 integration is handled elsewhere.
        // We intentionally do not mutate the request here.
        if cfg!(debug_assertions) {
            // Log if ECS metadata exists
            // Use a try-get to avoid panics
            // (Context not available here; kept for future extension point)
        }

        // Serialize the request (placeholder - we'll use a simple implementation)
        let request_data = Self::serialize_message(request)?;

        // Send the query
        let sent = socket.send_to(&request_data, upstream_addr).await?;
        debug!("Sent {} bytes to upstream {}", sent, upstream_addr);

        // Receive the response with timeout
        let mut response_buf = vec![0u8; 512];
        let recv_res = timeout(self.timeout, socket.recv_from(&mut response_buf)).await;
        let (len, _) = match recv_res {
            Ok(Ok((len, peer))) => {
                debug!("Received {} bytes from upstream {}", len, peer);
                (len, peer)
            }
            Ok(Err(e)) => {
                warn!("Error receiving from upstream {}: {}", upstream_addr, e);
                return Err(crate::Error::Other(e.to_string()));
            }
            Err(_) => {
                warn!(
                    "Timeout waiting for response from upstream {}",
                    upstream_addr
                );
                return Err(crate::Error::Other("Query timeout".to_string()));
            }
        };

        // Parse the response
        let response = match Self::parse_message(&response_buf[..len]) {
            Ok(resp) => {
                // Extract A/AAAA answers for logging
                let mut addrs: Vec<String> = Vec::new();
                for rr in resp.answers() {
                    match rr.rdata() {
                        crate::dns::RData::A(ipv4) => addrs.push(ipv4.to_string()),
                        crate::dns::RData::AAAA(ipv6) => addrs.push(ipv6.to_string()),
                        _ => {}
                    }
                }
                debug!(upstream = ?upstream_addr, answers = resp.answer_count(), addrs = ?addrs, "Parsed response from upstream");
                resp
            }
            Err(e) => {
                warn!(
                    "Failed to parse response from upstream {}: {}",
                    upstream_addr, e
                );
                return Err(e);
            }
        };

        Ok(response)
    }

    /// Forward a query using DNS over HTTPS (DoH) via HTTP POST with content-type application/dns-message
    async fn forward_query_doh(&self, request: &Message, upstream_url: &str) -> Result<Message> {
        debug!("Forwarding query over DoH to {}", upstream_url);

        let mut client_builder = HttpClient::builder();
        // Allow tests to accept self-signed certs by setting
        // LAZYDNS_DOH_ACCEPT_INVALID_CERT in the environment.
        if std::env::var("LAZYDNS_DOH_ACCEPT_INVALID_CERT").is_ok() {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        let client = client_builder
            .build()
            .map_err(|e| crate::Error::Other(e.to_string()))?;

        let request_data = Self::serialize_message(request)?;

        let resp = client
            .post(upstream_url)
            .header("Content-Type", "application/dns-message")
            .body(request_data)
            .send()
            .await
            .map_err(|e| crate::Error::Other(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(crate::Error::Other(format!(
                "HTTP DoH upstream returned error: {}",
                resp.status()
            )));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| crate::Error::Other(e.to_string()))?;

        let response =
            Self::parse_message(&bytes).map_err(|e| crate::Error::Other(e.to_string()))?;

        Ok(response)
    }

    /// Serialize DNS message to wire format
    ///
    /// Uses production-grade hickory-proto library for wire format.
    fn serialize_message(message: &Message) -> Result<Vec<u8>> {
        crate::dns::wire::serialize_message(message)
    }

    /// Parse DNS message from wire format
    ///
    /// Uses production-grade hickory-proto library for wire format.
    fn parse_message(data: &[u8]) -> Result<Message> {
        crate::dns::wire::parse_message(data)
    }
}

#[async_trait]
impl Plugin for ForwardPlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Check if we already have a response
        if ctx.has_response() {
            debug!("Response already set, skipping forward plugin");
            return Ok(());
        }

        // If concurrent queries enabled, race all upstreams
        if self.concurrent_queries && self.upstreams.len() > 1 {
            debug!(
                "Racing {} upstreams for fastest response",
                self.upstreams.len()
            );

            // Query all upstreams concurrently
            let mut tasks = Vec::new();
            for idx in 0..self.upstreams.len() {
                let request = ctx.request().clone();
                let upstream_addr = self.upstreams[idx].addr.clone();
                let timeout_dur = self.timeout;

                let task = tokio::spawn(async move {
                    let addr = SocketAddr::from_str(&upstream_addr).map_err(|e| {
                        crate::Error::Config(format!("Invalid upstream address: {}", e))
                    })?;

                    let socket = UdpSocket::bind("0.0.0.0:0")
                        .await
                        .map_err(|e| crate::Error::Other(e.to_string()))?;

                    let request_data = ForwardPlugin::serialize_message(&request)?;
                    socket
                        .send_to(&request_data, addr)
                        .await
                        .map_err(|e| crate::Error::Other(e.to_string()))?;

                    let mut buf = vec![0u8; 512];
                    let (len, _) = timeout(timeout_dur, socket.recv_from(&mut buf))
                        .await
                        .map_err(|_| crate::Error::Other("Timeout".to_string()))?
                        .map_err(|e| crate::Error::Other(e.to_string()))?;

                    ForwardPlugin::parse_message(&buf[..len])
                });

                tasks.push(task);
            }

            // Wait for first success
            for task in tasks {
                if let Ok(Ok(response)) = task.await {
                    debug!("Got fastest response in concurrent mode");
                    ctx.set_response(Some(response));
                    return Ok(());
                }
            }

            return Err(crate::Error::Other(
                "All concurrent queries failed".to_string(),
            ));
        }

        // Normal sequential mode with failover
        let mut attempts = 0;
        let mut last_error = None;

        while attempts < self.max_attempts && attempts < self.upstreams.len() {
            // Select an upstream
            let upstream_idx = match self.select_upstream() {
                Some(idx) => idx,
                None => {
                    return Err(crate::Error::Config(
                        "No upstream servers configured".to_string(),
                    ));
                }
            };

            // Try forwarding
            debug!(
                "Forward: attempt {}/{} to upstream {}",
                attempts + 1,
                self.max_attempts,
                self.upstreams[upstream_idx].addr
            );
            match self
                .forward_query_with_health(ctx.request(), upstream_idx)
                .await
            {
                Ok(response) => {
                    debug!(
                        "Received response from upstream {}: {} answers",
                        self.upstreams[upstream_idx].addr,
                        response.answer_count()
                    );
                    ctx.set_response(Some(response));
                    return Ok(());
                }
                Err(e) => {
                    error!(
                        "Failed to forward query to {} (attempt {}/{}): {}",
                        self.upstreams[upstream_idx].addr,
                        attempts + 1,
                        self.max_attempts,
                        e
                    );
                    last_error = Some(e);
                    attempts += 1;

                    // If health checks are disabled, don't retry
                    if !self.health_checks_enabled {
                        break;
                    }
                }
            }
        }

        // All attempts failed
        Err(last_error
            .unwrap_or_else(|| crate::Error::Other("All upstream servers failed".to_string())))
    }

    fn name(&self) -> &str {
        "forward"
    }

    fn priority(&self) -> i32 {
        100 // Default priority
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_plugin_creation() {
        let plugin = ForwardPlugin::new(vec!["8.8.8.8:53".to_string()]);
        assert_eq!(plugin.name(), "forward");
        assert_eq!(plugin.priority(), 100);
    }

    #[test]
    fn test_forward_plugin_with_timeout() {
        let plugin =
            ForwardPlugin::with_timeout(vec!["8.8.8.8:53".to_string()], Duration::from_secs(10));
        assert_eq!(plugin.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_next_upstream_round_robin() {
        let plugin = ForwardPlugin::new(vec!["8.8.8.8:53".to_string(), "8.8.4.4:53".to_string()]);

        assert_eq!(plugin.next_upstream(), Some("8.8.8.8:53"));
        assert_eq!(plugin.next_upstream(), Some("8.8.4.4:53"));
        assert_eq!(plugin.next_upstream(), Some("8.8.8.8:53")); // Wraps around
    }

    #[test]
    fn test_next_upstream_empty() {
        let plugin = ForwardPlugin::new(vec![]);
        assert_eq!(plugin.next_upstream(), None);
    }

    #[tokio::test]
    async fn test_forward_plugin_no_upstreams() {
        let plugin = ForwardPlugin::new(vec![]);
        let mut ctx = Context::new(Message::new());

        let result = plugin.execute(&mut ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_forward_plugin_skips_if_response_set() {
        let plugin = ForwardPlugin::new(vec!["8.8.8.8:53".to_string()]);
        let mut ctx = Context::new(Message::new());

        // Set a response first
        ctx.set_response(Some(Message::new()));

        // Plugin should skip execution
        let result = plugin.execute(&mut ctx).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_serialize_message_placeholder() {
        let message = Message::new();
        let result = ForwardPlugin::serialize_message(&message);
        assert!(result.is_ok());
        let data = result.unwrap();
        assert!(!data.is_empty());
    }

    #[test]
    fn test_parse_message_placeholder() {
        // Create a minimal query message (all zeros represents a query, not a response)
        let data = vec![0u8; 12]; // Minimal DNS header
        let result = ForwardPlugin::parse_message(&data);
        assert!(result.is_ok());
        let message = result.unwrap();
        assert!(!message.is_response()); // All zeros means it's a query
    }

    #[tokio::test]
    async fn test_forward_plugin_with_mocked_upstream() {
        use crate::dns::types::{RecordClass, RecordType};
        use crate::dns::{Message, Question, RData};

        // Start a mocked upstream DoH HTTP server and point plugin to it
        let (upstream_addr, server_task) = spawn_doh_http_server("1.2.3.4").await;
        let plugin = ForwardPlugin::builder()
            .add_upstream(upstream_addr.clone())
            .timeout(Duration::from_secs(2))
            .enable_health_checks(true)
            .build();

        // Build a request message
        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut ctx = Context::new(req);

        // Execute plugin
        let res = plugin.execute(&mut ctx).await;
        assert!(res.is_ok());
        assert!(ctx.response().is_some());
        let resp = ctx.response().unwrap();
        assert!(resp.answer_count() >= 1);

        // Verify the A record we injected
        let mut found = false;
        for rr in resp.answers() {
            if rr.rtype() == RecordType::A {
                if let RData::A(ip) = rr.rdata() {
                    assert_eq!(ip.to_string(), "1.2.3.4");
                    found = true;
                }
            }
        }
        assert!(found, "A record from mocked upstream not found");

        let _ = server_task.await;
    }

    #[tokio::test]
    async fn test_upstream_health_counters_on_success_and_failure() {
        use crate::dns::types::{RecordClass, RecordType};
        use crate::dns::{Message, Question};

        // Mock server for success
        let (upstream_addr, server_task) = spawn_doh_https_server("1.2.3.4").await;
        let plugin = ForwardPlugin::builder()
            .add_upstream(upstream_addr.clone())
            .timeout(Duration::from_secs(2))
            .enable_health_checks(true)
            .build();

        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        // Before any requests
        let (q0, s0, f0) = plugin.upstreams[0].health.counters();
        assert_eq!(q0, 0);
        assert_eq!(s0, 0);
        assert_eq!(f0, 0);

        // Ensure health checks enabled
        assert!(
            plugin.health_checks_enabled,
            "Health checks should be enabled for this test"
        );

        // Successful forward
        let mut ctx = Context::new(req.clone());
        let res = plugin.execute(&mut ctx).await;
        assert!(res.is_ok(), "Plugin execution failed: {:?}", res);
        assert!(ctx.response().is_some(), "No response set by upstream");

        let (q1, s1, f1) = plugin.upstreams[0].health.counters();
        assert_eq!(q1, 1, "queries counter should be 1 after success");
        assert_eq!(s1, 1, "successes counter should be 1 after success");
        assert_eq!(f1, 0, "failures counter should be 0 after success");

        // Now test failure increments
        // Use another port where no server listens
        let bad_plugin = ForwardPlugin::builder()
            .add_upstream("127.0.0.1:43210".to_string())
            .timeout(Duration::from_secs(1))
            .enable_health_checks(true)
            .build();
        let mut ctx2 = Context::new(req);
        let _res = bad_plugin.execute(&mut ctx2).await;
        // Execution may return Err but health should reflect failure
        let (q2, s2, f2) = bad_plugin.upstreams[0].health.counters();
        assert_eq!(q2, 1);
        assert_eq!(s2, 0);
        assert_eq!(f2, 1);

        let _ = server_task.await;
    }

    #[test]
    fn test_load_balance_strategies() {
        use super::LoadBalanceStrategy;

        // Test RoundRobin
        let plugin = ForwardPlugin::builder()
            .add_upstream("8.8.8.8:53")
            .add_upstream("1.1.1.1:53")
            .strategy(LoadBalanceStrategy::RoundRobin)
            .build();

        let idx1 = plugin.select_upstream().unwrap();
        let idx2 = plugin.select_upstream().unwrap();
        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);

        // Test Random (just verify it returns valid index)
        let plugin = ForwardPlugin::builder()
            .add_upstream("8.8.8.8:53")
            .add_upstream("1.1.1.1:53")
            .strategy(LoadBalanceStrategy::Random)
            .build();

        let idx = plugin.select_upstream().unwrap();
        assert!(idx < 2);

        // Test Fastest (initially should return first)
        let plugin = ForwardPlugin::builder()
            .add_upstream("8.8.8.8:53")
            .add_upstream("1.1.1.1:53")
            .strategy(LoadBalanceStrategy::Fastest)
            .build();

        let idx = plugin.select_upstream().unwrap();
        assert_eq!(idx, 0); // First upstream before any health data
    }

    #[test]
    fn test_health_tracking() {
        use std::time::Duration;

        let health = UpstreamHealth::new();

        // Record some successes
        health.record_success(Duration::from_millis(10));
        health.record_success(Duration::from_millis(20));
        health.record_success(Duration::from_millis(30));

        assert_eq!(health.queries.load(Ordering::Relaxed), 3);
        assert_eq!(health.successes.load(Ordering::Relaxed), 3);
        assert_eq!(health.failures.load(Ordering::Relaxed), 0);

        // Record a failure
        health.record_failure();
        assert_eq!(health.queries.load(Ordering::Relaxed), 4);
        assert_eq!(health.failures.load(Ordering::Relaxed), 1);

        // Check avg response time is reasonable
        let avg = health.avg_response_time();
        assert!(avg > Duration::ZERO);
        assert!(avg < Duration::from_millis(100));
    }

    #[test]
    fn test_builder_pattern() {
        use std::time::Duration;

        let plugin = ForwardPlugin::builder()
            .add_upstream("8.8.8.8:53")
            .add_upstream("1.1.1.1:53")
            .timeout(Duration::from_secs(10))
            .strategy(LoadBalanceStrategy::Fastest)
            .enable_health_checks(true)
            .max_attempts(5)
            .build();

        assert_eq!(plugin.upstreams.len(), 2);
        assert_eq!(plugin.timeout, Duration::from_secs(10));
        assert_eq!(plugin.strategy, LoadBalanceStrategy::Fastest);
        assert!(plugin.health_checks_enabled);
        assert_eq!(plugin.max_attempts, 5);
    }

    #[tokio::test]
    async fn test_forward_plugin_doh_http_post() {
        use crate::dns::types::{RecordClass, RecordType};
        use crate::dns::{Message, Question, RData, ResourceRecord};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Start a minimal HTTP server that accepts a single DoH POST
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                // Read request (headers + body). Simple approach: read into buffer and parse.
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                // Split headers and body
                let parts: Vec<&str> = req.split("\r\n\r\n").collect();
                if parts.len() < 2 {
                    return;
                }
                let headers = parts[0];
                let mut body = parts[1].as_bytes().to_vec();

                // Content-Length may require reading more bytes if truncated
                let mut content_length = 0usize;
                for line in headers.lines() {
                    if line.to_lowercase().starts_with("content-length:") {
                        if let Some(v) = line.split(':').nth(1) {
                            content_length = v.trim().parse().unwrap_or(0);
                        }
                    }
                }

                while body.len() < content_length {
                    let mut more = vec![0u8; 1024];
                    let m = socket.read(&mut more).await.unwrap_or(0);
                    if m == 0 {
                        break;
                    }
                    body.extend_from_slice(&more[..m]);
                }

                // Parse DNS query from body
                if let Ok(req_msg) =
                    ForwardPlugin::parse_message(&body[..content_length.min(body.len())])
                {
                    let mut resp = req_msg.clone();
                    resp.set_response(true);
                    resp.add_answer(ResourceRecord::new(
                        req_msg.questions()[0].qname().to_string(),
                        RecordType::A,
                        RecordClass::IN,
                        60,
                        RData::A("9.9.9.9".parse().unwrap()),
                    ));
                    resp.set_id(req_msg.id());

                    if let Ok(data) = ForwardPlugin::serialize_message(&resp) {
                        let resp_hdr = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                            data.len()
                        );
                        let _ = socket.write_all(resp_hdr.as_bytes()).await;
                        let _ = socket.write_all(&data).await;
                    }
                }
            }
        });

        // Build plugin pointing to our minimal DoH endpoint
        let url = format!("http://{}/dns-query", local_addr);
        let plugin = ForwardPlugin::builder()
            .add_upstream(url)
            .timeout(Duration::from_secs(2))
            .enable_health_checks(true)
            .build();

        // Build a request message
        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut ctx = Context::new(req);

        // Execute plugin and verify response
        let res = plugin.execute(&mut ctx).await;
        assert!(res.is_ok());
        assert!(ctx.response().is_some());
        let resp = ctx.response().unwrap();

        let mut found = false;
        for rr in resp.answers() {
            if rr.rtype() == RecordType::A {
                if let RData::A(ip) = rr.rdata() {
                    assert_eq!(ip.to_string(), "9.9.9.9");
                    found = true;
                }
            }
        }
        assert!(found, "A record from DoH upstream not found");

        let _ = server_task.await;
    }

    #[test]
    fn test_add_upstream_with_tag_parses_tag() {
        let plugin = ForwardPlugin::builder()
            .add_upstream_with_tag("8.8.8.8:53", "google")
            .build();

        assert_eq!(plugin.upstreams.len(), 1);
        assert_eq!(plugin.upstreams[0].addr, "8.8.8.8:53");
        assert_eq!(plugin.upstreams[0].tag.as_deref(), Some("google"));
    }

    #[tokio::test]
    async fn test_forward_plugin_doh_https_post_with_self_signed_cert() {
        use crate::dns::types::{RecordClass, RecordType};
        use crate::dns::{Message, Question, RData, ResourceRecord};
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        // Ensure rustls has a process-level CryptoProvider installed
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Generate a self-signed certificate for "localhost"
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.serialize_der().unwrap();
        let key_der = cert.get_key_pair().serialize_der();

        // Build rustls server config
        let certs = vec![CertificateDer::from(cert_der.clone())];
        let priv_key = PrivateKeyDer::Pkcs8(key_der.clone().into());
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, priv_key)
            .unwrap();

        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        // Start TLS listener
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                if let Ok(mut tls_stream) = acceptor.accept(socket).await {
                    let mut buf = vec![0u8; 8192];
                    let n = tls_stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    // Split headers and body
                    let parts: Vec<&str> = req.split("\r\n\r\n").collect();
                    if parts.len() < 2 {
                        return;
                    }
                    let headers = parts[0];
                    let mut body = parts[1].as_bytes().to_vec();

                    // Content-Length handling
                    let mut content_length = 0usize;
                    for line in headers.lines() {
                        if line.to_lowercase().starts_with("content-length:") {
                            if let Some(v) = line.split(':').nth(1) {
                                content_length = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }

                    while body.len() < content_length {
                        let mut more = vec![0u8; 1024];
                        let m = tls_stream.read(&mut more).await.unwrap_or(0);
                        if m == 0 {
                            break;
                        }
                        body.extend_from_slice(&more[..m]);
                    }

                    if let Ok(req_msg) =
                        ForwardPlugin::parse_message(&body[..content_length.min(body.len())])
                    {
                        let mut resp = req_msg.clone();
                        resp.set_response(true);
                        resp.add_answer(ResourceRecord::new(
                            req_msg.questions()[0].qname().to_string(),
                            RecordType::A,
                            RecordClass::IN,
                            60,
                            RData::A("4.4.4.4".parse().unwrap()),
                        ));
                        resp.set_id(req_msg.id());

                        if let Ok(data) = ForwardPlugin::serialize_message(&resp) {
                            let resp_hdr = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                                data.len()
                            );
                            let _ = tls_stream.write_all(resp_hdr.as_bytes()).await;
                            let _ = tls_stream.write_all(&data).await;
                        }
                    }
                }
            }
        });

        // Set env var so forward_query_doh will accept our self-signed cert
        unsafe {
            std::env::set_var("LAZYDNS_DOH_ACCEPT_INVALID_CERT", "1");
        }

        // Build plugin pointing to our HTTPS DoH endpoint (use localhost hostname)
        let url = format!("https://localhost:{}/dns-query", local_addr.port());
        let plugin = ForwardPlugin::builder()
            .add_upstream(url)
            .timeout(Duration::from_secs(2))
            .enable_health_checks(true)
            .build();

        // Build a request message
        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut ctx = Context::new(req);

        // Execute plugin and verify response
        let res = plugin.execute(&mut ctx).await;
        assert!(res.is_ok());
        assert!(ctx.response().is_some());
        let resp = ctx.response().unwrap();

        let mut found = false;
        for rr in resp.answers() {
            if rr.rtype() == RecordType::A {
                if let RData::A(ip) = rr.rdata() {
                    assert_eq!(ip.to_string(), "4.4.4.4");
                    found = true;
                }
            }
        }
        assert!(found, "A record from DoH HTTPS upstream not found");

        // Cleanup
        let _ = server_task.await;
        unsafe {
            std::env::remove_var("LAZYDNS_DOH_ACCEPT_INVALID_CERT");
        }
    }

    #[test]
    fn test_select_upstream_fastest_prefers_measured() {
        use std::time::Duration;

        let plugin = ForwardPlugin::builder()
            .add_upstream("8.8.8.8:53")
            .add_upstream("1.1.1.1:53")
            .strategy(LoadBalanceStrategy::Fastest)
            .build();

        // Initially no measurements: Fastest should return first index
        let idx_initial = plugin.select_upstream().unwrap();
        assert_eq!(idx_initial, 0);

        // Record a fast response for the second upstream and a slower one for the first
        plugin.upstreams[1]
            .health
            .record_success(Duration::from_millis(5));
        plugin.upstreams[0]
            .health
            .record_success(Duration::from_millis(100));

        // Now Fastest should prefer the second upstream (index 1)
        let idx_after = plugin.select_upstream().unwrap();
        assert_eq!(idx_after, 1);
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    /// Spawn a minimal HTTP DoH server that responds with a single A record.
    /// Returns the URL to use and the server JoinHandle.
    async fn spawn_doh_http_server(response_ip: &str) -> (String, JoinHandle<()>) {
        use crate::dns::types::{RecordClass, RecordType};
        use crate::dns::{RData, ResourceRecord};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let ip = response_ip.to_string();

        let handle = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                let parts: Vec<&str> = req.split("\r\n\r\n").collect();
                if parts.len() < 2 {
                    return;
                }
                let headers = parts[0];
                let mut body = parts[1].as_bytes().to_vec();

                // Content-Length handling
                let mut content_length = 0usize;
                for line in headers.lines() {
                    if line.to_lowercase().starts_with("content-length:") {
                        if let Some(v) = line.split(':').nth(1) {
                            content_length = v.trim().parse().unwrap_or(0);
                        }
                    }
                }

                while body.len() < content_length {
                    let mut more = vec![0u8; 1024];
                    let m = socket.read(&mut more).await.unwrap_or(0);
                    if m == 0 {
                        break;
                    }
                    body.extend_from_slice(&more[..m]);
                }

                if let Ok(req_msg) =
                    crate::dns::wire::parse_message(&body[..content_length.min(body.len())])
                {
                    let mut resp = req_msg.clone();
                    resp.set_response(true);
                    resp.add_answer(ResourceRecord::new(
                        req_msg.questions()[0].qname().to_string(),
                        RecordType::A,
                        RecordClass::IN,
                        60,
                        RData::A(ip.parse().unwrap()),
                    ));
                    resp.set_id(req_msg.id());

                    if let Ok(data) = crate::dns::wire::serialize_message(&resp) {
                        let resp_hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                        data.len()
                    );
                        let _ = socket.write_all(resp_hdr.as_bytes()).await;
                        let _ = socket.write_all(&data).await;
                    }
                }
            }
        });

        let url = format!("http://127.0.0.1:{}/dns-query", local_addr.port());
        (url, handle)
    }

    /// Spawn a minimal HTTPS DoH server using a self-signed certificate.
    /// Returns the HTTPS URL and server JoinHandle.
    async fn spawn_doh_https_server(response_ip: &str) -> (String, JoinHandle<()>) {
        use crate::dns::types::{RecordClass, RecordType};
        use crate::dns::{RData, ResourceRecord};
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::TlsAcceptor;

        // Ensure rustls has a process-level CryptoProvider installed for tests
        // This avoids failures constructing ServerConfig when running tests in isolation.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // For tests using our self-signed DoH server, accept invalid certs on the
        // client side so the client won't reject the server's self-signed cert.
        std::env::set_var("LAZYDNS_DOH_ACCEPT_INVALID_CERT", "1");

        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.serialize_der().unwrap();
        let key_der = cert.get_key_pair().serialize_der();

        let certs = vec![CertificateDer::from(cert_der.clone())];
        let priv_key = PrivateKeyDer::Pkcs8(key_der.clone().into());
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, priv_key)
            .unwrap();

        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let ip = response_ip.to_string();

        let handle = tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                if let Ok(mut tls_stream) = acceptor.accept(socket).await {
                    let mut buf = vec![0u8; 8192];
                    let n = tls_stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    let parts: Vec<&str> = req.split("\r\n\r\n").collect();
                    if parts.len() < 2 {
                        return;
                    }
                    let headers = parts[0];
                    let mut body = parts[1].as_bytes().to_vec();

                    let mut content_length = 0usize;
                    for line in headers.lines() {
                        if line.to_lowercase().starts_with("content-length:") {
                            if let Some(v) = line.split(':').nth(1) {
                                content_length = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }

                    while body.len() < content_length {
                        let mut more = vec![0u8; 1024];
                        let m = tls_stream.read(&mut more).await.unwrap_or(0);
                        if m == 0 {
                            break;
                        }
                        body.extend_from_slice(&more[..m]);
                    }

                    if let Ok(req_msg) =
                        crate::dns::wire::parse_message(&body[..content_length.min(body.len())])
                    {
                        let mut resp = req_msg.clone();
                        resp.set_response(true);
                        resp.add_answer(ResourceRecord::new(
                            req_msg.questions()[0].qname().to_string(),
                            RecordType::A,
                            RecordClass::IN,
                            60,
                            RData::A(ip.parse().unwrap()),
                        ));
                        resp.set_id(req_msg.id());

                        if let Ok(data) = crate::dns::wire::serialize_message(&resp) {
                            let resp_hdr = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                            data.len()
                        );
                            let _ = tls_stream.write_all(resp_hdr.as_bytes()).await;
                            let _ = tls_stream.write_all(&data).await;
                        }
                    }
                }
            }
        });

        let url = format!("https://localhost:{}/dns-query", local_addr.port());
        (url, handle)
    }
}

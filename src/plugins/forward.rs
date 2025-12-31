//! Forward plugin - forwards DNS queries to upstream resolvers
//!
//! This module wraps the core forward logic with the Plugin trait for execution
//! within the plugin chain. It supports multiple upstreams with various load
//! balancing strategies, health checks, failover, and concurrent queries.

use crate::Result;
use crate::config::PluginConfig;
use crate::dns::Message;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use reqwest::Client as HttpClient;
use serde_yaml::Value;
use std::any::Any;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant, timeout};
use tracing::{debug, trace, warn};

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

/// Health status tracker for an upstream server.
///
/// This struct maintains lightweight counters and timing information used
/// by the forwarding code and optional health-checking logic. Counters are
/// updated with relaxed atomic operations and are safe to read concurrently.
///
/// # Notes
/// - `queries`, `successes` and `failures` are monotonically increasing
///   counters used for simple health heuristics and Prometheus metrics.
/// - `avg_response_time_us` stores an average response time in microseconds.
/// - `last_success` stores the instant of the last successful query and is
///   protected by a small Mutex since it is rarely accessed and not on
///   the hot path.
#[derive(Debug)]
pub struct UpstreamHealth {
    /// Total queries sent
    pub queries: AtomicU64,
    /// Successful responses
    pub successes: AtomicU64,
    /// Failed queries
    pub failures: AtomicU64,
    /// Average response time in microseconds
    pub avg_response_time_us: AtomicU64,
    /// Last successful query timestamp
    pub last_success: std::sync::Mutex<Option<Instant>>,
}

impl UpstreamHealth {
    /// Create a new health tracker
    pub fn new() -> Self {
        Self {
            queries: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            avg_response_time_us: AtomicU64::new(0),
            last_success: std::sync::Mutex::new(None),
        }
    }

    // (methods continue)
    /// Record a successful query with response time
    pub fn record_success(&self, response_time: Duration) {
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

    /// Record a failed query
    pub fn record_failure(&self) {
        self.queries.fetch_add(1, Ordering::Relaxed);
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Get success rate as a fraction (0.0 to 1.0)
    pub fn success_rate(&self) -> f64 {
        let total = self.queries.load(Ordering::Relaxed);
        if total == 0 {
            return 1.0;
        }
        let successes = self.successes.load(Ordering::Relaxed);
        successes as f64 / total as f64
    }

    /// Get counters snapshot (queries, successes, failures)
    pub fn counters(&self) -> (u64, u64, u64) {
        (
            self.queries.load(Ordering::Relaxed),
            self.successes.load(Ordering::Relaxed),
            self.failures.load(Ordering::Relaxed),
        )
    }

    /// Get average response time
    pub fn avg_response_time(&self) -> Duration {
        let micros = self.avg_response_time_us.load(Ordering::Relaxed);
        Duration::from_micros(micros)
    }
}

impl Default for UpstreamHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for a single upstream DNS server
///
/// The `addr` field stores the network address used to contact the
/// resolver (e.g. `1.2.3.4:53` or a DoH URL like `https://...`). The
/// optional `tag` can be used to give a human-friendly identifier for
/// logging or metrics registration. The `health` field contains the
/// runtime health counters for this upstream.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// Server address (ip:port or https://... for DoH)
    pub addr: String,
    /// Optional tag for identification
    pub tag: Option<String>,
    /// Health tracking for this upstream
    pub health: Arc<UpstreamHealth>,
}

impl Upstream {
    /// Create a new upstream configuration
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            tag: None,
            health: Arc::new(UpstreamHealth::new()),
        }
    }

    /// Create a new upstream with an optional tag
    pub fn with_tag(addr: impl Into<String>, tag: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            tag: Some(tag.into()),
            health: Arc::new(UpstreamHealth::new()),
        }
    }
}

/// Core forwarding logic used by the `ForwardPlugin`.
///
/// `Forward` implements the actual network operations to contact upstream
/// resolvers (UDP/TCP/DoH), timeouts, and selection strategies. It is
/// intentionally independent of the plugin trait so it can be tested and
/// reused from other places in the codebase.
#[derive(Debug, Clone)]
pub struct Forward {
    /// Upstream servers
    pub upstreams: Vec<Upstream>,
    /// Query timeout
    pub timeout: Duration,
    /// Load balancing strategy
    pub strategy: LoadBalanceStrategy,
    /// Enable health checks
    pub health_checks_enabled: bool,
    /// Maximum failover attempts
    pub max_attempts: usize,
}

impl Forward {
    /// Create a new Forward
    pub fn new(upstreams: Vec<Upstream>, timeout: Duration, strategy: LoadBalanceStrategy) -> Self {
        Self {
            upstreams,
            timeout,
            strategy,
            health_checks_enabled: false,
            max_attempts: 3,
        }
    }

    /// Enable or disable health checks
    pub fn with_health_checks(mut self, enabled: bool) -> Self {
        self.health_checks_enabled = enabled;
        self
    }

    /// Set max failover attempts
    pub fn with_max_attempts(mut self, max: usize) -> Self {
        self.max_attempts = max;
        self
    }

    /// Select upstream based on strategy (requires current index for round-robin)
    pub fn select_upstream(&self, current_idx: usize) -> Option<usize> {
        if self.upstreams.is_empty() {
            return None;
        }

        match self.strategy {
            LoadBalanceStrategy::RoundRobin => Some(current_idx % self.upstreams.len()),
            LoadBalanceStrategy::Random => {
                use std::time::SystemTime;
                let nanos = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                Some((nanos as usize) % self.upstreams.len())
            }
            LoadBalanceStrategy::Fastest => {
                let mut best_idx = 0;
                let mut best_time = self.upstreams[0].health.avg_response_time();

                for (idx, upstream) in self.upstreams.iter().enumerate().skip(1) {
                    let avg_time = upstream.health.avg_response_time();

                    if best_time == Duration::ZERO {
                        // Keep first unmeasured upstream
                        continue;
                    }

                    // Prefer unmeasured upstreams or upstreams faster than current best
                    if avg_time == Duration::ZERO || avg_time < best_time {
                        best_idx = idx;
                        best_time = avg_time;
                    }
                }
                Some(best_idx)
            }
        }
    }

    /// Forward a query to an upstream server
    pub async fn forward_query(&self, request: &Message, upstream: &Upstream) -> Result<Message> {
        trace!("Forwarding query to upstream: {}", upstream.addr);

        if upstream.addr.starts_with("http://") || upstream.addr.starts_with("https://") {
            self.forward_query_doh(request, &upstream.addr).await
        } else {
            self.forward_query_udp(request, &upstream.addr).await
        }
    }

    /// Forward via UDP/TCP
    async fn forward_query_udp(&self, request: &Message, upstream: &str) -> Result<Message> {
        let upstream_addr = SocketAddr::from_str(upstream)
            .map_err(|e| crate::Error::Config(format!("Invalid upstream address: {}", e)))?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let request_data = Self::serialize_message(request)?;

        let sent = socket.send_to(&request_data, upstream_addr).await?;
        trace!("Sent {} bytes to upstream {}", sent, upstream_addr);

        let mut response_buf = vec![0u8; 512];
        let recv_res = timeout(self.timeout, socket.recv_from(&mut response_buf)).await;
        let (len, _) = match recv_res {
            Ok(Ok((len, peer))) => {
                trace!("Received {} bytes from upstream {}", len, peer);
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

        let response = Self::parse_message(&response_buf[..len])?;
        Ok(response)
    }

    /// Forward via DNS over HTTPS
    async fn forward_query_doh(&self, request: &Message, upstream_url: &str) -> Result<Message> {
        trace!("Forwarding query over DoH to {}", upstream_url);

        let mut client_builder = HttpClient::builder();
        // In test environments, accept invalid certificates for self-signed test servers
        if cfg!(test) || std::env::var("LAZYDNS_DOH_ACCEPT_INVALID_CERT").is_ok() {
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

        Self::parse_message(&bytes)
    }

    /// Serialize DNS message to wire format
    pub fn serialize_message(message: &Message) -> Result<Vec<u8>> {
        crate::dns::wire::serialize_message(message)
    }

    /// Parse DNS message from wire format
    pub fn parse_message(data: &[u8]) -> Result<Message> {
        crate::dns::wire::parse_message(data)
    }
}

/// Builder for `Forward` (parsing/validation of core settings)
/// Builder for `Forward`.
///
/// This builder parses configuration values (usually coming from plugin
/// args) and produces a ready-to-use `Forward` core instance. Use
/// `ForwardBuilder::from_args` to convert the YAML/JSON-like config map
/// into a `Forward`.
pub struct ForwardBuilder {
    upstreams: Vec<Upstream>,
    timeout: Duration,
    strategy: LoadBalanceStrategy,
    health_checks_enabled: bool,
    max_attempts: usize,
}

impl ForwardBuilder {
    /// Create a new builder with sensible defaults
    pub fn new() -> Self {
        Self {
            upstreams: Vec::new(),
            timeout: Duration::from_secs(5),
            strategy: LoadBalanceStrategy::RoundRobin,
            health_checks_enabled: false,
            max_attempts: 3,
        }
    }

    pub fn add_upstream(mut self, u: Upstream) -> Self {
        self.upstreams.push(u);
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn strategy(mut self, strategy: LoadBalanceStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    pub fn enable_health_checks(mut self, enabled: bool) -> Self {
        self.health_checks_enabled = enabled;
        self
    }

    pub fn max_attempts(mut self, max: usize) -> Self {
        self.max_attempts = max;
        self
    }

    /// Build the `Forward` from the builder
    pub fn build(self) -> Forward {
        Forward::new(self.upstreams, self.timeout, self.strategy)
            .with_health_checks(self.health_checks_enabled)
            .with_max_attempts(self.max_attempts)
    }

    /// Parse core settings from plugin args (effective args map)
    pub fn from_args(args: &HashMap<String, Value>) -> crate::Result<Forward> {
        // Parse upstreams (required)
        let upstreams_val = args.get("upstreams").ok_or_else(|| {
            crate::Error::Config("upstreams is required for forward plugin".to_string())
        })?;

        let mut upstreams = Vec::new();

        match upstreams_val {
            Value::Sequence(seq) => {
                for item in seq {
                    match item {
                        Value::String(s) => {
                            let mut entry = s.clone();

                            // Preserve DoH URLs (http/https), but strip udp:// and tcp://
                            if !(entry.starts_with("http://") || entry.starts_with("https://")) {
                                entry = entry
                                    .trim_start_matches("udp://")
                                    .trim_start_matches("tcp://")
                                    .to_string();

                                if !entry.contains(':') {
                                    entry.push_str(":53");
                                }
                            }

                            if let Some((addr, tag)) = entry.split_once('|') {
                                upstreams
                                    .push(Upstream::with_tag(addr.to_string(), tag.to_string()));
                            } else {
                                upstreams.push(Upstream::new(entry));
                            }
                        }
                        Value::Mapping(map) => {
                            // Support mapping form: { addr: "1.2.3.4:53", tag: "x" }
                            let mut addr = map
                                .get(Value::String("addr".to_string()))
                                .and_then(|v| v.as_str())
                                .ok_or_else(|| {
                                    crate::Error::Config(
                                        "upstream mapping must contain addr".to_string(),
                                    )
                                })?
                                .to_string();

                            // Preserve DoH URLs (http/https), but strip udp:// and tcp://
                            if !(addr.starts_with("http://") || addr.starts_with("https://")) {
                                addr = addr
                                    .trim_start_matches("udp://")
                                    .trim_start_matches("tcp://")
                                    .to_string();

                                if !addr.contains(':') {
                                    addr.push_str(":53");
                                }
                            }

                            let tag = map
                                .get(Value::String("tag".to_string()))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            if let Some(t) = tag {
                                upstreams.push(Upstream::with_tag(addr, t));
                            } else {
                                upstreams.push(Upstream::new(addr));
                            }
                        }
                        _ => {
                            return Err(crate::Error::Config(
                                "upstreams must be array of strings or mappings".to_string(),
                            ));
                        }
                    }
                }
            }
            _ => {
                return Err(crate::Error::Config(
                    "upstreams must be an array".to_string(),
                ));
            }
        }

        // timeout
        let mut builder = ForwardBuilder::new();

        if let Some(Value::Number(n)) = args.get("timeout") {
            let secs = n
                .as_i64()
                .ok_or_else(|| crate::Error::Config("Invalid timeout value".to_string()))?;
            builder = builder.timeout(Duration::from_secs(secs as u64));
        }

        // strategy
        if let Some(Value::String(s)) = args.get("strategy") {
            let strategy = match s.as_str() {
                "round_robin" | "roundrobin" => LoadBalanceStrategy::RoundRobin,
                "random" => LoadBalanceStrategy::Random,
                "fastest" => LoadBalanceStrategy::Fastest,
                _ => return Err(crate::Error::Config(format!("Unknown strategy: {}", s))),
            };
            builder = builder.strategy(strategy);
        }

        // health_checks
        if let Some(Value::Bool(enabled)) = args.get("health_checks") {
            builder = builder.enable_health_checks(*enabled);
        }

        // max_attempts
        if let Some(Value::Number(n)) = args.get("max_attempts") {
            let max = n
                .as_i64()
                .ok_or_else(|| crate::Error::Config("Invalid max_attempts value".to_string()))?
                as usize;
            builder = builder.max_attempts(max);
        }

        // add parsed upstreams
        for u in upstreams {
            builder = builder.add_upstream(u);
        }

        Ok(builder.build())
    }
}

impl Default for ForwardBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Forward plugin - forwards DNS queries to upstream resolvers
///
/// This plugin forwards DNS queries to configured upstream DNS servers.
/// It supports multiple upstreams with various load balancing strategies,
/// health checks, failover, and concurrent queries.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::forward::ForwardPlugin;
///
/// // Create a simple forward plugin from upstream addresses
/// let plugin = lazydns::plugins::forward::ForwardPlugin::new(vec![
///     "8.8.8.8:53".to_string(),
///     "8.8.4.4:53".to_string(),
///]);
/// ```
/// Runtime plugin wrapper for forwarding queries to upstream resolvers.
///
/// `ForwardPlugin` wraps a `Forward` core and implements the `Plugin`
/// trait so it can be inserted into the plugin chain. The plugin supports
/// optional concurrent (race) queries, health checks, and failover.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::forward::ForwardPlugin;
/// use std::time::Duration;
///
/// // Build a simple forward plugin that contacts two upstreams
/// let plugin = ForwardPlugin::new(vec!["8.8.8.8:53".into(), "1.1.1.1:53".into()]);
/// ```
#[derive(Debug)]
pub struct ForwardPlugin {
    /// Core forwarding logic
    core: Forward,
    /// Current upstream index for round-robin
    current: AtomicUsize,
    /// Enable concurrent queries (race mode)
    concurrent_queries: bool,
}

impl ForwardPlugin {
    /// Create a new forward plugin with default settings
    ///
    /// # Arguments
    ///
    /// * `upstreams` - List of upstream DNS server addresses (format: "ip:port")
    pub fn new(upstreams: Vec<String>) -> Self {
        let ups: Vec<Upstream> = upstreams
            .into_iter()
            .map(|entry| {
                if let Some((addr, tag)) = entry.split_once('|') {
                    Upstream::with_tag(addr.to_string(), tag.to_string())
                } else {
                    Upstream::new(entry)
                }
            })
            .collect();

        let core = Forward::new(ups, Duration::from_secs(5), LoadBalanceStrategy::RoundRobin)
            .with_health_checks(false)
            .with_max_attempts(3);

        ForwardPlugin {
            core,
            current: AtomicUsize::new(0),
            concurrent_queries: false,
        }
    }

    /// Create a forward plugin with custom timeout (legacy method)
    ///
    /// # Arguments
    ///
    /// * `upstreams` - List of upstream DNS server addresses
    /// * `timeout` - Query timeout duration
    pub fn with_timeout(upstreams: Vec<String>, timeout: Duration) -> Self {
        let ups: Vec<Upstream> = upstreams
            .into_iter()
            .map(|entry| {
                if let Some((addr, tag)) = entry.split_once('|') {
                    Upstream::with_tag(addr.to_string(), tag.to_string())
                } else {
                    Upstream::new(entry)
                }
            })
            .collect();

        let core = Forward::new(ups, timeout, LoadBalanceStrategy::RoundRobin)
            .with_health_checks(false)
            .with_max_attempts(3);

        ForwardPlugin {
            core,
            current: AtomicUsize::new(0),
            concurrent_queries: false,
        }
    }

    /// Return a list of upstream address strings (for testing/inspection)
    pub fn upstream_addrs(&self) -> Vec<String> {
        self.core.upstreams.iter().map(|u| u.addr.clone()).collect()
    }

    /// Select an upstream based on the configured strategy
    fn select_upstream(&self) -> Option<usize> {
        let idx = self.current.fetch_add(1, Ordering::Relaxed);
        self.core.select_upstream(idx)
    }

    /// Get the next upstream server for round-robin (legacy method)
    #[allow(dead_code)]
    fn next_upstream(&self) -> Option<&str> {
        let idx = self.select_upstream()?;
        Some(&self.core.upstreams[idx].addr)
    }

    /// Record upstream health and metrics (success/failure)
    fn record_upstream_health(&self, upstream: &Upstream, elapsed: Duration, success: bool) {
        if !self.core.health_checks_enabled {
            return;
        }

        if success {
            upstream.health.record_success(elapsed);
            #[cfg(feature = "metrics")]
            {
                use crate::metrics::{UPSTREAM_DURATION_SECONDS, UPSTREAM_QUERIES_TOTAL};
                UPSTREAM_QUERIES_TOTAL
                    .with_label_values(&[upstream.addr.as_str(), "success"])
                    .inc();
                UPSTREAM_DURATION_SECONDS
                    .with_label_values(&[upstream.addr.as_str()])
                    .observe(elapsed.as_secs_f64());
            }
        } else {
            upstream.health.record_failure();
            #[cfg(feature = "metrics")]
            {
                use crate::metrics::UPSTREAM_QUERIES_TOTAL;
                UPSTREAM_QUERIES_TOTAL
                    .with_label_values(&[upstream.addr.as_str(), "error"])
                    .inc();
            }
        }
    }

    /// Extract A/AAAA answer addresses from response
    fn extract_answer_addresses(response: &Message) -> Vec<String> {
        response
            .answers()
            .iter()
            .filter_map(|rr| match rr.rdata() {
                crate::dns::RData::A(ipv4) => Some(ipv4.to_string()),
                crate::dns::RData::AAAA(ipv6) => Some(ipv6.to_string()),
                _ => None,
            })
            .collect()
    }

    /// Forward a query to an upstream server with health tracking
    async fn forward_query_with_health(
        &self,
        request: &Message,
        upstream_idx: usize,
    ) -> Result<Message> {
        let upstream = &self.core.upstreams[upstream_idx];
        let start = std::time::Instant::now();

        match self.core.forward_query(request, upstream).await {
            Ok(response) => {
                let elapsed = start.elapsed();
                self.record_upstream_health(upstream, elapsed, true);

                let (queries, successes, failures) = upstream.health.counters();
                let addrs = Self::extract_answer_addresses(&response);

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
                self.record_upstream_health(upstream, start.elapsed(), false);

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

    /// Execute concurrent queries to all upstreams, return first success
    async fn execute_concurrent(&self, request: &Message) -> Result<Message> {
        let mut tasks = Vec::new();

        for idx in 0..self.core.upstreams.len() {
            let req = request.clone();
            let core = self.core.clone();

            let task = tokio::spawn(async move {
                let upstream = &core.upstreams[idx];
                trace!("Concurrent query to: {}", upstream.addr);
                let start = std::time::Instant::now();

                match core.forward_query(&req, upstream).await {
                    Ok(response) => {
                        let elapsed = start.elapsed();
                        if core.health_checks_enabled {
                            upstream.health.record_success(elapsed);
                            #[cfg(feature = "metrics")]
                            {
                                use crate::metrics::{
                                    UPSTREAM_DURATION_SECONDS, UPSTREAM_QUERIES_TOTAL,
                                };
                                UPSTREAM_QUERIES_TOTAL
                                    .with_label_values(&[upstream.addr.as_str(), "success"])
                                    .inc();
                                UPSTREAM_DURATION_SECONDS
                                    .with_label_values(&[upstream.addr.as_str()])
                                    .observe(elapsed.as_secs_f64());
                            }
                        }

                        Ok(response)
                    }
                    Err(e) => {
                        if core.health_checks_enabled {
                            upstream.health.record_failure();
                            #[cfg(feature = "metrics")]
                            {
                                use crate::metrics::UPSTREAM_QUERIES_TOTAL;
                                UPSTREAM_QUERIES_TOTAL
                                    .with_label_values(&[upstream.addr.as_str(), "error"])
                                    .inc();
                            }
                        }
                        Err(e)
                    }
                }
            });

            tasks.push(task);
        }

        // Wait for first success
        for task in tasks {
            if let Ok(Ok(response)) = task.await {
                trace!(answers = ?response.answers(), "Got fastest response in concurrent mode");
                return Ok(response);
            }
        }

        Err(crate::Error::Other(
            "All concurrent queries failed".to_string(),
        ))
    }

    /// Execute sequential failover through upstreams
    async fn execute_sequential(&self, ctx: &mut Context, request: &Message) -> Result<()> {
        let mut attempts = 0;
        let mut last_error = None;

        while attempts < self.core.max_attempts && attempts < self.core.upstreams.len() {
            let upstream_idx = match self.select_upstream() {
                Some(idx) => idx,
                None => {
                    return Err(crate::Error::Config(
                        "No upstream servers configured".to_string(),
                    ));
                }
            };

            debug!(
                "Forward: attempt {}/{} to upstream {}",
                attempts + 1,
                self.core.max_attempts,
                self.core.upstreams[upstream_idx].addr
            );

            match self.forward_query_with_health(request, upstream_idx).await {
                Ok(response) => {
                    debug!(
                        "Received response from upstream {}: {} answers",
                        self.core.upstreams[upstream_idx].addr,
                        response.answer_count()
                    );
                    ctx.set_response(Some(response));
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "Failed to forward query to {} (attempt {}/{}): {}",
                        self.core.upstreams[upstream_idx].addr,
                        attempts + 1,
                        self.core.max_attempts,
                        e
                    );
                    last_error = Some(e);
                    attempts += 1;

                    if !self.core.health_checks_enabled {
                        break;
                    }
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| crate::Error::Other("All upstream servers failed".to_string())))
    }
}

/// Automatically delegate Forward's public methods to ForwardPlugin
/// via the Deref trait. This eliminates the need for proxy methods.
impl Deref for ForwardPlugin {
    type Target = Forward;

    fn deref(&self) -> &Forward {
        &self.core
    }
}

#[async_trait]
impl Plugin for ForwardPlugin {
    fn init(config: &PluginConfig) -> Result<Arc<dyn Plugin>> {
        let args = config.effective_args();

        // Reuse centralized core parser to build Forward
        let core = ForwardBuilder::from_args(&args)?;

        // Parse concurrent flag (legacy behavior: concurrent > 1 -> race)
        let concurrent = match args.get("concurrent") {
            Some(Value::Number(n)) => n.as_i64().unwrap_or(1) > 1,
            _ => false,
        };

        let plugin = ForwardPlugin {
            core,
            current: AtomicUsize::new(0),
            concurrent_queries: concurrent,
        };

        Ok(Arc::new(plugin))
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        if ctx.has_response() {
            debug!("Response already set, skipping forward plugin");
            return Ok(());
        }

        let request = ctx.request().clone();

        // Try concurrent queries if enabled
        if self.concurrent_queries && self.core.upstreams.len() > 1 {
            debug!(
                "Racing {} upstreams for fastest response",
                self.core.upstreams.len()
            );

            if let Ok(response) = self.execute_concurrent(&request).await {
                ctx.set_response(Some(response));
                return Ok(());
            }
        }

        // Fall back to sequential failover
        self.execute_sequential(ctx, &request).await
    }

    fn name(&self) -> &str {
        "forward"
    }

    fn priority(&self) -> i32 {
        100 // Default priority
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// Auto-register the plugin using macro
crate::register_plugin_builder!(ForwardPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{Message, Question, RData, ResourceRecord};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // ============ Tests from core Forward logic ============

    #[test]
    fn test_select_upstream_random_and_fastest() {
        // Random: ensure index is in range
        let upstreams = vec![Upstream::new("8.8.8.8:53"), Upstream::new("1.1.1.1:53")];
        let core = Forward::new(
            upstreams.clone(),
            Duration::from_secs(5),
            LoadBalanceStrategy::Random,
        );
        for _ in 0..10 {
            let idx = core.select_upstream(0).unwrap();
            assert!(idx < core.upstreams.len());
        }

        // Fastest: prefer measured faster upstream
        let ups = upstreams;
        // initially no measurements -> should return first
        let core2 = Forward::new(
            ups.clone(),
            Duration::from_secs(5),
            LoadBalanceStrategy::Fastest,
        );
        let idx_initial = core2.select_upstream(0).unwrap();
        assert_eq!(idx_initial, 0);

        // Record fast time on second upstream and slower on first
        ups[1].health.record_success(Duration::from_millis(5));
        ups[0].health.record_success(Duration::from_millis(100));
        let core3 = Forward::new(ups, Duration::from_secs(5), LoadBalanceStrategy::Fastest);
        let idx_after = core3.select_upstream(0).unwrap();
        assert_eq!(idx_after, 1);
    }

    #[test]
    fn test_serialize_parse_roundtrip() {
        let mut msg = Message::new();
        msg.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let data = Forward::serialize_message(&msg).expect("serialize");
        let parsed = Forward::parse_message(&data).expect("parse");
        assert_eq!(parsed.questions().len(), 1);
        assert_eq!(parsed.questions()[0].qname(), "example.com");
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

    #[tokio::test]
    async fn test_forward_plugin_doh_http_post_basic() {
        // Start a mocked upstream DoH HTTP server and point plugin to it
        let (upstream_addr, server_task) = spawn_doh_http_server("1.2.3.4").await;
        let core = ForwardBuilder::new()
            .add_upstream(Upstream::new(upstream_addr.clone()))
            .timeout(Duration::from_secs(2))
            .enable_health_checks(true)
            .build();
        let plugin = ForwardPlugin {
            core,
            current: AtomicUsize::new(0),
            concurrent_queries: false,
        };

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
            if rr.rtype() == RecordType::A
                && let RData::A(ip) = rr.rdata()
            {
                assert_eq!(ip.to_string(), "1.2.3.4");
                found = true;
            }
        }
        assert!(found, "A record from mocked upstream not found");

        let _ = server_task.await;
    }

    #[cfg(feature = "rustls")]
    #[tokio::test]
    async fn test_upstream_health_counters_on_success_and_failure() {
        // Install process-level CryptoProvider for rustls v0.23
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Mock server for success
        let (upstream_addr, server_task) = spawn_doh_https_server("1.2.3.4").await;
        let core = ForwardBuilder::new()
            .add_upstream(Upstream::new(upstream_addr.clone()))
            .timeout(Duration::from_secs(2))
            .enable_health_checks(true)
            .build();
        let plugin = ForwardPlugin {
            core,
            current: AtomicUsize::new(0),
            concurrent_queries: false,
        };

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
        let core = ForwardBuilder::new()
            .add_upstream(Upstream::new("127.0.0.1:43210".to_string()))
            .timeout(Duration::from_secs(1))
            .enable_health_checks(true)
            .build();
        let bad_plugin = ForwardPlugin {
            core,
            current: AtomicUsize::new(0),
            concurrent_queries: false,
        };
        let mut ctx2 = Context::new(req);
        let _res = bad_plugin.execute(&mut ctx2).await;
        let (q2, s2, f2) = bad_plugin.upstreams[0].health.counters();
        assert_eq!(q2, 1);
        assert_eq!(s2, 0);
        assert_eq!(f2, 1);

        let _ = server_task.await;
    }

    #[test]
    fn test_builder_pattern() {
        let core = ForwardBuilder::new()
            .add_upstream(Upstream::new("8.8.8.8:53".to_string()))
            .add_upstream(Upstream::new("1.1.1.1:53".to_string()))
            .timeout(Duration::from_secs(10))
            .strategy(LoadBalanceStrategy::Fastest)
            .enable_health_checks(true)
            .max_attempts(5)
            .build();
        let plugin = ForwardPlugin {
            core,
            current: AtomicUsize::new(0),
            concurrent_queries: false,
        };

        assert_eq!(plugin.upstreams.len(), 2);
        assert_eq!(plugin.timeout, Duration::from_secs(10));
        assert_eq!(plugin.strategy, LoadBalanceStrategy::Fastest);
        assert!(plugin.health_checks_enabled);
    }

    #[tokio::test]
    async fn test_forward_plugin_doh_http_post() {
        // Start a minimal HTTP server that accepts a single DoH POST
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
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

                let mut content_length = 0usize;
                for line in headers.lines() {
                    if line.to_lowercase().starts_with("content-length:")
                        && let Some(v) = line.split(':').nth(1)
                    {
                        content_length = v.trim().parse().unwrap_or(0);
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

                if let Ok(req_msg) = Forward::parse_message(&body[..content_length.min(body.len())])
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

                    if let Ok(data) = Forward::serialize_message(&resp) {
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

        let url = format!("http://{}/dns-query", local_addr);
        let core = ForwardBuilder::new()
            .add_upstream(Upstream::new(url))
            .timeout(Duration::from_secs(2))
            .enable_health_checks(true)
            .build();
        let plugin = ForwardPlugin {
            core,
            current: AtomicUsize::new(0),
            concurrent_queries: false,
        };

        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut ctx = Context::new(req);

        let res = plugin.execute(&mut ctx).await;
        assert!(res.is_ok());
        assert!(ctx.response().is_some());
        let resp = ctx.response().unwrap();

        let mut found = false;
        for rr in resp.answers() {
            if rr.rtype() == RecordType::A
                && let RData::A(ip) = rr.rdata()
            {
                assert_eq!(ip.to_string(), "9.9.9.9");
                found = true;
            }
        }
        assert!(found, "A record from DoH upstream not found");

        let _ = server_task.await;
    }

    #[test]
    fn test_add_upstream_with_tag_parses_tag() {
        let core = ForwardBuilder::new()
            .add_upstream(Upstream::with_tag(
                "8.8.8.8:53".to_string(),
                "google".to_string(),
            ))
            .build();
        let plugin = ForwardPlugin {
            core,
            current: AtomicUsize::new(0),
            concurrent_queries: false,
        };

        assert_eq!(plugin.upstreams.len(), 1);
        assert_eq!(plugin.upstreams[0].addr, "8.8.8.8:53");
        assert_eq!(plugin.upstreams[0].tag.as_deref(), Some("google"));
    }

    #[tokio::test]
    #[cfg(any(feature = "doh", feature = "dot"))]
    async fn test_forward_plugin_doh_https_post_with_self_signed_cert() {
        use rcgen::generate_simple_self_signed;
        use rustls::ServerConfig;
        use rustls::pki_types::PrivateKeyDer;
        use std::sync::Arc;
        use tokio_rustls::TlsAcceptor;

        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = cert.signing_key.serialize_der();

        let certs = vec![cert_der.clone()];
        let priv_key = PrivateKeyDer::Pkcs8(key_der.clone().into());
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, priv_key)
            .unwrap();

        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await
                && let Ok(mut tls_stream) = acceptor.accept(socket).await
            {
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
                    if line.to_lowercase().starts_with("content-length:")
                        && let Some(v) = line.split(':').nth(1)
                    {
                        content_length = v.trim().parse().unwrap_or(0);
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

                if let Ok(req_msg) = Forward::parse_message(&body[..content_length.min(body.len())])
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

                    if let Ok(data) = Forward::serialize_message(&resp) {
                        let resp_hdr = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                            data.len()
                        );
                        let _ = tls_stream.write_all(resp_hdr.as_bytes()).await;
                        let _ = tls_stream.write_all(&data).await;
                    }
                }
            }
        });

        unsafe {
            std::env::set_var("LAZYDNS_DOH_ACCEPT_INVALID_CERT", "1");
        }

        let url = format!("https://localhost:{}/dns-query", local_addr.port());
        let core = ForwardBuilder::new()
            .add_upstream(Upstream::new(url))
            .timeout(Duration::from_secs(2))
            .enable_health_checks(true)
            .build();
        let plugin = ForwardPlugin {
            core,
            current: AtomicUsize::new(0),
            concurrent_queries: false,
        };

        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut ctx = Context::new(req);

        let res = plugin.execute(&mut ctx).await;
        assert!(res.is_ok());
        assert!(ctx.response().is_some());
        let resp = ctx.response().unwrap();

        let mut found = false;
        for rr in resp.answers() {
            if rr.rtype() == RecordType::A
                && let RData::A(ip) = rr.rdata()
            {
                assert_eq!(ip.to_string(), "4.4.4.4");
                found = true;
            }
        }
        assert!(found, "A record from DoH HTTPS upstream not found");

        let _ = server_task.await;
        unsafe {
            std::env::remove_var("LAZYDNS_DOH_ACCEPT_INVALID_CERT");
        }
    }

    /// Spawn a minimal HTTP DoH server that responds with a single A record.
    async fn spawn_doh_http_server(response_ip: &str) -> (String, tokio::task::JoinHandle<()>) {
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

                let mut content_length = 0usize;
                for line in headers.lines() {
                    if line.to_lowercase().starts_with("content-length:")
                        && let Some(v) = line.split(':').nth(1)
                    {
                        content_length = v.trim().parse().unwrap_or(0);
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

                if let Ok(req_msg) = Forward::parse_message(&body[..content_length.min(body.len())])
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

                    if let Ok(data) = Forward::serialize_message(&resp) {
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

    #[cfg(any(feature = "doh", feature = "dot"))]
    /// Spawn a minimal HTTPS DoH server using a self-signed certificate.
    async fn spawn_doh_https_server(response_ip: &str) -> (String, tokio::task::JoinHandle<()>) {
        use rcgen::generate_simple_self_signed;
        use rustls::ServerConfig;
        use rustls::pki_types::PrivateKeyDer;
        use std::sync::Arc;
        use tokio_rustls::TlsAcceptor;

        unsafe {
            std::env::set_var("LAZYDNS_DOH_ACCEPT_INVALID_CERT", "1");
        }

        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = cert.signing_key.serialize_der();

        let certs = vec![cert_der.clone()];
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
            if let Ok((socket, _)) = listener.accept().await
                && let Ok(mut tls_stream) = acceptor.accept(socket).await
            {
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
                    if line.to_lowercase().starts_with("content-length:")
                        && let Some(v) = line.split(':').nth(1)
                    {
                        content_length = v.trim().parse().unwrap_or(0);
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

                if let Ok(req_msg) = Forward::parse_message(&body[..content_length.min(body.len())])
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

                    if let Ok(data) = Forward::serialize_message(&resp) {
                        let resp_hdr = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                            data.len()
                        );
                        let _ = tls_stream.write_all(resp_hdr.as_bytes()).await;
                        let _ = tls_stream.write_all(&data).await;
                    }
                }
            }
        });

        let url = format!("https://localhost:{}/dns-query", local_addr.port());
        (url, handle)
    }
}

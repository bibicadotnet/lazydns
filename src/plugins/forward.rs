//! Forward plugin core logic
//!
//! This module contains the core business logic for forwarding DNS queries
//! to upstream resolvers. The actual executable plugin implementation is
//! in `executable/forward.rs`.

use crate::dns::Message;
use crate::Result;
use reqwest::Client as HttpClient;
use serde_yaml::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration, Instant};
use tracing::{debug, warn};

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

/// Health status tracking for an upstream server
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

/// Configuration for an upstream DNS server
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

/// Core forward query logic (business logic, no Plugin trait)
///
/// This struct encapsulates the upstream query forwarding logic
/// and is used by the executable ForwardPlugin.
#[derive(Debug)]
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
        debug!("Forwarding query to upstream: {}", upstream.addr);

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
        debug!("Sent {} bytes to upstream {}", sent, upstream_addr);

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

        let response = Self::parse_message(&response_buf[..len])?;
        Ok(response)
    }

    /// Forward via DNS over HTTPS
    async fn forward_query_doh(&self, request: &Message, upstream_url: &str) -> Result<Message> {
        debug!("Forwarding query over DoH to {}", upstream_url);

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
                            let addr = map
                                .get(Value::String("addr".to_string()))
                                .and_then(|v| v.as_str())
                                .ok_or_else(|| {
                                    crate::Error::Config(
                                        "upstream mapping must contain addr".to_string(),
                                    )
                                })?;
                            let addr = if !addr.contains(':') && !addr.starts_with("http") {
                                format!("{}:53", addr)
                            } else {
                                addr.to_string()
                            };
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
                            ))
                        }
                    }
                }
            }
            _ => {
                return Err(crate::Error::Config(
                    "upstreams must be an array".to_string(),
                ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_balance_strategies() {
        let upstreams = vec![Upstream::new("8.8.8.8:53"), Upstream::new("1.1.1.1:53")];
        let core = Forward::new(
            upstreams,
            Duration::from_secs(5),
            LoadBalanceStrategy::RoundRobin,
        );

        let idx1 = core.select_upstream(0).unwrap();
        let idx2 = core.select_upstream(1).unwrap();
        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
    }

    #[test]
    fn test_upstream_health() {
        let health = UpstreamHealth::new();
        health.record_success(Duration::from_millis(10));
        health.record_success(Duration::from_millis(20));

        let (q, s, f) = health.counters();
        assert_eq!(q, 2);
        assert_eq!(s, 2);
        assert_eq!(f, 0);
    }

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
        use crate::dns::types::{RecordClass, RecordType};
        use crate::dns::{Message, Question};

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
}

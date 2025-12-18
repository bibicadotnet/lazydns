//! Forward plugin - executable wrapper
//!
//! This module wraps the core forward logic (from `plugins::forward`)
//! with the Plugin trait for execution within the plugin chain.

use crate::config::PluginConfig;
use crate::dns::Message;
use crate::plugin::{Context, Plugin};
use crate::plugins::forward::{Forward, LoadBalanceStrategy, Upstream};
use crate::Result;
use async_trait::async_trait;
use serde_yaml::Value;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, error, warn};

/// Forward plugin - forwards DNS queries to upstream resolvers
///
/// This plugin forwards DNS queries to configured upstream DNS servers.
/// It supports multiple upstreams with various load balancing strategies,
/// health checks, failover, and concurrent queries.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::executable::forward::ForwardPlugin;
///
/// // Create a simple forward plugin from upstream addresses
/// let plugin = lazydns::plugins::executable::forward::ForwardPlugin::new(vec![
///     "8.8.8.8:53".to_string(),
///     "8.8.4.4:53".to_string(),
///]);
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
                if self.core.health_checks_enabled {
                    upstream.health.record_success(elapsed);
                    // Report to Prometheus metrics for observability
                    #[cfg(feature = "admin")]
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
                if self.core.health_checks_enabled {
                    upstream.health.record_failure();
                    // Report failure to Prometheus metrics
                    #[cfg(feature = "admin")]
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

    /// Get upstreams (for testing)
    pub fn upstreams(&self) -> &[Upstream] {
        &self.core.upstreams
    }

    /// Get timeout
    pub fn timeout(&self) -> Duration {
        self.core.timeout
    }

    /// Is health checks enabled
    pub fn health_checks_enabled(&self) -> bool {
        self.core.health_checks_enabled
    }

    /// Get strategy
    pub fn strategy(&self) -> LoadBalanceStrategy {
        self.core.strategy
    }

    /// Serialize message (delegate to core)
    fn serialize_message(message: &Message) -> Result<Vec<u8>> {
        Forward::serialize_message(message)
    }

    /// Parse message (delegate to core)
    fn parse_message(data: &[u8]) -> Result<Message> {
        Forward::parse_message(data)
    }
}

#[async_trait]
impl Plugin for ForwardPlugin {
    fn create(config: &PluginConfig) -> Result<Arc<dyn Plugin>> {
        let args = config.effective_args();

        // Reuse centralized core parser to build Forward
        let core = crate::plugins::forward::ForwardBuilder::from_args(&args)?;

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

    fn plugin_type() -> &'static str {
        "forward"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Check if we already have a response
        if ctx.has_response() {
            debug!("Response already set, skipping forward plugin");
            return Ok(());
        }

        // If concurrent queries enabled, race all upstreams
        if self.concurrent_queries && self.core.upstreams.len() > 1 {
            debug!(
                "Racing {} upstreams for fastest response",
                self.core.upstreams.len()
            );

            // Query all upstreams concurrently
            let mut tasks = Vec::new();
            for idx in 0..self.core.upstreams.len() {
                let request = ctx.request().clone();
                let upstream_addr = self.core.upstreams[idx].addr.clone();
                let timeout_dur = self.core.timeout;

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

        while attempts < self.core.max_attempts && attempts < self.core.upstreams.len() {
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
                self.core.max_attempts,
                self.core.upstreams[upstream_idx].addr
            );
            match self
                .forward_query_with_health(ctx.request(), upstream_idx)
                .await
            {
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
                    error!(
                        "Failed to forward query to {} (attempt {}/{}): {}",
                        self.core.upstreams[upstream_idx].addr,
                        attempts + 1,
                        self.core.max_attempts,
                        e
                    );
                    last_error = Some(e);
                    attempts += 1;

                    // If health checks are disabled, don't retry
                    if !self.core.health_checks_enabled {
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

// Auto-register the plugin using macro
crate::register_plugin_builder!(ForwardPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{Message, Question, RData, ResourceRecord};
    use crate::plugins::forward::UpstreamHealth;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
        assert_eq!(plugin.timeout(), Duration::from_secs(10));
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
        // Create a minimal query message
        let data = vec![0u8; 12];
        let result = ForwardPlugin::parse_message(&data);
        assert!(result.is_ok());
        let message = result.unwrap();
        assert!(!message.is_response());
    }

    #[tokio::test]
    async fn test_forward_plugin_with_mocked_upstream() {
        // Start a mocked upstream DoH HTTP server and point plugin to it
        let (upstream_addr, server_task) = spawn_doh_http_server("1.2.3.4").await;
        let core = crate::plugins::forward::ForwardBuilder::new()
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

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn test_upstream_health_counters_on_success_and_failure() {
        // Ensure tests accept self-signed certs in CI environments
        std::env::set_var("LAZYDNS_DOH_ACCEPT_INVALID_CERT", "1");

        // Mock server for success
        let (upstream_addr, server_task) = spawn_doh_https_server("1.2.3.4").await;
        let core = crate::plugins::forward::ForwardBuilder::new()
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
        let (q0, s0, f0) = plugin.upstreams()[0].health.counters();
        assert_eq!(q0, 0);
        assert_eq!(s0, 0);
        assert_eq!(f0, 0);

        // Ensure health checks enabled
        assert!(
            plugin.health_checks_enabled(),
            "Health checks should be enabled for this test"
        );

        // Successful forward
        let mut ctx = Context::new(req.clone());
        let res = plugin.execute(&mut ctx).await;
        assert!(res.is_ok(), "Plugin execution failed: {:?}", res);
        assert!(ctx.response().is_some(), "No response set by upstream");

        let (q1, s1, f1) = plugin.upstreams()[0].health.counters();
        assert_eq!(q1, 1, "queries counter should be 1 after success");
        assert_eq!(s1, 1, "successes counter should be 1 after success");
        assert_eq!(f1, 0, "failures counter should be 0 after success");

        // Now test failure increments
        let core = crate::plugins::forward::ForwardBuilder::new()
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
        let (q2, s2, f2) = bad_plugin.upstreams()[0].health.counters();
        assert_eq!(q2, 1);
        assert_eq!(s2, 0);
        assert_eq!(f2, 1);

        let _ = server_task.await;
        std::env::remove_var("LAZYDNS_DOH_ACCEPT_INVALID_CERT");
    }

    #[test]
    fn test_load_balance_strategies() {
        // Test RoundRobin
        let core = crate::plugins::forward::ForwardBuilder::new()
            .add_upstream(Upstream::new("8.8.8.8:53".to_string()))
            .add_upstream(Upstream::new("1.1.1.1:53".to_string()))
            .strategy(LoadBalanceStrategy::RoundRobin)
            .build();
        let plugin = ForwardPlugin {
            core,
            current: AtomicUsize::new(0),
            concurrent_queries: false,
        };

        let idx1 = plugin.select_upstream().unwrap();
        let idx2 = plugin.select_upstream().unwrap();
        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);

        // Test Random (just verify it returns valid index)
        let core = crate::plugins::forward::ForwardBuilder::new()
            .add_upstream(Upstream::new("8.8.8.8:53".to_string()))
            .add_upstream(Upstream::new("1.1.1.1:53".to_string()))
            .strategy(LoadBalanceStrategy::Random)
            .build();
        let plugin = ForwardPlugin {
            core,
            current: AtomicUsize::new(0),
            concurrent_queries: false,
        };

        let idx = plugin.select_upstream().unwrap();
        assert!(idx < 2);

        // Test Fastest (initially should return first)
        let core = crate::plugins::forward::ForwardBuilder::new()
            .add_upstream(Upstream::new("8.8.8.8:53".to_string()))
            .add_upstream(Upstream::new("1.1.1.1:53".to_string()))
            .strategy(LoadBalanceStrategy::Fastest)
            .build();
        let plugin = ForwardPlugin {
            core,
            current: AtomicUsize::new(0),
            concurrent_queries: false,
        };

        let idx = plugin.select_upstream().unwrap();
        assert_eq!(idx, 0); // First upstream before any health data
    }

    #[test]
    fn test_health_tracking() {
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
        let core = crate::plugins::forward::ForwardBuilder::new()
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

        assert_eq!(plugin.upstreams().len(), 2);
        assert_eq!(plugin.timeout(), Duration::from_secs(10));
        assert_eq!(plugin.strategy(), LoadBalanceStrategy::Fastest);
        assert!(plugin.health_checks_enabled());
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

        let url = format!("http://{}/dns-query", local_addr);
        let core = crate::plugins::forward::ForwardBuilder::new()
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
        let core = crate::plugins::forward::ForwardBuilder::new()
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

        assert_eq!(plugin.upstreams().len(), 1);
        assert_eq!(plugin.upstreams()[0].addr, "8.8.8.8:53");
        assert_eq!(plugin.upstreams()[0].tag.as_deref(), Some("google"));
    }

    #[tokio::test]
    #[cfg(any(feature = "doh", feature = "dot"))]
    async fn test_forward_plugin_doh_https_post_with_self_signed_cert() {
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use std::sync::Arc;
        use tokio_rustls::TlsAcceptor;

        let _ = rustls::crypto::ring::default_provider().install_default();

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

        let server_task = tokio::spawn(async move {
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

        std::env::set_var("LAZYDNS_DOH_ACCEPT_INVALID_CERT", "1");

        let url = format!("https://localhost:{}/dns-query", local_addr.port());
        let core = crate::plugins::forward::ForwardBuilder::new()
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
            if rr.rtype() == RecordType::A {
                if let RData::A(ip) = rr.rdata() {
                    assert_eq!(ip.to_string(), "4.4.4.4");
                    found = true;
                }
            }
        }
        assert!(found, "A record from DoH HTTPS upstream not found");

        let _ = server_task.await;
        std::env::remove_var("LAZYDNS_DOH_ACCEPT_INVALID_CERT");
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
                    ForwardPlugin::parse_message(&body[..content_length.min(body.len())])
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

        let url = format!("http://127.0.0.1:{}/dns-query", local_addr.port());
        (url, handle)
    }

    #[cfg(any(feature = "doh", feature = "dot"))]
    /// Spawn a minimal HTTPS DoH server using a self-signed certificate.
    async fn spawn_doh_https_server(response_ip: &str) -> (String, tokio::task::JoinHandle<()>) {
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use std::sync::Arc;
        use tokio_rustls::TlsAcceptor;

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
                        ForwardPlugin::parse_message(&body[..content_length.min(body.len())])
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

        let url = format!("https://localhost:{}/dns-query", local_addr.port());
        (url, handle)
    }
}

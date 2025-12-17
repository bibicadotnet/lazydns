//! Advanced and utility plugins mirroring upstream mosdns behaviors.
//!
//! This module groups smaller plugins that provide control-flow helpers
//! and response mutations that exist in the upstream implementation.
//! They are lightweight, dependency-free Rust ports designed to be
//! configuration-compatible with their mosdns counterparts.

use crate::dns::{Message, RData, RecordClass, RecordType, ResourceRecord};
use crate::plugin::{Context, Plugin, RETURN_FLAG};
use crate::Result;
use async_trait::async_trait;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::debug;

/// Signals the executor to stop executing subsequent plugins.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReturnPlugin;

impl ReturnPlugin {
    /// Create a new return plugin.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Plugin for ReturnPlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        ctx.set_metadata(RETURN_FLAG, true);
        Ok(())
    }

    fn name(&self) -> &str {
        "return"
    }
}

/// Executes plugins in "parallel" (sequential fallback) until a response or return flag is set.
#[derive(Debug, Default)]
pub struct ParallelPlugin {
    plugins: Vec<Arc<dyn Plugin>>,
}

impl ParallelPlugin {
    /// Create a new parallel plugin with the provided plugins.
    pub fn new(plugins: Vec<Arc<dyn Plugin>>) -> Self {
        Self { plugins }
    }
}

#[async_trait]
impl Plugin for ParallelPlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        run_plugins(&self.plugins, ctx, true, true).await
    }

    fn name(&self) -> &str {
        "parallel"
    }
}

async fn run_plugins(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut Context,
    stop_on_return: bool,
    stop_on_response: bool,
) -> Result<()> {
    for plugin in plugins {
        plugin.execute(ctx).await?;
        if stop_on_return && matches!(ctx.get_metadata::<bool>(RETURN_FLAG), Some(true)) {
            break;
        }
        if stop_on_response && ctx.has_response() {
            break;
        }
    }
    Ok(())
}

/// Conditional execution plugin.
pub struct IfPlugin {
    condition: Arc<dyn Fn(&Context) -> bool + Send + Sync>,
    inner: Arc<dyn Plugin>,
}

impl std::fmt::Debug for IfPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IfPlugin").finish()
    }
}

impl IfPlugin {
    /// Create a new conditional plugin.
    pub fn new(
        condition: Arc<dyn Fn(&Context) -> bool + Send + Sync>,
        inner: Arc<dyn Plugin>,
    ) -> Self {
        Self { condition, inner }
    }
}

#[async_trait]
impl Plugin for IfPlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        if (self.condition)(ctx) {
            self.inner.execute(ctx).await?;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "if"
    }
}

/// Goto plugin: records a target label for higher-level executors.
#[derive(Debug, Clone)]
pub struct GotoPlugin {
    label: String,
}

impl GotoPlugin {
    /// Create a new goto plugin with target label.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }
}

#[async_trait]
impl Plugin for GotoPlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        ctx.set_metadata("goto_label", self.label.clone());
        ctx.set_metadata(RETURN_FLAG, true);
        Ok(())
    }

    fn name(&self) -> &str {
        "goto"
    }
}

/// ECS plugin: adds EDNS Client Subnet information to queries.
///
/// This plugin implements RFC 7871 (Client Subnet in DNS Queries) by adding
/// an EDNS0 CLIENT-SUBNET option to outgoing DNS queries. This allows
/// authoritative servers to provide geographically-appropriate responses.
#[derive(Debug, Clone)]
pub struct EcsPlugin {
    client_ip: IpAddr,
    source_prefix_len: u8,
}

impl EcsPlugin {
    /// Create a new ECS plugin with the provided client IP.
    ///
    /// The source prefix length defaults to 24 for IPv4 and 56 for IPv6.
    pub fn new(client_ip: IpAddr) -> Self {
        let source_prefix_len = match client_ip {
            IpAddr::V4(_) => 24,
            IpAddr::V6(_) => 56,
        };
        Self {
            client_ip,
            source_prefix_len,
        }
    }

    /// Create a new ECS plugin with a custom source prefix length.
    pub fn with_prefix_len(client_ip: IpAddr, source_prefix_len: u8) -> Self {
        Self {
            client_ip,
            source_prefix_len,
        }
    }

    /// Generate ECS option data according to RFC 7871.
    ///
    /// Format: FAMILY (2 bytes) | SOURCE PREFIX-LENGTH (1 byte) |
    ///         SCOPE PREFIX-LENGTH (1 byte) | ADDRESS (variable)
    #[allow(clippy::manual_div_ceil)]
    fn generate_ecs_data(&self) -> Vec<u8> {
        let mut data = Vec::new();

        match self.client_ip {
            IpAddr::V4(ipv4) => {
                // Family: 1 = IPv4
                data.push(0);
                data.push(1);
                // Source prefix length
                data.push(self.source_prefix_len);
                // Scope prefix length (0 in queries)
                data.push(0);
                // Address bytes (only prefix bytes needed)
                let addr_bytes = ipv4.octets();
                let num_bytes = ((self.source_prefix_len + 7) / 8) as usize;
                data.extend_from_slice(&addr_bytes[..num_bytes.min(4)]);
            }
            IpAddr::V6(ipv6) => {
                // Family: 2 = IPv6
                data.push(0);
                data.push(2);
                // Source prefix length
                data.push(self.source_prefix_len);
                // Scope prefix length (0 in queries)
                data.push(0);
                // Address bytes (only prefix bytes needed)
                let addr_bytes = ipv6.octets();
                let num_bytes = ((self.source_prefix_len + 7) / 8) as usize;
                data.extend_from_slice(&addr_bytes[..num_bytes.min(16)]);
            }
        }

        data
    }
}

#[async_trait]
impl Plugin for EcsPlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Store ECS data in metadata for use by forward plugin
        ctx.set_metadata("ecs_client_ip", self.client_ip);
        ctx.set_metadata("ecs_source_prefix_len", self.source_prefix_len);

        // Store the ECS option data for integration with EDNS0
        let ecs_data = self.generate_ecs_data();
        ctx.set_metadata("ecs_option_data", ecs_data);

        debug!(
            "ECS plugin: set client subnet {}/{} for forwarding",
            self.client_ip, self.source_prefix_len
        );

        Ok(())
    }

    fn name(&self) -> &str {
        "ecs"
    }
}

/// ipset plugin: integrates with Linux ipset for IP address tracking.
///
/// This plugin extracts IP addresses from DNS responses and can add them
/// to system ipset sets for use with iptables/netfilter. This is useful
/// for dynamic firewall rules based on DNS responses.
#[derive(Debug, Clone)]
pub struct IpsetPlugin {
    name: String,
    addrs: HashSet<IpAddr>,
    track_responses: bool,
}

impl IpsetPlugin {
    /// Create a new ipset plugin with the set name and addresses.
    pub fn new(name: impl Into<String>, addrs: HashSet<IpAddr>) -> Self {
        Self {
            name: name.into(),
            addrs,
            track_responses: true,
        }
    }

    /// Enable or disable response IP tracking.
    pub fn track_responses(mut self, enabled: bool) -> Self {
        self.track_responses = enabled;
        self
    }

    /// Extract all IP addresses from a DNS response.
    fn extract_response_ips(ctx: &Context) -> Vec<IpAddr> {
        let mut ips = Vec::new();

        if let Some(resp) = ctx.response() {
            for rr in resp.answers() {
                match rr.rdata() {
                    RData::A(ipv4) => ips.push(IpAddr::V4(*ipv4)),
                    RData::AAAA(ipv6) => ips.push(IpAddr::V6(*ipv6)),
                    _ => {}
                }
            }
        }

        ips
    }
}

#[async_trait]
impl Plugin for IpsetPlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Mark if response IPs match configured set
        mark_set(ctx, "ipset", &self.name, &self.addrs);

        // Track response IPs for potential ipset integration
        if self.track_responses {
            let response_ips = Self::extract_response_ips(ctx);

            if !response_ips.is_empty() {
                // Store in metadata for potential system integration
                ctx.set_metadata(format!("ipset:{}:ips", self.name), response_ips.clone());

                // Log for audit trail
                debug!(
                    "ipset plugin '{}': tracked {} IP(s) from response",
                    self.name,
                    response_ips.len()
                );

                // TODO: Integration point for actual ipset system calls
                // Example: ipset add <name> <ip> timeout <ttl>
                // This would require elevated privileges and is left as a
                // platform-specific integration point.
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "ipset"
    }
}

/// nftset plugin: integrates with nftables sets for IP address tracking.
///
/// This plugin extracts IP addresses from DNS responses and can add them
/// to nftables sets for use with modern Linux firewalls. This provides
/// similar functionality to ipset but for the newer nftables framework.
#[derive(Debug, Clone)]
pub struct NftsetPlugin {
    name: String,
    addrs: HashSet<IpAddr>,
    table_family: String,
    table_name: String,
    track_responses: bool,
}

impl NftsetPlugin {
    /// Create a new nftset plugin with the set name and addresses.
    ///
    /// Uses default table family "inet" and table name "filter".
    pub fn new(name: impl Into<String>, addrs: HashSet<IpAddr>) -> Self {
        Self {
            name: name.into(),
            addrs,
            table_family: "inet".to_string(),
            table_name: "filter".to_string(),
            track_responses: true,
        }
    }

    /// Set the nftables table family (inet, ip, ip6, etc.).
    pub fn with_table_family(mut self, family: impl Into<String>) -> Self {
        self.table_family = family.into();
        self
    }

    /// Set the nftables table name.
    pub fn with_table_name(mut self, table: impl Into<String>) -> Self {
        self.table_name = table.into();
        self
    }

    /// Enable or disable response IP tracking.
    pub fn track_responses(mut self, enabled: bool) -> Self {
        self.track_responses = enabled;
        self
    }

    /// Extract all IP addresses from a DNS response.
    fn extract_response_ips(ctx: &Context) -> Vec<IpAddr> {
        let mut ips = Vec::new();

        if let Some(resp) = ctx.response() {
            for rr in resp.answers() {
                match rr.rdata() {
                    RData::A(ipv4) => ips.push(IpAddr::V4(*ipv4)),
                    RData::AAAA(ipv6) => ips.push(IpAddr::V6(*ipv6)),
                    _ => {}
                }
            }
        }

        ips
    }
}

#[async_trait]
impl Plugin for NftsetPlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Mark if response IPs match configured set
        mark_set(ctx, "nftset", &self.name, &self.addrs);

        // Track response IPs for potential nftables integration
        if self.track_responses {
            let response_ips = Self::extract_response_ips(ctx);

            if !response_ips.is_empty() {
                // Store in metadata for potential system integration
                ctx.set_metadata(format!("nftset:{}:ips", self.name), response_ips.clone());
                ctx.set_metadata(
                    format!("nftset:{}:table", self.name),
                    format!("{} {}", self.table_family, self.table_name),
                );

                // Log for audit trail
                debug!(
                    "nftset plugin '{}': tracked {} IP(s) from response (table: {} {})",
                    self.name,
                    response_ips.len(),
                    self.table_family,
                    self.table_name
                );

                // TODO: Integration point for actual nftables system calls
                // Example: nft add element <family> <table> <set> { <ip> }
                // This would require elevated privileges and is left as a
                // platform-specific integration point.
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "nftset"
    }
}

fn mark_set(ctx: &mut Context, prefix: &str, name: &str, addrs: &HashSet<IpAddr>) {
    if let Some(resp) = ctx.response() {
        let mut matched = false;
        for rr in resp.answers() {
            match rr.rdata() {
                RData::A(ip) => {
                    if addrs.contains(&IpAddr::V4(*ip)) {
                        matched = true;
                    }
                }
                RData::AAAA(ip) => {
                    if addrs.contains(&IpAddr::V6(*ip)) {
                        matched = true;
                    }
                }
                _ => {}
            }
        }
        if matched {
            ctx.set_metadata(format!("{prefix}:{name}"), true);
        }
    }
}

/// Metrics collector plugin: comprehensive DNS query and response metrics.
///
/// Tracks detailed statistics about DNS operations including query counts,
/// response codes, latency measurements, and queries per second.
#[derive(Debug, Clone)]
pub struct MetricsCollectorPlugin {
    counter: Arc<AtomicUsize>,
    _start_time: std::time::Instant,
    last_reset: Arc<std::sync::RwLock<std::time::Instant>>,
    total_latency_ms: Arc<AtomicUsize>,
}

impl MetricsCollectorPlugin {
    /// Create a new metrics collector with shared counter.
    pub fn new(counter: Arc<AtomicUsize>) -> Self {
        let now = std::time::Instant::now();
        Self {
            counter,
            _start_time: now,
            last_reset: Arc::new(std::sync::RwLock::new(now)),
            total_latency_ms: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Get the total query count.
    pub fn count(&self) -> usize {
        self.counter.load(Ordering::SeqCst)
    }

    /// Calculate queries per second since last reset.
    pub fn queries_per_second(&self) -> f64 {
        let count = self.count() as f64;
        let last_reset = self.last_reset.read().unwrap();
        let duration = last_reset.elapsed().as_secs_f64();

        if duration > 0.0 {
            count / duration
        } else {
            0.0
        }
    }

    /// Get average latency in milliseconds.
    pub fn average_latency_ms(&self) -> f64 {
        let total_latency = self.total_latency_ms.load(Ordering::SeqCst) as f64;
        let count = self.count() as f64;

        if count > 0.0 {
            total_latency / count
        } else {
            0.0
        }
    }

    /// Reset the metrics counters.
    pub fn reset(&self) {
        self.counter.store(0, Ordering::SeqCst);
        self.total_latency_ms.store(0, Ordering::SeqCst);
        *self.last_reset.write().unwrap() = std::time::Instant::now();
    }

    /// Get time since metrics were last reset.
    pub fn time_since_reset(&self) -> std::time::Duration {
        self.last_reset.read().unwrap().elapsed()
    }
}

#[async_trait]
impl Plugin for MetricsCollectorPlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Increment query counter
        self.counter.fetch_add(1, Ordering::SeqCst);

        // Track latency if available from metadata
        if let Some(latency_ms) = ctx.get_metadata::<f64>("query_latency_ms") {
            self.total_latency_ms
                .fetch_add((*latency_ms) as usize, Ordering::SeqCst);
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "metrics_collector"
    }
}

/// Convenience constructor for an arbitrary A/AAAA response.
#[derive(Debug, Clone)]
pub struct ArbitraryRecordBuilder {
    name: String,
    ttl: u32,
    records: Vec<ResourceRecord>,
}

impl ArbitraryRecordBuilder {
    /// Start a new builder for the given name and TTL.
    pub fn new(name: impl Into<String>, ttl: u32) -> Self {
        Self {
            name: name.into(),
            ttl,
            records: Vec::new(),
        }
    }

    /// Add an IPv4 address answer.
    pub fn with_a(mut self, addr: std::net::Ipv4Addr) -> Self {
        self.records.push(ResourceRecord::new(
            self.name.clone(),
            RecordType::A,
            RecordClass::IN,
            self.ttl,
            RData::A(addr),
        ));
        self
    }

    /// Add an IPv6 address answer.
    pub fn with_aaaa(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.records.push(ResourceRecord::new(
            self.name.clone(),
            RecordType::AAAA,
            RecordClass::IN,
            self.ttl,
            RData::AAAA(addr),
        ));
        self
    }

    /// Finalize the builder into an arbitrary response message.
    pub fn build(self, id: u16) -> Message {
        let mut msg = Message::new();
        msg.set_id(id);
        msg.set_response(true);
        for record in self.records {
            msg.add_answer(record);
        }
        msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Question, RecordClass, RecordType};
    use crate::plugin::Executor;
    use crate::plugins::executable::arbitrary::{ArbitraryArgs, ArbitraryPlugin};
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_arbitrary_plugin_sets_response() {
        // Use the rule-based `Arbitrary` plugin from `plugins::executable::arbitrary`.
        let args = ArbitraryArgs {
            rules: Some(vec!["example.com A 10.0.0.1".to_string()]),
            files: None,
        };
        let plugin = ArbitraryPlugin::new(args).unwrap();

        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(req);
        plugin.execute(&mut ctx).await.unwrap();

        let resp = ctx.response().unwrap();
        assert_eq!(resp.answer_count(), 1);
        if let RData::A(ip) = resp.answers()[0].rdata() {
            assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 1));
        } else {
            panic!("expected A");
        }
    }

    #[tokio::test]
    async fn test_return_plugin_stops_execution() {
        #[derive(Debug)]
        struct Counter {
            counter: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl Plugin for Counter {
            async fn execute(&self, _ctx: &mut Context) -> Result<()> {
                self.counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn name(&self) -> &str {
                "counter"
            }
        }

        let mut executor = Executor::new();
        executor.add_plugin(Arc::new(ReturnPlugin::new()));
        let counter = Arc::new(AtomicUsize::new(0));
        executor.add_plugin(Arc::new(Counter {
            counter: counter.clone(),
        }));

        let mut ctx = Context::new(Message::new());
        executor.execute(&mut ctx).await.unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert_eq!(
            ctx.get_metadata::<bool>(RETURN_FLAG),
            Some(&true),
            "return flag should be set"
        );
    }

    #[tokio::test]
    async fn test_parallel_plugin_stops_on_response() {
        #[derive(Debug)]
        struct Responder;

        #[async_trait]
        impl Plugin for Responder {
            async fn execute(&self, ctx: &mut Context) -> Result<()> {
                let mut resp = Message::new();
                resp.set_response(true);
                ctx.set_response(Some(resp));
                Ok(())
            }

            fn name(&self) -> &str {
                "responder"
            }
        }

        #[derive(Debug)]
        struct ShouldNotRun {
            hit: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl Plugin for ShouldNotRun {
            async fn execute(&self, _ctx: &mut Context) -> Result<()> {
                self.hit.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn name(&self) -> &str {
                "after"
            }
        }

        let hit = Arc::new(AtomicUsize::new(0));
        let plugin = ParallelPlugin::new(vec![
            Arc::new(Responder),
            Arc::new(ShouldNotRun { hit: hit.clone() }),
        ]);

        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        assert!(ctx.has_response());
        assert_eq!(hit.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_if_plugin_executes_conditionally() {
        #[derive(Debug)]
        struct FlagSetter;

        #[async_trait]
        impl Plugin for FlagSetter {
            async fn execute(&self, ctx: &mut Context) -> Result<()> {
                ctx.set_metadata("flag", true);
                Ok(())
            }

            fn name(&self) -> &str {
                "flag"
            }
        }

        let inner = Arc::new(FlagSetter);
        let cond = Arc::new(|_ctx: &Context| true);
        let plugin = IfPlugin::new(cond, inner);

        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();
        assert_eq!(ctx.get_metadata::<bool>("flag"), Some(&true));
    }

    #[tokio::test]
    async fn test_goto_sets_label_and_return() {
        let plugin = GotoPlugin::new("target");
        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        assert_eq!(
            ctx.get_metadata::<String>("goto_label"),
            Some(&"target".into())
        );
        assert_eq!(ctx.get_metadata::<bool>(RETURN_FLAG), Some(&true));
    }

    #[tokio::test]
    async fn test_ecs_sets_metadata() {
        let plugin = EcsPlugin::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.get_metadata::<IpAddr>("ecs_client_ip"),
            Some(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        );
    }

    #[tokio::test]
    async fn test_ipset_and_nftset_match() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut resp = Message::new();
        resp.set_response(true);
        resp.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
            60,
            RData::A(Ipv4Addr::new(10, 0, 0, 1)),
        ));

        let mut ctx = Context::new(Message::new());
        ctx.set_response(Some(resp));

        let mut set = HashSet::new();
        set.insert(addr);
        let ipset = IpsetPlugin::new("testset", set.clone());
        let nftset = NftsetPlugin::new("testnft", set);

        ipset.execute(&mut ctx).await.unwrap();
        nftset.execute(&mut ctx).await.unwrap();

        assert_eq!(ctx.get_metadata::<bool>("ipset:testset"), Some(&true));
        assert_eq!(ctx.get_metadata::<bool>("nftset:testnft"), Some(&true));
    }

    #[tokio::test]
    async fn test_metrics_collector_increments() {
        let counter = Arc::new(AtomicUsize::new(0));
        let plugin = MetricsCollectorPlugin::new(counter.clone());
        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();
        plugin.execute(&mut ctx).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

}

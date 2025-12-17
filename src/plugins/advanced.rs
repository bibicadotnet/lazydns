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
use std::net::IpAddr;
// atomic types are provided by executable collector; keep advanced.rs free of them
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

// Re-export the executable implementation of the metrics collector so
// callers that referenced `MetricsCollectorPlugin` from this module
// continue to compile while the canonical implementation lives under
// `plugins::executable::collector`.
pub use crate::plugins::executable::collector::MetricsCollectorPlugin;

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
    use crate::plugin::Executor;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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
    async fn test_metrics_collector_increments() {
        let counter = Arc::new(AtomicUsize::new(0));
        let plugin = MetricsCollectorPlugin::new(counter.clone());
        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();
        plugin.execute(&mut ctx).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }
}

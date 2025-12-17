//! Control flow plugins
//!
//! Plugins that control the execution flow of the DNS query processing pipeline.

use crate::dns::{Message, RecordType, ResponseCode};
use crate::plugin::{Context, Plugin, RETURN_FLAG};
use crate::Result;
use async_trait::async_trait;
use std::sync::Arc;

/// Accept plugin - accepts the current response and stops execution
///
/// This plugin sets the return flag to indicate that processing should stop
/// and the current response should be returned to the client.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::AcceptPlugin;
///
/// let plugin = AcceptPlugin::new();
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct AcceptPlugin;

impl AcceptPlugin {
    /// Create a new accept plugin
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Plugin for AcceptPlugin {
    fn name(&self) -> &str {
        "accept"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Set the return flag to stop further execution
        ctx.set_metadata(RETURN_FLAG, true);
        Ok(())
    }
}

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

/// Reject plugin - rejects the query with a specific response code
///
/// This plugin generates a DNS response with the specified response code
/// and stops further execution.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::RejectPlugin;
///
/// // Reject with NXDOMAIN (code 3)
/// let plugin = RejectPlugin::new(3);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RejectPlugin {
    /// Response code to use for rejection
    rcode: u8,
}

impl RejectPlugin {
    /// Create a new reject plugin with the specified response code
    ///
    /// Common response codes:
    /// - 0: NOERROR
    /// - 1: FORMERR (format error)
    /// - 2: SERVFAIL (server failure)
    /// - 3: NXDOMAIN (name error)
    /// - 4: NOTIMP (not implemented)
    /// - 5: REFUSED
    pub fn new(rcode: u8) -> Self {
        Self { rcode }
    }

    /// Create a reject plugin that returns NXDOMAIN
    pub fn nxdomain() -> Self {
        Self::new(3)
    }

    /// Create a reject plugin that returns REFUSED
    pub fn refused() -> Self {
        Self::new(5)
    }

    /// Create a reject plugin that returns SERVFAIL
    pub fn servfail() -> Self {
        Self::new(2)
    }
}

#[async_trait]
impl Plugin for RejectPlugin {
    fn name(&self) -> &str {
        "reject"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Create a response with the error code
        let mut response = Message::new();
        response.set_id(ctx.request().id());
        response.set_response_code(ResponseCode::from_u8(self.rcode));
        response.set_response(true);

        // Copy questions from request
        for question in ctx.request().questions() {
            response.add_question(question.clone());
        }

        ctx.set_response(Some(response));

        // Set return flag to stop further execution
        ctx.set_metadata(RETURN_FLAG, true);
        Ok(())
    }
}

/// Jump plugin - jumps to a named plugin/sequence
///
/// This plugin stores a jump target in the context metadata.
/// The executor should handle the jump by executing the named plugin.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::JumpPlugin;
///
/// let plugin = JumpPlugin::new("gfw-list");
/// ```
#[derive(Debug, Clone)]
pub struct JumpPlugin {
    /// Target plugin/sequence name to jump to
    target: String,
}

impl JumpPlugin {
    /// Create a new jump plugin
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
        }
    }

    /// Get the jump target
    pub fn target(&self) -> &str {
        &self.target
    }
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

#[async_trait]
impl Plugin for JumpPlugin {
    fn name(&self) -> &str {
        "jump"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Store jump target in metadata
        ctx.set_metadata("jump_target", self.target.clone());
        // Signal executor to stop current sequence so the jump can be handled
        ctx.set_metadata(RETURN_FLAG, true);
        Ok(())
    }
}

/// Prefer IPv4 plugin - removes AAAA records from response
///
/// This plugin removes IPv6 (AAAA) records from the DNS response,
/// leaving only IPv4 (A) records. Useful for clients that prefer IPv4.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::PreferIpv4Plugin;
///
/// let plugin = PreferIpv4Plugin::new();
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct PreferIpv4Plugin;

impl PreferIpv4Plugin {
    /// Create a new prefer IPv4 plugin
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Plugin for PreferIpv4Plugin {
    fn name(&self) -> &str {
        "prefer_ipv4"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        if let Some(response) = ctx.response_mut() {
            // Remove AAAA records from answers
            let answers = response.answers_mut();
            answers.retain(|record| !matches!(record.rtype(), RecordType::AAAA));

            // Also remove from additional section
            let additional = response.additional_mut();
            additional.retain(|record| !matches!(record.rtype(), RecordType::AAAA));
        }
        Ok(())
    }
}

/// Prefer IPv6 plugin - removes A records from response
///
/// This plugin removes IPv4 (A) records from the DNS response,
/// leaving only IPv6 (AAAA) records. Useful for clients that prefer IPv6.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::PreferIpv6Plugin;
///
/// let plugin = PreferIpv6Plugin::new();
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct PreferIpv6Plugin;

impl PreferIpv6Plugin {
    /// Create a new prefer IPv6 plugin
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Plugin for PreferIpv6Plugin {
    fn name(&self) -> &str {
        "prefer_ipv6"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        if let Some(response) = ctx.response_mut() {
            // Remove A records from answers
            let answers = response.answers_mut();
            answers.retain(|record| !matches!(record.rtype(), RecordType::A));

            // Also remove from additional section
            let additional = response.additional_mut();
            additional.retain(|record| !matches!(record.rtype(), RecordType::A));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Message, RData, RecordClass, ResourceRecord};
    use crate::plugin::Executor;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_accept_plugin() {
        let plugin = AcceptPlugin::new();
        assert_eq!(plugin.name(), "accept");

        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        // Verify return flag is set
        assert_eq!(ctx.get_metadata::<bool>(RETURN_FLAG), Some(&true));
    }

    #[tokio::test]
    async fn test_reject_plugin() {
        let plugin = RejectPlugin::new(3); // NXDOMAIN
        assert_eq!(plugin.name(), "reject");

        let mut request = Message::new();
        request.set_id(12345);
        let mut ctx = Context::new(request);

        plugin.execute(&mut ctx).await.unwrap();

        // Verify response is set with error code
        assert!(ctx.has_response());
        let response = ctx.response().unwrap();
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        assert!(response.is_response());
        assert_eq!(response.id(), 12345);

        // Verify return flag is set
        assert_eq!(ctx.get_metadata::<bool>(RETURN_FLAG), Some(&true));
    }

    #[tokio::test]
    async fn test_reject_helpers() {
        let nxdomain = RejectPlugin::nxdomain();
        let refused = RejectPlugin::refused();
        let servfail = RejectPlugin::servfail();

        assert_eq!(nxdomain.rcode, 3);
        assert_eq!(refused.rcode, 5);
        assert_eq!(servfail.rcode, 2);
    }

    #[tokio::test]
    async fn test_jump_plugin() {
        let plugin = JumpPlugin::new("gfw-list");
        assert_eq!(plugin.name(), "jump");
        assert_eq!(plugin.target(), "gfw-list");

        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        // Verify jump target is set in metadata
        assert_eq!(
            ctx.get_metadata::<String>("jump_target"),
            Some(&"gfw-list".to_string())
        );
    }

    #[tokio::test]
    async fn test_prefer_ipv4_plugin() {
        let plugin = PreferIpv4Plugin::new();
        assert_eq!(plugin.name(), "prefer_ipv4");

        let mut ctx = Context::new(Message::new());
        let mut response = Message::new();

        // Add both A and AAAA records
        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
            300,
            RData::A("192.0.2.1".parse().unwrap()),
        ));

        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
            300,
            RData::AAAA("2001:db8::1".parse().unwrap()),
        ));

        ctx.set_response(Some(response));
        plugin.execute(&mut ctx).await.unwrap();

        // Verify only A record remains
        let response = ctx.response().unwrap();
        assert_eq!(response.answers().len(), 1);
        assert!(matches!(response.answers()[0].rtype(), RecordType::A));
    }

    #[tokio::test]
    async fn test_prefer_ipv6_plugin() {
        let plugin = PreferIpv6Plugin::new();
        assert_eq!(plugin.name(), "prefer_ipv6");

        let mut ctx = Context::new(Message::new());
        let mut response = Message::new();

        // Add both A and AAAA records
        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
            300,
            RData::A("192.0.2.1".parse().unwrap()),
        ));

        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
            300,
            RData::AAAA("2001:db8::1".parse().unwrap()),
        ));

        ctx.set_response(Some(response));
        plugin.execute(&mut ctx).await.unwrap();

        // Verify only AAAA record remains
        let response = ctx.response().unwrap();
        assert_eq!(response.answers().len(), 1);
        assert!(matches!(response.answers()[0].rtype(), RecordType::AAAA));
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
}

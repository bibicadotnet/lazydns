//! Plugin system module
//!
//! This module provides the plugin system architecture for lazydns.
//! Plugins are the core building blocks that process DNS queries in a
//! flexible and composable way.
//!
//! # Architecture
//!
//! The plugin system consists of:
//! - **Plugin trait**: The core interface all plugins must implement
//! - **Context**: Execution context passed between plugins
//! - **Executor**: Manages plugin execution and ordering
//! - **Registry**: Manages plugin registration and lookup
//!
//! # Example
//!
//! ```rust
//! use lazydns::plugin::{Plugin, Context};
//! use lazydns::Result;
//! use async_trait::async_trait;
//!
//! #[derive(Debug)]
//! struct MyPlugin;
//!
//! #[async_trait]
//! impl Plugin for MyPlugin {
//!     async fn execute(&self, ctx: &mut Context) -> Result<()> {
//!         // Process the DNS query in context
//!         Ok(())
//!     }
//!
//!     fn name(&self) -> &str {
//!         "my_plugin"
//!     }
//! }
//! ```

pub mod builder;
pub mod context;
pub mod executor;
pub mod registry;
pub mod traits;

/// Metadata key used by control-flow plugins to stop execution.
pub const RETURN_FLAG: &str = "__return_flag";

// Re-export commonly used types
pub use builder::{get_all_plugin_types, get_builder, initialize, ConfigPluginBuilder};
pub use context::Context;
pub use executor::Executor;
pub use registry::Registry;
pub use traits::Plugin;
pub use traits::PluginBuilder;

use crate::dns::Message;
use crate::server::RequestHandler;
use crate::Result;
use std::sync::Arc;
use tracing::{debug, warn};

/// Request handler that uses the plugin registry
pub struct PluginHandler {
    pub registry: Arc<Registry>,
    pub entry: String,
}

#[async_trait::async_trait]
impl RequestHandler for PluginHandler {
    async fn handle(&self, request: Message) -> Result<Message> {
        use crate::plugin::Context;

        let mut ctx = Context::new(request);

        if let Some(plugin) = self.registry.get(&self.entry) {
            plugin.execute(&mut ctx).await?;
        }

        // Handle jump targets set by plugins (jump should interrupt sequence)
        // Execute jump targets in a loop in case of nested jumps.
        while ctx.has_metadata("jump_target") {
            if let Some(target) = ctx.get_metadata::<String>("jump_target").cloned() {
                // Remove jump target metadata and return flag before executing target
                ctx.remove_metadata("jump_target");
                ctx.remove_metadata(RETURN_FLAG);

                debug!(jump_target = %target, "Handling jump target: executing plugin");

                if let Some(plugin) = self.registry.get(&target) {
                    plugin.execute(&mut ctx).await?;
                } else {
                    warn!(jump_target = %target, "Jump target plugin not found");
                    break;
                }
            } else {
                break;
            }
        }

        // After executing sequence and jump targets, allow reverse-lookup
        // plugins to observe the populated response and save IP->name mappings.
        if ctx.has_response() {
            if let Some(resp) = ctx.response() {
                for name in self.registry.plugin_names() {
                    if let Some(p) = self.registry.get(&name) {
                        if p.name() == "reverse_lookup" {
                            if let Some(rl) = p
                                .as_ref()
                                .as_any()
                                .downcast_ref::<crate::plugins::executable::ReverseLookupPlugin>(
                            ) {
                                rl.save_ips_after(ctx.request(), resp);
                            }
                        }
                    }
                }
            }
        }

        // Ensure any response uses the original request ID
        let req_id = ctx.request().id();
        let mut response = ctx.take_response().unwrap_or_else(|| {
            let mut r = Message::new();
            r.set_response_code(crate::dns::ResponseCode::ServFail);
            r
        });
        response.set_id(req_id);

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;
    use async_trait::async_trait;

    #[derive(Debug)]
    struct TestPlugin;

    #[async_trait]
    impl Plugin for TestPlugin {
        async fn execute(&self, _ctx: &mut Context) -> crate::Result<()> {
            Ok(())
        }

        fn name(&self) -> &str {
            "test"
        }
    }

    #[test]
    fn test_plugin_system_reexports() {
        // Verify all re-exported types are accessible
        let request = Message::new();
        let _ctx = Context::new(request);
        let _registry = Registry::new();
    }

    #[tokio::test]
    async fn test_executor_creation() {
        // Verify Executor is accessible and can be created
        let executor = Executor::new();
        let request = Message::new();
        let mut ctx = Context::new(request);

        // Should execute with empty executor
        let result = executor.execute(&mut ctx).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_registry_plugin_registration() {
        use std::sync::Arc;

        let mut registry = Registry::new();
        let plugin: Arc<dyn Plugin> = Arc::new(TestPlugin);

        registry.register(plugin.clone()).ok();
        let retrieved = registry.get("test");
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_return_flag_constant() {
        // Verify the RETURN_FLAG constant is accessible
        assert_eq!(RETURN_FLAG, "__return_flag");
    }

    #[tokio::test]
    async fn test_context_metadata() {
        let request = Message::new();
        let mut ctx = Context::new(request);

        // Test metadata operations using set_metadata and get_metadata
        ctx.set_metadata("key", "value".to_string());
        let value = ctx.get_metadata::<String>("key");
        assert_eq!(value, Some(&"value".to_string()));
    }
}

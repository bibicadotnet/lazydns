//! Plugin trait definitions
//!
//! Defines the core Plugin trait that all plugins must implement.

use crate::plugin::Context;
use crate::Result;
use async_trait::async_trait;
use std::fmt::Debug;
use crate::config::types::PluginConfig;
use std::sync::Arc;

/// Core plugin trait
///
/// All DNS query processing plugins must implement this trait.
/// Plugins receive a mutable context containing the DNS query and can
/// modify it or add a response.
///
/// # Example
///
/// ```rust
/// use lazydns::plugin::{Plugin, Context};
/// use lazydns::Result;
/// use async_trait::async_trait;
///
/// #[derive(Debug)]
/// struct LogPlugin;
///
/// #[async_trait]
/// impl Plugin for LogPlugin {
///     async fn execute(&self, ctx: &mut Context) -> Result<()> {
///         println!("Processing query: {:?}", ctx.request().questions());
///         Ok(())
///     }
///
///     fn name(&self) -> &str {
///         "log"
///     }
/// }
/// ```
#[async_trait]
pub trait Plugin: Send + Sync + Debug + std::any::Any {
    /// Execute the plugin logic
    ///
    /// This method is called to process a DNS query. The plugin can:
    /// - Read the query from the context
    /// - Modify the query
    /// - Set a response
    /// - Add metadata for other plugins
    ///
    /// # Arguments
    ///
    /// * `ctx` - The execution context containing the DNS query and response
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if plugin execution fails.
    async fn execute(&self, ctx: &mut Context) -> Result<()>;

    /// Get the plugin name
    ///
    /// Returns a unique identifier for this plugin.
    fn name(&self) -> &str;

    /// Check if this plugin should execute
    ///
    /// Plugins can override this to provide conditional execution logic.
    /// By default, plugins always execute.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The execution context
    ///
    /// # Returns
    ///
    /// Returns `true` if the plugin should execute, `false` otherwise.
    fn should_execute(&self, _ctx: &Context) -> bool {
        true
    }

    /// Plugin priority for execution ordering
    ///
    /// Lower values execute first. Default is 100.
    fn priority(&self) -> i32 {
        100
    }

    /// Get the plugin as Any for downcasting
    fn as_any(&self) -> &dyn std::any::Any {
        // This is a default implementation that won't work for downcasting
        // Concrete implementations should override this
        &()
    }
}

/// Matcher trait for plugins that can match against DNS data
#[async_trait]
pub trait Matcher: Plugin {
    /// Check if the context matches this matcher
    fn matches_context(&self, ctx: &Context) -> bool;
}

/// Plugin builder trait for self-registering plugins
///
/// Implement this trait on your plugin type to enable automatic
/// registration without needing a separate factory struct.
pub trait PluginBuilder: Send + Sync + 'static {
    /// Create a plugin instance from configuration
    fn create(config: &PluginConfig) -> Result<Arc<dyn Plugin>>
    where
        Self: Sized;

    /// Get the plugin type name
    fn plugin_type() -> &'static str
    where
        Self: Sized;

    /// Get alternative names (optional)
    fn aliases() -> Vec<&'static str>
    where
        Self: Sized,
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[derive(Debug)]
    struct TestPlugin {
        name: String,
        priority: i32,
    }

    #[async_trait]
    impl Plugin for TestPlugin {
        async fn execute(&self, _ctx: &mut Context) -> Result<()> {
            Ok(())
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn priority(&self) -> i32 {
            self.priority
        }
    }

    #[tokio::test]
    async fn test_plugin_trait() {
        let plugin = TestPlugin {
            name: "test".to_string(),
            priority: 50,
        };

        assert_eq!(plugin.name(), "test");
        assert_eq!(plugin.priority(), 50);

        let request = Message::new();
        let mut ctx = Context::new(request);
        assert!(plugin.should_execute(&ctx));
        assert!(plugin.execute(&mut ctx).await.is_ok());
    }

    #[test]
    fn test_default_priority() {
        let plugin = TestPlugin {
            name: "test".to_string(),
            priority: 100,
        };

        assert_eq!(plugin.priority(), 100);
    }
}

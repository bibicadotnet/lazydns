//! Plugin trait definitions
//!
//! Defines the core Plugin trait that all plugins must implement.

use crate::config::PluginConfig;
use crate::plugin::Context;
use crate::Result;
use async_trait::async_trait;
use std::any::Any;
use std::fmt::Debug;
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
pub trait Plugin: Send + Sync + Debug + Any + 'static {
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

    /// Optional shutdown method for graceful cleanup
    ///
    /// Plugins can override this method to perform cleanup operations
    /// when the application is shutting down. The default implementation
    /// does nothing.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful shutdown, or an error if cleanup fails.
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    /// Get the plugin as Any for downcasting
    fn as_any(&self) -> &dyn Any {
        // This is a default implementation that won't work for downcasting
        // Concrete implementations should override this
        &()
    }

    /// factory method to init a plugin instance from configuration.
    ///
    /// Default implementation returns an error indicating no builder is
    /// provided for this plugin type. Implementations that support
    /// configuration-based construction should override this method.
    fn init(_config: &PluginConfig) -> Result<Arc<dyn Plugin>>
    where
        Self: Sized,
    {
        Err(crate::Error::Config(format!(
            "no builder for plugin {}",
            std::any::type_name::<Self>()
        )))
    }

    /// Optional aliases for plugin type names.
    fn aliases() -> Vec<&'static str>
    where
        Self: Sized,
    {
        Vec::new()
    }
}

/// Trait for executable plugins that support quick setup from strings
///
/// Exec plugins are a special category of plugins that can be quickly
/// instantiated from simple string configurations, typically used in
/// exec-style configurations similar to mosdns.
pub trait ExecPlugin: Plugin {
    /// Quick setup from prefix and exec string
    ///
    /// # Arguments
    /// * `prefix` - The plugin type prefix (e.g., "ttl")
    /// * `exec_str` - The execution configuration string (e.g., "60" or "30-300")
    ///
    /// # Returns
    /// A configured plugin instance, or an error if setup fails.
    fn quick_setup(prefix: &str, exec_str: &str) -> Result<Arc<dyn Plugin>>
    where
        Self: Sized;
}

/// Shutdown trait for plugins that need cleanup
///
/// Plugins that require graceful shutdown (e.g., closing connections,
/// flushing caches, stopping background tasks) should implement this trait.
#[async_trait]
pub trait Shutdown: Send + Sync {
    /// Perform graceful shutdown
    ///
    /// This method is called when the application is shutting down.
    /// Plugins should clean up resources, flush data, and stop background tasks.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful shutdown, or an error if cleanup fails.
    async fn shutdown(&self) -> Result<()>;
}

/// Matcher trait for plugins that can match against DNS data
#[async_trait]
pub trait Matcher: Plugin {
    /// Check if the context matches this matcher
    fn matches_context(&self, ctx: &Context) -> bool;
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

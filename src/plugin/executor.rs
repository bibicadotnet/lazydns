//! Plugin executor
//!
//! Manages the execution of plugins in a defined order.

use crate::plugin::{Context, Plugin, RETURN_FLAG};
use crate::Result;
use std::sync::Arc;
use tracing::{debug, warn};

/// Plugin executor
///
/// The executor runs a chain of plugins in order, passing a context
/// through each one. Plugins can modify the context and set a response.
///
/// # Example
///
/// ```rust
/// use lazydns::plugin::{Executor, Context, Plugin};
/// use lazydns::dns::Message;
/// use lazydns::Result;
/// use async_trait::async_trait;
/// use std::sync::Arc;
///
/// #[derive(Debug)]
/// struct MyPlugin;
///
/// #[async_trait]
/// impl Plugin for MyPlugin {
///     async fn execute(&self, _ctx: &mut Context) -> Result<()> {
///         Ok(())
///     }
///
///     fn name(&self) -> &str {
///         "my_plugin"
///     }
/// }
///
/// # async fn example() -> Result<()> {
/// let mut executor = Executor::new();
/// executor.add_plugin(Arc::new(MyPlugin));
///
/// let request = Message::new();
/// let mut ctx = Context::new(request);
/// executor.execute(&mut ctx).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct Executor {
    /// Ordered list of plugins to execute
    plugins: Vec<Arc<dyn Plugin>>,
}

impl Executor {
    /// Create a new executor
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Add a plugin to the executor
    ///
    /// Plugins are executed in the order they are added.
    ///
    /// # Arguments
    ///
    /// * `plugin` - The plugin to add
    pub fn add_plugin(&mut self, plugin: Arc<dyn Plugin>) {
        self.plugins.push(plugin);
    }

    /// Add multiple plugins to the executor
    ///
    /// # Arguments
    ///
    /// * `plugins` - The plugins to add
    pub fn add_plugins(&mut self, plugins: Vec<Arc<dyn Plugin>>) {
        self.plugins.extend(plugins);
    }

    /// Sort plugins by priority
    ///
    /// Plugins with lower priority values execute first.
    pub fn sort_by_priority(&mut self) {
        self.plugins.sort_by_key(|p| p.priority());
    }

    /// Execute all plugins in order
    ///
    /// Each plugin is executed in sequence. If a plugin returns an error,
    /// execution stops and the error is returned.
    ///
    /// Plugins can be skipped if their `should_execute` method returns false.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The execution context
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all plugins executed successfully, or the first error.
    pub async fn execute(&self, ctx: &mut Context) -> Result<()> {
        debug!("Executing {} plugins", self.plugins.len());

        for plugin in &self.plugins {
            let name = plugin.name();

            // Skip plugins that shouldn't execute based on context
            if !plugin.should_execute(ctx) {
                debug!("Skipping plugin '{}'", name);
                continue;
            }

            debug!("Executing plugin '{}'", name);

            // Execute the plugin and propagate any errors
            if let Err(e) = plugin.execute(ctx).await {
                warn!("Plugin '{}' failed: {}", name, e);
                return Err(e);
            }

            // Check if a plugin set the return flag (early exit)
            if let Some(true) = ctx.get_metadata::<bool>(RETURN_FLAG) {
                debug!("Return flag set by plugin '{}', stopping execution", name);
                break;
            }

            // Log when a response is set (but continue execution)
            if ctx.has_response() {
                debug!("Response set by plugin '{}'", name);
            }
        }

        Ok(())
    }

    /// Execute plugins until one sets a response
    ///
    /// This is useful when you want the first plugin that can answer
    /// the query to stop the chain.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The execution context
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when a response is set or all plugins have executed.
    pub async fn execute_until_response(&self, ctx: &mut Context) -> Result<()> {
        debug!("Executing plugins until response is set");

        for plugin in &self.plugins {
            let name = plugin.name();

            if !plugin.should_execute(ctx) {
                debug!("Skipping plugin '{}'", name);
                continue;
            }

            debug!("Executing plugin '{}'", name);

            if let Err(e) = plugin.execute(ctx).await {
                warn!("Plugin '{}' failed: {}", name, e);
                return Err(e);
            }

            if let Some(true) = ctx.get_metadata::<bool>(RETURN_FLAG) {
                debug!("Return flag set by plugin '{}', stopping execution", name);
                return Ok(());
            }

            if ctx.has_response() {
                debug!("Response set by plugin '{}', stopping execution", name);
                return Ok(());
            }
        }

        debug!("No plugin set a response");
        Ok(())
    }

    /// Get the number of plugins
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Check if the executor has no plugins
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Clear all plugins
    pub fn clear(&mut self) {
        self.plugins.clear();
    }

    /// Get plugin names in execution order
    pub fn plugin_names(&self) -> Vec<String> {
        self.plugins.iter().map(|p| p.name().to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;
    use crate::plugin::Plugin;
    use async_trait::async_trait;

    #[derive(Debug)]
    struct CounterPlugin {
        name: String,
        counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl Plugin for CounterPlugin {
        async fn execute(&self, _ctx: &mut Context) -> Result<()> {
            self.counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[derive(Debug)]
    struct ResponsePlugin {
        name: String,
    }

    #[async_trait]
    impl Plugin for ResponsePlugin {
        async fn execute(&self, ctx: &mut Context) -> Result<()> {
            let mut response = Message::new();
            response.set_id(ctx.request().id());
            response.set_response(true);
            ctx.set_response(Some(response));
            Ok(())
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[tokio::test]
    async fn test_executor_creation() {
        let executor = Executor::new();
        assert!(executor.is_empty());
        assert_eq!(executor.len(), 0);
    }

    #[tokio::test]
    async fn test_add_plugin() {
        let mut executor = Executor::new();
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        executor.add_plugin(Arc::new(CounterPlugin {
            name: "test".to_string(),
            counter: counter.clone(),
        }));

        assert_eq!(executor.len(), 1);

        let request = Message::new();
        let mut ctx = Context::new(request);
        executor.execute(&mut ctx).await.unwrap();

        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_execute_multiple_plugins() {
        let mut executor = Executor::new();
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        for i in 0..3 {
            executor.add_plugin(Arc::new(CounterPlugin {
                name: format!("plugin{}", i),
                counter: counter.clone(),
            }));
        }

        assert_eq!(executor.len(), 3);

        let request = Message::new();
        let mut ctx = Context::new(request);
        executor.execute(&mut ctx).await.unwrap();

        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_execute_until_response() {
        let mut executor = Executor::new();
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Add counter plugin
        executor.add_plugin(Arc::new(CounterPlugin {
            name: "counter1".to_string(),
            counter: counter.clone(),
        }));

        // Add response plugin
        executor.add_plugin(Arc::new(ResponsePlugin {
            name: "response".to_string(),
        }));

        // Add another counter plugin (should not execute)
        executor.add_plugin(Arc::new(CounterPlugin {
            name: "counter2".to_string(),
            counter: counter.clone(),
        }));

        let request = Message::new();
        let mut ctx = Context::new(request);
        executor.execute_until_response(&mut ctx).await.unwrap();

        // Only first counter should have executed
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(ctx.has_response());
    }

    #[test]
    fn test_plugin_names() {
        let mut executor = Executor::new();
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        executor.add_plugin(Arc::new(CounterPlugin {
            name: "plugin1".to_string(),
            counter: counter.clone(),
        }));

        executor.add_plugin(Arc::new(CounterPlugin {
            name: "plugin2".to_string(),
            counter,
        }));

        let names = executor.plugin_names();
        assert_eq!(names, vec!["plugin1", "plugin2"]);
    }

    #[test]
    fn test_clear() {
        let mut executor = Executor::new();
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        executor.add_plugin(Arc::new(CounterPlugin {
            name: "test".to_string(),
            counter,
        }));

        assert_eq!(executor.len(), 1);
        executor.clear();
        assert!(executor.is_empty());
    }

    #[derive(Debug)]
    struct PriorityPlugin {
        name: String,
        priority: i32,
    }

    #[async_trait]
    impl Plugin for PriorityPlugin {
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

    #[test]
    fn test_sort_by_priority() {
        let mut executor = Executor::new();

        executor.add_plugin(Arc::new(PriorityPlugin {
            name: "high".to_string(),
            priority: 10,
        }));

        executor.add_plugin(Arc::new(PriorityPlugin {
            name: "low".to_string(),
            priority: 100,
        }));

        executor.add_plugin(Arc::new(PriorityPlugin {
            name: "medium".to_string(),
            priority: 50,
        }));

        executor.sort_by_priority();

        let names = executor.plugin_names();
        assert_eq!(names, vec!["high", "medium", "low"]);
    }
}

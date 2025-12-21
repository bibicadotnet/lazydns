//! Plugin registry for runtime plugin management.
//!
//! Manages plugin registration and lookup.

use crate::Error;
use crate::plugin::Plugin;
use std::collections::HashMap;
use std::sync::Arc;

/// Plugin registry
///
/// The registry stores and manages all available plugins.
/// Plugins are registered by name and can be looked up later.
///
/// # Example
///
/// ```rust
/// use lazydns::plugin::{Registry, Plugin, Context};
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
/// let mut registry = Registry::new();
/// registry.register(Arc::new(MyPlugin));
///
/// assert!(registry.get("my_plugin").is_some());
/// ```
#[derive(Debug, Default)]
pub struct Registry {
    /// Map of plugin name to plugin instance
    plugins: HashMap<String, Arc<dyn Plugin>>,
}

impl Registry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Register a plugin
    ///
    /// # Arguments
    ///
    /// * `plugin` - The plugin to register
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if a plugin with the same name
    /// is already registered.
    pub fn register(&mut self, plugin: Arc<dyn Plugin>) -> crate::Result<()> {
        let name = plugin.name().to_string();

        if self.plugins.contains_key(&name) {
            return Err(Error::Plugin(format!(
                "Plugin '{}' is already registered",
                name
            )));
        }

        self.plugins.insert(name, plugin);
        Ok(())
    }

    /// Register a plugin, replacing any existing plugin with the same name
    ///
    /// # Arguments
    ///
    /// * `plugin` - The plugin to register
    pub fn register_replace(&mut self, plugin: Arc<dyn Plugin>) {
        let name = plugin.name().to_string();
        self.plugins.insert(name, plugin);
    }

    /// Register a plugin under an explicit name, replacing any existing plugin with that name
    pub fn register_replace_with_name(&mut self, name: &str, plugin: Arc<dyn Plugin>) {
        self.plugins.insert(name.to_string(), plugin);
    }

    /// Get a plugin by name
    ///
    /// # Arguments
    ///
    /// * `name` - The plugin name
    ///
    /// # Returns
    ///
    /// Returns the plugin if found, or `None` if no plugin with that name exists.
    pub fn get(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.plugins.get(name).cloned()
    }

    /// Check if a plugin is registered
    ///
    /// # Arguments
    ///
    /// * `name` - The plugin name
    pub fn contains(&self, name: &str) -> bool {
        self.plugins.contains_key(name)
    }

    /// Remove a plugin
    ///
    /// # Arguments
    ///
    /// * `name` - The plugin name
    ///
    /// # Returns
    ///
    /// Returns the removed plugin if it existed.
    pub fn remove(&mut self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.plugins.remove(name)
    }

    /// Get the number of registered plugins
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Get all plugin names
    pub fn plugin_names(&self) -> Vec<String> {
        self.plugins.keys().cloned().collect()
    }

    /// Clear all plugins
    pub fn clear(&mut self) {
        self.plugins.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::{Context, Plugin};
    use async_trait::async_trait;

    #[derive(Debug)]
    struct TestPlugin {
        name: String,
    }

    #[async_trait]
    impl Plugin for TestPlugin {
        async fn execute(&self, _ctx: &mut Context) -> crate::Result<()> {
            Ok(())
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[test]
    fn test_registry_creation() {
        let registry = Registry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_register_plugin() {
        let mut registry = Registry::new();
        let plugin = Arc::new(TestPlugin {
            name: "test".to_string(),
        });

        assert!(registry.register(plugin).is_ok());
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
        assert!(registry.contains("test"));
    }

    #[test]
    fn test_register_duplicate() {
        let mut registry = Registry::new();
        let plugin1 = Arc::new(TestPlugin {
            name: "test".to_string(),
        });
        let plugin2 = Arc::new(TestPlugin {
            name: "test".to_string(),
        });

        assert!(registry.register(plugin1).is_ok());
        assert!(registry.register(plugin2).is_err());
    }

    #[test]
    fn test_register_replace() {
        let mut registry = Registry::new();
        let plugin1 = Arc::new(TestPlugin {
            name: "test".to_string(),
        });
        let plugin2 = Arc::new(TestPlugin {
            name: "test".to_string(),
        });

        registry.register_replace(plugin1);
        assert_eq!(registry.len(), 1);

        registry.register_replace(plugin2);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_get_plugin() {
        let mut registry = Registry::new();
        let plugin = Arc::new(TestPlugin {
            name: "test".to_string(),
        });

        registry.register(plugin).unwrap();

        let retrieved = registry.get("test");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name(), "test");

        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_remove_plugin() {
        let mut registry = Registry::new();
        let plugin = Arc::new(TestPlugin {
            name: "test".to_string(),
        });

        registry.register(plugin).unwrap();
        assert!(registry.contains("test"));

        let removed = registry.remove("test");
        assert!(removed.is_some());
        assert!(!registry.contains("test"));
        assert!(registry.is_empty());

        assert!(registry.remove("test").is_none());
    }

    #[test]
    fn test_plugin_names() {
        let mut registry = Registry::new();

        registry
            .register(Arc::new(TestPlugin {
                name: "plugin1".to_string(),
            }))
            .unwrap();

        registry
            .register(Arc::new(TestPlugin {
                name: "plugin2".to_string(),
            }))
            .unwrap();

        let names = registry.plugin_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"plugin1".to_string()));
        assert!(names.contains(&"plugin2".to_string()));
    }

    #[test]
    fn test_clear() {
        let mut registry = Registry::new();

        registry
            .register(Arc::new(TestPlugin {
                name: "plugin1".to_string(),
            }))
            .unwrap();

        registry
            .register(Arc::new(TestPlugin {
                name: "plugin2".to_string(),
            }))
            .unwrap();

        assert_eq!(registry.len(), 2);

        registry.clear();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }
}

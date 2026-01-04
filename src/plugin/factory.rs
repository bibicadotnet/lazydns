//! Plugin factory registration system
//!
//! Manages plugin type registration and factory lookup.
//! This module provides the infrastructure for registering plugin factories
//! and creating plugin instances from configuration.

use crate::config::types::PluginConfig;
use crate::plugin::Plugin;
use std::sync::Arc;
use tracing::debug;

/// Plugin factory trait for self-registering plugins
///
/// Implement this trait directly on your plugin type to enable automatic
/// registration without needing a separate factory struct.
///
/// # Example
///
/// ```ignore
/// use lazydns::plugin::factory::PluginFactory;
/// use lazydns::config::types::PluginConfig;
/// use std::sync::Arc;
/// use async_trait::async_trait;
///
/// #[derive(Debug)]
/// struct MyPlugin { config: String }
///
/// impl PluginFactory for MyPlugin {
///     fn create(&self, config: &PluginConfig) -> crate::Result<Arc<dyn lazydns::plugin::Plugin>> {
///         // Create plugin from config
///         Ok(Arc::new(Self { config: "default".to_string() }))
///     }
///
///     fn plugin_type(&self) -> &'static str {
///         "my_plugin"
///     }
///
///     fn aliases(&self) -> &'static [&'static str] {
///         &[]
///     }
/// }
/// ```
pub trait PluginFactory: Send + Sync {
    fn create(&self, config: &PluginConfig) -> crate::Result<Arc<dyn Plugin>>;
    fn plugin_type(&self) -> &'static str;
    fn aliases(&self) -> &'static [&'static str];
}

/// Exec plugin factory trait for exec plugins
///
/// Similar to PluginFactory but specifically for exec plugins that implement ExecPlugin.
pub trait ExecPluginFactory: Send + Sync {
    fn create(&self, prefix: &str, exec_str: &str) -> crate::Result<Arc<dyn Plugin>>;
    fn plugin_type(&self) -> &'static str;
    fn aliases(&self) -> &'static [&'static str];
}

/// Distributed slice for collecting plugin factories
#[linkme::distributed_slice]
pub static PLUGIN_FACTORIES_SLICE: [fn() -> Arc<dyn PluginFactory>];

/// Distributed slice for collecting exec plugin factories
#[linkme::distributed_slice]
pub static EXEC_PLUGIN_FACTORIES_SLICE: [fn() -> Arc<dyn ExecPluginFactory>];

/// Get a plugin factory by type name
pub fn get_plugin_factory(plugin_type: &str) -> Option<Arc<dyn PluginFactory>> {
    // Search through the distributed slice for a factory with matching type
    for factory_constructor in PLUGIN_FACTORIES_SLICE {
        let factory = factory_constructor();
        if factory.plugin_type() == plugin_type {
            return Some(factory);
        }
        // Also check aliases
        for alias in factory.aliases() {
            if *alias == plugin_type {
                return Some(factory);
            }
        }
    }
    None
}

/// Get an exec plugin factory by type name
pub fn get_exec_plugin_factory(plugin_type: &str) -> Option<Arc<dyn ExecPluginFactory>> {
    // Search through the distributed slice for a factory with matching type
    for factory_constructor in EXEC_PLUGIN_FACTORIES_SLICE {
        let factory = factory_constructor();
        if factory.plugin_type() == plugin_type {
            return Some(factory);
        }
        // Also check aliases
        for alias in factory.aliases() {
            if *alias == plugin_type {
                return Some(factory);
            }
        }
    }
    None
}

/// Get all registered plugin types
pub fn get_all_plugin_types() -> Vec<String> {
    let mut types: Vec<String> = PLUGIN_FACTORIES_SLICE
        .iter()
        .flat_map(|factory_constructor| {
            let factory = factory_constructor();
            let mut names = vec![factory.plugin_type().to_string()];
            names.extend(factory.aliases().iter().map(|s| s.to_string()));
            names
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    types.sort();
    types
}

/// Get all registered exec plugin types
pub fn get_all_exec_plugin_types() -> Vec<String> {
    let mut types: Vec<String> = EXEC_PLUGIN_FACTORIES_SLICE
        .iter()
        .flat_map(|factory_constructor| {
            let factory = factory_constructor();
            let mut names = vec![factory.plugin_type().to_string()];
            names.extend(factory.aliases().iter().map(|s| s.to_string()));
            names
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    types.sort();
    types
}

/// Initialize all plugin and exec plugin factories
/// This function should be called early in program initialization.
pub fn init() {
    initialize_all_plugin_factories();
    initialize_all_exec_plugin_factories();
}

/// Initialize all plugin factories
///
/// This function ensures that all plugin factory registrations are triggered.
/// It should be called early in program initialization, before any plugins
/// are created from configuration.
///
/// The function works by iterating over all factories in the distributed slice
/// and registering them automatically.
///
/// # Example
///
/// ```rust
/// use lazydns::plugin::factory::initialize_all_plugin_factories;
///
/// // Initialize plugin factories before loading config
/// initialize_all_plugin_factories();
/// ```
pub fn initialize_all_plugin_factories() {
    use once_cell::sync::OnceCell;

    static INIT: OnceCell<()> = OnceCell::new();

    INIT.get_or_init(|| {
        // Force initialization by accessing the distributed slice
        // This ensures all linkme-registered factories are available
        let _ = PLUGIN_FACTORIES_SLICE.len();

        let types = get_all_plugin_types();
        debug!("Initialized {} plugin factories: {:?}", types.len(), types);
    });
}

/// Initialize all exec plugin factories
///
/// Similar to initialize_all_plugin_factories but for exec plugins.
fn initialize_all_exec_plugin_factories() {
    use once_cell::sync::OnceCell;

    static EXEC_INIT: OnceCell<()> = OnceCell::new();

    EXEC_INIT.get_or_init(|| {
        // Force initialization by accessing the distributed slice
        // This ensures all linkme-registered factories are available
        let _ = EXEC_PLUGIN_FACTORIES_SLICE.len();

        let types = get_all_exec_plugin_types();
        debug!(
            "Initialized {} exec plugin factories: {:?}",
            types.len(),
            types
        );
    });
}

/// Backward compatibility macro for registering plugin factories
///
/// This macro is deprecated - use `#[derive(RegisterPlugin)]` instead.
///
/// # Example
///
/// ```ignore
/// register_plugin_builder!(MyPlugin);
/// // Equivalent to:
/// #[derive(RegisterPlugin)]
/// struct MyPlugin;
/// ```
#[macro_export]
#[deprecated(since = "0.2.61", note = "Use #[derive(RegisterPlugin)] instead.")]
macro_rules! register_plugin_builder {
    ($plugin_type:ty) => {
        compile_error!(
            "register_plugin_builder! is deprecated. Use #[derive(RegisterPlugin)] instead."
        );
    };
}

/// Backward compatibility macro for registering exec plugin factories
///
/// This macro is deprecated - use `#[derive(RegisterExecPlugin)]` instead.
///
/// # Example
///
/// ```ignore
/// register_exec_plugin_builder!(MyExecPlugin);
/// // Equivalent to:
/// #[derive(RegisterExecPlugin)]
/// struct MyExecPlugin;
/// ```
#[macro_export]
#[deprecated(since = "0.2.61", note = "Use #[derive(RegisterExecPlugin)] instead.")]
macro_rules! register_exec_plugin_builder {
    ($plugin_type:ty) => {
        compile_error!("register_exec_plugin_builder! is deprecated. Use #[derive(RegisterExecPlugin)] instead.");
    };
}

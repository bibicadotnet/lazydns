//! Plugin factory registration system
//!
//! Manages plugin type registration and factory lookup.
//! This module provides the infrastructure for registering plugin factories
//! and creating plugin instances from configuration.

use crate::config::types::PluginConfig;
use crate::plugin::Plugin;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
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

/// Global plugin factory registry
static PLUGIN_FACTORIES: Lazy<RwLock<HashMap<String, Arc<dyn PluginFactory>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Global exec plugin factory registry
static EXEC_PLUGIN_FACTORIES: Lazy<RwLock<HashMap<String, Arc<dyn ExecPluginFactory>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Register a plugin factory (internal use)
pub fn register_plugin_factory(factory: Arc<dyn PluginFactory>) {
    let mut factories = PLUGIN_FACTORIES
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let plugin_type = factory.plugin_type();
    // Check for duplicates
    if factories.contains_key(plugin_type) {
        panic!("Duplicate plugin factory registration: {}", plugin_type);
    }

    // Register primary name
    factories.insert(plugin_type.to_string(), Arc::clone(&factory));

    // Register aliases
    for alias in factory.aliases() {
        let alias = *alias; // alias: &str (slice elements are &&str)
        // Skip redundant alias identical to primary name
        if alias == plugin_type {
            continue;
        }
        if factories.contains_key(alias) {
            panic!(
                "Duplicate plugin factory alias: {} (for {})",
                alias, plugin_type
            );
        }
        factories.insert(alias.to_string(), Arc::clone(&factory));
    }
}

/// Register an exec plugin factory (internal use)
pub fn register_exec_plugin_factory(factory: Arc<dyn ExecPluginFactory>) {
    let mut factories = EXEC_PLUGIN_FACTORIES
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let plugin_type = factory.plugin_type();
    // Check for duplicates
    if factories.contains_key(plugin_type) {
        panic!(
            "Duplicate exec plugin factory registration: {}",
            plugin_type
        );
    }

    // Register primary name
    factories.insert(plugin_type.to_string(), Arc::clone(&factory));

    // Register aliases
    for alias in factory.aliases() {
        let alias = *alias; // alias: &str (slice elements are &&str)
        // Skip redundant alias identical to primary name
        if alias == plugin_type {
            continue;
        }
        if factories.contains_key(alias) {
            panic!(
                "Duplicate exec plugin factory alias: {} (for {})",
                alias, plugin_type
            );
        }
        factories.insert(alias.to_string(), Arc::clone(&factory));
    }
}

/// Get a plugin factory by type name
pub fn get_plugin_factory(plugin_type: &str) -> Option<Arc<dyn PluginFactory>> {
    let factories = PLUGIN_FACTORIES
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    factories.get(plugin_type).cloned()
}

/// Get an exec plugin factory by type name
pub fn get_exec_plugin_factory(plugin_type: &str) -> Option<Arc<dyn ExecPluginFactory>> {
    let factories = EXEC_PLUGIN_FACTORIES
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    factories.get(plugin_type).cloned()
}

/// Get all registered plugin types
pub fn get_all_plugin_types() -> Vec<String> {
    let factories = PLUGIN_FACTORIES
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut types: Vec<String> = factories
        .values()
        .map(|f| f.plugin_type().to_string())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    types.sort();
    types
}

/// Get all registered exec plugin types
pub fn get_all_exec_plugin_types() -> Vec<String> {
    let factories = EXEC_PLUGIN_FACTORIES
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut types: Vec<String> = factories
        .values()
        .map(|f| f.plugin_type().to_string())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    types.sort();
    types
}

/// Initialize the plugin factory system
pub fn initialize_plugin_factories() {
    // Force lazy initialization
    Lazy::force(&PLUGIN_FACTORIES);
}

/// Initialize the exec plugin factory system
pub fn initialize_exec_plugin_factories() {
    // Force lazy initialization
    Lazy::force(&EXEC_PLUGIN_FACTORIES);
}

/// Derive macro to auto-register a plugin factory
///
/// This derive macro automatically creates a factory wrapper for types that
/// implement `Plugin` with an `init` method and registers it.
///
/// The canonical plugin name is derived from the type name:
/// - Use the last path segment (e.g., "ForwardPlugin" from "crate::plugins::forward::ForwardPlugin")
/// - Strip the "Plugin" suffix if present
/// - Convert PascalCase to snake_case
///
/// # Example
///
/// ```ignore
/// use lazydns::lazydns_macros::RegisterPlugin;
/// use lazydns::plugin::Plugin;
/// use lazydns::config::types::PluginConfig;
/// use std::sync::Arc;
///
/// #[derive(Debug, RegisterPlugin)]
/// struct MyPlugin;
///
/// impl Plugin for MyPlugin {
///     async fn execute(&self, _ctx: &mut lazydns::plugin::Context) -> crate::Result<()> {
///         Ok(())
///     }
///
///     fn name(&self) -> &str {
///         "my_plugin"
///     }
///
///     fn init(_config: &PluginConfig) -> crate::Result<Arc<dyn Plugin>> {
///         Ok(Arc::new(Self))
///     }
/// }
/// ```
///
/// Re-exported for backward compatibility and convenience.
pub use lazydns_macros::RegisterPlugin;

/// Derive macro to auto-register an exec plugin factory
///
/// This derive macro automatically creates a factory wrapper for types that
/// implement `ExecPlugin` and registers it in the exec plugin registry.
///
/// The canonical plugin name is derived from the type name (same rules as `RegisterPlugin`).
///
/// # Example
///
/// ```ignore
/// use lazydns::lazydns_macros::RegisterExecPlugin;
/// use lazydns::plugin::{Plugin, ExecPlugin};
/// use std::sync::Arc;
///
/// #[derive(Debug, RegisterExecPlugin)]
/// struct MyExecPlugin;
///
/// impl Plugin for MyExecPlugin {
///     async fn execute(&self, _ctx: &mut lazydns::plugin::Context) -> crate::Result<()> {
///         Ok(())
///     }
///
///     fn name(&self) -> &str {
///         "my_exec_plugin"
///     }
/// }
///
/// impl ExecPlugin for MyExecPlugin {
///     fn quick_setup(prefix: &str, exec_str: &str) -> crate::Result<Arc<dyn Plugin>> {
///         // Implementation
///         Ok(Arc::new(Self))
///     }
/// }
/// ```
///
/// Re-exported for backward compatibility and convenience.
pub use lazydns_macros::RegisterExecPlugin;

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
/// The function works by accessing lazy_static variables in each plugin module
/// that contain the factory registration code. This triggers the initialization
/// of those statics, which in turn registers the factories.
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
        use once_cell::sync::Lazy;

        // Force initialization by accessing the Lazy statics generated by register_plugin_builder! macro
        // Note: Macro generates names like CACHE_PLUGIN_FACTORY from CachePlugin
        Lazy::force(&crate::plugins::cache::CACHE_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::forward::FORWARD_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::dataset::hosts::HOSTS_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::acl::QUERY_ACL_PLUGIN_FACTORY);

        Lazy::force(&crate::plugins::dataset::arbitrary::ARBITRARY_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::dataset::domain_set::DOMAIN_SET_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::dataset::ip_set::IP_SET_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::ratelimit::RATE_LIMIT_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::ros_addrlist::ROS_ADDRLIST_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::black_hole::BLACKHOLE_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::fallback::FALLBACK_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::redirect::REDIRECT_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::edns0opt::EDNS0_OPT_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::reverse_lookup::REVERSE_LOOKUP_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::dual_selector::DUAL_SELECTOR_PLUGIN_FACTORY);

        Lazy::force(&crate::plugins::geoip::GEO_IP_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::geosite::GEO_SITE_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::domain_validator::DOMAIN_VALIDATOR_PLUGIN_FACTORY);

        #[cfg(feature = "cron")]
        Lazy::force(&crate::plugins::cron::CRON_PLUGIN_FACTORY);
        #[cfg(feature = "cron")]
        Lazy::force(&crate::plugins::executable::downloader::DOWNLOADER_PLUGIN_FACTORY);

        // TODO: DoH, Dot, DoQ and other plugins

        // Initialize the factory system
        initialize_plugin_factories();

        let count = get_all_plugin_types().len();
        if count > 0 {
            let types = get_all_plugin_types();
            debug!("Initialized {} plugin factories: {:?}", count, types);
        }
    });
}

/// Initialize all exec plugin factories
///
/// Similar to initialize_all_plugin_factories but for exec plugins.
pub fn initialize_all_exec_plugin_factories() {
    use once_cell::sync::OnceCell;

    static EXEC_INIT: OnceCell<()> = OnceCell::new();

    EXEC_INIT.get_or_init(|| {
        // Force initialization of exec plugin factories
        Lazy::force(&crate::plugins::executable::ttl::TTL_PLUGIN_EXEC_FACTORY);
        // Use the auto-generated factory for blackhole (now supports aliases via macro)
        Lazy::force(&crate::plugins::executable::black_hole::BLACKHOLE_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::executable::sleep::SLEEP_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::executable::debug_print::DEBUG_PRINT_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::executable::drop_resp::DROP_RESP_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::executable::fallback::FALLBACK_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::executable::query_summary::QUERY_SUMMARY_PLUGIN_EXEC_FACTORY);

        Lazy::force(&crate::plugins::flow::accept::ACCEPT_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::flow::goto::GOTO_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::flow::jump::JUMP_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::flow::reject::REJECT_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::flow::prefer_ipv4::PREFER_IPV4_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::flow::prefer_ipv6::PREFER_IPV6_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::flow::return_plugin::RETURN_PLUGIN_EXEC_FACTORY);

        Lazy::force(&crate::plugins::executable::ipset::IP_SET_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::executable::nftset::NFT_SET_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::executable::ecs::ECS_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::executable::collector::METRICS_COLLECTOR_PLUGIN_EXEC_FACTORY);
        Lazy::force(&crate::plugins::executable::mark::MARK_PLUGIN_EXEC_FACTORY);
        #[cfg(feature = "metrics")]
        Lazy::force(
            &crate::plugins::executable::collector::PROM_METRICS_COLLECTOR_PLUGIN_EXEC_FACTORY,
        );

        // Initialize the exec factory system
        initialize_exec_plugin_factories();

        let count = get_all_exec_plugin_types().len();
        if count > 0 {
            let types = get_all_exec_plugin_types();
            debug!("Initialized {} exec plugin factories: {:?}", count, types);
        }
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

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
///     fn aliases(&self) -> Vec<&'static str> {
///         Vec::new()
///     }
/// }
/// ```
pub trait PluginFactory: Send + Sync {
    fn create(&self, config: &PluginConfig) -> crate::Result<Arc<dyn Plugin>>;
    fn plugin_type(&self) -> &'static str;
    fn aliases(&self) -> Vec<&'static str>;
}

/// Global plugin factory registry
static PLUGIN_FACTORIES: Lazy<RwLock<HashMap<String, Arc<dyn PluginFactory>>>> =
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
        if factories.contains_key(alias) {
            panic!(
                "Duplicate plugin factory alias: {} (for {})",
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

/// Initialize the plugin factory system
pub fn initialize_plugin_factories() {
    // Force lazy initialization
    Lazy::force(&PLUGIN_FACTORIES);
}

/// Macro to register a plugin factory
///
/// This macro automatically creates a factory wrapper for types that
/// implement `Plugin` with an `init` method and registers it.
///
/// # Example
///
/// ```ignore
/// use lazydns::register_plugin_builder;
/// use lazydns::plugin::Plugin;
/// use lazydns::config::types::PluginConfig;
/// use std::sync::Arc;
/// use async_trait::async_trait;
///
/// #[derive(Debug)]
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
///
/// register_plugin_builder!(MyPlugin);
/// ```
#[macro_export]
macro_rules! register_plugin_builder {
    ($plugin_type:ty) => {
        $crate::paste::paste! {
            // Create an auto-generated factory wrapper
            #[derive(Default)]
            struct [<$plugin_type FactoryWrapper>];

            impl $crate::plugin::factory::PluginFactory for [<$plugin_type FactoryWrapper>] {
                fn create(&self, config: &$crate::config::types::PluginConfig)
                    -> $crate::Result<std::sync::Arc<dyn $crate::plugin::Plugin>>
                {
                    <$plugin_type as $crate::plugin::Plugin>::init(config)
                }

                fn plugin_type(&self) -> &'static str {
                    // Derive a canonical plugin name from the Rust type name and cache it as a
                    // `'static` string so it can be used by the global registry.
                    //
                    // Name derivation rules:
                    //  - Use the last path segment of the Rust type name (e.g. "crate::plugins::forward::ForwardPlugin" -> "ForwardPlugin").
                    //  - If the last segment ends with the suffix "Plugin", strip that suffix ("ForwardPlugin" -> "Forward").
                    //  - Convert PascalCase/CamelCase to snake_case by inserting '_' before uppercase
                    //    letters (except the first character) and lowercasing ("DropResp" -> "drop_resp").
                    //  - The computed `String` is stored in a `once_cell::sync::Lazy<&'static str>` and
                    //    leaked to produce a `&'static str` on demand.
                    //
                    // Note: `register_plugin_factory` will panic if a duplicate canonical name is registered.
                    //       That means two different Rust types that derive the same canonical name
                    //       will cause a registration-time panic; the tests below check for accidental
                    //       collisions among existing plugin types.
                    $crate::paste::paste! {
                        static [<$plugin_type:snake:upper _DERIVED>]: once_cell::sync::Lazy<&'static str> =
                            once_cell::sync::Lazy::new(|| {
                                let t = std::any::type_name::<$plugin_type>();
                                let last = t.rsplit("::").next().unwrap_or(t);
                                let base = last.strip_suffix("Plugin").unwrap_or(last);
                                // PascalCase/CamelCase -> snake_case
                                let mut s = String::new();
                                for (i, ch) in base.chars().enumerate() {
                                    if ch.is_uppercase() {
                                        if i != 0 {
                                            s.push('_');
                                        }
                                        for lc in ch.to_lowercase() {
                                            s.push(lc);
                                        }
                                    } else {
                                        s.push(ch);
                                    }
                                }
                                Box::leak(s.into_boxed_str())
                            });

                        [<$plugin_type:snake:upper _DERIVED>].clone()
                    }
                }

                fn aliases(&self) -> Vec<&'static str> {
                    Vec::new()
                }
            }

            // Auto-register using lazy static
            pub(crate) static [<$plugin_type:snake:upper _FACTORY>]: once_cell::sync::Lazy<()> =
                once_cell::sync::Lazy::new(|| {
                    $crate::plugin::factory::register_plugin_factory(
                        std::sync::Arc::new([<$plugin_type FactoryWrapper>]::default())
                    );
                });
        }
    };
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
/// use lazydns::plugin::factory::initialize_all_factories;
///
/// // Initialize plugin factories before loading config
/// initialize_all_factories();
/// ```
pub fn initialize_all_factories() {
    use once_cell::sync::OnceCell;

    static INIT: OnceCell<()> = OnceCell::new();

    INIT.get_or_init(|| {
        use once_cell::sync::Lazy;

        // Force initialization by accessing the Lazy statics generated by register_plugin_builder! macro
        // Note: Macro generates names like CACHE_PLUGIN_FACTORY from CachePlugin
        Lazy::force(&crate::plugins::executable::cache::CACHE_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::forward::FORWARD_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::ratelimit::RATE_LIMIT_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::drop_resp::DROP_RESP_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::dataset::domain_set::DOMAIN_SET_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::dataset::ip_set::IP_SET_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::hosts::HOSTS_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::ros_addrlist::ROS_ADDRLIST_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::ttl::TTL_PLUGIN_FACTORY);

        // Exec/Flow plugins
        // TODO: try other ways?
        // SeeAlso: src/plugin/builder.rs: 494 fn parse_exec_action
        Lazy::force(&crate::plugins::executable::black_hole::BLACKHOLE_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::fallback::FALLBACK_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::matcher::has_resp::HAS_RESP_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::executable::redirect::REDIRECT_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::server::UDP_SERVER_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::server::TCP_SERVER_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::flow::accept::ACCEPT_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::flow::reject::REJECT_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::flow::return_plugin::RETURN_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::flow::jump::JUMP_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::flow::prefer_ipv4::PREFER_IPV4_PLUGIN_FACTORY);
        Lazy::force(&crate::plugins::flow::prefer_ipv6::PREFER_IPV6_PLUGIN_FACTORY);

        // Initialize the factory system
        initialize_plugin_factories();

        let count = get_all_plugin_types().len();
        if count > 0 {
            tracing::info!("Initialized {} plugin factories", count);
        }
    });
}

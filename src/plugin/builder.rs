//! Plugin builder system
//!
//! This module provides a builder pattern for creating plugin instances from configuration.
//! It supports both the new PluginBuilder trait pattern and legacy hardcoded plugins.

use crate::config::types::PluginConfig;
use crate::plugin::traits::Matcher;
use crate::plugin::{Context, Plugin};
use crate::plugins::executable::SequenceStep;
use crate::plugins::*;
use crate::Error;
use crate::Result;
use once_cell::sync::Lazy;
use serde_yaml::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

/// Plugin builder trait for self-registering plugins
///
/// Implement this trait directly on your plugin type to enable automatic
/// registration without needing a separate factory struct.
///
/// # Example
///
/// ```ignore
/// use lazydns::plugin::builder::PluginBuilder;
/// use lazydns::plugin::Plugin;
/// use lazydns::config::types::PluginConfig;
/// use std::sync::Arc;
///
/// struct MyPlugin { config: String }
///
/// impl PluginBuilder for MyPlugin {
///     fn create_from_config(config: &PluginConfig) -> lazydns::Result<Arc<dyn Plugin>> {
///         let args = config.effective_args();
///         let my_config = args.get("config")
///             .and_then(|v| v.as_str())
///             .unwrap_or("default")
///             .to_string();
///         Ok(Arc::new(Self { config: my_config }))
///     }
///     
///     fn plugin_type() -> &'static str {
///         "my_plugin"
///     }
/// }
///
/// // Auto-register with macro
/// lazydns::register_plugin_builder!(MyPlugin);
/// ```
/// ```
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

/// Internal trait for dynamic dispatch of PluginBuilder implementations
#[doc(hidden)]
pub trait PluginBuilderFactory: Send + Sync {
    fn create(&self, config: &PluginConfig) -> Result<Arc<dyn Plugin>>;
    fn plugin_type(&self) -> &'static str;
    fn aliases(&self) -> Vec<&'static str>;
}

/// Global plugin builder registry
static PLUGIN_BUILDERS: Lazy<RwLock<HashMap<String, Arc<dyn PluginBuilderFactory>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Register a plugin builder (internal use)
#[doc(hidden)]
pub fn register_builder(builder: Arc<dyn PluginBuilderFactory>) {
    let mut builders = PLUGIN_BUILDERS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let plugin_type = builder.plugin_type();

    // Check for duplicates
    if builders.contains_key(plugin_type) {
        panic!("Duplicate plugin builder registration: {}", plugin_type);
    }

    // Register primary name
    builders.insert(plugin_type.to_string(), Arc::clone(&builder));

    // Register aliases
    for alias in builder.aliases() {
        if builders.contains_key(alias) {
            panic!(
                "Duplicate plugin builder alias: {} (for {})",
                alias, plugin_type
            );
        }
        builders.insert(alias.to_string(), Arc::clone(&builder));
    }
}

/// Get a plugin builder by type name
pub fn get_builder(plugin_type: &str) -> Option<Arc<dyn PluginBuilderFactory>> {
    let builders = PLUGIN_BUILDERS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    builders.get(plugin_type).cloned()
}

/// Get all registered plugin types
pub fn get_all_plugin_types() -> Vec<String> {
    let builders = PLUGIN_BUILDERS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut types: Vec<String> = builders
        .values()
        .map(|b| b.plugin_type().to_string())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    types.sort();
    types
}

/// Initialize the plugin builder system
pub fn initialize() {
    // Force lazy initialization
    Lazy::force(&PLUGIN_BUILDERS);
}

/// Macro to register a plugin builder
///
/// This macro automatically creates a builder wrapper for types that
/// implement `PluginBuilder` and registers it.
///
/// # Example
///
/// ```ignore
/// use lazydns::register_plugin_builder;
///
/// struct MyPlugin;
/// impl PluginBuilder for MyPlugin {
///     fn create_from_config(config: &PluginConfig) -> Result<Arc<dyn Plugin>> {
///         Ok(Arc::new(Self))
///     }
///     fn plugin_type() -> &'static str { "my_plugin" }
/// }
///
/// register_plugin_builder!(MyPlugin);
/// ```
#[macro_export]
macro_rules! register_plugin_builder {
    ($plugin_type:ty) => {
        $crate::paste::paste! {
            // Create an auto-generated builder wrapper
            #[derive(Default)]
            struct [<$plugin_type BuilderWrapper>];

            impl $crate::plugin::builder::PluginBuilderFactory for [<$plugin_type BuilderWrapper>] {
                fn create(&self, config: &$crate::config::types::PluginConfig)
                    -> $crate::Result<std::sync::Arc<dyn $crate::plugin::Plugin>>
                {
                    <$plugin_type as $crate::plugin::builder::PluginBuilder>::create(config)
                }

                fn plugin_type(&self) -> &'static str {
                    <$plugin_type as $crate::plugin::builder::PluginBuilder>::plugin_type()
                }

                fn aliases(&self) -> Vec<&'static str> {
                    <$plugin_type as $crate::plugin::builder::PluginBuilder>::aliases()
                }
            }

            // Auto-register using lazy static
            pub(crate) static [<$plugin_type:snake:upper _BUILDER>]: once_cell::sync::Lazy<()> =
                once_cell::sync::Lazy::new(|| {
                    $crate::plugin::builder::register_builder(
                        std::sync::Arc::new([<$plugin_type BuilderWrapper>]::default())
                    );
                });
        }
    };
}

// ============================================================================
// Main Plugin Builder (Configuration-based Plugin Creation)
// ============================================================================

/// Plugin builder that creates plugin instances from configuration
pub struct ConfigPluginBuilder {
    /// Registry of named plugins for reference
    plugins: HashMap<String, Arc<dyn Plugin>>,
    /// Server plugin tags
    server_plugin_tags: Vec<String>,
}

impl ConfigPluginBuilder {
    /// Create a new plugin builder
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            server_plugin_tags: Vec::new(),
        }
    }

    /// Build a plugin from configuration
    pub fn build(&mut self, config: &PluginConfig) -> Result<Arc<dyn Plugin>> {
        // Normalize plugin type for more forgiving parsing (trim and lowercase)
        let plugin_type = config.plugin_type.trim().to_lowercase();

        // Try to get builder from registry first
        if let Some(builder) = get_builder(&plugin_type) {
            info!("Creating plugin '{}' using registered builder", plugin_type);
            let plugin = builder.create(config)?;

            // Store in registry if it has a tag or name
            let effective_name = config.effective_name().to_string();
            self.plugins.insert(effective_name, Arc::clone(&plugin));

            return Ok(plugin);
        }

        // Fallback to legacy hardcoded match for backward compatibility
        warn!(
            "Plugin type '{}' not found in builder registry, using legacy match",
            plugin_type
        );

        let plugin: Arc<dyn Plugin> = match plugin_type.as_str() {
            "cache" => {
                let args = &config.effective_args();
                let size = get_int_arg(args, "size", 1024)?;
                Arc::new(CachePlugin::new(size as usize))
            }

            // "forward" => {
            //     let args = &config.effective_args();
            //     let upstreams = get_string_array_arg(args, "upstreams")?;
            //     let _concurrent = get_int_arg(args, "concurrent", 1)? as usize;

            //     let mut builder = ForwardPluginBuilder::new();
            //     for upstream in upstreams {
            //         // Parse upstream address - handle udp:// and tcp:// prefixes
            //         let mut addr = upstream
            //             .trim_start_matches("udp://")
            //             .trim_start_matches("tcp://")
            //             .to_string();

            //         // Ensure the address includes a port. If parsing as a SocketAddr
            //         // fails, try appending the default DNS port 53.
            //         if addr.parse::<std::net::SocketAddr>().is_err() {
            //             let with_port = format!("{}:53", addr);
            //             if with_port.parse::<std::net::SocketAddr>().is_ok() {
            //                 addr = with_port;
            //             }
            //         }

            //         builder = builder.add_upstream(addr);
            //     }

            //     // Build plugin and log configured upstream addresses for visibility
            //     let fp = Arc::new(builder.build());
            //     if let Some(fwd) = fp.as_ref().as_any().downcast_ref::<ForwardPlugin>() {
            //         debug!(upstreams = ?fwd.upstream_addrs(), "Built forward plugin with upstreams");
            //     }
            //     fp
            // }
            "hosts" => {
                let args = &config.effective_args();
                let mut plugin = HostsPlugin::new();

                if let Some(files) = get_optional_string_array_arg(args, "files") {
                    plugin = plugin.with_files(files);
                }

                if let Some(auto_reload) = get_optional_bool_arg(args, "auto_reload") {
                    plugin = plugin.with_auto_reload(auto_reload);
                }

                // Load hosts immediately
                if let Err(e) = plugin.load_hosts() {
                    warn!(error = %e, "Failed to load hosts, continuing");
                }

                // Start file watcher if auto-reload is enabled
                plugin.start_file_watcher();

                Arc::new(plugin)
            }

            "domain_set" => {
                let args = &config.effective_args();
                let tag = get_string_arg(args, "tag", "")?;
                let name = if !tag.is_empty() {
                    tag
                } else {
                    plugin_type.clone()
                };

                let mut plugin = DomainSetPlugin::new(name);

                if let Some(files) = get_optional_string_array_arg(args, "files") {
                    plugin = plugin.with_files(files);
                }

                if let Some(auto_reload) = get_optional_bool_arg(args, "auto_reload") {
                    plugin = plugin.with_auto_reload(auto_reload);
                }

                // Load domains immediately
                plugin.load_domains()?;

                // Start file watcher if auto-reload is enabled
                plugin.start_file_watcher();

                Arc::new(plugin)
            }

            "ip_set" => {
                let args = &config.effective_args();
                let tag = get_string_arg(args, "tag", "")?;
                let name = if !tag.is_empty() {
                    tag
                } else {
                    plugin_type.clone()
                };

                let mut plugin = IpSetPlugin::new(name);

                if let Some(files) = get_optional_string_array_arg(args, "files") {
                    plugin = plugin.with_files(files);
                }

                if let Some(auto_reload) = get_optional_bool_arg(args, "auto_reload") {
                    plugin = plugin.with_auto_reload(auto_reload);
                }

                // Load IPs immediately
                plugin.load_networks()?;

                // Start file watcher if auto-reload is enabled
                plugin.start_file_watcher();

                Arc::new(plugin)
            }

            "ros_addrlist" => {
                let args = &config.effective_args();
                let addrlist = get_string_arg(args, "addrlist", "default")?;
                let mut plugin = RosAddrListPlugin::new(addrlist);
                if let Some(server) = args.get("server").and_then(|v| v.as_str()) {
                    plugin = plugin.with_server(server.to_string());
                }
                if let Some(user) = args.get("user").and_then(|v| v.as_str()) {
                    if let Some(pass) = args.get("passwd").and_then(|v| v.as_str()) {
                        plugin = plugin.with_auth(user.to_string(), pass.to_string());
                    }
                }
                if let Some(mask4) = args.get("mask4").and_then(|v| v.as_i64()) {
                    plugin = plugin.with_mask4(mask4 as u8);
                }
                if let Some(mask6) = args.get("mask6").and_then(|v| v.as_i64()) {
                    plugin = plugin.with_mask6(mask6 as u8);
                }
                Arc::new(plugin)
            }

            "sequence" => {
                // Handle different sequence formats
                if let Value::Mapping(map) = &config.args {
                    // Check if args contains "plugins" key (simple format)
                    if let Some(plugins_value) = map.get(Value::String("plugins".to_string())) {
                        if let Value::Sequence(plugin_names) = plugins_value {
                            let plugins = Vec::new();
                            for name_value in plugin_names {
                                if let Value::String(_name) = name_value {
                                    // We'll resolve plugin references in a second pass
                                    // For now, store the name and resolve later
                                    // This is a placeholder - actual resolution needs to be implemented
                                    warn!("Sequence plugin with 'plugins' key not fully implemented yet");
                                }
                            }
                            Arc::new(SequencePlugin::new(plugins))
                        } else {
                            return Err(Error::Config(
                                "sequence 'plugins' must be an array".to_string(),
                            ));
                        }
                    } else {
                        // Other mapping formats - not implemented yet
                        warn!("Sequence plugin mapping format not implemented yet, using empty sequence");
                        Arc::new(SequencePlugin::new(Vec::new()))
                    }
                } else if let Value::Sequence(sequence) = &config.args {
                    // Complex format - parse the steps
                    match parse_sequence_steps(self, sequence) {
                        Ok(steps) => Arc::new(SequencePlugin::with_steps(steps)),
                        Err(e) => {
                            warn!(
                                "Failed to parse complex sequence: {}, using empty sequence",
                                e
                            );
                            Arc::new(SequencePlugin::new(Vec::new()))
                        }
                    }
                } else {
                    // Other formats
                    warn!("Sequence plugin args format not recognized, using empty sequence");
                    Arc::new(SequencePlugin::new(Vec::new()))
                }
            }

            "fallback" => {
                // Fallback plugins reference other plugins by name
                // We'll handle this in a second pass
                let args = &config.effective_args();
                let primary = get_string_arg(args, "primary", "")?;
                let secondary = get_string_arg(args, "secondary", "")?;
                info!("Creating fallback plugin (will resolve references later): primary={}, secondary={}", primary, secondary);
                Arc::new(FallbackPlugin::new(Vec::new()))
            }

            "ttl" => {
                let args = &config.effective_args();
                let ttl = get_int_arg(args, "ttl", 300)? as u32;
                Arc::new(TtlPlugin::new(ttl, 0, 0))
            }

            "drop_resp" => Arc::new(DropRespPlugin::new()),
            "accept" => Arc::new(AcceptPlugin::new()),

            "reject" => {
                let args = &config.effective_args();
                let rcode = get_int_arg(args, "rcode", 3)? as u8;
                Arc::new(RejectPlugin::new(rcode))
            }

            "black_hole" | "blackhole" => {
                Arc::new(BlackholePlugin::new_from_strs(Vec::<&str>::new()).unwrap())
            }

            "redirect" => {
                let args = &config.effective_args();
                // Expect `rules` to be an array. Each entry can be a simple string
                // like "from to" or a mapping with `from`/`to` keys. We'll use
                // the first rule if multiple are provided.
                if let Some(Value::Sequence(seq)) = args.get("rules") {
                    if seq.is_empty() {
                        return Err(Error::Config(
                            "redirect requires at least one rule".to_string(),
                        ));
                    }

                    let first = &seq[0];
                    if let Value::String(s) = first {
                        let parts: Vec<&str> = s.split_whitespace().collect();
                        if parts.len() == 2 {
                            Arc::new(crate::plugins::executable::RedirectPlugin::new(
                                parts[0].to_string(),
                                parts[1].to_string(),
                            ))
                        } else {
                            return Err(Error::Config(
                                "redirect rule must be 'from to'".to_string(),
                            ));
                        }
                    } else if let Value::Mapping(map) = first {
                        let from = map
                            .get(Value::String("from".to_string()))
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                Error::Config("redirect rule mapping missing 'from'".to_string())
                            })?;
                        let to = map
                            .get(Value::String("to".to_string()))
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                Error::Config("redirect rule mapping missing 'to'".to_string())
                            })?;
                        Arc::new(crate::plugins::executable::RedirectPlugin::new(
                            from.to_string(),
                            to.to_string(),
                        ))
                    } else {
                        return Err(Error::Config(
                            "unsupported redirect rule format".to_string(),
                        ));
                    }
                } else {
                    return Err(Error::Config(
                        "redirect plugin requires 'rules' array".to_string(),
                    ));
                }
            }

            "prefer_ipv4" => Arc::new(PreferIpv4Plugin::new()),
            "prefer_ipv6" => Arc::new(PreferIpv6Plugin::new()),

            "jump" => {
                let args = &config.effective_args();
                let target = get_string_arg(args, "target", "")?;
                Arc::new(JumpPlugin::new(target))
            }

            "return" => Arc::new(ReturnPlugin::new()),

            // Matcher plugins
            "has_resp" => Arc::new(HasRespMatcherPlugin::new()),

            // Server plugins
            "udp_server" => {
                let args = &config.effective_args();
                let listen = get_string_arg(args, "listen", "0.0.0.0:53")?;
                let entry = get_string_arg(args, "entry", "main_sequence")?;
                // Accept shorthand like ":5353" and normalize to "0.0.0.0:5353"
                let listen_parse_str = if listen.starts_with(':') {
                    format!("0.0.0.0{}", listen)
                } else {
                    listen.clone()
                };
                let addr = listen_parse_str.parse().map_err(|e| {
                    Error::Config(format!("Invalid listen address '{}': {}", listen, e))
                })?;
                let tag = config.effective_name().to_string();
                self.server_plugin_tags.push(tag);
                Arc::new(UdpServerPlugin::new(addr, entry))
            }

            "tcp_server" => {
                let args = &config.effective_args();
                let listen = get_string_arg(args, "listen", "0.0.0.0:53")?;
                let entry = get_string_arg(args, "entry", "main_sequence")?;
                // Accept shorthand like ":5353" and normalize to "0.0.0.0:5353"
                let listen_parse_str = if listen.starts_with(':') {
                    format!("0.0.0.0{}", listen)
                } else {
                    listen.clone()
                };
                let addr = listen_parse_str.parse().map_err(|e| {
                    Error::Config(format!("Invalid listen address '{}': {}", listen, e))
                })?;
                let tag = config.effective_name().to_string();
                self.server_plugin_tags.push(tag);
                Arc::new(TcpServerPlugin::new(addr, entry))
            }

            // Accept doh/dot server plugin types at build time so configuration
            // parsing succeeds. The actual servers are started by the application
            // runtime (main.rs) when TLS and certs are available. Here we return
            // a benign plugin instance (AcceptPlugin) so the name is registered
            // and can be referenced by other plugins.
            "doh_server" | "dot_server" | "doq_server" => {
                let tag = config.effective_name().to_string();
                self.server_plugin_tags.push(tag.clone());
                Arc::new(crate::plugins::AcceptPlugin::new())
            }

            _ => {
                return Err(Error::Config(format!(
                    "Unknown plugin type: {}",
                    plugin_type
                )))
            }
        };

        // Store in registry if it has a tag or name
        let effective_name = config.effective_name().to_string();
        self.plugins.insert(effective_name, Arc::clone(&plugin));

        Ok(plugin)
    }

    /// After building all plugins, resolve any references between plugins
    /// (for example, `fallback` refers to other plugins by name).
    /// This also re-parses sequences to update plugin references after fallback resolution.
    pub fn resolve_references(&mut self, configs: &[PluginConfig]) -> Result<()> {
        // First pass: resolve fallback plugins
        for config in configs {
            if config.plugin_type == "fallback" {
                let args = config.effective_args();
                let primary = get_string_arg(&args, "primary", "")?;
                let secondary = get_string_arg(&args, "secondary", "")?;

                debug!(
                    "Resolving fallback references: primary={}, secondary={}",
                    primary, secondary
                );
                debug!(
                    "Available plugins: {:?}",
                    self.plugins.keys().collect::<Vec<_>>()
                );

                let mut children: Vec<Arc<dyn Plugin>> = Vec::new();

                if !primary.is_empty() {
                    if let Some(p) = self.plugins.get(&primary).cloned() {
                        debug!("Found primary plugin: {}", primary);
                        children.push(p);
                    } else {
                        warn!(primary = %primary, "Fallback primary plugin not found");
                    }
                }

                if !secondary.is_empty() {
                    if let Some(p) = self.plugins.get(&secondary).cloned() {
                        debug!("Found secondary plugin: {}", secondary);
                        children.push(p);
                    } else {
                        warn!(secondary = %secondary, "Fallback secondary plugin not found");
                    }
                }

                debug!("Fallback plugin resolved with {} children", children.len());
                let fallback_plugin = Arc::new(FallbackPlugin::new(children));
                let name = config.effective_name().to_string();
                self.plugins.insert(name, fallback_plugin);
            }
        }

        // Second pass: update sequence plugins to reflect resolved plugins
        for config in configs {
            if config.plugin_type == "sequence" {
                if let Value::Sequence(sequence) = &config.args {
                    // Re-parse the steps with the now-resolved plugins
                    match parse_sequence_steps(self, sequence) {
                        Ok(steps) => {
                            let sequence_plugin = Arc::new(SequencePlugin::with_steps(steps));
                            let name = config.effective_name().to_string();
                            self.plugins.insert(name.clone(), sequence_plugin);
                            debug!(
                                "Updated sequence plugin '{}' with resolved references",
                                name
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to update sequence '{}': {}",
                                config.effective_name(),
                                e
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get a plugin by name from the registry
    pub fn get_plugin(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.plugins.get(name).cloned()
    }

    /// Get all plugins
    pub fn get_all_plugins(&self) -> Vec<Arc<dyn Plugin>> {
        self.plugins.values().cloned().collect()
    }

    /// Convert the builder's plugin map into a Registry
    pub fn into_registry(self) -> crate::plugin::Registry {
        let mut registry = crate::plugin::Registry::new();
        for (name, plugin) in self.plugins {
            registry.register_replace_with_name(&name, plugin);
        }
        registry
    }

    /// Get a Registry containing all plugins (clone-based)
    pub fn get_registry(&self) -> crate::plugin::Registry {
        let mut registry = crate::plugin::Registry::new();
        for (name, plugin) in &self.plugins {
            registry.register_replace_with_name(name, Arc::clone(plugin));
        }
        registry
    }

    /// Get server plugin tags
    pub fn get_server_plugin_tags(&self) -> &[String] {
        &self.server_plugin_tags
    }
}

impl Default for ConfigPluginBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// For backward compatibility, create a type alias
pub type PluginConfigBuilder = ConfigPluginBuilder;

// Helper functions for extracting configuration values

fn get_string_arg(args: &HashMap<String, Value>, key: &str, default: &str) -> Result<String> {
    match args.get(key) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(Error::Config(format!(
            "Expected string for '{}', got different type",
            key
        ))),
        None => Ok(default.to_string()),
    }
}

fn get_int_arg(args: &HashMap<String, Value>, key: &str, default: i64) -> Result<i64> {
    match args.get(key) {
        Some(Value::Number(n)) => n
            .as_i64()
            .ok_or_else(|| Error::Config(format!("Invalid integer value for '{}'", key))),
        Some(_) => Err(Error::Config(format!(
            "Expected integer for '{}', got different type",
            key
        ))),
        None => Ok(default),
    }
}

fn get_optional_bool_arg(args: &HashMap<String, Value>, key: &str) -> Option<bool> {
    match args.get(key) {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

fn get_string_array_arg(args: &HashMap<String, Value>, key: &str) -> Result<Vec<String>> {
    match args.get(key) {
        Some(Value::Sequence(seq)) => {
            let mut result = Vec::new();
            for item in seq {
                match item {
                    Value::String(s) => result.push(s.clone()),
                    Value::Mapping(map) => {
                        // Handle upstream format like "- addr: udp://8.8.8.8"
                        if let Some(Value::String(addr)) =
                            map.get(Value::String("addr".to_string()))
                        {
                            result.push(addr.clone());
                        }
                    }
                    _ => {}
                }
            }
            Ok(result)
        }
        Some(_) => Err(Error::Config(format!(
            "Expected array for '{}', got different type",
            key
        ))),
        None => Ok(Vec::new()),
    }
}

fn get_optional_string_array_arg(args: &HashMap<String, Value>, key: &str) -> Option<Vec<String>> {
    get_string_array_arg(args, key).ok()
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{Message, Question};
    use serde_yaml::Mapping;

    #[test]
    fn test_plugin_builder_creation() {
        let builder = ConfigPluginBuilder::new();
        assert_eq!(builder.plugins.len(), 0);
    }

    #[test]
    fn test_build_cache_plugin() {
        let mut builder = ConfigPluginBuilder::new();
        let mut config_map = HashMap::new();
        config_map.insert("size".to_string(), Value::Number(2048.into()));

        let config = PluginConfig {
            tag: Some("my_cache".to_string()),
            plugin_type: "cache".to_string(),
            args: Value::Mapping(Mapping::new()),
            name: Some("my_cache".to_string()),
            priority: 100,
            config: config_map,
        };

        let plugin = builder.build(&config).unwrap();
        assert_eq!(plugin.name(), "cache");
    }

    #[test]
    fn test_build_forward_plugin() {
        let mut builder = ConfigPluginBuilder::new();
        let mut config_map = HashMap::new();

        let upstreams = vec![
            Value::String("udp://8.8.8.8:53".to_string()),
            Value::String("tcp://1.1.1.1:53".to_string()),
        ];
        config_map.insert("upstreams".to_string(), Value::Sequence(upstreams));

        let config = PluginConfig {
            tag: None,
            plugin_type: "forward".to_string(),
            args: Value::Mapping(Mapping::new()),
            name: None,
            priority: 100,
            config: config_map,
        };

        let plugin = builder.build(&config).unwrap();
        assert_eq!(plugin.name(), "forward");
    }

    #[test]
    fn test_build_forward_plugin_with_default_port() {
        let mut builder = ConfigPluginBuilder::new();
        let mut config_map = HashMap::new();

        let upstreams = vec![Value::String("udp://119.29.29.29".to_string())];
        config_map.insert("upstreams".to_string(), Value::Sequence(upstreams));

        let config = PluginConfig {
            tag: None,
            plugin_type: "forward".to_string(),
            args: Value::Mapping(Mapping::new()),
            name: None,
            priority: 100,
            config: config_map,
        };

        let plugin = builder.build(&config).unwrap();
        assert_eq!(plugin.name(), "forward");

        // Downcast to ForwardPlugin to inspect upstreams
        if let Some(fp) = plugin.as_ref().as_any().downcast_ref::<ForwardPlugin>() {
            let addrs = fp.upstream_addrs();
            assert_eq!(addrs.len(), 1);
            assert_eq!(addrs[0], "119.29.29.29:53");
        } else {
            panic!("Failed to downcast plugin to ForwardPlugin");
        }
    }

    #[test]
    fn test_parse_condition_qtype_single_and_multiple() {
        let builder = ConfigPluginBuilder::new();

        // Single type
        let cond = parse_condition(&builder, "qtype 1").unwrap();
        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let ctx = Context::new(req);
        assert!(cond(&ctx));

        // Multiple types
        let cond2 = parse_condition(&builder, "qtype 1 28").unwrap();
        let mut req2 = Message::new();
        req2.add_question(Question::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));
        let ctx2 = Context::new(req2);
        assert!(cond2(&ctx2));
    }

    #[test]
    fn test_parse_condition_qtype_invalid() {
        let builder = ConfigPluginBuilder::new();

        assert!(parse_condition(&builder, "qtype").is_err());
        assert!(parse_condition(&builder, "qtype abc").is_err());
        assert!(parse_condition(&builder, "qtype 1 abc").is_err());
    }

    #[test]
    fn test_build_control_flow_plugins() {
        let mut builder = ConfigPluginBuilder::new();

        // Test accept
        let config = PluginConfig::new("accept".to_string());
        let plugin = builder.build(&config).unwrap();
        assert_eq!(plugin.name(), "accept");

        // Test reject
        let config = PluginConfig::new("reject".to_string());
        let plugin = builder.build(&config).unwrap();
        assert_eq!(plugin.name(), "reject");

        // Test prefer_ipv4
        let config = PluginConfig::new("prefer_ipv4".to_string());
        let plugin = builder.build(&config).unwrap();
        assert_eq!(plugin.name(), "prefer_ipv4");
    }

    #[test]
    fn test_get_string_arg() {
        let mut args = HashMap::new();
        args.insert("key".to_string(), Value::String("value".to_string()));

        assert_eq!(get_string_arg(&args, "key", "default").unwrap(), "value");
        assert_eq!(
            get_string_arg(&args, "missing", "default").unwrap(),
            "default"
        );
    }

    #[test]
    fn test_get_int_arg() {
        let mut args = HashMap::new();
        args.insert("key".to_string(), Value::Number(42.into()));

        assert_eq!(get_int_arg(&args, "key", 0).unwrap(), 42);
        assert_eq!(get_int_arg(&args, "missing", 100).unwrap(), 100);
    }

    #[test]
    fn test_build_udp_server_with_shorthand_listen() {
        let mut builder = ConfigPluginBuilder::new();
        let mut args_map = Mapping::new();
        args_map.insert(
            Value::String("listen".to_string()),
            Value::String(":5353".to_string()),
        );
        args_map.insert(
            Value::String("entry".to_string()),
            Value::String("main_sequence".to_string()),
        );

        let config = PluginConfig {
            tag: Some("udp_server".to_string()),
            plugin_type: "udp_server".to_string(),
            args: Value::Mapping(args_map),
            name: None,
            priority: 100,
            config: HashMap::new(),
        };

        let plugin = builder.build(&config).unwrap();
        assert_eq!(plugin.name(), "udp_server");
    }

    #[test]
    fn test_build_tcp_server_with_shorthand_listen() {
        let mut builder = ConfigPluginBuilder::new();
        let mut args_map = Mapping::new();
        args_map.insert(
            Value::String("listen".to_string()),
            Value::String(":5353".to_string()),
        );
        args_map.insert(
            Value::String("entry".to_string()),
            Value::String("main_sequence".to_string()),
        );

        let config = PluginConfig {
            tag: Some("tcp_server".to_string()),
            plugin_type: "tcp_server".to_string(),
            args: Value::Mapping(args_map),
            name: None,
            priority: 100,
            config: HashMap::new(),
        };

        let plugin = builder.build(&config).unwrap();
        assert_eq!(plugin.name(), "tcp_server");
    }

    #[tokio::test]
    async fn test_build_redirect_from_string_rule_executes() {
        let mut builder = ConfigPluginBuilder::new();
        let mut args_map = Mapping::new();
        args_map.insert(
            Value::String("rules".to_string()),
            Value::Sequence(vec![Value::String("example.com example.net".to_string())]),
        );

        let config = PluginConfig {
            tag: Some("redirect_str".to_string()),
            plugin_type: "redirect".to_string(),
            args: Value::Mapping(args_map),
            name: None,
            priority: 100,
            config: HashMap::new(),
        };

        let plugin = builder.build(&config).expect("build redirect plugin");
        assert_eq!(plugin.name(), "redirect");

        // Execute plugin and verify it rewrites the qname
        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        plugin.execute(&mut ctx).await.expect("execute");

        let got = ctx
            .request()
            .questions()
            .first()
            .unwrap()
            .qname()
            .to_string();
        assert_eq!(got, "example.net");
    }

    #[tokio::test]
    async fn test_build_redirect_from_mapping_rule_executes() {
        let mut builder = ConfigPluginBuilder::new();
        let mut args_map = Mapping::new();

        let mut rule_map = Mapping::new();
        rule_map.insert(
            Value::String("from".to_string()),
            Value::String("foo.example".to_string()),
        );
        rule_map.insert(
            Value::String("to".to_string()),
            Value::String("bar.example".to_string()),
        );

        args_map.insert(
            Value::String("rules".to_string()),
            Value::Sequence(vec![Value::Mapping(rule_map)]),
        );

        let config = PluginConfig {
            tag: Some("redirect_map".to_string()),
            plugin_type: "redirect".to_string(),
            args: Value::Mapping(args_map),
            name: None,
            priority: 100,
            config: HashMap::new(),
        };

        let plugin = builder.build(&config).expect("build redirect plugin");
        assert_eq!(plugin.name(), "redirect");

        // Execute plugin and verify it rewrites the qname
        let mut request = Message::new();
        request.add_question(Question::new(
            "foo.example".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        plugin.execute(&mut ctx).await.expect("execute");

        let got = ctx
            .request()
            .questions()
            .first()
            .unwrap()
            .qname()
            .to_string();
        assert_eq!(got, "bar.example");
    }

    #[test]
    fn test_build_plugin_type_case_insensitive() {
        let mut builder = ConfigPluginBuilder::new();
        let mut args_map = Mapping::new();
        args_map.insert(
            Value::String("rules".to_string()),
            Value::Sequence(vec![Value::String("a b".to_string())]),
        );

        let config = PluginConfig {
            tag: Some("redirect_upper".to_string()),
            plugin_type: "Redirect".to_string(),
            args: Value::Mapping(args_map),
            name: None,
            priority: 100,
            config: HashMap::new(),
        };

        let plugin = builder.build(&config).expect("build redirect plugin");
        assert_eq!(plugin.name(), "redirect");
    }
}

/// Parse complex sequence steps from YAML sequence
fn parse_sequence_steps(
    builder: &ConfigPluginBuilder,
    sequence: &[Value],
) -> Result<Vec<SequenceStep>> {
    use crate::plugins::executable::SequenceStep;
    info!("Parsing {} sequence steps", sequence.len());
    let mut steps = Vec::new();

    for step_value in sequence {
        match step_value {
            Value::Mapping(map) => {
                // Check if it's a conditional step (has "matches" key)
                if let Some(matches_value) = map.get(Value::String("matches".to_string())) {
                    if let Value::String(condition_str) = matches_value {
                        // Parse condition
                        let condition = parse_condition(builder, condition_str)?;

                        // Get the exec action
                        if let Some(exec_value) = map.get(Value::String("exec".to_string())) {
                            let action = parse_exec_action(builder, exec_value)?;
                            steps.push(SequenceStep::If {
                                condition,
                                action,
                                desc: condition_str.to_string(),
                            });
                        } else {
                            return Err(Error::Config("matches step must have exec".to_string()));
                        }
                    } else {
                        return Err(Error::Config("matches value must be string".to_string()));
                    }
                } else if let Some(exec_value) = map.get(Value::String("exec".to_string())) {
                    // Simple exec step
                    let plugin = parse_exec_action(builder, exec_value)?;
                    steps.push(SequenceStep::Exec(plugin));
                } else {
                    return Err(Error::Config(
                        "sequence step must have exec or matches".to_string(),
                    ));
                }
            }
            _ => return Err(Error::Config("sequence step must be a mapping".to_string())),
        }
    }

    Ok(steps)
}

/// Parse exec action from YAML value
fn parse_exec_action(builder: &ConfigPluginBuilder, exec_value: &Value) -> Result<Arc<dyn Plugin>> {
    match exec_value {
        Value::String(exec_str) => {
            // Handle different exec formats
            if let Some(plugin_name) = exec_str.strip_prefix('$') {
                // Plugin reference: $plugin_name
                if let Some(plugin) = builder.get_plugin(plugin_name) {
                    Ok(plugin)
                } else {
                    Err(Error::Config(format!(
                        "Referenced plugin '{}' not found",
                        plugin_name
                    )))
                }
            } else if exec_str == "accept" {
                Ok(Arc::new(crate::plugins::AcceptPlugin::new()))
            } else if exec_str == "drop_resp" {
                Ok(Arc::new(crate::plugins::DropRespPlugin::new()))
            } else if exec_str.starts_with("reject") {
                // reject [rcode] - default to 3 (NXDOMAIN)
                let rcode = if let Some(rest) = exec_str.strip_prefix("reject") {
                    rest.trim().parse::<u8>().unwrap_or(3)
                } else {
                    3
                };
                Ok(Arc::new(crate::plugins::RejectPlugin::new(rcode)))
            } else if let Some(ttl_part) = exec_str.strip_prefix("ttl ") {
                // ttl 300-3600 format - take the first number
                if let Some(first_num) = ttl_part.split('-').next() {
                    if let Ok(ttl) = first_num.parse::<u32>() {
                        Ok(Arc::new(crate::plugins::TtlPlugin::new(ttl, 0, 0)))
                    } else {
                        Err(Error::Config(format!("Invalid TTL value: {}", ttl_part)))
                    }
                } else {
                    Err(Error::Config(format!("Invalid TTL format: {}", exec_str)))
                }
            } else if exec_str.starts_with("black_hole") {
                Ok(Arc::new(
                    crate::plugins::BlackholePlugin::new_from_strs(Vec::<&str>::new()).unwrap(),
                ))
            } else if let Some(target) = exec_str.strip_prefix("jump ") {
                // jump target_name
                let target = target.trim();
                Ok(Arc::new(crate::plugins::JumpPlugin::new(target)))
            } else if exec_str == "prefer_ipv4" {
                Ok(Arc::new(crate::plugins::PreferIpv4Plugin::new()))
            } else if exec_str == "prefer_ipv6" {
                Ok(Arc::new(crate::plugins::PreferIpv6Plugin::new()))
            } else {
                Err(Error::Config(format!("Unknown exec action: {}", exec_str)))
            }
        }
        _ => Err(Error::Config("exec value must be string".to_string())),
    }
}
#[allow(clippy::type_complexity)]
fn parse_condition(
    builder: &ConfigPluginBuilder,
    condition_str: &str,
) -> Result<Arc<dyn Fn(&Context) -> bool + Send + Sync>> {
    // Simple condition parsing - this is a basic implementation
    // In a full implementation, this would need to handle more complex expressions

    if condition_str == "has_resp" {
        Ok(Arc::new(|ctx: &crate::plugin::Context| ctx.has_response()))
    } else if let Some(ip_set_ref) = condition_str.strip_prefix("resp_ip ") {
        let ip_set_name = if let Some(name) = ip_set_ref.strip_prefix('$') {
            name
        } else {
            ip_set_ref
        };
        // Get the IP set plugin and create a matcher
        if let Some(plugin) = builder.get_plugin(ip_set_name) {
            if plugin.name() == "ip_set" {
                let plugin_clone = Arc::clone(&plugin);
                Ok(Arc::new(move |ctx: &crate::plugin::Context| {
                    if let Some(matcher) = plugin_clone
                        .as_ref()
                        .as_any()
                        .downcast_ref::<crate::plugins::data_provider::IpSetPlugin>(
                    ) {
                        matcher.matches_context(ctx)
                    } else {
                        false
                    }
                }))
            } else {
                warn!("Plugin '{}' is not an IP set plugin", ip_set_name);
                Ok(Arc::new(|_ctx: &crate::plugin::Context| false))
            }
        } else {
            warn!("IP set plugin '{}' not found", ip_set_name);
            Ok(Arc::new(|_ctx: &crate::plugin::Context| false))
        }
    } else if let Some(ip_set_ref) = condition_str.strip_prefix("!resp_ip ") {
        let ip_set_name = if let Some(name) = ip_set_ref.strip_prefix('$') {
            name
        } else {
            ip_set_ref
        };
        // Negated IP matching
        if let Some(plugin) = builder.get_plugin(ip_set_name) {
            if plugin.name() == "ip_set" {
                let plugin_clone = Arc::clone(&plugin);
                Ok(Arc::new(move |ctx: &crate::plugin::Context| {
                    if let Some(matcher) = plugin_clone
                        .as_ref()
                        .as_any()
                        .downcast_ref::<crate::plugins::data_provider::IpSetPlugin>(
                    ) {
                        !matcher.matches_context(ctx)
                    } else {
                        true
                    }
                }))
            } else {
                warn!("Plugin '{}' is not an IP set plugin", ip_set_name);
                Ok(Arc::new(|_ctx: &crate::plugin::Context| true))
            }
        } else {
            warn!("IP set plugin '{}' not found", ip_set_name);
            Ok(Arc::new(|_ctx: &crate::plugin::Context| true))
        }
    } else if let Some(domain_set_ref) = condition_str.strip_prefix("qname ") {
        let domain_set_name = if let Some(name) = domain_set_ref.strip_prefix('$') {
            name
        } else {
            domain_set_ref
        };
        // Domain matching
        if let Some(plugin) = builder.get_plugin(domain_set_name) {
            if plugin.name() == "domain_set" {
                let plugin_clone = Arc::clone(&plugin);
                Ok(Arc::new(move |ctx: &crate::plugin::Context| {
                    if let Some(matcher) = plugin_clone
                        .as_ref()
                        .as_any()
                        .downcast_ref::<crate::plugins::data_provider::DomainSetPlugin>(
                    ) {
                        matcher.matches_context(ctx)
                    } else {
                        false
                    }
                }))
            } else {
                warn!("Plugin '{}' is not a domain set plugin", domain_set_name);
                Ok(Arc::new(|_ctx: &crate::plugin::Context| false))
            }
        } else {
            warn!("Domain set plugin '{}' not found", domain_set_name);
            Ok(Arc::new(|_ctx: &crate::plugin::Context| false))
        }
    } else if let Some(domain) = condition_str.strip_prefix("!qname ") {
        // Negated domain matching - for single domain, not domain set
        let domain_lower = domain.to_lowercase();
        Ok(Arc::new(move |ctx: &crate::plugin::Context| {
            if let Some(question) = ctx.request().questions().first() {
                let qname = question.qname().to_string().to_lowercase();
                !qname.eq(&domain_lower)
            } else {
                true
            }
        }))
    } else if condition_str.starts_with("qtype ") {
        // qtype 12 65 - query type matching
        let type_str = condition_str.strip_prefix("qtype ").unwrap_or_default();
        let mut qtypes = Vec::new();

        // Parse space-separated type numbers
        for type_part in type_str.split_whitespace() {
            match type_part.parse::<u16>() {
                Ok(qtype_num) => {
                    qtypes.push(qtype_num);
                }
                Err(_) => {
                    return Err(Error::Config(format!(
                        "Invalid query type number '{}': {}",
                        type_part, condition_str
                    )));
                }
            }
        }

        if qtypes.is_empty() {
            return Err(Error::Config(format!(
                "No query types specified: {}",
                condition_str
            )));
        }

        Ok(Arc::new(move |ctx: &crate::plugin::Context| {
            if let Some(question) = ctx.request().questions().first() {
                let qtype = question.qtype().to_u16();
                qtypes.contains(&qtype)
            } else {
                false
            }
        }))
    } else {
        Err(Error::Config(format!(
            "Unknown condition: {}",
            condition_str
        )))
    }
}

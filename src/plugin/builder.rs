//! Plugin builder system
//!
//! This module provides a builder pattern for creating plugin instances from configuration.
//! It supports both the new Plugin trait pattern and legacy hardcoded plugins.

use crate::config::types::PluginConfig;
use crate::plugin::traits::Matcher;
use crate::plugin::{Context, Plugin};
use crate::plugins::executable::SequenceStep;
use crate::plugins::*;
use crate::Error;
use crate::Result;
use serde_yaml::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

// ============================================================================
// Main Plugin Builder (Configuration-based Plugin Creation)
// ============================================================================

/// Plugin builder that creates plugin instances from configuration
pub struct PluginBuilder {
    /// Registry of named plugins for reference
    plugins: HashMap<String, Arc<dyn Plugin>>,
    /// Server plugin tags
    server_plugin_tags: Vec<String>,
}

impl PluginBuilder {
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

        // Ensure plugin builders from plugin modules are initialized (register themselves)
        crate::plugin::factory::initialize_all_factories();

        // Try to get builder from registry first
        if let Some(builder) = crate::plugin::factory::get_plugin_factory(&plugin_type) {
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

            // Accept doh/dot/doq server plugin types at build time so configuration
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
        // First pass: ask fallback plugins to resolve their pending child references
        for config in configs {
            if config.plugin_type == "fallback" {
                let name = config.effective_name().to_string();
                debug!("Resolving fallback plugin: {}", name);
                if let Some(plugin) = self.plugins.get(&name).cloned() {
                    // Attempt to downcast to FallbackPlugin and let it resolve itself
                    if let Some(fp) = plugin.as_ref().as_any().downcast_ref::<FallbackPlugin>() {
                        fp.resolve_children(&self.plugins);
                    } else {
                        warn!(plugin = %name, "Plugin registered under name is not a FallbackPlugin");
                    }
                } else {
                    warn!(plugin = %name, "Fallback plugin not found in registry");
                }
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

impl Default for PluginBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse complex sequence steps from YAML sequence
fn parse_sequence_steps(builder: &PluginBuilder, sequence: &[Value]) -> Result<Vec<SequenceStep>> {
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
fn parse_exec_action(builder: &PluginBuilder, exec_value: &Value) -> Result<Arc<dyn Plugin>> {
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
    builder: &PluginBuilder,
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
                        .downcast_ref::<crate::plugins::dataset::IpSetPlugin>()
                    {
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
                        .downcast_ref::<crate::plugins::dataset::IpSetPlugin>()
                    {
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
                        .downcast_ref::<crate::plugins::dataset::DomainSetPlugin>(
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

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{Message, Question};
    use serde_yaml::Mapping;

    #[test]
    fn test_plugin_builder_creation() {
        let builder = PluginBuilder::new();
        assert_eq!(builder.plugins.len(), 0);
    }

    #[test]
    fn test_build_cache_plugin() {
        let mut builder = PluginBuilder::new();
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
        let mut builder = PluginBuilder::new();
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
        let mut builder = PluginBuilder::new();
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
        let builder = PluginBuilder::new();

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
        let builder = PluginBuilder::new();

        assert!(parse_condition(&builder, "qtype").is_err());
        assert!(parse_condition(&builder, "qtype abc").is_err());
        assert!(parse_condition(&builder, "qtype 1 abc").is_err());
    }

    #[test]
    fn test_build_control_flow_plugins() {
        let mut builder = PluginBuilder::new();

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
    fn test_build_udp_server_with_shorthand_listen() {
        let mut builder = PluginBuilder::new();
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
    fn test_derived_plugin_type_names() {
        // Ensure the macro-based derivation registers canonical names derived from type names
        crate::plugin::factory::initialize_all_factories();
        let types = crate::plugin::factory::get_all_plugin_types();
        assert!(types.contains(&"drop_resp".to_string()));
        assert!(types.contains(&"forward".to_string()));
        assert!(crate::plugin::factory::get_plugin_factory("drop_resp").is_some());
        assert!(crate::plugin::factory::get_plugin_factory("forward").is_some());
    }

    #[test]
    fn test_derived_plugin_name_mapping() {
        // Local helper that mirrors the macro's derivation algorithm
        fn derive<T: 'static>() -> String {
            let t = std::any::type_name::<T>();
            let last = t.rsplit("::").next().unwrap_or(t);
            let base = last.strip_suffix("Plugin").unwrap_or(last);
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
            s
        }

        assert_eq!(
            derive::<crate::plugins::executable::DropRespPlugin>(),
            "drop_resp"
        );
        assert_eq!(
            derive::<crate::plugins::executable::ForwardPlugin>(),
            "forward"
        );
        assert_eq!(derive::<crate::plugins::AcceptPlugin>(), "accept");
        assert_eq!(
            derive::<crate::plugins::flow::return_plugin::ReturnPlugin>(),
            "return"
        );
        assert_eq!(derive::<crate::plugins::flow::jump::JumpPlugin>(), "jump");
        assert_eq!(
            derive::<crate::plugins::flow::reject::RejectPlugin>(),
            "reject"
        );
        assert_eq!(
            derive::<crate::plugins::flow::prefer_ipv4::PreferIpv4Plugin>(),
            "prefer_ipv4"
        );
        assert_eq!(
            derive::<crate::plugins::flow::prefer_ipv6::PreferIpv6Plugin>(),
            "prefer_ipv6"
        );
        assert_eq!(derive::<crate::plugins::CachePlugin>(), "cache");
        assert_eq!(
            derive::<crate::plugins::dataset::DomainSetPlugin>(),
            "domain_set"
        );
    }

    #[test]
    fn test_no_derived_name_collisions() {
        fn derive<T: 'static>() -> String {
            let t = std::any::type_name::<T>();
            let last = t.rsplit("::").next().unwrap_or(t);
            let base = last.strip_suffix("Plugin").unwrap_or(last);
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
            s
        }

        // A representative set of plugin types to check for accidental collisions
        let derived = vec![
            derive::<crate::plugins::executable::DropRespPlugin>(),
            derive::<crate::plugins::executable::ForwardPlugin>(),
            derive::<crate::plugins::AcceptPlugin>(),
            derive::<crate::plugins::flow::return_plugin::ReturnPlugin>(),
            derive::<crate::plugins::flow::jump::JumpPlugin>(),
            derive::<crate::plugins::flow::reject::RejectPlugin>(),
            derive::<crate::plugins::flow::prefer_ipv4::PreferIpv4Plugin>(),
            derive::<crate::plugins::flow::prefer_ipv6::PreferIpv6Plugin>(),
            derive::<crate::plugins::executable::CachePlugin>(),
            derive::<crate::plugins::dataset::DomainSetPlugin>(),
            derive::<crate::plugins::geoip::GeoIpPlugin>(),
            derive::<crate::plugins::geosite::GeoSitePlugin>(),
            derive::<crate::plugins::executable::HostsPlugin>(),
        ];

        let set: std::collections::HashSet<_> = derived.iter().cloned().collect();
        assert_eq!(
            set.len(),
            derived.len(),
            "Derived plugin names collided: {:?}",
            {
                // Build a list of duplicates for better diagnostics
                let mut counts = std::collections::HashMap::new();
                for name in &derived {
                    *counts.entry(name.clone()).or_insert(0usize) += 1;
                }
                counts
                    .into_iter()
                    .filter_map(|(k, v)| if v > 1 { Some(k) } else { None })
                    .collect::<Vec<_>>()
            }
        );
    }

    #[test]
    fn test_build_tcp_server_with_shorthand_listen() {
        let mut builder = PluginBuilder::new();
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
        let mut builder = PluginBuilder::new();
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
        let mut builder = PluginBuilder::new();
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
        let mut builder = PluginBuilder::new();
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

    #[test]
    fn test_fallback_resolves_children() {
        let mut builder = PluginBuilder::new();

        // Build primary and secondary helper plugins (use 'accept' as a benign plugin type)
        let primary_cfg = PluginConfig {
            tag: None,
            plugin_type: "accept".to_string(),
            args: Value::Mapping(Mapping::new()),
            name: Some("primary".to_string()),
            priority: 100,
            config: HashMap::new(),
        };
        let secondary_cfg = PluginConfig {
            tag: None,
            plugin_type: "accept".to_string(),
            args: Value::Mapping(Mapping::new()),
            name: Some("secondary".to_string()),
            priority: 100,
            config: HashMap::new(),
        };
        builder.build(&primary_cfg).unwrap();
        builder.build(&secondary_cfg).unwrap();

        // Create fallback config referencing the above by name
        let mut args_map = Mapping::new();
        args_map.insert(
            Value::String("primary".to_string()),
            Value::String("primary".to_string()),
        );
        args_map.insert(
            Value::String("secondary".to_string()),
            Value::String("secondary".to_string()),
        );

        let fb_cfg = PluginConfig {
            tag: None,
            plugin_type: "fallback".to_string(),
            args: Value::Mapping(args_map),
            name: Some("my_fallback".to_string()),
            priority: 100,
            config: HashMap::new(),
        };

        builder.build(&fb_cfg).unwrap();

        // Resolve references
        builder
            .resolve_references(&[primary_cfg, secondary_cfg, fb_cfg])
            .unwrap();

        // Verify fallback has resolved children
        let plugin = builder
            .get_plugin("my_fallback")
            .expect("fallback plugin present");
        if let Some(fp) = plugin
            .as_ref()
            .as_any()
            .downcast_ref::<crate::plugins::executable::FallbackPlugin>()
        {
            assert_eq!(fp.resolved_child_count(), 2);
            assert_eq!(fp.pending_child_count(), 0);
        } else {
            panic!("fallback plugin is wrong type");
        }
    }
}

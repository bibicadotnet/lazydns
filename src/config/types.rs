//! Configuration type definitions
//!
//! Common types used across configuration modules.

use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Listener configuration
///
/// Defines a network listener for the DNS server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenerConfig {
    /// Protocol (udp or tcp)
    pub protocol: String,

    /// Listen address
    pub addr: SocketAddr,
}

impl ListenerConfig {
    /// Create a new listener configuration
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::config::types::ListenerConfig;
    /// use std::net::SocketAddr;
    ///
    /// let addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
    /// let config = ListenerConfig::new("udp".to_string(), addr);
    /// assert_eq!(config.protocol, "udp");
    /// ```
    pub fn new(protocol: String, addr: SocketAddr) -> Self {
        Self { protocol, addr }
    }

    /// Create a UDP listener configuration
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::config::types::ListenerConfig;
    /// use std::net::SocketAddr;
    ///
    /// let addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
    /// let config = ListenerConfig::udp(addr);
    /// assert_eq!(config.protocol, "udp");
    /// ```
    pub fn udp(addr: SocketAddr) -> Self {
        Self::new("udp".to_string(), addr)
    }

    /// Create a TCP listener configuration
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::config::types::ListenerConfig;
    /// use std::net::SocketAddr;
    ///
    /// let addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
    /// let config = ListenerConfig::tcp(addr);
    /// assert_eq!(config.protocol, "tcp");
    /// ```
    pub fn tcp(addr: SocketAddr) -> Self {
        Self::new("tcp".to_string(), addr)
    }
}

/// Plugin configuration
///
/// Defines a plugin instance with its settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Plugin tag/name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Plugin type
    #[serde(rename = "type", alias = "plugin_type")]
    pub plugin_type: String,

    /// Plugin-specific arguments/configuration
    #[serde(default)]
    pub args: serde_yaml::Value,

    /// Plugin priority (lower executes first)
    #[serde(
        default = "default_priority",
        skip_serializing_if = "is_default_priority"
    )]
    pub priority: i32,

    /// Plugin-specific configuration (legacy, use args instead)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub config: HashMap<String, serde_yaml::Value>,
}

fn default_priority() -> i32 {
    100
}

fn is_default_priority(priority: &i32) -> bool {
    *priority == 100
}

impl PluginConfig {
    /// Create a new plugin configuration
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::config::types::PluginConfig;
    ///
    /// let config = PluginConfig::new("forward".to_string());
    /// assert_eq!(config.plugin_type, "forward");
    /// assert_eq!(config.priority, 100);
    /// ```
    pub fn new(plugin_type: String) -> Self {
        Self {
            tag: None,
            plugin_type,
            args: Value::Mapping(Mapping::new()),
            priority: default_priority(),
            config: HashMap::new(),
        }
    }

    /// Set the plugin tag
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::config::types::PluginConfig;
    ///
    /// let config = PluginConfig::new("forward".to_string())
    ///     .with_tag("my_forward".to_string());
    /// assert_eq!(config.effective_name(), "my_forward");
    /// ```
    pub fn with_tag(mut self, tag: String) -> Self {
        self.tag = Some(tag);
        self
    }

    /// Set the plugin priority
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::config::types::PluginConfig;
    ///
    /// let config = PluginConfig::new("forward".to_string())
    ///     .with_priority(50);
    /// assert_eq!(config.priority, 50);
    /// ```
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Add an argument value
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::config::types::PluginConfig;
    ///
    /// let config = PluginConfig::new("forward".to_string())
    ///     .with_arg("key".to_string(), serde_yaml::Value::String("value".to_string()));
    /// assert!(config.effective_args().contains_key("key"));
    /// ```
    pub fn with_arg(mut self, key: String, value: Value) -> Self {
        if let Value::Mapping(ref mut map) = self.args {
            map.insert(Value::String(key), value);
        } else {
            // If args is not a mapping, replace it with a mapping
            let mut map = Mapping::new();
            map.insert(Value::String(key), value);
            self.args = Value::Mapping(map);
        }
        self
    }

    /// Add a configuration value (legacy method, use with_arg instead)
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::config::types::PluginConfig;
    ///
    /// let config = PluginConfig::new("forward".to_string())
    ///     .with_config("key".to_string(), serde_yaml::Value::String("value".to_string()));
    /// assert!(config.config.contains_key("key"));
    /// ```
    pub fn with_config(mut self, key: String, value: serde_yaml::Value) -> Self {
        self.config.insert(key, value);
        self
    }

    /// Get the effective name (tag, name, or plugin_type in that order)
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::config::types::PluginConfig;
    ///
    /// let config1 = PluginConfig::new("forward".to_string());
    /// assert_eq!(config1.effective_name(), "forward");
    ///
    /// let config2 = PluginConfig::new("forward".to_string())
    ///     .with_tag("my_forward".to_string());
    /// assert_eq!(config2.effective_name(), "my_forward");
    /// ```
    pub fn effective_name(&self) -> &str {
        self.tag.as_deref().unwrap_or(&self.plugin_type)
    }

    /// Get the effective args (merges args and config for backward compatibility)
    pub fn effective_args(&self) -> HashMap<String, Value> {
        let mut result = self.config.clone();

        // If args is a mapping, extend with it
        if let Value::Mapping(map) = &self.args {
            for (k, v) in map {
                if let Value::String(key) = k {
                    result.insert(key.clone(), v.clone());
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_listener_config() {
        let addr = SocketAddr::from_str("127.0.0.1:53").unwrap();
        let config = ListenerConfig::udp(addr);

        assert_eq!(config.protocol, "udp");
        assert_eq!(config.addr, addr);
    }

    #[test]
    fn test_listener_tcp() {
        let addr = SocketAddr::from_str("127.0.0.1:53").unwrap();
        let config = ListenerConfig::tcp(addr);

        assert_eq!(config.protocol, "tcp");
    }

    #[test]
    fn test_plugin_config_creation() {
        let config = PluginConfig::new("forward".to_string());

        assert_eq!(config.plugin_type, "forward");
        assert_eq!(config.priority, 100);
    }

    #[test]
    fn test_plugin_config_builder() {
        let config = PluginConfig::new("forward".to_string())
            .with_tag("my_forward".to_string())
            .with_priority(50);

        assert_eq!(config.effective_name(), "my_forward");
        assert_eq!(config.priority, 50);
    }

    #[test]
    fn test_plugin_effective_name() {
        let config1 = PluginConfig::new("forward".to_string()).with_tag("forward".to_string());
        assert_eq!(config1.effective_name(), "forward");

        let config2 = PluginConfig::new("forward".to_string()).with_tag("my_forward".to_string());
        assert_eq!(config2.effective_name(), "my_forward");
    }

    #[test]
    fn test_plugin_config_with_values() {
        let config = PluginConfig::new("forward".to_string()).with_config(
            "upstream".to_string(),
            serde_yaml::Value::String("8.8.8.8".to_string()),
        );

        assert!(config.config.contains_key("upstream"));
    }
}

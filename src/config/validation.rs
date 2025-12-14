//! Configuration validation
//!
//! Validates configuration values for correctness and consistency.

use crate::config::Config;
use crate::{Error, Result};

/// Validate a configuration
///
/// Checks that all configuration values are valid and consistent.
///
/// # Arguments
///
/// * `config` - The configuration to validate
///
/// # Errors
///
/// Returns an error if validation fails.
pub fn validate_config(config: &Config) -> Result<()> {
    // Validate log level
    validate_log_level(&config.log_level)?;

    // Validate server configuration
    validate_server(&config.server)?;

    // Validate plugins
    validate_plugins(&config.plugins)?;

    Ok(())
}

/// Validate log level
fn validate_log_level(level: &str) -> Result<()> {
    let valid_levels = ["trace", "debug", "info", "warn", "error"];

    if !valid_levels.contains(&level) {
        return Err(Error::Config(format!(
            "Invalid log level '{}'. Must be one of: {}",
            level,
            valid_levels.join(", ")
        )));
    }

    Ok(())
}

/// Validate server configuration
fn validate_server(server: &crate::config::ServerConfig) -> Result<()> {
    // Check that we have at least one listener
    if server.listen_addrs.is_empty() {
        return Err(Error::Config(
            "Server must have at least one listener".to_string(),
        ));
    }

    // Validate listener protocols
    for listener in &server.listen_addrs {
        if listener.protocol != "udp" && listener.protocol != "tcp" {
            return Err(Error::Config(format!(
                "Invalid listener protocol '{}'. Must be 'udp' or 'tcp'",
                listener.protocol
            )));
        }
    }

    // Validate timeout
    if server.timeout_secs == 0 {
        return Err(Error::Config("Timeout must be greater than 0".to_string()));
    }

    // Validate max connections
    if server.max_connections == 0 {
        return Err(Error::Config(
            "Max connections must be greater than 0".to_string(),
        ));
    }

    // Validate packet sizes
    if server.max_udp_size == 0 {
        return Err(Error::Config(
            "Max UDP size must be greater than 0".to_string(),
        ));
    }

    if server.max_tcp_size == 0 {
        return Err(Error::Config(
            "Max TCP size must be greater than 0".to_string(),
        ));
    }

    Ok(())
}

/// Validate plugins
fn validate_plugins(plugins: &[crate::config::PluginConfig]) -> Result<()> {
    // Check for duplicate plugin names
    let mut names = std::collections::HashSet::new();

    for plugin in plugins {
        let name = plugin.effective_name();

        if !names.insert(name) {
            return Err(Error::Config(format!("Duplicate plugin name: '{}'", name)));
        }
    }

    // Validate plugin types are not empty
    for plugin in plugins {
        if plugin.plugin_type.is_empty() {
            return Err(Error::Config("Plugin type cannot be empty".to_string()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ListenerConfig, PluginConfig, ServerConfig};

    #[test]
    fn test_validate_valid_config() {
        let config = Config::new();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_log_level_valid() {
        assert!(validate_log_level("info").is_ok());
        assert!(validate_log_level("debug").is_ok());
        assert!(validate_log_level("trace").is_ok());
        assert!(validate_log_level("warn").is_ok());
        assert!(validate_log_level("error").is_ok());
    }

    #[test]
    fn test_validate_log_level_invalid() {
        let result = validate_log_level("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_server_no_listeners() {
        let mut server = ServerConfig::default();
        server.listen_addrs.clear();

        let result = validate_server(&server);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_server_invalid_protocol() {
        let mut server = ServerConfig::default();
        server.listen_addrs.clear();
        server.listen_addrs.push(ListenerConfig {
            protocol: "http".to_string(),
            addr: "127.0.0.1:5353".parse().unwrap(),
        });

        let result = validate_server(&server);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_server_zero_timeout() {
        let server = ServerConfig {
            timeout_secs: 0,
            ..Default::default()
        };

        let result = validate_server(&server);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_server_zero_max_connections() {
        let server = ServerConfig {
            max_connections: 0,
            ..Default::default()
        };

        let result = validate_server(&server);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_plugins_duplicate_names() {
        let plugins = vec![
            PluginConfig::new("forward".to_string()).with_name("test".to_string()),
            PluginConfig::new("cache".to_string()).with_name("test".to_string()),
        ];

        let result = validate_plugins(&plugins);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_plugins_empty_type() {
        let plugins = vec![PluginConfig::new("".to_string())];

        let result = validate_plugins(&plugins);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_plugins_valid() {
        let plugins = vec![
            PluginConfig::new("forward".to_string()),
            PluginConfig::new("cache".to_string()),
        ];

        let result = validate_plugins(&plugins);
        assert!(result.is_ok());
    }
}

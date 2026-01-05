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
    // Validate logging configuration
    validate_log_level(&config.log.level)?;
    validate_log_format(&config.log.format)?;
    validate_log_rotation(&config.log.rotate)?;

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

fn validate_log_format(format: &str) -> Result<()> {
    let valid = ["text", "json"];
    if !valid.contains(&format) {
        return Err(Error::Config(format!(
            "Invalid log format '{}'. Must be one of: {}",
            format,
            valid.join(", ")
        )));
    }
    Ok(())
}

fn validate_log_rotation(rot: &str) -> Result<()> {
    let valid = ["never", "daily", "hourly"];
    if !valid.contains(&rot) {
        return Err(Error::Config(format!(
            "Invalid rotate '{}'. Must be one of: {}",
            rot,
            valid.join(", ")
        )));
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
    use crate::config::PluginConfig;

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
    fn test_validate_log_rotation() {
        assert!(validate_log_rotation("never").is_ok());
        assert!(validate_log_rotation("daily").is_ok());
        assert!(validate_log_rotation("hourly").is_ok());

        let result = validate_log_rotation("weekly");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_plugins_duplicate_names() {
        // Duplicate names should fail: two forward plugins is a duplicate
        let plugins = vec![
            PluginConfig::new("forward".to_string()),
            PluginConfig::new("forward".to_string()),
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

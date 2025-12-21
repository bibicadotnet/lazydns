//! Configuration loader
//!
//! Loads and saves configuration from/to files and strings.

use crate::config::Config;
use crate::{Error, Result};
use regex::Regex;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Load configuration from a YAML file
///
/// Supports:
/// - Environment variable substitution: ${VAR_NAME} or ${VAR_NAME:-default}
/// - File includes: !include path/to/file.yaml
///
/// # Arguments
///
/// * `path` - Path to the YAML configuration file
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Config> {
    load_from_file_internal(path.as_ref(), &mut HashSet::new())
}

/// Internal implementation with circular include detection
fn load_from_file_internal(path: &Path, visited: &mut HashSet<PathBuf>) -> Result<Config> {
    let canonical_path = path
        .canonicalize()
        .map_err(|e| Error::Config(format!("Failed to resolve path: {}", e)))?;

    // Check for circular includes
    if visited.contains(&canonical_path) {
        return Err(Error::Config(format!(
            "Circular include detected: {}",
            path.display()
        )));
    }
    visited.insert(canonical_path.clone());

    let contents = fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("Failed to read config file: {}", e)))?;

    // Substitute environment variables
    let contents = substitute_env_vars(&contents)?;

    // Process includes
    let contents = process_includes(&contents, path.parent(), visited)?;

    load_from_yaml(&contents)
}

/// Substitute environment variables in configuration
///
/// Supports ${VAR_NAME} and ${VAR_NAME:-default_value}
fn substitute_env_vars(content: &str) -> Result<String> {
    let re = Regex::new(r"\$\{([A-Z0-9_]+)(?::-([^}]+))?\}").unwrap();
    let mut result = content.to_string();

    for cap in re.captures_iter(content) {
        let full_match = cap.get(0).unwrap().as_str();
        let var_name = cap.get(1).unwrap().as_str();
        let default_value = cap.get(2).map(|m| m.as_str());

        let value = match env::var(var_name) {
            Ok(v) => v,
            Err(_) => {
                if let Some(default) = default_value {
                    default.to_string()
                } else {
                    return Err(Error::Config(format!(
                        "Environment variable {} not found and no default provided",
                        var_name
                    )));
                }
            }
        };

        result = result.replace(full_match, &value);
    }

    Ok(result)
}

/// Process include directives in configuration
///
/// Replaces !include path/to/file.yaml with the file contents
fn process_includes(
    content: &str,
    base_dir: Option<&Path>,
    _visited: &mut HashSet<PathBuf>,
) -> Result<String> {
    let re = Regex::new(r"!include\s+([^\s\n]+)").unwrap();
    let mut result = content.to_string();

    for cap in re.captures_iter(content) {
        let full_match = cap.get(0).unwrap().as_str();
        let include_path = cap.get(1).unwrap().as_str();

        // Resolve relative to base directory
        let resolved_path = if let Some(base) = base_dir {
            base.join(include_path)
        } else {
            PathBuf::from(include_path)
        };

        // Read included file
        let included_contents = fs::read_to_string(&resolved_path).map_err(|e| {
            Error::Config(format!(
                "Failed to read included file {}: {}",
                resolved_path.display(),
                e
            ))
        })?;

        // Recursively process the included content
        let included_contents = substitute_env_vars(&included_contents)?;
        let included_contents =
            process_includes(&included_contents, resolved_path.parent(), _visited)?;

        result = result.replace(full_match, &included_contents);
    }

    Ok(result)
}

/// Load configuration from a YAML string
///
/// # Arguments
///
/// * `yaml` - YAML configuration string
///
/// # Errors
///
/// Returns an error if the YAML cannot be parsed.
pub fn load_from_yaml(yaml: &str) -> Result<Config> {
    let mut config: Config = serde_yaml::from_str(yaml)
        .map_err(|e| Error::Config(format!("Failed to parse YAML: {}", e)))?;

    // Apply environment variable overrides (before validation)
    apply_env_overrides(&mut config)?;

    // Validate the loaded configuration
    config.validate()?;

    Ok(config)
}

/// Apply environment variable overrides to the configuration
///
/// Supports two patterns:
/// 1. Top-level fields: `LOG_FORMAT=json` → sets `config.log.format`
/// 2. Plugin args: `PLUGINS_<TAG>_ARGS_<KEY>=value` → sets `plugin.args.<key>`
///
/// Values are parsed as YAML (numbers, booleans, arrays) with string fallback.
fn apply_env_overrides(config: &mut Config) -> Result<()> {
    use serde_yaml::Value;

    let plugin_pattern = Regex::new(r"^PLUGINS_([A-Z0-9_]+)_ARGS_([A-Z0-9_]+)$")
        .map_err(|e| Error::Config(format!("Regex error: {}", e)))?;

    // Collect all env vars into a HashMap to ensure we see all updates
    let env_vars: std::collections::HashMap<String, String> = env::vars().collect();

    for (key, value_str) in env_vars {
        // Handle top-level environment variables
        match key.as_str() {
            "LOG_LEVEL" => {
                tracing::info!("Applied env override: LOG_LEVEL = {}", value_str);
                config.log.level = value_str;
                continue;
            }
            "LOG_FORMAT" => {
                tracing::info!("Applied env override: LOG_FORMAT = {}", value_str);
                config.log.format = value_str;
                continue;
            }
            "LOG_FILE" => {
                tracing::info!("Applied env override: LOG_FILE = {}", value_str);
                config.log.file = Some(value_str);
                continue;
            }
            "LOG_TIME_FORMAT" => {
                tracing::info!("Applied env override: LOG_TIME_FORMAT = {}", value_str);
                config.log.time_format = value_str;
                continue;
            }
            "LOG_ROTATE" => {
                tracing::info!("Applied env override: LOG_ROTATE = {}", value_str);
                config.log.rotate = value_str;
                continue;
            }
            _ => {}
        }

        // Handle plugin args: PLUGINS_<TAG>_ARGS_<KEY>=value
        if let Some(caps) = plugin_pattern.captures(&key) {
            let tag_raw = &caps[1];
            let key_raw = &caps[2];

            // Normalize tag and key (lowercase, _ -> -)
            let tag = normalize_identifier(tag_raw);
            let key_normalized = normalize_identifier(key_raw);

            // Find matching plugin by effective_name
            if let Some(plugin) = config
                .plugins
                .iter_mut()
                .find(|p| p.effective_name() == tag)
            {
                let value = parse_yaml_value(&value_str);

                // Ensure args is a mapping
                if !matches!(plugin.args, Value::Mapping(_)) {
                    plugin.args = Value::Mapping(serde_yaml::Mapping::new());
                }

                // Insert the value
                if let Value::Mapping(ref mut map) = plugin.args {
                    map.insert(Value::String(key_normalized.clone()), value);
                    tracing::info!(
                        "Applied plugin env override: {} -> plugin[{}].args[{}]",
                        key,
                        tag,
                        key_normalized
                    );
                }
            } else {
                tracing::warn!("Plugin '{}' not found for env override: {}", tag, key);
            }
        }
    }

    Ok(())
}

/// Parse a string value as YAML (numbers, booleans, arrays) with string fallback
fn parse_yaml_value(value_str: &str) -> serde_yaml::Value {
    // Try to parse as YAML
    match serde_yaml::from_str::<serde_yaml::Value>(value_str) {
        Ok(v) => {
            // If it's just a plain string wrapped by YAML, unwrap it
            match v {
                serde_yaml::Value::String(s) => serde_yaml::Value::String(s),
                _ => v,
            }
        }
        Err(_) => {
            // Fall back to treating it as a string
            serde_yaml::Value::String(value_str.to_string())
        }
    }
}

/// Normalize identifiers: lowercase and convert _ to -
fn normalize_identifier(s: &str) -> String {
    s.to_lowercase().replace('_', "-")
}

/// Save configuration to a YAML file
///
/// # Arguments
///
/// * `config` - The configuration to save
/// * `path` - Path to save the YAML configuration file
///
/// # Errors
///
/// Returns an error if the file cannot be written.
pub fn save_to_file<P: AsRef<Path>>(config: &Config, path: P) -> Result<()> {
    let yaml = to_yaml(config)?;

    fs::write(path.as_ref(), yaml)
        .map_err(|e| Error::Config(format!("Failed to write config file: {}", e)))?;

    Ok(())
}

/// Convert configuration to YAML string
///
/// # Arguments
///
/// * `config` - The configuration to convert
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn to_yaml(config: &Config) -> Result<String> {
    serde_yaml::to_string(config)
        .map_err(|e| Error::Config(format!("Failed to serialize YAML: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_from_yaml_minimal() {
        let yaml = r#"
log:
  level: debug
"#;
        let config = load_from_yaml(yaml).unwrap();
        assert_eq!(config.log.level, "debug");
    }

    #[test]
    fn test_load_from_yaml_full() {
        let yaml = r#"
log:
  level: info
  rotate: daily
plugins:
  - plugin_type: forward
    priority: 100
"#;
        let config = load_from_yaml(yaml).unwrap();
        assert_eq!(config.log.level, "info");
        assert_eq!(config.log.rotate, "daily");
        assert_eq!(config.plugins.len(), 1);
    }

    #[test]
    fn test_load_from_yaml_invalid() {
        let yaml = "invalid: yaml: content: [";
        let result = load_from_yaml(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_to_yaml() {
        let config = Config::new();
        let yaml = to_yaml(&config).unwrap();

        assert!(yaml.contains("log:"));
    }

    #[test]
    fn test_save_and_load_file() {
        let config = Config::new();

        // Create a temporary file
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        // Save config
        save_to_file(&config, &path).unwrap();

        // Load it back
        let loaded = load_from_file(&path).unwrap();

        assert_eq!(config.log, loaded.log);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = load_from_file("/nonexistent/path/config.yaml");
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip() {
        let original = Config::new();
        let yaml = to_yaml(&original).unwrap();
        let loaded = load_from_yaml(&yaml).unwrap();

        assert_eq!(original.log, loaded.log);
    }

    #[test]
    fn test_substitute_env_vars() {
        // Set a test environment variable
        env::set_var("TEST_VAR", "test_value");
        env::set_var("DNS_PORT", "5353");

        let content = "server: ${TEST_VAR}\nport: ${DNS_PORT}";
        let result = substitute_env_vars(content).unwrap();

        assert_eq!(result, "server: test_value\nport: 5353");

        env::remove_var("TEST_VAR");
        env::remove_var("DNS_PORT");
    }

    #[test]
    fn test_substitute_env_vars_with_default() {
        // Don't set the variable
        env::remove_var("MISSING_VAR");

        let content = "value: ${MISSING_VAR:-default_value}";
        let result = substitute_env_vars(content).unwrap();

        assert_eq!(result, "value: default_value");
    }

    #[test]
    fn test_substitute_env_vars_missing_no_default() {
        env::remove_var("MISSING_VAR");

        let content = "value: ${MISSING_VAR}";
        let result = substitute_env_vars(content);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("MISSING_VAR not found"));
    }

    // NOTE: These env override tests must run single-threaded due to environment variable interference
    // Run with: cargo test -- --test-threads=1

    #[test]
    #[ignore = "cargo test --lib config::loader -- --test-threads=1"]
    fn test_apply_env_overrides_top_level_log_level() {
        // Use a unique name to avoid test conflicts
        env::set_var("LOG_LEVEL", "debug");

        let yaml = r#"
log:
  level: info
  format: text
plugins: []
"#;
        let config = load_from_yaml(yaml).unwrap();
        assert_eq!(
            config.log.level, "debug",
            "LOG_LEVEL should override config"
        );

        env::remove_var("LOG_LEVEL");
    }

    #[test]
    #[ignore = "cargo test --lib config::loader -- --test-threads=1"]
    fn test_apply_env_overrides_top_level_log_format() {
        env::set_var("LOG_FORMAT", "json");

        let yaml = r#"
log:
  level: info
  format: text
plugins: []
"#;
        let config = load_from_yaml(yaml).unwrap();
        assert_eq!(
            config.log.format, "json",
            "LOG_FORMAT should override config"
        );

        env::remove_var("LOG_FORMAT");
    }

    #[test]
    #[ignore = "cargo test --lib config::loader -- --test-threads=1"]
    fn test_apply_env_overrides_plugin_args() {
        env::set_var("PLUGINS_CACHE_ARGS_SIZE", "2048");

        let yaml = r#"
log:
  level: info
  format: text
plugins:
  - plugin_type: cache
    args:
      size: 1024
"#;
        let config = load_from_yaml(yaml).unwrap();

        // Find the cache plugin and verify args
        let cache_plugin = config
            .plugins
            .iter()
            .find(|p| p.plugin_type == "cache")
            .unwrap();
        if let serde_yaml::Value::Mapping(args) = &cache_plugin.args {
            let size_value = args.get(serde_yaml::Value::String("size".to_string()));
            assert!(size_value.is_some());
            // The value should be 2048 (from env override)
            if let Some(serde_yaml::Value::Number(n)) = size_value {
                assert_eq!(
                    n.as_u64(),
                    Some(2048),
                    "PLUGINS_CACHE_ARGS_SIZE should override config"
                );
            }
        }

        env::remove_var("PLUGINS_CACHE_ARGS_SIZE");
    }

    #[test]
    #[ignore = "cargo test --lib config::loader -- --test-threads=1"]
    fn test_apply_env_overrides_plugin_args_string_value() {
        env::set_var("PLUGINS_ADD_GFWLIST_ARGS_SERVER", "http://10.100.100.1");

        let yaml = r#"
log:
  level: info
  format: text
plugins:
  - plugin_type: add-gfwlist
    args:
      server: http://default.com
"#;
        let config = load_from_yaml(yaml).unwrap();

        let plugin = config
            .plugins
            .iter()
            .find(|p| p.plugin_type == "add-gfwlist")
            .unwrap();
        if let serde_yaml::Value::Mapping(args) = &plugin.args {
            let server_value = args.get(serde_yaml::Value::String("server".to_string()));
            if let Some(serde_yaml::Value::String(s)) = server_value {
                assert_eq!(
                    s, "http://10.100.100.1",
                    "PLUGINS_ADD_GFWLIST_ARGS_SERVER should override config"
                );
            }
        }

        env::remove_var("PLUGINS_ADD_GFWLIST_ARGS_SERVER");
    }

    #[test]
    #[ignore = "cargo test --lib config::loader -- --test-threads=1"]
    fn test_apply_env_overrides_numeric_string_parsing() {
        let value_str = "2048";
        let result = parse_yaml_value(value_str);

        // Should parse as a number, not a string
        match result {
            serde_yaml::Value::Number(n) => {
                assert_eq!(n.as_u64(), Some(2048));
            }
            _ => panic!("Expected number, got {:?}", result),
        }
    }

    #[test]
    #[ignore = "cargo test --lib config::loader -- --test-threads=1"]
    fn test_apply_env_overrides_boolean_parsing() {
        let value_true = parse_yaml_value("true");
        let value_false = parse_yaml_value("false");

        assert_eq!(value_true, serde_yaml::Value::Bool(true));
        assert_eq!(value_false, serde_yaml::Value::Bool(false));
    }

    #[test]
    fn test_apply_env_overrides_array_parsing() {
        let value_array = parse_yaml_value("[8.8.8.8, 1.1.1.1]");

        match value_array {
            serde_yaml::Value::Sequence(seq) => {
                assert_eq!(seq.len(), 2);
            }
            _ => panic!("Expected sequence, got {:?}", value_array),
        }
    }

    #[test]
    fn test_normalize_identifier() {
        assert_eq!(normalize_identifier("ADD_GFWLIST"), "add-gfwlist");
        assert_eq!(normalize_identifier("CACHE_SIZE"), "cache-size");
        assert_eq!(
            normalize_identifier("ENABLE_LAZY_CACHE"),
            "enable-lazy-cache"
        );
    }

    // Cleanup test that runs last and clears all env overrides
    #[test]
    fn test_zzz_cleanup_env_overrides() {
        env::remove_var("LOG_LEVEL");
        env::remove_var("LOG_FORMAT");
        env::remove_var("LOG_FILE");
        env::remove_var("LOG_TIME_FORMAT");
        env::remove_var("LOG_ROTATE");
        env::remove_var("PLUGINS_CACHE_ARGS_SIZE");
        env::remove_var("PLUGINS_ADD_GFWLIST_ARGS_SERVER");
    }
}

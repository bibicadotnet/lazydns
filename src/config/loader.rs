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
    let config: Config = serde_yaml::from_str(yaml)
        .map_err(|e| Error::Config(format!("Failed to parse YAML: {}", e)))?;

    // Validate the loaded configuration
    config.validate()?;

    Ok(config)
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
server:
  timeout_secs: 10
  max_connections: 500
plugins:
  - plugin_type: forward
    priority: 100
"#;
        let config = load_from_yaml(yaml).unwrap();
        assert_eq!(config.log.level, "info");
        assert_eq!(config.log.rotate, "daily");
        assert_eq!(config.server.timeout_secs, 10);
        assert_eq!(config.server.max_connections, 500);
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
        assert!(yaml.contains("server"));
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
        assert_eq!(original.server.timeout_secs, loaded.server.timeout_secs);
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
}

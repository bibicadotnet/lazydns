//! Configuration module
//!
//! This module provides configuration loading and validation for lazydns.
//! It supports YAML configuration files with comprehensive validation.
//!
//! # Example
//!
//! ```rust,no_run
//! use lazydns::config::Config;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::from_file("config.yaml")?;
//! println!("Configured plugins: {:?}", config.plugins);
//! # Ok(())
//! # }
//! ```

pub mod loader;
pub mod reload;
pub mod types;
pub mod validation;

use crate::Result;
use crate::log::RotationTrigger;
use serde::{Deserialize, Serialize};
use std::path::Path;

// Re-export commonly used types
pub use reload::ConfigReloader;
pub use types::PluginConfig;

/// File logging configuration with rotation support.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileLogConfig {
    /// Whether file logging is enabled (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// Path to the log file.
    #[serde(default = "default_file_path")]
    pub path: String,

    /// Rotation configuration.
    #[serde(default)]
    pub rotation: RotationTrigger,

    /// Whether to compress rotated files (reserved for future use).
    #[serde(default)]
    pub compress: bool,
}

fn default_file_path() -> String {
    "lazydns.log".to_string()
}

impl Default for FileLogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_file_path(),
            rotation: RotationTrigger::default(),
            compress: false,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogConfig {
    /// Log level: trace|debug|info|warn|error
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Whether to output logs to console/stdout (default: false).
    #[serde(default = "default_console")]
    pub console: bool,

    /// Log output format: text|json
    #[serde(default = "default_log_format")]
    pub format: String,

    /// File logging configuration.
    #[serde(default)]
    pub file: Option<FileLogConfig>,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_console() -> bool {
    false
}

fn default_log_format() -> String {
    "text".to_string()
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            console: default_console(),
            format: default_log_format(),
            file: None,
        }
    }
}

/// Admin API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    /// Enable admin API
    #[serde(default = "default_admin_enabled")]
    pub enabled: bool,

    /// Listen address for admin API (e.g., "127.0.0.1:8080")
    #[serde(default = "default_admin_addr")]
    pub addr: String,
}

fn default_admin_enabled() -> bool {
    false
}

fn default_admin_addr() -> String {
    "127.0.0.1:8080".to_string()
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: default_admin_enabled(),
            addr: default_admin_addr(),
        }
    }
}

/// Monitoring server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable monitoring server
    #[serde(default = "default_monitoring_enabled")]
    pub enabled: bool,

    /// Listen address for monitoring server (e.g., "127.0.0.1:9090")
    #[serde(default = "default_monitoring_addr")]
    pub addr: String,
}

fn default_monitoring_enabled() -> bool {
    false
}

fn default_monitoring_addr() -> String {
    "127.0.0.1:9090".to_string()
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: default_monitoring_enabled(),
            addr: default_monitoring_addr(),
        }
    }
}

/// Main configuration structure
///
/// This is the root configuration object that contains settings for
/// plugins and logging. The legacy `server` configuration section has
/// been removed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Plugin configurations
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,

    /// Logging configuration
    #[serde(default = "default_log_config")]
    pub log: LogConfig,

    /// Admin API configuration
    #[serde(default = "default_admin_config")]
    pub admin: AdminConfig,

    /// Monitoring server configuration
    #[serde(default = "default_monitoring_config", alias = "metrics")]
    pub monitoring: MonitoringConfig,
}

fn default_log_config() -> LogConfig {
    LogConfig::default()
}

fn default_admin_config() -> AdminConfig {
    AdminConfig::default()
}

fn default_monitoring_config() -> MonitoringConfig {
    MonitoringConfig::default()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            plugins: Vec::new(),
            log: default_log_config(),
            admin: default_admin_config(),
            monitoring: default_monitoring_config(),
            // rotation disabled by default
            // `rotate_dir` defaults to None which means use parent dir of `file` if provided
        }
    }
}

impl Config {
    /// Create a new default configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from a YAML file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the YAML configuration file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        loader::load_from_file(path)
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
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        loader::load_from_yaml(yaml)
    }

    /// Validate the configuration
    ///
    /// Checks that all configuration values are valid and consistent.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn validate(&self) -> Result<()> {
        validation::validate_config(self)
    }

    /// Save configuration to a YAML file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to save the YAML configuration file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        loader::save_to_file(self, path)
    }

    /// Convert configuration to YAML string
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_yaml(&self) -> Result<String> {
        loader::to_yaml(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.log.level, "info");
        assert!(config.plugins.is_empty());
    }

    #[test]
    fn test_new_config() {
        let config = Config::new();
        assert_eq!(config.log.level, "info");
    }

    #[test]
    fn test_from_yaml_minimal() {
        let yaml = r#"
log:
  level: debug
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.log.level, "debug");
    }

    #[test]
    fn test_to_yaml() {
        let config = Config::new();
        let yaml = config.to_yaml().unwrap();
        assert!(yaml.contains("log:"));
    }
}

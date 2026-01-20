//! Audit configuration types

use serde::de::{self, Visitor};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Audit logging configuration
///
/// Controls DNS query logging and security event tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AuditConfig {
    /// Enable audit logging (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// Query logging configuration
    #[serde(default)]
    pub query_log: Option<QueryLogConfig>,

    /// Security event logging configuration
    #[serde(default)]
    pub security_events: Option<SecurityEventConfig>,
}

/// Query log configuration
///
/// Controls what DNS queries are logged and where.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QueryLogConfig {
    /// Path to query log file
    #[serde(default = "default_query_log_path")]
    pub path: String,

    /// Output format: "json" or "text" (default: json)
    #[serde(default = "default_format")]
    pub format: String,

    /// Sampling rate (0.0 to 1.0): fraction of queries to log (default: 1.0 = all)
    /// Use 0.1 to log 10% of queries, reducing I/O overhead
    #[serde(default = "default_sampling_rate")]
    pub sampling_rate: f64,

    /// Include response details in log entries (default: true)
    #[serde(default = "default_include_response")]
    pub include_response: bool,

    /// Include client IP in log entries (default: true)
    #[serde(default = "default_include_client_ip")]
    pub include_client_ip: bool,

    /// Log buffer size before flush (default: 100)
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Maximum file size in bytes before rotation (default: 100MB)
    #[serde(
        default = "default_max_file_size",
        deserialize_with = "deserialize_max_file_size"
    )]
    pub max_file_size: u64,

    /// Number of rotated files to keep (default: 10)
    #[serde(default = "default_max_files")]
    pub max_files: u32,
}

fn default_query_log_path() -> String {
    "queries.log".to_string()
}

fn default_format() -> String {
    "json".to_string()
}

fn default_sampling_rate() -> f64 {
    1.0
}

fn default_include_response() -> bool {
    true
}

fn default_include_client_ip() -> bool {
    true
}

fn default_buffer_size() -> usize {
    100
}

fn default_max_file_size() -> u64 {
    100 * 1024 * 1024 // 100MB
}

fn default_max_files() -> u32 {
    10
}

impl Default for QueryLogConfig {
    fn default() -> Self {
        Self {
            path: default_query_log_path(),
            format: default_format(),
            sampling_rate: default_sampling_rate(),
            include_response: default_include_response(),
            include_client_ip: default_include_client_ip(),
            buffer_size: default_buffer_size(),
            max_file_size: default_max_file_size(),
            max_files: default_max_files(),
        }
    }
}

/// Security event logging configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityEventConfig {
    /// Enable security event logging (default: true when present)
    #[serde(default = "default_security_enabled")]
    pub enabled: bool,

    /// Path to security event log file
    #[serde(default = "default_security_log_path")]
    pub path: String,

    /// Events to track (empty = all events)
    #[serde(default)]
    pub events: Vec<String>,

    /// Include full query details (default: true)
    #[serde(default = "default_include_query_details")]
    pub include_query_details: bool,
}

fn default_security_enabled() -> bool {
    true
}

fn default_security_log_path() -> String {
    "security.log".to_string()
}

fn default_include_query_details() -> bool {
    true
}

impl Default for SecurityEventConfig {
    fn default() -> Self {
        Self {
            enabled: default_security_enabled(),
            path: default_security_log_path(),
            events: Vec::new(), // empty = all events
            include_query_details: default_include_query_details(),
        }
    }
}

/// Parse a size string with optional units (K, M, G, case-insensitive)
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size string".to_string());
    }

    let (num_str, unit) = if s.chars().last().unwrap().is_alphabetic() {
        let len = s.len();
        let last_two = if len >= 2 {
            s[len - 2..].to_ascii_uppercase()
        } else {
            "".to_string()
        };

        if last_two == "KB" || last_two == "MB" || last_two == "GB" {
            (
                &s[..len - 2],
                s.chars().nth(len - 2).unwrap().to_ascii_uppercase(),
            )
        } else {
            let unit_char = s.chars().last().unwrap().to_ascii_uppercase();
            (&s[..len - 1], unit_char)
        }
    } else {
        (s, 'B')
    };

    let num: u64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid number: {}", num_str))?;

    let multiplier = match unit {
        'B' => 1,
        'K' => 1024,
        'M' => 1024 * 1024,
        'G' => 1024 * 1024 * 1024,
        _ => return Err(format!("invalid unit: {}, supported: K, M, G", unit)),
    };

    num.checked_mul(multiplier)
        .ok_or_else(|| "size too large".to_string())
}

/// Custom deserializer for max_file_size to support human-readable strings
fn deserialize_max_file_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct MaxFileSizeVisitor;

    impl<'de> Visitor<'de> for MaxFileSizeVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a number or a string with units (e.g., 100K, 10M, 1G)")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v < 0 {
                return Err(de::Error::custom("negative file size"));
            }
            Ok(v as u64)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_size(v).map_err(de::Error::custom)
        }
    }

    deserializer.deserialize_any(MaxFileSizeVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_config_default() {
        let config = AuditConfig::default();
        assert!(!config.enabled);
        assert!(config.query_log.is_none());
        assert!(config.security_events.is_none());
    }

    #[test]
    fn test_query_log_config_default() {
        let config = QueryLogConfig::default();
        assert_eq!(config.path, "queries.log");
        assert_eq!(config.format, "json");
        assert!((config.sampling_rate - 1.0).abs() < f64::EPSILON);
        assert!(config.include_response);
        assert!(config.include_client_ip);
    }

    #[test]
    fn test_security_event_config_default() {
        let config = SecurityEventConfig::default();
        assert!(config.enabled);
        assert_eq!(config.path, "security.log");
        assert!(config.events.is_empty());
    }

    #[test]
    fn test_audit_config_deserialize() {
        let yaml = r#"
enabled: true
query_log:
  path: /var/log/queries.log
  sampling_rate: 0.1
security_events:
  enabled: true
  events:
    - rate_limit_exceeded
    - blocked_domain_query
"#;
        let config: AuditConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enabled);

        let query_log = config.query_log.unwrap();
        assert_eq!(query_log.path, "/var/log/queries.log");
        assert!((query_log.sampling_rate - 0.1).abs() < f64::EPSILON);

        let security = config.security_events.unwrap();
        assert!(security.enabled);
        assert_eq!(security.events.len(), 2);
    }

    #[test]
    fn test_max_file_size_parsing() {
        let yaml = r#"
query_log:
  max_file_size: 10M
"#;
        let config: AuditConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.query_log.unwrap().max_file_size, 10 * 1024 * 1024);

        let yaml = r#"
query_log:
  max_file_size: 100K
"#;
        let config: AuditConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.query_log.unwrap().max_file_size, 100 * 1024);

        let yaml = r#"
query_log:
  max_file_size: 1G
"#;
        let config: AuditConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.query_log.unwrap().max_file_size, 1024 * 1024 * 1024);
    }
}

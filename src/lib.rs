//! lazydns - A DNS server implementation in Rust
//!
//! This crate provides a complete DNS server implementation
//!
//! # Architecture
//!
//! The crate is organized into several main modules:
//!
//! - `dns`: DNS protocol implementation (parsing, serialization, message handling)
//! - `server`: DNS server implementations (UDP, TCP, DoH, DoT, DoQ)
//! - `plugin`: Plugin system architecture and core plugin trait
//! - `plugins`: Collection of DNS plugins (forward, cache, hosts, etc.)
//! - `config`: Configuration loading and validation
//! - `error`: Error types and handling
//!

// #![warn(clippy::all)]

// Re-export proc_macro derives for plugin registration
pub use lazydns_macros::{RegisterExecPlugin, RegisterPlugin, ShutdownPlugin};

/// DNS protocol implementation
///
/// This module provides DNS message parsing, serialization, and core DNS types.
pub mod dns;

/// DNS server implementations
///
/// Includes UDP, TCP, DoH (DNS over HTTPS), DoT (DNS over TLS), and DoQ (DNS over QUIC) servers.
pub mod server;

/// Plugin system architecture
///
/// Defines the plugin trait and execution pipeline.
pub mod plugin;

/// Collection of DNS plugins
///
/// Includes forward, cache, hosts, domain matching, and other plugins.
pub mod plugins;

/// Utility helpers shared across the crate
pub mod utils;

/// Configuration loading and validation
///
/// Supports YAML configuration files with validation.
pub mod config;

/// Logging initialization utilities with rotation support.
///
/// Provides time-based, size-based, or hybrid log rotation.
pub mod log;

/// Metrics collection and Prometheus exporter
///
/// Provides monitoring metrics for DNS server operations.
#[cfg(feature = "metrics")]
pub mod metrics;

/// Error types and handling
///
/// Provides unified error types for the entire crate.
pub mod error {

    use thiserror::Error;

    /// Main error type for lazydns
    #[derive(Error, Debug)]
    pub enum Error {
        /// DNS protocol error
        #[error("DNS protocol error: {0}")]
        DnsProtocol(String),

        /// Configuration error
        #[error("Configuration error: {0}")]
        Config(String),

        /// Plugin error
        #[error("Plugin error: {0}")]
        Plugin(String),

        /// IO error
        #[error("IO error: {0}")]
        Io(#[from] std::io::Error),

        /// Other error
        #[error("Error: {0}")]
        Other(String),
    }

    /// Result type for lazydns operations
    pub type Result<T> = std::result::Result<T, Error>;
}

// Re-export commonly used types
pub use error::{Error, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_types() {
        // Test error type creation
        let _dns_err = Error::DnsProtocol("test error".to_string());
        let _config_err = Error::Config("test error".to_string());
        let _plugin_err = Error::Plugin("test error".to_string());
    }
}

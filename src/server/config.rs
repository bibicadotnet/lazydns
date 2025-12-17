//! Server configuration
//!
//! Types and helpers for configuring the DNS servers used by lazydns.
//!
//! The `ServerConfig` encapsulates listen addresses, timeouts, limits,
//! and other runtime parameters. It provides a builder-style API for
//! convenient construction and modification.
//!
//! # Examples
//!
//! Construct a default configuration and override the UDP address:
//!
//! ```rust
//! use std::str::FromStr;
//! use lazydns::server::config::ServerConfig;
//! let cfg = ServerConfig::default().with_udp_addr(FromStr::from_str("192.0.2.1:53").unwrap());
//! ```

use std::net::SocketAddr;
use std::time::Duration;

/// DNS server configuration
///
/// Holds settings that control server behavior. The struct is `Clone` so it
/// can be shared safely across server components. Typical fields include
/// listen addresses for UDP/TCP, request timeouts, and protocol-specific
/// size limits.
///
/// Use the builder-style methods (e.g. `with_udp_addr`) to customize a
/// configuration built from `ServerConfig::default()`.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// UDP listen address
    pub udp_addr: Option<SocketAddr>,

    /// TCP listen address
    pub tcp_addr: Option<SocketAddr>,

    /// Maximum number of concurrent connections
    pub max_connections: usize,

    /// Query timeout duration
    pub timeout: Duration,

    /// Maximum UDP packet size
    pub max_udp_size: usize,

    /// Maximum TCP message size
    pub max_tcp_size: usize,
}

impl Default for ServerConfig {
    /// Return a sensible default configuration intended for local testing
    /// and development.
    ///
    /// Defaults:
    /// - `udp_addr` / `tcp_addr`: `127.0.0.1:5353`
    /// - `max_connections`: 1000
    /// - `timeout`: 5 seconds
    /// - `max_udp_size`: 512
    /// - `max_tcp_size`: 65535
    fn default() -> Self {
        Self {
            udp_addr: Some("127.0.0.1:5353".parse().unwrap()),
            tcp_addr: Some("127.0.0.1:5353".parse().unwrap()),
            max_connections: 1000,
            timeout: Duration::from_secs(5),
            max_udp_size: 512,
            max_tcp_size: 65535,
        }
    }
}

impl ServerConfig {
    /// Create a new server configuration with the given UDP and TCP addresses.
    ///
    /// This helper sets the supplied addresses and inherits remaining defaults
    /// from `ServerConfig::default()`.
    ///
    /// # Arguments
    ///
    /// * `udp_addr` - Optional UDP listen address
    /// * `tcp_addr` - Optional TCP listen address
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use lazydns::server::config::ServerConfig;
    /// let cfg = ServerConfig::new(Some(FromStr::from_str("192.0.2.1:53").unwrap()), None);
    /// ```
    pub fn new(udp_addr: Option<SocketAddr>, tcp_addr: Option<SocketAddr>) -> Self {
        Self {
            udp_addr,
            tcp_addr,
            ..Default::default()
        }
    }

    /// Set the UDP listen address.
    ///
    /// This follows a builder pattern and returns `self` for chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use lazydns::server::config::ServerConfig;
    /// let cfg = ServerConfig::default().with_udp_addr(FromStr::from_str("0.0.0.0:53").unwrap());
    /// ```
    pub fn with_udp_addr(mut self, addr: SocketAddr) -> Self {
        self.udp_addr = Some(addr);
        self
    }

    /// Set the TCP listen address.
    ///
    /// Returns `self` to allow chaining with other builder methods.
    pub fn with_tcp_addr(mut self, addr: SocketAddr) -> Self {
        self.tcp_addr = Some(addr);
        self
    }

    /// Set the maximum number of concurrent connections.
    ///
    /// This limit is applied per-server instance and helps control resource
    /// usage under load.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the query timeout duration.
    ///
    /// This timeout applies to upstream queries and socket operations that
    /// respect the configured deadline.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum UDP packet size (in bytes).
    ///
    /// This value controls buffer allocation for UDP reads and may affect
    /// truncation behavior when responses exceed the buffer size.
    pub fn with_max_udp_size(mut self, size: usize) -> Self {
        self.max_udp_size = size;
        self
    }

    /// Set the maximum TCP message size (in bytes).
    ///
    /// Controls how large a single TCP DNS message can be; larger messages
    /// may be rejected or truncated based on this setting.
    pub fn with_max_tcp_size(mut self, size: usize) -> Self {
        self.max_tcp_size = size;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert!(config.udp_addr.is_some());
        assert!(config.tcp_addr.is_some());
        assert_eq!(config.max_connections, 1000);
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert_eq!(config.max_udp_size, 512);
        assert_eq!(config.max_tcp_size, 65535);
    }

    #[test]
    fn test_builder_pattern() {
        let addr = SocketAddr::from_str("192.0.2.1:53").unwrap();
        let config = ServerConfig::default()
            .with_udp_addr(addr)
            .with_max_connections(500)
            .with_timeout(Duration::from_secs(10));

        assert_eq!(config.udp_addr, Some(addr));
        assert_eq!(config.max_connections, 500);
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_new_config() {
        let udp = SocketAddr::from_str("192.0.2.1:53").unwrap();
        let tcp = SocketAddr::from_str("192.0.2.2:53").unwrap();
        let config = ServerConfig::new(Some(udp), Some(tcp));

        assert_eq!(config.udp_addr, Some(udp));
        assert_eq!(config.tcp_addr, Some(tcp));
    }
}

//! Server configuration
//!
//! Defines configuration structures for DNS servers

use std::net::SocketAddr;
use std::time::Duration;

/// DNS server configuration
///
/// Contains settings for server behavior including listen addresses,
/// timeouts, and limits.
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
    /// Create a new server configuration with the given UDP and TCP addresses
    ///
    /// # Arguments
    ///
    /// * `udp_addr` - Optional UDP listen address
    /// * `tcp_addr` - Optional TCP listen address
    pub fn new(udp_addr: Option<SocketAddr>, tcp_addr: Option<SocketAddr>) -> Self {
        Self {
            udp_addr,
            tcp_addr,
            ..Default::default()
        }
    }

    /// Set the UDP listen address
    pub fn with_udp_addr(mut self, addr: SocketAddr) -> Self {
        self.udp_addr = Some(addr);
        self
    }

    /// Set the TCP listen address
    pub fn with_tcp_addr(mut self, addr: SocketAddr) -> Self {
        self.tcp_addr = Some(addr);
        self
    }

    /// Set the maximum number of concurrent connections
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the query timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum UDP packet size
    pub fn with_max_udp_size(mut self, size: usize) -> Self {
        self.max_udp_size = size;
        self
    }

    /// Set the maximum TCP message size
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

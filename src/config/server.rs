//! Server configuration
//!
//! Configuration for DNS server listeners and behavior.

use crate::config::ListenerConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// Server configuration
///
/// Defines how the DNS server listens and behaves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen addresses
    #[serde(default = "default_listen_addrs")]
    pub listen_addrs: Vec<ListenerConfig>,

    /// Query timeout in seconds
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Maximum number of concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Maximum UDP packet size
    #[serde(default = "default_max_udp_size")]
    pub max_udp_size: usize,

    /// Maximum TCP message size
    #[serde(default = "default_max_tcp_size")]
    pub max_tcp_size: usize,
}

fn default_listen_addrs() -> Vec<ListenerConfig> {
    vec![
        ListenerConfig::udp("127.0.0.1:5353".parse().unwrap()),
        ListenerConfig::tcp("127.0.0.1:5353".parse().unwrap()),
    ]
}

fn default_timeout_secs() -> u64 {
    5
}

fn default_max_connections() -> usize {
    1000
}

fn default_max_udp_size() -> usize {
    512
}

fn default_max_tcp_size() -> usize {
    65535
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addrs: default_listen_addrs(),
            timeout_secs: default_timeout_secs(),
            max_connections: default_max_connections(),
            max_udp_size: default_max_udp_size(),
            max_tcp_size: default_max_tcp_size(),
        }
    }
}

impl ServerConfig {
    /// Create a new server configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the query timeout as a Duration
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Get UDP listen addresses
    pub fn udp_addrs(&self) -> Vec<SocketAddr> {
        self.listen_addrs
            .iter()
            .filter(|l| l.protocol == "udp")
            .map(|l| l.addr)
            .collect()
    }

    /// Get TCP listen addresses
    pub fn tcp_addrs(&self) -> Vec<SocketAddr> {
        self.listen_addrs
            .iter()
            .filter(|l| l.protocol == "tcp")
            .map(|l| l.addr)
            .collect()
    }

    /// Add a listener
    pub fn add_listener(&mut self, listener: ListenerConfig) {
        self.listen_addrs.push(listener);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_server_config() {
        let config = ServerConfig::default();

        assert_eq!(config.listen_addrs.len(), 2);
        assert_eq!(config.timeout_secs, 5);
        assert_eq!(config.max_connections, 1000);
        assert_eq!(config.max_udp_size, 512);
        assert_eq!(config.max_tcp_size, 65535);
    }

    #[test]
    fn test_timeout_duration() {
        let config = ServerConfig::default();
        assert_eq!(config.timeout(), Duration::from_secs(5));
    }

    #[test]
    fn test_udp_addrs() {
        let config = ServerConfig::default();
        let udp_addrs = config.udp_addrs();

        assert_eq!(udp_addrs.len(), 1);
        assert_eq!(udp_addrs[0].port(), 5353);
    }

    #[test]
    fn test_tcp_addrs() {
        let config = ServerConfig::default();
        let tcp_addrs = config.tcp_addrs();

        assert_eq!(tcp_addrs.len(), 1);
        assert_eq!(tcp_addrs[0].port(), 5353);
    }

    #[test]
    fn test_add_listener() {
        let mut config = ServerConfig::default();
        let initial_count = config.listen_addrs.len();

        config.add_listener(ListenerConfig::udp("127.0.0.1:8053".parse().unwrap()));

        assert_eq!(config.listen_addrs.len(), initial_count + 1);
    }

    #[test]
    fn test_serialize_deserialize() {
        let config = ServerConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let deserialized: ServerConfig = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(config.timeout_secs, deserialized.timeout_secs);
        assert_eq!(config.max_connections, deserialized.max_connections);
    }
}

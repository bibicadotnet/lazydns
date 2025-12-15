//! DNS server implementations module
//!
//! This module provides DNS server implementations for various protocols:
//! - UDP: Standard DNS over UDP (port 53)
//! - TCP: DNS over TCP for large responses
//! - DoH: DNS over HTTPS (RFC 8484)
//! - DoT: DNS over TLS (RFC 7858)
//! - DoQ: DNS over QUIC (future)
//!
//! # Example
//!
//! ```rust,no_run
//! use lazydns::server::{UdpServer, ServerConfig, DefaultHandler};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ServerConfig::default();
//! let handler = Arc::new(DefaultHandler);
//! let server = UdpServer::new(config, handler).await?;
//! // server.run().await?;
//! # Ok(())
//! # }
//! ```

pub mod admin;
pub mod config;
pub mod doh;
#[cfg(feature = "doq")]
pub mod doq;
#[cfg(feature = "tls")]
pub mod dot;
pub mod handler;
pub mod monitoring;
pub mod tcp;
pub mod tls;
pub mod udp;

// Re-export commonly used types
pub use admin::{AdminServer, AdminState};
pub use config::ServerConfig;
pub use doh::DohServer;
#[cfg(feature = "doq")]
pub use doq::DoqServer;
#[cfg(feature = "tls")]
pub use dot::DotServer;
pub use handler::{DefaultHandler, RequestHandler};
pub use monitoring::MonitoringServer;
pub use tcp::TcpServer;
pub use tls::TlsConfig;
pub use udp::UdpServer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_accessible() {
        // Verify ServerConfig is accessible
        let config = ServerConfig::default();
        assert!(config.udp_addr.is_some());
        assert!(config.tcp_addr.is_some());
    }

    #[test]
    fn test_server_config_builder_pattern() {
        // Verify ServerConfig builder pattern works
        use std::net::SocketAddr;
        let addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let config = ServerConfig::default()
            .with_udp_addr(addr)
            .with_timeout(std::time::Duration::from_secs(10))
            .with_max_connections(500);

        assert_eq!(config.udp_addr, Some(addr));
        assert_eq!(config.timeout, std::time::Duration::from_secs(10));
        assert_eq!(config.max_connections, 500);
    }

    #[test]
    fn test_admin_state_creation() {
        use crate::config::Config;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        // Verify AdminState can be created
        let config = Arc::new(RwLock::new(Config::new()));
        let state = AdminState::new(config, None);
        // AdminState doesn't have a version method, just verify it was created
        let _ = state;
    }

    #[test]
    fn test_tls_config_accessible() {
        // Verify TlsConfig type is accessible and has non-zero size
        assert!(std::mem::size_of::<TlsConfig>() > 0);
    }

    #[tokio::test]
    async fn test_default_handler_creation() {
        // Verify DefaultHandler can be created
        let _handler = DefaultHandler;
    }

    #[test]
    fn test_all_server_types_accessible() {
        // Verify all server types exist by checking their sizes
        assert!(std::mem::size_of::<UdpServer>() > 0);
        assert!(std::mem::size_of::<TcpServer>() > 0);
        assert!(std::mem::size_of::<DohServer>() > 0);
        #[cfg(feature = "tls")]
        assert!(std::mem::size_of::<DotServer>() > 0);
        assert!(std::mem::size_of::<AdminServer>() > 0);
        assert!(std::mem::size_of::<MonitoringServer>() > 0);
    }
}

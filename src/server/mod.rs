//! DNS server implementations module
//!
//! This module groups the concrete server implementations and shared
//! configuration types used by lazydns. It exposes the following protocol
//! implementations (some are feature gated):
//!
//! - **UDP**: Standard DNS over UDP (default behavior, port configurable)
//! - **TCP**: DNS over TCP for large responses (un-gated)
//! - **DoH** (feature = "doh"): DNS over HTTPS (RFC 8484)
//! - **DoT** (feature = "dot"): DNS over TLS (RFC 7858)
//! - **DoQ** (feature = "doq"): DNS over QUIC (experimental)
//!
//! The module exposes a number of commonly-used types through re-exports
//! such as `ServerConfig`, `UdpServer`, `TcpServer` and, when the
//! corresponding feature is enabled, `DohServer`, `DotServer`, and
//! `DoqServer`. See the individual modules for implementation details.
//!
//! Feature notes:
//! - Build with `--features doh` to enable DoH support.
//! - Build with `--features dot` (and an appropriate TLS backend) to enable DoT.
//! - Build with `--features doq` to enable QUIC/DoQ support.
//!
//! # Example
//!
//! Construct and use a UDP server with the default configuration:
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

use crate::Result;

/// Unified server interface trait
///
/// This trait provides a common interface for all DNS server implementations,
/// enabling uniform configuration and lifecycle management.
///
/// # Example
///
/// ```rust,ignore
/// use lazydns::server::{Server, ServerConfig, UdpServer};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = ServerConfig::default();
/// let server = UdpServer::from_config(config).await?;
/// server.run().await?;
/// # Ok(())
/// # }
/// ```
#[async_trait::async_trait]
pub trait Server: Send + Sync + Sized {
    /// Create a new server instance from configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration containing all necessary parameters
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot be created with the given configuration
    async fn from_config(config: ServerConfig) -> Result<Self>;

    /// Run the server
    ///
    /// This method starts the server and runs until shutdown or error.
    ///
    /// # Errors
    ///
    /// Returns an error if the server encounters a fatal error during operation
    async fn run(self) -> Result<()>;
}

#[cfg(feature = "admin")]
pub mod admin;
pub mod config;
#[cfg(feature = "doh")]
pub mod doh;
#[cfg(feature = "doq")]
pub mod doq;
#[cfg(feature = "dot")]
pub mod dot;
pub mod handler;
pub mod launcher;
#[cfg(feature = "metrics")]
pub mod monitoring;
pub mod tcp;
#[cfg(any(feature = "doh", feature = "dot"))]
pub mod tls;
pub mod udp;

// Re-export commonly used types
#[cfg(feature = "admin")]
pub use admin::{AdminServer, AdminState};
pub use config::ServerConfig;
#[cfg(feature = "doh")]
pub use doh::DohServer;
#[cfg(feature = "doq")]
pub use doq::DoqServer;
#[cfg(feature = "dot")]
pub use dot::DotServer;
pub use handler::{ClientInfo, DefaultHandler, Protocol, RequestContext, RequestHandler};
pub use launcher::ServerLauncher;
#[cfg(feature = "metrics")]
pub use monitoring::MonitoringServer;
pub use tcp::TcpServer;
#[cfg(any(feature = "doh", feature = "dot"))]
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
    #[cfg(feature = "admin")]
    fn test_admin_state_creation() {
        use crate::config::Config;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        // Verify AdminState can be created
        let config = Arc::new(RwLock::new(Config::new()));
        let registry = Arc::new(crate::plugin::Registry::new());
        let state = AdminState::new(config, Arc::clone(&registry));
        // AdminState doesn't have a version method, just verify it was created
        let _ = state;
    }

    #[test]
    #[cfg(any(feature = "doh", feature = "dot"))]
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
        #[cfg(feature = "doh")]
        assert!(std::mem::size_of::<DohServer>() > 0);
        #[cfg(feature = "dot")]
        assert!(std::mem::size_of::<DotServer>() > 0);
        #[cfg(feature = "admin")]
        assert!(std::mem::size_of::<AdminServer>() > 0);
        #[cfg(feature = "metrics")]
        assert!(std::mem::size_of::<MonitoringServer>() > 0);
    }
}

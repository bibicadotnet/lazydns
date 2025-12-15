//! Server launcher module
//!
//! This module provides utilities to launch DNS servers based on plugin configurations,
//! reducing code duplication in main.rs.

use crate::config::PluginConfig;
use crate::plugin::{PluginHandler, Registry};
#[cfg(feature = "doq")]
use crate::server::DoqServer;
#[cfg(feature = "tls")]
use crate::server::{DohServer, DotServer, TlsConfig};
use crate::server::{ServerConfig, TcpServer, UdpServer};
use serde_yaml::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, warn};

/// Normalize listen address shorthand like ":5353" -> "0.0.0.0:5353"
fn normalize_listen_addr(listen: &str) -> String {
    if listen.starts_with(':') {
        format!("0.0.0.0{}", listen)
    } else {
        listen.to_string()
    }
}

/// Server launcher responsible for starting DNS servers based on plugin configurations
pub struct ServerLauncher {
    registry: Arc<Registry>,
}

impl ServerLauncher {
    /// Create a new ServerLauncher with the given plugin registry
    pub fn new(registry: Arc<Registry>) -> Self {
        Self { registry }
    }

    /// Launch all servers configured in the plugin list
    pub async fn launch_all(&self, plugins: &[PluginConfig]) {
        for plugin_config in plugins {
            match plugin_config.plugin_type.as_str() {
                "udp_server" => self.launch_udp_server(plugin_config).await,
                "tcp_server" => self.launch_tcp_server(plugin_config).await,
                "doh_server" => self.launch_doh_server(plugin_config).await,
                "dot_server" => self.launch_dot_server(plugin_config).await,
                "doq_server" => self.launch_doq_server(plugin_config).await,
                _ => continue,
            }
        }
    }

    /// Parse listen address from plugin args
    fn parse_listen_addr(
        &self,
        args: &HashMap<String, Value>,
        default: &str,
    ) -> Option<SocketAddr> {
        let listen_str = args
            .get("listen")
            .and_then(|v| v.as_str())
            .unwrap_or(default);
        let normalized = normalize_listen_addr(listen_str);

        match normalized.parse::<SocketAddr>() {
            Ok(addr) => Some(addr),
            Err(e) => {
                error!("Failed to parse listen address '{}': {}", listen_str, e);
                None
            }
        }
    }

    /// Get entry plugin name from args
    fn get_entry(&self, args: &HashMap<String, Value>) -> String {
        args.get("entry")
            .and_then(|v| v.as_str())
            .unwrap_or("main_sequence")
            .to_string()
    }

    /// Create plugin handler for the given entry
    fn create_handler(&self, entry: String) -> Arc<PluginHandler> {
        Arc::new(PluginHandler {
            registry: Arc::clone(&self.registry),
            entry,
        })
    }

    /// Launch UDP server
    async fn launch_udp_server(&self, plugin_config: &PluginConfig) {
        let args = plugin_config.effective_args();
        let Some(addr) = self.parse_listen_addr(&args, "0.0.0.0:53") else {
            return;
        };

        let entry = self.get_entry(&args);
        let config = ServerConfig {
            udp_addr: Some(addr),
            ..Default::default()
        };
        let handler = self.create_handler(entry);

        match UdpServer::new(config, handler).await {
            Ok(server) => {
                tokio::spawn(async move {
                    if let Err(e) = server.run().await {
                        error!("UDP server error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to start UDP server on {}: {}", addr, e);
            }
        }
    }

    /// Launch TCP server
    async fn launch_tcp_server(&self, plugin_config: &PluginConfig) {
        let args = plugin_config.effective_args();
        let Some(addr) = self.parse_listen_addr(&args, "0.0.0.0:53") else {
            return;
        };

        let entry = self.get_entry(&args);
        let config = ServerConfig {
            tcp_addr: Some(addr),
            ..Default::default()
        };
        let handler = self.create_handler(entry);

        match TcpServer::new(config, handler).await {
            Ok(server) => {
                tokio::spawn(async move {
                    if let Err(e) = server.run().await {
                        error!("TCP server error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to start TCP server on {}: {}", addr, e);
            }
        }
    }

    /// Launch DoH (DNS over HTTPS) server
    #[cfg(feature = "tls")]
    async fn launch_doh_server(&self, plugin_config: &PluginConfig) {
        let args = plugin_config.effective_args();
        let Some(addr) = self.parse_listen_addr(&args, "0.0.0.0:443") else {
            return;
        };

        let cert_path = args.get("cert_file").and_then(|v| v.as_str());
        let key_path = args.get("key_file").and_then(|v| v.as_str());

        let (Some(cert_path), Some(key_path)) = (cert_path, key_path) else {
            warn!("doh_server plugin configured without cert_file/key_file");
            return;
        };

        let tls = match TlsConfig::from_files(cert_path, key_path) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to load TLS config for DoH: {}", e);
                return;
            }
        };

        let entry = self.get_entry(&args);
        let handler = self.create_handler(entry);
        let server = DohServer::new(addr.to_string(), tls, handler);

        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                error!("DoH server error: {}", e);
            }
        });
    }

    #[cfg(not(feature = "tls"))]
    async fn launch_doh_server(&self, _plugin_config: &PluginConfig) {
        warn!("DoH server requested but TLS feature is not enabled");
    }

    /// Launch DoT (DNS over TLS) server
    #[cfg(feature = "tls")]
    async fn launch_dot_server(&self, plugin_config: &PluginConfig) {
        let args = plugin_config.effective_args();
        let Some(addr) = self.parse_listen_addr(&args, "0.0.0.0:853") else {
            return;
        };

        let cert_path = args.get("cert_file").and_then(|v| v.as_str());
        let key_path = args.get("key_file").and_then(|v| v.as_str());

        let (Some(cert_path), Some(key_path)) = (cert_path, key_path) else {
            warn!("dot_server plugin configured without cert_file/key_file");
            return;
        };

        let tls = match TlsConfig::from_files(cert_path, key_path) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to load TLS config for DoT: {}", e);
                return;
            }
        };

        let entry = self.get_entry(&args);
        let handler = self.create_handler(entry);
        let server = DotServer::new(addr.to_string(), tls, handler);

        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                error!("DoT server error: {}", e);
            }
        });
    }

    #[cfg(not(feature = "tls"))]
    async fn launch_dot_server(&self, _plugin_config: &PluginConfig) {
        warn!("DoT server requested but TLS feature is not enabled");
    }

    /// Launch DoQ (DNS over QUIC) server
    #[cfg(feature = "doq")]
    async fn launch_doq_server(&self, plugin_config: &PluginConfig) {
        let args = plugin_config.effective_args();
        let Some(addr) = self.parse_listen_addr(&args, "0.0.0.0:784") else {
            return;
        };

        let cert_path = args.get("cert_file").and_then(|v| v.as_str());
        let key_path = args.get("key_file").and_then(|v| v.as_str());

        let (Some(cert_path), Some(key_path)) = (cert_path, key_path) else {
            warn!("doq_server plugin configured without cert_file/key_file");
            return;
        };

        let entry = self.get_entry(&args);
        let handler = self.create_handler(entry);
        let server = DoqServer::new(addr.to_string(), cert_path, key_path, handler);

        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                error!("DoQ server error: {}", e);
            }
        });
    }

    #[cfg(not(feature = "doq"))]
    async fn launch_doq_server(&self, _plugin_config: &PluginConfig) {
        warn!("DoQ server requested but DoQ feature is not enabled");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::{Plugin, Registry};
    use async_trait::async_trait;
    use serde_yaml::Value;
    use std::collections::HashMap;

    // Mock plugin for testing
    #[derive(Debug)]
    struct MockPlugin;

    #[async_trait]
    impl Plugin for MockPlugin {
        async fn execute(&self, _ctx: &mut crate::plugin::Context) -> crate::Result<()> {
            Ok(())
        }

        fn name(&self) -> &str {
            "mock_plugin"
        }
    }

    #[test]
    fn test_normalize_listen_addr() {
        assert_eq!(normalize_listen_addr(":5353"), "0.0.0.0:5353");
        assert_eq!(normalize_listen_addr("127.0.0.1:8080"), "127.0.0.1:8080");
        assert_eq!(normalize_listen_addr("0.0.0.0:53"), "0.0.0.0:53");
        assert_eq!(normalize_listen_addr("[::1]:53"), "[::1]:53");
        assert_eq!(normalize_listen_addr("localhost:8080"), "localhost:8080");
    }

    #[test]
    fn test_parse_listen_addr_with_ipv6() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let mut args = HashMap::new();
        args.insert(
            "listen".to_string(),
            Value::String("[::1]:5353".to_string()),
        );

        let addr = launcher.parse_listen_addr(&args, "0.0.0.0:53");
        assert_eq!(addr, Some("[::1]:5353".parse().unwrap()));
    }

    #[test]
    fn test_parse_listen_addr_with_hostname() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let mut args = HashMap::new();
        args.insert(
            "listen".to_string(),
            Value::String("127.0.0.1:8080".to_string()),
        );

        let addr = launcher.parse_listen_addr(&args, "0.0.0.0:53");
        assert_eq!(addr, Some("127.0.0.1:8080".parse().unwrap()));
    }

    #[test]
    fn test_get_entry_with_non_string_value() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let mut args = HashMap::new();
        args.insert(
            "entry".to_string(),
            Value::Number(serde_yaml::Number::from(42)),
        );

        // Should fall back to default when entry is not a string
        let entry = launcher.get_entry(&args);
        assert_eq!(entry, "main_sequence");
    }

    #[test]
    fn test_launch_all_with_multiple_plugins() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let plugin1 = crate::config::PluginConfig::new("udp_server".to_string()).with_arg(
            "listen".to_string(),
            Value::String("127.0.0.1:0".to_string()),
        );

        let plugin2 = crate::config::PluginConfig::new("unknown_plugin".to_string());

        let plugin3 = crate::config::PluginConfig::new("tcp_server".to_string()).with_arg(
            "listen".to_string(),
            Value::String("127.0.0.1:0".to_string()),
        );

        let plugins = vec![plugin1, plugin2, plugin3];

        // Should handle multiple plugins, launching servers for known types and skipping unknown ones
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            launcher.launch_all(&plugins).await;
        });
    }

    #[test]
    fn test_launch_all_with_tcp_server_config() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let plugin_config = crate::config::PluginConfig::new("tcp_server".to_string()).with_arg(
            "listen".to_string(),
            Value::String("127.0.0.1:0".to_string()),
        );

        let plugins = vec![plugin_config];

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            launcher.launch_all(&plugins).await;
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_launch_all_with_doh_server_config() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let plugin_config = crate::config::PluginConfig::new("doh_server".to_string())
            .with_arg(
                "listen".to_string(),
                Value::String("127.0.0.1:0".to_string()),
            )
            .with_arg(
                "cert_file".to_string(),
                Value::String("/nonexistent/cert.pem".to_string()),
            )
            .with_arg(
                "key_file".to_string(),
                Value::String("/nonexistent/key.pem".to_string()),
            );

        let plugins = vec![plugin_config];

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            launcher.launch_all(&plugins).await;
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_launch_all_with_dot_server_config() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let plugin_config = crate::config::PluginConfig::new("dot_server".to_string())
            .with_arg(
                "listen".to_string(),
                Value::String("127.0.0.1:0".to_string()),
            )
            .with_arg(
                "cert_file".to_string(),
                Value::String("/nonexistent/cert.pem".to_string()),
            )
            .with_arg(
                "key_file".to_string(),
                Value::String("/nonexistent/key.pem".to_string()),
            );

        let plugins = vec![plugin_config];

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            launcher.launch_all(&plugins).await;
        });
    }

    #[cfg(feature = "doq")]
    #[test]
    fn test_launch_all_with_doq_server_config() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let plugin_config = crate::config::PluginConfig::new("doq_server".to_string())
            .with_arg(
                "listen".to_string(),
                Value::String("127.0.0.1:0".to_string()),
            )
            .with_arg(
                "cert_file".to_string(),
                Value::String("/nonexistent/cert.pem".to_string()),
            )
            .with_arg(
                "key_file".to_string(),
                Value::String("/nonexistent/key.pem".to_string()),
            );

        let plugins = vec![plugin_config];

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            launcher.launch_all(&plugins).await;
        });
    }

    #[test]
    fn test_server_launcher_creation() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);
        // Just verify it was created successfully
        let _ = launcher;
    }

    #[test]
    fn test_parse_listen_addr_with_valid_address() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let mut args = HashMap::new();
        args.insert(
            "listen".to_string(),
            Value::String("127.0.0.1:5353".to_string()),
        );

        let addr = launcher.parse_listen_addr(&args, "0.0.0.0:53");
        assert_eq!(addr, Some("127.0.0.1:5353".parse().unwrap()));
    }

    #[test]
    fn test_parse_listen_addr_with_shorthand() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let mut args = HashMap::new();
        args.insert("listen".to_string(), Value::String(":8080".to_string()));

        let addr = launcher.parse_listen_addr(&args, "0.0.0.0:53");
        assert_eq!(addr, Some("0.0.0.0:8080".parse().unwrap()));
    }

    #[test]
    fn test_parse_listen_addr_with_default() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let args = HashMap::new(); // No listen key

        let addr = launcher.parse_listen_addr(&args, "0.0.0.0:53");
        assert_eq!(addr, Some("0.0.0.0:53".parse().unwrap()));
    }

    #[test]
    fn test_parse_listen_addr_with_invalid_address() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let mut args = HashMap::new();
        args.insert(
            "listen".to_string(),
            Value::String("invalid:address".to_string()),
        );

        let addr = launcher.parse_listen_addr(&args, "0.0.0.0:53");
        assert!(addr.is_none());
    }

    #[test]
    fn test_get_entry_with_custom_entry() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let mut args = HashMap::new();
        args.insert(
            "entry".to_string(),
            Value::String("custom_sequence".to_string()),
        );

        let entry = launcher.get_entry(&args);
        assert_eq!(entry, "custom_sequence");
    }

    #[test]
    fn test_get_entry_with_default() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let args = HashMap::new(); // No entry key

        let entry = launcher.get_entry(&args);
        assert_eq!(entry, "main_sequence");
    }

    #[test]
    fn test_create_handler() {
        let mut registry = Registry::new();
        registry.register(Arc::new(MockPlugin)).unwrap();
        let registry = Arc::new(registry);

        let launcher = ServerLauncher::new(Arc::clone(&registry));

        let handler = launcher.create_handler("mock_plugin".to_string());
        assert_eq!(handler.entry, "mock_plugin");
        assert!(Arc::ptr_eq(&handler.registry, &registry));
    }

    #[test]
    fn test_launch_all_with_empty_plugins() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let plugins = Vec::new();

        // This should not panic and should complete quickly
        // We can't easily test the async launch_all without complex mocking,
        // but we can at least verify it doesn't crash with empty input
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            launcher.launch_all(&plugins).await;
        });
    }

    #[test]
    fn test_launch_all_with_unknown_plugin_type() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let plugin_config = crate::config::PluginConfig::new("unknown_server".to_string());

        let plugins = vec![plugin_config];

        // This should not panic and should skip unknown plugin types
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            launcher.launch_all(&plugins).await;
        });
    }

    #[test]
    fn test_launch_all_with_udp_server_config() {
        let registry = Arc::new(Registry::new());
        let launcher = ServerLauncher::new(registry);

        let plugin_config = crate::config::PluginConfig::new("udp_server".to_string()).with_arg(
            "listen".to_string(),
            serde_yaml::Value::String("127.0.0.1:0".to_string()),
        );

        let plugins = vec![plugin_config];

        // This will attempt to start a server but should fail gracefully
        // since we can't bind to privileged ports in tests
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            launcher.launch_all(&plugins).await;
        });
    }
}

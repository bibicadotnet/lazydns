//! lazydns - A DNS server implementation in Rust
//!
//! This is a Rust implementation of mosdns, aiming for 100% feature parity or better.
//!
//! # Features
//! - Full DNS protocol support (UDP, TCP, DoH, DoT, DoQ)
//! - Flexible plugin architecture
//! - High performance with Rust's zero-cost abstractions
//! - Comprehensive caching
//! - GeoIP/GeoSite support
//! - Full test and documentation coverage

use clap::Parser;
use lazydns::config::Config;
use lazydns::plugin::{PluginBuilder, PluginHandler};
use lazydns::server::{ServerConfig, TcpServer, UdpServer};
use std::sync::Arc;
use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Normalize listen address shorthand like ":5353" -> "0.0.0.0:5353"
pub(crate) fn normalize_listen_addr(listen: &str) -> String {
    if listen.starts_with(':') {
        format!("0.0.0.0{}", listen)
    } else {
        listen.to_string()
    }
}

/// lazydns command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// Working directory
    #[arg(short, long)]
    dir: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing/logging
    let log_level = if args.verbose {
        "debug"
    } else {
        &args.log_level
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_level.into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("lazydns starting...");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    info!("Configuration file: {}", args.config);

    // Change working directory if specified
    if let Some(dir) = &args.dir {
        if let Err(e) = std::env::set_current_dir(dir) {
            info!("Failed to change working directory to {}: {}", dir, e);
            return Err(anyhow::anyhow!("Failed to change working directory"));
        }
        info!("Working directory changed to: {}", dir);
    }

    // Load configuration
    let config = match Config::from_file(&args.config) {
        Ok(config) => {
            info!("Configuration loaded successfully");
            config
        }
        Err(e) => {
            info!("Failed to load configuration: {}", e);
            info!("Using default configuration");
            Config::default()
        }
    };

    // Validate configuration
    if let Err(e) = config.validate() {
        info!("Configuration validation warning: {}", e);
    }

    // Build plugins from configuration
    let mut builder = PluginBuilder::new();
    let mut plugin_count = 0;

    for plugin_config in &config.plugins {
        match builder.build(plugin_config) {
            Ok(_plugin) => {
                info!(
                    "Loaded plugin: {} (type: {})",
                    plugin_config.effective_name(),
                    plugin_config.plugin_type
                );
                plugin_count += 1;
            }
            Err(e) => {
                info!(
                    "Failed to load plugin {}: {}",
                    plugin_config.effective_name(),
                    e
                );
            }
        }
    }

    info!("Loaded {} plugins", plugin_count);

    // Resolve inter-plugin references (e.g., fallback primary/secondary plugin names)
    if let Err(e) = builder.resolve_references(&config.plugins) {
        info!("Failed to resolve plugin references: {}", e);
    }

    // Get the plugin registry for servers to use
    let registry = Arc::new(builder.get_registry());
    debug!(plugins = ?registry.plugin_names(), "Plugin registry contents");

    // Start UDP and TCP servers based on the config
    // Look for server plugin configurations

    for plugin_config in &config.plugins {
        if plugin_config.plugin_type == "udp_server" {
            let args = plugin_config.effective_args();
            let listen_str = args
                .get("listen")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0.0:53");
            let entry = args
                .get("entry")
                .and_then(|v| v.as_str())
                .unwrap_or("main_sequence")
                .to_string();

            // Accept shorthand listen address like ":5353" and treat as "0.0.0.0:5353"
            let listen_parse_str = normalize_listen_addr(listen_str);

            if let Ok(addr) = listen_parse_str.parse() {
                let config = ServerConfig {
                    udp_addr: Some(addr),
                    ..Default::default()
                };
                let handler = Arc::new(PluginHandler {
                    registry: Arc::clone(&registry),
                    entry,
                });

                match UdpServer::new(config, handler).await {
                    Ok(server) => {
                        info!("udp_server started on {}", addr);
                        tokio::spawn(async move {
                            if let Err(e) = server.run().await {
                                error!("UDP server error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        info!("Failed to start UDP server: {}", e);
                    }
                }
            }
        } else if plugin_config.plugin_type == "tcp_server" {
            let args = plugin_config.effective_args();
            let listen_str = args
                .get("listen")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0.0:53");
            let entry = args
                .get("entry")
                .and_then(|v| v.as_str())
                .unwrap_or("main_sequence")
                .to_string();

            // Accept shorthand listen address like ":5353" and treat as "0.0.0.0:5353"
            let listen_parse_str = normalize_listen_addr(listen_str);

            if let Ok(addr) = listen_parse_str.parse() {
                let config = ServerConfig {
                    tcp_addr: Some(addr),
                    ..Default::default()
                };
                let handler = Arc::new(PluginHandler {
                    registry: Arc::clone(&registry),
                    entry,
                });

                match TcpServer::new(config, handler).await {
                    Ok(server) => {
                        info!("tcp_server started on {}", addr);
                        tokio::spawn(async move {
                            if let Err(e) = server.run().await {
                                error!("TCP server error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to start TCP server: {}", e);
                    }
                }
            }
        }
    }

    info!("lazydns initialized successfully");

    // Keep the process running
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::normalize_listen_addr;

    #[test]
    fn test_normalize_listen_addr_shorthand() {
        assert_eq!(normalize_listen_addr(":5353"), "0.0.0.0:5353");
        assert_eq!(normalize_listen_addr("127.0.0.1:8080"), "127.0.0.1:8080");
        assert_eq!(normalize_listen_addr("0.0.0.0:53"), "0.0.0.0:53");
    }
}

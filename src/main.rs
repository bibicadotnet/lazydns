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

use clap::CommandFactory;
use clap::Parser;
use lazydns::config::Config;
use lazydns::logging;
use lazydns::plugin::PluginBuilder;
use lazydns::server::ServerLauncher;
use std::sync::Arc;
use tracing::{debug, error, info};

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
    // If no arguments were provided (only program name), print help and exit.
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.len() <= 1 {
        let _ = Args::command().print_help();
        println!();
        return Ok(());
    }

    // Parse command line arguments
    let args = Args::parse();

    // Change working directory if specified (do this before loading config so relative
    // paths inside the config file behave as expected)
    if let Some(dir) = &args.dir {
        if let Err(e) = std::env::set_current_dir(dir) {
            error!("Failed to change working directory to {}: {}", dir, e);
            return Err(anyhow::anyhow!("Failed to change working directory"));
        }
        info!("Working directory changed to: {}", dir);
    }

    // Load configuration (before initializing logging so config can control logs)
    let config = match Config::from_file(&args.config) {
        Ok(config) => {
            println!("Configuration loaded successfully");
            config
        }
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            eprintln!("Using default configuration");
            Config::default()
        }
    };

    // Validate configuration
    if let Err(e) = config.validate() {
        eprintln!("Configuration validation warning: {}", e);
    }

    // Determine final logging configuration, CLI overrides config
    let mut final_log = config.log.clone();
    if args.verbose {
        final_log.level = "debug".to_string();
    } else if !args.log_level.is_empty() {
        final_log.level = args.log_level.clone();
    }

    // Initialize logging
    if let Err(e) = crate::logging::init_logging(&final_log) {
        eprintln!("Failed to initialize logging: {}", e);
    }

    info!("lazydns starting...");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    info!("Configuration file: {}", args.config);

    // Ensure rustls has a process-level CryptoProvider installed (ring)
    let _ = rustls::crypto::ring::default_provider().install_default();

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
                error!(
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
        error!("Failed to resolve plugin references: {}", e);
    }

    // Get the plugin registry for servers to use
    let registry = Arc::new(builder.get_registry());
    debug!(plugins = ?registry.plugin_names(), "Plugin registry contents");

    // Launch all configured servers using ServerLauncher
    let launcher = ServerLauncher::new(Arc::clone(&registry));
    launcher.launch_all(&config.plugins).await;

    info!("lazydns initialized successfully");

    // Keep the process running
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}

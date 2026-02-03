//! Shared state for the WebUI server

use crate::Result;
use crate::config::Config;
use crate::plugin::Registry;
use crate::web::config::WebConfig;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;

use super::alerts::AlertEngine;
use super::metrics::MetricsCollector;

/// Shared state for the WebUI server
pub struct WebState {
    /// Configuration
    config: WebConfig,
    /// Metrics collector
    metrics_collector: Arc<MetricsCollector>,
    /// Alert engine
    alert_engine: Arc<AlertEngine>,
    /// Server start time
    start_time: Instant,
    /// Plugin registry (optional, for admin operations)
    registry: Option<Arc<Registry>>,
    /// Global config (optional, for config reload)
    config_arc: Option<Arc<RwLock<Config>>>,
    /// Active SSE connections counter
    sse_connections: Arc<AtomicU64>,
    /// Active WebSocket connections counter
    ws_connections: Arc<AtomicU64>,
}

impl WebState {
    /// Create a new WebState
    pub async fn new(config: &WebConfig) -> Result<Self> {
        let metrics_collector = Arc::new(MetricsCollector::new(&config.metrics)?);
        let alert_engine = Arc::new(AlertEngine::new(&config.alerts)?);

        Ok(Self {
            config: config.clone(),
            metrics_collector,
            alert_engine,
            start_time: Instant::now(),
            registry: None,
            config_arc: None,
            sse_connections: Arc::new(AtomicU64::new(0)),
            ws_connections: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Set the plugin registry for admin operations
    pub fn set_registry(&mut self, registry: Arc<Registry>) {
        self.registry = Some(registry);
    }

    /// Set the global config for reload operations
    pub fn set_config_arc(&mut self, config: Arc<RwLock<Config>>) {
        self.config_arc = Some(config);
    }

    /// Get the plugin registry
    pub fn registry(&self) -> Option<Arc<Registry>> {
        self.registry.clone()
    }

    /// Get the global config
    pub fn config_arc(&self) -> Option<Arc<RwLock<Config>>> {
        self.config_arc.clone()
    }

    /// Get the configuration
    pub fn config(&self) -> &WebConfig {
        &self.config
    }

    /// Get the metrics collector
    pub fn metrics_collector(&self) -> Arc<MetricsCollector> {
        Arc::clone(&self.metrics_collector)
    }

    /// Get the alert engine
    pub fn alert_engine(&self) -> Arc<AlertEngine> {
        Arc::clone(&self.alert_engine)
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get SSE connection counter
    pub fn sse_connections(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.sse_connections)
    }

    /// Get WebSocket connection counter
    pub fn ws_connections(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.ws_connections)
    }

    /// Get active SSE connections count
    pub fn active_sse_connections(&self) -> u64 {
        self.sse_connections.load(Ordering::Relaxed)
    }

    /// Get active WebSocket connections count
    pub fn active_ws_connections(&self) -> u64 {
        self.ws_connections.load(Ordering::Relaxed)
    }
}

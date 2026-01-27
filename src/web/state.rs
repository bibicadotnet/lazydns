//! Shared state for the WebUI server

use crate::Result;
use crate::web::config::WebConfig;
use std::sync::Arc;

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
        })
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
}

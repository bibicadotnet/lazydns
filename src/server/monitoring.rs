//! Monitoring and administration HTTP server
//!
//! Provides endpoints for metrics, health checks, and stats.

use crate::metrics;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

/// Health check response
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Server status
    pub status: String,
    /// Server version
    pub version: String,
    /// Uptime in seconds
    pub uptime_seconds: u64,
}

/// Stats response
#[derive(Debug, Serialize, Deserialize)]
pub struct StatsResponse {
    /// Total queries processed
    pub total_queries: u64,
    /// Cache hit rate (0.0 to 1.0)
    pub cache_hit_rate: f64,
    /// Active connections
    pub active_connections: i64,
}

/// Monitoring server state
#[derive(Clone)]
pub struct MonitoringState {
    start_time: std::time::Instant,
}

impl MonitoringState {
    /// Create new monitoring state
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
        }
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

impl Default for MonitoringState {
    fn default() -> Self {
        Self::new()
    }
}

/// Monitoring server
pub struct MonitoringServer {
    addr: String,
    state: Arc<MonitoringState>,
}

impl MonitoringServer {
    /// Create a new monitoring server
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to bind to (e.g., "0.0.0.0:9090")
    ///
    /// # Example
    ///
    /// ```no_run
    /// use lazydns::server::monitoring::MonitoringServer;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let server = MonitoringServer::new("0.0.0.0:9090");
    /// // server.run().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            state: Arc::new(MonitoringState::new()),
        }
    }

    /// Start the monitoring server
    pub async fn run(self) -> Result<(), std::io::Error> {
        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler))
            .route("/stats", get(stats_handler))
            .with_state(self.state);

        info!("Monitoring server listening on {}", self.addr);

        let listener = TcpListener::bind(&self.addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

/// Handle metrics endpoint (Prometheus format)
async fn metrics_handler() -> Response {
    let metrics_text = metrics::gather_metrics();
    (StatusCode::OK, metrics_text).into_response()
}

/// Handle health check endpoint
async fn health_handler(State(state): State<Arc<MonitoringState>>) -> Response {
    let health = HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.uptime_seconds(),
    };

    Json(health).into_response()
}

/// Handle stats endpoint
async fn stats_handler() -> Response {
    // Gather statistics from metrics
    let cache_hits = metrics::CACHE_HITS_TOTAL.get();
    let cache_misses = metrics::CACHE_MISSES_TOTAL.get();
    let cache_hit_rate = if cache_hits + cache_misses > 0 {
        cache_hits as f64 / (cache_hits + cache_misses) as f64
    } else {
        0.0
    };

    // Get active connections (sum across all protocols)
    let active_conns: i64 = metrics::ACTIVE_CONNECTIONS
        .with_label_values(&["udp"])
        .get()
        + metrics::ACTIVE_CONNECTIONS
            .with_label_values(&["tcp"])
            .get();

    let stats = StatsResponse {
        total_queries: 0, // Would need to sum all query counters
        cache_hit_rate,
        active_connections: active_conns,
    };

    Json(stats).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitoring_state_creation() {
        let state = MonitoringState::new();
        assert_eq!(state.uptime_seconds(), 0);
    }

    #[test]
    fn test_monitoring_state_uptime() {
        let state = MonitoringState::new();
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(state.uptime_seconds() >= 1);
    }

    #[test]
    fn test_health_response_serialization() {
        let health = HealthResponse {
            status: "healthy".to_string(),
            version: "0.1.0".to_string(),
            uptime_seconds: 100,
        };

        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("healthy"));
        assert!(json.contains("0.1.0"));
    }

    #[test]
    fn test_stats_response_serialization() {
        let stats = StatsResponse {
            total_queries: 1000,
            cache_hit_rate: 0.75,
            active_connections: 10,
        };

        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("1000"));
        assert!(json.contains("0.75"));
    }
}

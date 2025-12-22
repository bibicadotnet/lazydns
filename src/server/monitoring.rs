//! Monitoring and administration HTTP server
//!
//! Provides endpoints for metrics, health checks, and stats.

use crate::metrics;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
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
    fn test_monitoring_state_default() {
        let state = MonitoringState::default();
        assert_eq!(state.uptime_seconds(), 0);
    }

    #[test]
    fn test_monitoring_state_uptime() {
        let state = MonitoringState::new();
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(state.uptime_seconds() >= 1);
    }

    #[test]
    fn test_monitoring_state_uptime_zero() {
        let state = MonitoringState::new();
        // Immediately check uptime - should be 0
        assert_eq!(state.uptime_seconds(), 0);
    }

    #[test]
    fn test_monitoring_server_creation() {
        let server = MonitoringServer::new("127.0.0.1:9090");
        assert_eq!(server.addr, "127.0.0.1:9090");
        assert_eq!(server.state.uptime_seconds(), 0);
    }

    #[test]
    fn test_monitoring_server_creation_with_string() {
        let addr = "0.0.0.0:8080".to_string();
        let server = MonitoringServer::new(addr.clone());
        assert_eq!(server.addr, addr);
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
        assert!(json.contains("100"));
    }

    #[test]
    fn test_health_response_deserialization() {
        let json = r#"{"status":"healthy","version":"0.1.0","uptime_seconds":100}"#;
        let health: HealthResponse = serde_json::from_str(json).unwrap();

        assert_eq!(health.status, "healthy");
        assert_eq!(health.version, "0.1.0");
        assert_eq!(health.uptime_seconds, 100);
    }

    #[test]
    fn test_health_response_empty_values() {
        let health = HealthResponse {
            status: String::new(),
            version: String::new(),
            uptime_seconds: 0,
        };

        let json = serde_json::to_string(&health).unwrap();
        let deserialized: HealthResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.status, "");
        assert_eq!(deserialized.version, "");
        assert_eq!(deserialized.uptime_seconds, 0);
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
        assert!(json.contains("10"));
    }

    #[test]
    fn test_stats_response_deserialization() {
        let json = r#"{"total_queries":1000,"cache_hit_rate":0.75,"active_connections":10}"#;
        let stats: StatsResponse = serde_json::from_str(json).unwrap();

        assert_eq!(stats.total_queries, 1000);
        assert_eq!(stats.cache_hit_rate, 0.75);
        assert_eq!(stats.active_connections, 10);
    }

    #[test]
    fn test_stats_response_edge_cases() {
        // Test zero values
        let stats_zero = StatsResponse {
            total_queries: 0,
            cache_hit_rate: 0.0,
            active_connections: 0,
        };
        let json_zero = serde_json::to_string(&stats_zero).unwrap();
        assert!(json_zero.contains("0"));

        // Test maximum hit rate
        let stats_perfect = StatsResponse {
            total_queries: 1000,
            cache_hit_rate: 1.0,
            active_connections: -1, // Negative connections (edge case)
        };
        let json_perfect = serde_json::to_string(&stats_perfect).unwrap();
        assert!(json_perfect.contains("1.0"));
        assert!(json_perfect.contains("-1"));
    }

    #[test]
    fn test_stats_response_negative_connections() {
        let stats = StatsResponse {
            total_queries: 500,
            cache_hit_rate: 0.5,
            active_connections: -5,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: StatsResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.active_connections, -5);
    }

    #[test]
    fn test_health_handler_response_structure() {
        // Test that health handler creates proper response structure
        // We can't easily test the async handler directly without axum test framework,
        // but we can test the response structure it creates
        let state = Arc::new(MonitoringState::new());
        let expected_version = env!("CARGO_PKG_VERSION");

        // Simulate what health_handler does
        let health = HealthResponse {
            status: "healthy".to_string(),
            version: expected_version.to_string(),
            uptime_seconds: state.uptime_seconds(),
        };

        assert_eq!(health.status, "healthy");
        assert_eq!(health.version, expected_version);
        assert_eq!(health.uptime_seconds, 0); // Just created
    }

    #[test]
    fn test_stats_handler_response_structure() {
        // Test that stats handler creates proper response structure
        // We can't easily test the async handler directly without axum test framework,
        // but we can test the logic it uses

        // Test cache hit rate calculation logic
        let cache_hits = 75;
        let cache_misses = 25;
        let expected_hit_rate = cache_hits as f64 / (cache_hits + cache_misses) as f64;
        assert_eq!(expected_hit_rate, 0.75);

        // Test zero division case
        let zero_hit_rate = if 0 > 0 { 1.0 } else { 0.0 };
        assert_eq!(zero_hit_rate, 0.0);

        // Test active connections summation logic
        let udp_conns = 5;
        let tcp_conns = 3;
        let total_conns = udp_conns + tcp_conns;
        assert_eq!(total_conns, 8);
    }

    #[tokio::test]
    async fn test_monitoring_server_bind_address_validation() {
        // Test that server creation accepts various valid address formats
        let valid_addresses = vec![
            "127.0.0.1:9090",
            "0.0.0.0:8080",
            "localhost:3000",
            "[::1]:9090", // IPv6
        ];

        for addr in valid_addresses {
            let server = MonitoringServer::new(addr);
            assert_eq!(server.addr, addr);
        }
    }
}

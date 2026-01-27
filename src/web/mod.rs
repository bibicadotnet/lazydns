//! WebUI server module
//!
//! Provides a real-time dashboard and API for monitoring DNS server operations.
//!
//! # Features
//!
//! - **REST API**: Query metrics, alerts, and configuration
//! - **SSE Streaming**: Real-time query logs and security events
//! - **WebSocket**: Live metrics updates
//! - **Alert Engine**: Configurable alerting with webhook support
//! - **Static File Serving**: Development mode for WebUI frontend
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                    WebUI Server                      │
//! ├─────────────────────────────────────────────────────┤
//! │  Routes:                                             │
//! │  ├── /api/dashboard/overview      GET               │
//! │  ├── /api/metrics/top-domains     GET               │
//! │  ├── /api/metrics/top-clients     GET               │
//! │  ├── /api/metrics/upstream-health GET               │
//! │  ├── /api/alerts/recent           GET               │
//! │  ├── /api/audit/query-logs/stream GET (SSE)         │
//! │  ├── /api/audit/security/stream   GET (SSE)         │
//! │  └── /ws/metrics                  WebSocket         │
//! └─────────────────────────────────────────────────────┘
//! ```

pub mod alerts;
pub mod config;
pub mod metrics;
pub mod routes;
pub mod state;
pub mod upstream_registry;
pub mod websocket;

use crate::Result;
use crate::plugins::audit::init_event_bus;
use axum::{Router, routing::get};
use config::WebConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info};

// Re-export upstream registry for easy access
pub use upstream_registry::{
    UpstreamHealthData, UpstreamHealthSnapshot, UpstreamRegistry, get_all_upstream_health,
    register_upstream, unregister_upstream, upstream_registry,
};

pub use state::WebState;

/// WebUI Server
pub struct WebServer {
    config: WebConfig,
    state: Arc<WebState>,
}

impl WebServer {
    /// Create a new WebUI server
    pub async fn new(config: WebConfig) -> Result<Self> {
        // Validate configuration
        config.validate().map_err(crate::Error::Config)?;

        // Initialize event bus if not already initialized (normally done in main.rs)
        // This is a fallback for cases where WebServer is created directly
        if crate::plugins::audit::event_bus().is_none() {
            init_event_bus(config.event_bus_capacity);
        }

        // Create shared state
        let state = Arc::new(WebState::new(&config).await?);

        Ok(Self { config, state })
    }

    /// Build the router with all routes
    fn build_router(&self) -> Router {
        let state = Arc::clone(&self.state);

        // Build CORS layer
        let cors = if self.config.cors.allowed_origins.is_empty() {
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
        } else {
            let origins: Vec<_> = self
                .config
                .cors
                .allowed_origins
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods(Any)
                .allow_headers(Any)
        };

        // API routes
        let api_router = Router::new()
            // Dashboard
            .route("/dashboard/overview", get(routes::dashboard::overview))
            .route("/alerts/recent", get(routes::dashboard::recent_alerts))
            // Metrics
            .route("/metrics/top-domains", get(routes::metrics::top_domains))
            .route("/metrics/top-clients", get(routes::metrics::top_clients))
            .route(
                "/metrics/upstream-health",
                get(routes::metrics::upstream_health),
            )
            .route(
                "/metrics/latency",
                get(routes::metrics::latency_distribution),
            )
            .route("/metrics/qps", get(routes::metrics::qps_history))
            // SSE streams
            .route(
                "/audit/query-logs/stream",
                get(routes::audit::query_logs_stream),
            )
            .route(
                "/audit/security-events/stream",
                get(routes::audit::security_events_stream),
            )
            .with_state(state.clone());

        // WebSocket routes
        let ws_router = Router::new()
            .route("/metrics", get(websocket::handler::metrics_ws))
            .with_state(state.clone());

        // Main router
        let mut router = Router::new()
            .nest("/api", api_router)
            .nest("/ws", ws_router)
            .layer(cors);

        // Static file serving (development mode)
        if let Some(ref static_dir) = self.config.static_dir {
            info!(path = %static_dir, "Serving static files");
            router = router.fallback_service(
                tower_http::services::ServeDir::new(static_dir)
                    .append_index_html_on_directories(true),
            );
        }

        router
    }

    /// Run the WebUI server
    pub async fn run(self) -> Result<()> {
        let addr: SocketAddr = self
            .config
            .socket_addr()
            .map_err(|e| crate::Error::Config(format!("Invalid address: {}", e)))?;

        let router = self.build_router();

        info!(address = %addr, "Starting WebUI server");

        // Start metrics collector
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            if let Err(e) = state.metrics_collector().run().await {
                error!(error = %e, "Metrics collector failed");
            }
        });

        // Start alert engine if enabled
        if self.config.alerts.enabled {
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                if let Err(e) = state.alert_engine().run().await {
                    error!(error = %e, "Alert engine failed");
                }
            });
        }

        // Run the server
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(crate::Error::Io)?;

        axum::serve(listener, router)
            .await
            .map_err(crate::Error::Io)?;

        Ok(())
    }

    /// Get a reference to the shared state
    pub fn state(&self) -> Arc<WebState> {
        Arc::clone(&self.state)
    }
}

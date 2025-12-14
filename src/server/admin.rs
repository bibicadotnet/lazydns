//! Admin API for runtime management
//!
//! Provides HTTP endpoints for managing the DNS server at runtime.

use crate::config::Config;
use crate::plugins::cache::CachePlugin;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Cache control request
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheControlRequest {
    /// Action to perform: "clear", "stats"
    pub action: String,
}

/// Cache statistics response
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheStatsResponse {
    /// Current cache size
    pub size: usize,
    /// Cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Cache evictions
    pub evictions: u64,
    /// Hit rate percentage
    pub hit_rate: f64,
}

/// Config reload request
#[derive(Debug, Serialize, Deserialize)]
pub struct ReloadConfigRequest {
    /// Optional path to config file (uses default if not specified)
    pub path: Option<String>,
}

/// Generic success response
#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessResponse {
    /// Success message
    pub message: String,
}

/// Generic error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Error message
    pub error: String,
}

/// Admin server state
#[derive(Clone)]
pub struct AdminState {
    /// Shared configuration
    config: Arc<RwLock<Config>>,
    /// Cache plugin reference (optional)
    cache: Option<Arc<CachePlugin>>,
}

impl AdminState {
    /// Create new admin state
    ///
    /// # Arguments
    ///
    /// * `config` - Shared configuration reference
    /// * `cache` - Optional cache plugin reference
    ///
    /// # Example
    ///
    /// ```no_run
    /// use lazydns::server::admin::AdminState;
    /// use lazydns::config::Config;
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// let config = Arc::new(RwLock::new(Config::new()));
    /// let state = AdminState::new(Arc::clone(&config), None);
    /// ```
    pub fn new(config: Arc<RwLock<Config>>, cache: Option<Arc<CachePlugin>>) -> Self {
        Self { config, cache }
    }
}

/// Admin API server
///
/// Provides administrative endpoints for runtime management.
///
/// # Example
///
/// ```no_run
/// use lazydns::server::admin::{AdminServer, AdminState};
/// use lazydns::config::Config;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Arc::new(RwLock::new(Config::new()));
/// let state = AdminState::new(Arc::clone(&config), None);
/// let server = AdminServer::new("127.0.0.1:8080", state);
/// // server.run().await?;
/// # Ok(())
/// # }
/// ```
pub struct AdminServer {
    addr: String,
    state: Arc<AdminState>,
}

impl AdminServer {
    /// Create a new admin server
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to bind to (e.g., "127.0.0.1:8080")
    /// * `state` - Admin state
    pub fn new(addr: impl Into<String>, state: AdminState) -> Self {
        Self {
            addr: addr.into(),
            state: Arc::new(state),
        }
    }

    /// Start the admin server
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to bind or start.
    pub async fn run(self) -> Result<(), std::io::Error> {
        let app = Router::new()
            .route("/api/cache/control", post(cache_control))
            .route("/api/cache/stats", get(cache_stats))
            .route("/api/config/reload", post(reload_config))
            .route("/api/server/status", get(server_status))
            .with_state(self.state);

        info!("Admin API server listening on {}", self.addr);

        let listener = TcpListener::bind(&self.addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

/// Handle cache control requests
///
/// Supports actions: "clear", "stats"
async fn cache_control(
    State(state): State<Arc<AdminState>>,
    Json(request): Json<CacheControlRequest>,
) -> Response {
    let cache = match &state.cache {
        Some(c) => c,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Cache not configured".to_string(),
                }),
            )
                .into_response();
        }
    };

    match request.action.as_str() {
        "clear" => {
            cache.clear();
            info!("Cache cleared via admin API");
            (
                StatusCode::OK,
                Json(SuccessResponse {
                    message: "Cache cleared successfully".to_string(),
                }),
            )
                .into_response()
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Unknown action: {}", request.action),
            }),
        )
            .into_response(),
    }
}

/// Get cache statistics
async fn cache_stats(State(state): State<Arc<AdminState>>) -> Response {
    let cache = match &state.cache {
        Some(c) => c,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Cache not configured".to_string(),
                }),
            )
                .into_response();
        }
    };

    let stats = cache.stats();
    let hits = stats.hits();
    let misses = stats.misses();
    let total = hits + misses;
    let hit_rate = if total > 0 {
        (hits as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let response = CacheStatsResponse {
        size: cache.size(),
        hits,
        misses,
        evictions: stats.evictions(),
        hit_rate,
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// Reload configuration
async fn reload_config(
    State(state): State<Arc<AdminState>>,
    Json(request): Json<ReloadConfigRequest>,
) -> Response {
    let path = request.path.unwrap_or_else(|| "config.yaml".to_string());

    match crate::config::loader::load_from_file(&path) {
        Ok(new_config) => match new_config.validate() {
            Ok(_) => {
                let mut config = state.config.write().await;
                *config = new_config;
                info!("Configuration reloaded from {} via admin API", path);

                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: format!("Configuration reloaded from {}", path),
                    }),
                )
                    .into_response()
            }
            Err(e) => {
                warn!("Configuration validation failed: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Configuration validation failed: {}", e),
                    }),
                )
                    .into_response()
            }
        },
        Err(e) => {
            warn!("Failed to load configuration: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to load configuration: {}", e),
                }),
            )
                .into_response()
        }
    }
}

/// Get server status
async fn server_status() -> Response {
    #[derive(Serialize)]
    struct StatusResponse {
        status: String,
        version: String,
    }

    let response = StatusResponse {
        status: "running".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    (StatusCode::OK, Json(response)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_state_creation() {
        let config = Arc::new(RwLock::new(Config::new()));
        let state = AdminState::new(config, None);
        assert!(state.cache.is_none());
    }

    #[test]
    fn test_cache_control_request_serialization() {
        let req = CacheControlRequest {
            action: "clear".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("clear"));
    }

    #[test]
    fn test_cache_stats_response_serialization() {
        let resp = CacheStatsResponse {
            size: 100,
            hits: 80,
            misses: 20,
            evictions: 5,
            hit_rate: 80.0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("100"));
        assert!(json.contains("80.0"));
    }

    #[tokio::test]
    async fn test_server_status_endpoint() {
        let response = server_status().await;
        // Response should be OK
        let (parts, _body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::OK);
    }
}

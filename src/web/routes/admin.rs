//! Admin routes for WebUI
//!
//! Provides admin operations like cache control and config reload.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use crate::web::state::WebState;

/// Cache control request
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheControlRequest {
    /// Action to perform: "clear"
    pub action: String,
}

/// Config reload request
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigReloadRequest {
    /// Optional path to config file
    pub path: Option<String>,
}

/// Generic success response
#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessResponse {
    pub success: bool,
    pub message: String,
}

/// Generic error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: String,
}

/// Clear cache handler
///
/// POST /api/admin/cache/clear
pub async fn clear_cache(State(state): State<Arc<WebState>>) -> Response {
    // Try to get the cache plugin from the registry
    let Some(registry) = state.registry() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                success: false,
                error: "Plugin registry not available".to_string(),
            }),
        )
            .into_response();
    };

    let Some(cache) = registry.get("cache") else {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                success: false,
                error: "Cache plugin not configured".to_string(),
            }),
        )
            .into_response();
    };

    // Downcast to CachePlugin and clear
    if let Some(cache_plugin) = cache
        .as_ref()
        .as_any()
        .downcast_ref::<crate::plugins::CachePlugin>()
    {
        let size_before = cache_plugin.size();
        cache_plugin.clear();
        info!(
            entries_cleared = size_before,
            "Cache cleared via WebUI admin API"
        );

        (
            StatusCode::OK,
            Json(SuccessResponse {
                success: true,
                message: format!(
                    "Cache cleared successfully ({} entries removed)",
                    size_before
                ),
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                success: false,
                error: "Failed to access cache plugin".to_string(),
            }),
        )
            .into_response()
    }
}

/// Reload configuration handler
///
/// POST /api/admin/config/reload
pub async fn reload_config(
    State(state): State<Arc<WebState>>,
    Json(request): Json<ConfigReloadRequest>,
) -> Response {
    let Some(config) = state.config_arc() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                success: false,
                error: "Configuration not available for reload".to_string(),
            }),
        )
            .into_response();
    };

    // Use provided path or default
    let path = request.path.unwrap_or_else(|| "config.yaml".to_string());

    // Load and validate new config
    match crate::config::loader::load_from_file(&path) {
        Ok(new_config) => match new_config.validate() {
            Ok(_) => {
                let mut cfg = config.write().await;
                *cfg = new_config;
                info!(path = %path, "Configuration reloaded via WebUI admin API");

                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        success: true,
                        message: format!("Configuration reloaded from {}", path),
                    }),
                )
                    .into_response()
            }
            Err(e) => {
                warn!(error = %e, "Configuration validation failed");
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        success: false,
                        error: format!("Configuration validation failed: {}", e),
                    }),
                )
                    .into_response()
            }
        },
        Err(e) => {
            warn!(error = %e, path = %path, "Failed to load configuration");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    success: false,
                    error: format!("Failed to load configuration: {}", e),
                }),
            )
                .into_response()
        }
    }
}

/// Get cache statistics
///
/// GET /api/admin/cache/stats
pub async fn cache_stats(State(state): State<Arc<WebState>>) -> Response {
    #[derive(Serialize)]
    struct CacheStatsResponse {
        size: usize,
        hits: u64,
        misses: u64,
        evictions: u64,
        expirations: u64,
        hit_rate: f64,
    }

    let Some(registry) = state.registry() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                success: false,
                error: "Plugin registry not available".to_string(),
            }),
        )
            .into_response();
    };

    let Some(cache) = registry.get("cache") else {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                success: false,
                error: "Cache plugin not configured".to_string(),
            }),
        )
            .into_response();
    };

    if let Some(cache_plugin) = cache
        .as_ref()
        .as_any()
        .downcast_ref::<crate::plugins::CachePlugin>()
    {
        let stats = cache_plugin.stats();
        let hits = stats.hits();
        let misses = stats.misses();
        let total = hits + misses;
        let hit_rate = if total > 0 {
            (hits as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        (
            StatusCode::OK,
            Json(CacheStatsResponse {
                size: cache_plugin.size(),
                hits,
                misses,
                evictions: stats.evictions(),
                expirations: stats.expirations(),
                hit_rate,
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                success: false,
                error: "Failed to access cache plugin".to_string(),
            }),
        )
            .into_response()
    }
}

/// Get server info
///
/// GET /api/admin/server/info
pub async fn server_info(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    #[derive(Serialize)]
    struct ServerInfoResponse {
        version: String,
        uptime_secs: u64,
    }

    Json(ServerInfoResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: state.uptime_secs(),
    })
}

/// Acknowledge all alerts
///
/// POST /api/admin/alerts/acknowledge-all
pub async fn acknowledge_all_alerts(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    state.alert_engine().acknowledge_all();
    info!("All alerts acknowledged via WebUI admin API");

    Json(SuccessResponse {
        success: true,
        message: "All alerts acknowledged".to_string(),
    })
}

/// Acknowledge a single alert
///
/// POST /api/admin/alerts/acknowledge/:id
pub async fn acknowledge_alert(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(alert_id): axum::extract::Path<String>,
) -> Response {
    if state.alert_engine().acknowledge(&alert_id) {
        info!(alert_id = %alert_id, "Alert acknowledged via WebUI admin API");
        (
            StatusCode::OK,
            Json(SuccessResponse {
                success: true,
                message: format!("Alert {} acknowledged", alert_id),
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                success: false,
                error: format!("Alert {} not found", alert_id),
            }),
        )
            .into_response()
    }
}

/// Clear all alerts
///
/// POST /api/admin/alerts/clear
pub async fn clear_alerts(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    state.alert_engine().clear();
    info!("All alerts cleared via WebUI admin API");

    Json(SuccessResponse {
        success: true,
        message: "All alerts cleared".to_string(),
    })
}

/// Export logs request
#[derive(Debug, Deserialize)]
pub struct ExportLogsRequest {
    /// Log type: "query" or "security"
    pub log_type: String,
    /// Format: "json" or "csv"
    #[serde(default = "default_export_format")]
    pub format: String,
    /// Maximum number of entries to export
    #[serde(default = "default_export_limit")]
    pub limit: usize,
}

fn default_export_format() -> String {
    "json".to_string()
}

fn default_export_limit() -> usize {
    1000
}

/// Export logs handler
///
/// POST /api/admin/logs/export
pub async fn export_logs(
    State(state): State<Arc<WebState>>,
    Json(request): Json<ExportLogsRequest>,
) -> Response {
    use axum::http::header;

    let alerts = state.alert_engine().recent_alerts(request.limit);

    match request.log_type.as_str() {
        "alerts" => {
            let content = if request.format == "csv" {
                // CSV format
                let mut csv =
                    String::from("id,rule_name,severity,message,timestamp,acknowledged\n");
                for alert in &alerts {
                    csv.push_str(&format!(
                        "{},{},{:?},{},{},{}\n",
                        alert.id,
                        alert.rule_name,
                        alert.severity,
                        alert.message.replace(',', ";").replace('\n', " "),
                        alert.timestamp,
                        alert.acknowledged
                    ));
                }
                csv
            } else {
                // JSON format
                serde_json::to_string_pretty(&alerts).unwrap_or_else(|_| "[]".to_string())
            };

            let content_type = if request.format == "csv" {
                "text/csv"
            } else {
                "application/json"
            };

            let filename = format!("lazydns_alerts_{}.{}", chrono_timestamp(), request.format);

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type)
                .header(
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", filename),
                )
                .body(axum::body::Body::from(content))
                .unwrap()
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                success: false,
                error: format!("Unknown log type: {}. Supported: alerts", request.log_type),
            }),
        )
            .into_response(),
    }
}

/// Generate a timestamp string for filenames
fn chrono_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", secs)
}

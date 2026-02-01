//! Dashboard API routes

use crate::web::state::WebState;
use axum::{Json, extract::State};
use serde::Serialize;
use std::sync::Arc;

/// Dashboard overview response
#[derive(Debug, Serialize)]
pub struct DashboardOverview {
    /// Server status
    pub status: String,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Metrics overview
    pub metrics: crate::web::metrics::collector::MetricsOverview,
    /// Recent alert count
    pub recent_alerts: usize,
    /// Active SSE connections
    pub active_sse_connections: usize,
    /// Active WebSocket connections
    pub active_ws_connections: usize,
}

/// GET /api/dashboard/overview
pub async fn overview(State(state): State<Arc<WebState>>) -> Json<DashboardOverview> {
    let metrics = state.metrics_collector().get_overview();
    let alert_count = state.alert_engine().recent_alert_count();

    // TODO: Track actual SSE/WS connections
    let response = DashboardOverview {
        status: "running".to_string(),
        uptime_secs: state.uptime_secs(),
        metrics,
        recent_alerts: alert_count,
        active_sse_connections: 0,
        active_ws_connections: 0,
    };

    Json(response)
}

/// Cache statistics response
#[derive(Debug, Serialize)]
pub struct CacheStatsResponse {
    pub size: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub expirations: u64,
    pub hit_rate: f64,
}

/// GET /api/dashboard/cache/stats
pub async fn cache_stats(State(state): State<Arc<WebState>>) -> Json<CacheStatsResponse> {
    let Some(registry) = state.registry() else {
        return Json(CacheStatsResponse {
            size: 0,
            hits: 0,
            misses: 0,
            evictions: 0,
            expirations: 0,
            hit_rate: 0.0,
        });
    };

    let Some(cache) = registry.get("cache") else {
        return Json(CacheStatsResponse {
            size: 0,
            hits: 0,
            misses: 0,
            evictions: 0,
            expirations: 0,
            hit_rate: 0.0,
        });
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

        Json(CacheStatsResponse {
            size: cache_plugin.size(),
            hits,
            misses,
            evictions: stats.evictions(),
            expirations: stats.expirations(),
            hit_rate,
        })
    } else {
        Json(CacheStatsResponse {
            size: 0,
            hits: 0,
            misses: 0,
            evictions: 0,
            expirations: 0,
            hit_rate: 0.0,
        })
    }
}

/// Server info response
#[derive(Debug, Serialize)]
pub struct ServerInfoResponse {
    pub version: String,
    pub uptime_secs: u64,
}

/// GET /api/dashboard/server/info
pub async fn server_info(State(state): State<Arc<WebState>>) -> Json<ServerInfoResponse> {
    Json(ServerInfoResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: state.uptime_secs(),
    })
}

/// Recent alerts response
#[derive(Debug, Serialize)]
pub struct RecentAlertsResponse {
    pub alerts: Vec<crate::web::alerts::Alert>,
    pub total: usize,
}

/// GET /api/alerts/recent
pub async fn recent_alerts(State(state): State<Arc<WebState>>) -> Json<RecentAlertsResponse> {
    let alerts = state.alert_engine().recent_alerts(50);
    let total = alerts.len();

    Json(RecentAlertsResponse { alerts, total })
}

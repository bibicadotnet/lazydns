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

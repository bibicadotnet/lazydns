//! Metrics API routes

use crate::web::metrics::timeseries::{LatencyDistributionSnapshot, TimeSeriesPoint};
use crate::web::metrics::top_n::TopNEntry;
use crate::web::state::WebState;
use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Query parameters for top-N endpoints
#[derive(Debug, Deserialize)]
pub struct TopNParams {
    /// Number of items to return (default: 10)
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    10
}

/// Top domains response
#[derive(Debug, Serialize)]
pub struct TopDomainsResponse {
    pub domains: Vec<TopNEntry<String>>,
    pub total_unique: u64,
}

/// GET /api/metrics/top-domains
pub async fn top_domains(
    State(state): State<Arc<WebState>>,
    Query(params): Query<TopNParams>,
) -> Json<TopDomainsResponse> {
    let mut domains = state.metrics_collector().get_top_domains();
    domains.truncate(params.limit);

    let overview = state.metrics_collector().get_overview();

    Json(TopDomainsResponse {
        domains,
        total_unique: overview.unique_domains,
    })
}

/// Top clients response
#[derive(Debug, Serialize)]
pub struct TopClientsResponse {
    pub clients: Vec<TopNEntry<String>>,
    pub total_unique: u64,
}

/// GET /api/metrics/top-clients
pub async fn top_clients(
    State(state): State<Arc<WebState>>,
    Query(params): Query<TopNParams>,
) -> Json<TopClientsResponse> {
    let mut clients = state.metrics_collector().get_top_clients();
    clients.truncate(params.limit);

    let overview = state.metrics_collector().get_overview();

    Json(TopClientsResponse {
        clients,
        total_unique: overview.unique_clients,
    })
}

/// Upstream health status
#[derive(Debug, Serialize)]
pub struct UpstreamHealthStatus {
    pub address: String,
    pub tag: Option<String>,
    pub status: String,
    pub success_rate: f64,
    pub avg_response_time_ms: f64,
    pub queries: u64,
    pub successes: u64,
    pub failures: u64,
    pub last_success: Option<String>,
}

/// Upstream health response
#[derive(Debug, Serialize)]
pub struct UpstreamHealthResponse {
    pub upstreams: Vec<UpstreamHealthStatus>,
}

/// GET /api/metrics/upstream-health
pub async fn upstream_health(State(_state): State<Arc<WebState>>) -> Json<UpstreamHealthResponse> {
    // Get actual upstream health from the global registry
    let snapshots = crate::web::upstream_registry::get_all_upstream_health();

    let upstreams = snapshots
        .into_iter()
        .map(|s| UpstreamHealthStatus {
            address: s.address,
            tag: s.tag,
            status: s.status,
            success_rate: s.success_rate,
            avg_response_time_ms: s.avg_response_time_ms,
            queries: s.queries,
            successes: s.successes,
            failures: s.failures,
            last_success: s.last_success,
        })
        .collect();

    Json(UpstreamHealthResponse { upstreams })
}

/// Latency distribution response
#[derive(Debug, Serialize)]
pub struct LatencyResponse {
    pub distribution: LatencyDistributionSnapshot,
}

/// GET /api/metrics/latency
pub async fn latency_distribution(State(state): State<Arc<WebState>>) -> Json<LatencyResponse> {
    let distribution = state.metrics_collector().get_latency_distribution();
    Json(LatencyResponse { distribution })
}

/// QPS history response
#[derive(Debug, Serialize)]
pub struct QpsHistoryResponse {
    pub points: Vec<TimeSeriesPoint>,
    pub current_qps: f64,
    pub stats: crate::web::metrics::timeseries::TimeSeriesStats,
}

/// GET /api/metrics/qps
pub async fn qps_history(State(state): State<Arc<WebState>>) -> Json<QpsHistoryResponse> {
    let collector = state.metrics_collector();

    Json(QpsHistoryResponse {
        points: collector.get_qps_history(),
        current_qps: collector.get_current_qps(),
        stats: collector.get_qps_stats(),
    })
}

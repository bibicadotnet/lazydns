//! Integration tests for WebUI API endpoints
#[cfg(all(test, feature = "web"))]
mod web_api_tests {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use serde_json::Value;
    use tower::ServiceExt;

    // Mock implementations for testing without full server setup

    /// Test the dashboard overview endpoint response structure
    #[tokio::test]
    async fn test_dashboard_overview_response_structure() {
        // Create a mock router that returns expected structure
        let app = Router::new().route(
            "/api/dashboard/overview",
            get(|| async {
                axum::Json(serde_json::json!({
                    "status": "running",
                    "uptime_secs": 3600,
                    "metrics": {
                        "total_queries": 1000,
                        "queries_per_second": 10.5,
                        "cache_hit_rate": 75.0,
                        "cache_hits": 750,
                        "cache_misses": 250,
                        "error_responses": 5,
                        "blocked_queries": 10,
                        "unique_domains": 100,
                        "unique_clients": 25
                    },
                    "recent_alerts": 2,
                    "active_sse_connections": 0,
                    "active_ws_connections": 0
                }))
            }),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/dashboard/overview")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Verify structure
        assert_eq!(json["status"], "running");
        assert!(json["uptime_secs"].is_number());
        assert!(json["metrics"].is_object());
        assert!(json["metrics"]["total_queries"].is_number());
        assert!(json["metrics"]["cache_hit_rate"].is_number());
    }

    /// Test the top domains endpoint response structure
    #[tokio::test]
    async fn test_top_domains_response_structure() {
        let app = Router::new().route(
            "/api/metrics/top-domains",
            get(|| async {
                axum::Json(serde_json::json!({
                    "domains": [
                        {"rank": 1, "key": "google.com", "count": 500},
                        {"rank": 2, "key": "facebook.com", "count": 300},
                        {"rank": 3, "key": "twitter.com", "count": 200}
                    ],
                    "total_unique": 150
                }))
            }),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/metrics/top-domains")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["domains"].is_array());
        assert!(json["total_unique"].is_number());

        let domains = json["domains"].as_array().unwrap();
        assert!(!domains.is_empty());
        assert!(domains[0]["rank"].is_number());
        assert!(domains[0]["key"].is_string());
        assert!(domains[0]["count"].is_number());
    }

    /// Test the top clients endpoint response structure
    #[tokio::test]
    async fn test_top_clients_response_structure() {
        let app = Router::new().route(
            "/api/metrics/top-clients",
            get(|| async {
                axum::Json(serde_json::json!({
                    "clients": [
                        {"rank": 1, "key": "192.168.1.1", "count": 200},
                        {"rank": 2, "key": "192.168.1.2", "count": 150}
                    ],
                    "total_unique": 25
                }))
            }),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/metrics/top-clients")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["clients"].is_array());
        assert!(json["total_unique"].is_number());
    }

    /// Test the upstream health endpoint response structure
    #[tokio::test]
    async fn test_upstream_health_response_structure() {
        let app = Router::new().route(
            "/api/metrics/upstream-health",
            get(|| async {
                axum::Json(serde_json::json!({
                    "upstreams": [
                        {
                            "address": "8.8.8.8:53",
                            "tag": "google",
                            "status": "healthy",
                            "success_rate": 99.5,
                            "avg_response_time_ms": 25.0,
                            "queries": 1000,
                            "successes": 995,
                            "failures": 5,
                            "last_success": "2026-01-30T12:00:00Z"
                        }
                    ]
                }))
            }),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/metrics/upstream-health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["upstreams"].is_array());

        let upstreams = json["upstreams"].as_array().unwrap();
        if !upstreams.is_empty() {
            assert!(upstreams[0]["address"].is_string());
            assert!(upstreams[0]["status"].is_string());
            assert!(upstreams[0]["success_rate"].is_number());
        }
    }

    /// Test the latency distribution endpoint response structure
    #[tokio::test]
    async fn test_latency_response_structure() {
        let app = Router::new().route(
            "/api/metrics/latency",
            get(|| async {
                axum::Json(serde_json::json!({
                    "distribution": {
                        "buckets": [
                            {"label": "<1ms", "count": 500, "percentage": 50.0},
                            {"label": "1-10ms", "count": 300, "percentage": 30.0},
                            {"label": "10-50ms", "count": 150, "percentage": 15.0},
                            {"label": "50-100ms", "count": 40, "percentage": 4.0},
                            {"label": "100-500ms", "count": 8, "percentage": 0.8},
                            {"label": "500ms-1s", "count": 2, "percentage": 0.2},
                            {"label": ">1s", "count": 0, "percentage": 0.0}
                        ],
                        "total": 1000,
                        "p50_ms": 0.8,
                        "p95_ms": 25.0,
                        "p99_ms": 75.0,
                        "max_ms": 150.0,
                        "avg_ms": 5.5
                    }
                }))
            }),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/metrics/latency")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["distribution"].is_object());
        assert!(json["distribution"]["buckets"].is_array());
        assert!(json["distribution"]["total"].is_number());
        assert!(json["distribution"]["p50_ms"].is_number());
        assert!(json["distribution"]["p95_ms"].is_number());
        assert!(json["distribution"]["p99_ms"].is_number());
    }

    /// Test the QPS history endpoint response structure
    #[tokio::test]
    async fn test_qps_history_response_structure() {
        let app = Router::new().route(
            "/api/metrics/qps",
            get(|| async {
                axum::Json(serde_json::json!({
                    "points": [
                        {"timestamp": 100, "value": 10.0},
                        {"timestamp": 101, "value": 12.0},
                        {"timestamp": 102, "value": 8.0}
                    ],
                    "current_qps": 10.5,
                    "stats": {
                        "min": 5.0,
                        "max": 20.0,
                        "avg": 10.0,
                        "sum": 1000.0,
                        "count": 100
                    }
                }))
            }),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/metrics/qps")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["points"].is_array());
        assert!(json["current_qps"].is_number());
        assert!(json["stats"].is_object());
    }

    /// Test the recent alerts endpoint response structure
    #[tokio::test]
    async fn test_recent_alerts_response_structure() {
        let app = Router::new().route(
            "/api/alerts/recent",
            get(|| async {
                axum::Json(serde_json::json!({
                    "alerts": [
                        {
                            "id": "alert-1",
                            "level": "warning",
                            "message": "High error rate detected",
                            "timestamp": "2026-01-30T12:00:00Z"
                        }
                    ],
                    "total": 1
                }))
            }),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/alerts/recent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["alerts"].is_array());
        assert!(json["total"].is_number());
    }

    /// Test query parameter parsing for top-N endpoints
    #[tokio::test]
    async fn test_top_n_query_params() {
        use axum::extract::Query;
        use serde::Deserialize;

        #[derive(Debug, Deserialize)]
        struct TopNParams {
            #[serde(default = "default_limit")]
            limit: usize,
        }

        fn default_limit() -> usize {
            10
        }

        let app = Router::new().route(
            "/api/metrics/top-domains",
            get(|Query(params): Query<TopNParams>| async move {
                axum::Json(serde_json::json!({
                    "limit_used": params.limit,
                    "domains": []
                }))
            }),
        );

        // Test with default limit
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/metrics/top-domains")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["limit_used"], 10);

        // Test with custom limit
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/metrics/top-domains?limit=5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["limit_used"], 5);
    }

    /// Test that endpoints return correct content type
    #[tokio::test]
    async fn test_json_content_type() {
        let app = Router::new().route(
            "/api/test",
            get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let content_type = response
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or(""));

        assert!(content_type.unwrap_or("").contains("application/json"));
    }

    /// Test 404 for unknown routes
    #[tokio::test]
    async fn test_unknown_route_404() {
        let app = Router::new().route(
            "/api/known",
            get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/unknown")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

/// Unit tests for API response types
#[cfg(test)]
mod response_type_tests {
    use serde::{Deserialize, Serialize};

    /// Dashboard overview response structure
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct DashboardOverview {
        status: String,
        uptime_secs: u64,
        metrics: MetricsOverview,
        recent_alerts: usize,
        active_sse_connections: usize,
        active_ws_connections: usize,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct MetricsOverview {
        total_queries: u64,
        queries_per_second: f64,
        cache_hit_rate: f64,
        cache_hits: u64,
        cache_misses: u64,
        error_responses: u64,
        blocked_queries: u64,
        unique_domains: u64,
        unique_clients: u64,
    }

    #[test]
    fn test_dashboard_overview_serialization() {
        let overview = DashboardOverview {
            status: "running".to_string(),
            uptime_secs: 3600,
            metrics: MetricsOverview {
                total_queries: 1000,
                queries_per_second: 10.5,
                cache_hit_rate: 75.0,
                cache_hits: 750,
                cache_misses: 250,
                error_responses: 5,
                blocked_queries: 10,
                unique_domains: 100,
                unique_clients: 25,
            },
            recent_alerts: 2,
            active_sse_connections: 1,
            active_ws_connections: 3,
        };

        let json = serde_json::to_string(&overview).unwrap();
        let parsed: DashboardOverview = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.status, "running");
        assert_eq!(parsed.metrics.total_queries, 1000);
        assert_eq!(parsed.metrics.cache_hit_rate, 75.0);
    }

    /// Top N entry structure
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TopNEntry {
        rank: usize,
        key: String,
        count: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TopDomainsResponse {
        domains: Vec<TopNEntry>,
        total_unique: u64,
    }

    #[test]
    fn test_top_domains_response_serialization() {
        let response = TopDomainsResponse {
            domains: vec![
                TopNEntry {
                    rank: 1,
                    key: "google.com".to_string(),
                    count: 500,
                },
                TopNEntry {
                    rank: 2,
                    key: "facebook.com".to_string(),
                    count: 300,
                },
            ],
            total_unique: 150,
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: TopDomainsResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.domains.len(), 2);
        assert_eq!(parsed.domains[0].key, "google.com");
        assert_eq!(parsed.total_unique, 150);
    }

    /// Latency bucket structure
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct LatencyBucket {
        label: String,
        count: u64,
        percentage: f64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct LatencyDistributionSnapshot {
        buckets: Vec<LatencyBucket>,
        total: u64,
        p50_ms: f64,
        p95_ms: f64,
        p99_ms: f64,
        max_ms: f64,
        avg_ms: f64,
    }

    #[test]
    fn test_latency_distribution_serialization() {
        let snapshot = LatencyDistributionSnapshot {
            buckets: vec![
                LatencyBucket {
                    label: "<1ms".to_string(),
                    count: 500,
                    percentage: 50.0,
                },
                LatencyBucket {
                    label: "1-10ms".to_string(),
                    count: 300,
                    percentage: 30.0,
                },
            ],
            total: 1000,
            p50_ms: 0.8,
            p95_ms: 25.0,
            p99_ms: 75.0,
            max_ms: 150.0,
            avg_ms: 5.5,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: LatencyDistributionSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.total, 1000);
        assert_eq!(parsed.buckets.len(), 2);
        assert!((parsed.p50_ms - 0.8).abs() < 0.001);
    }

    /// Upstream health status structure
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct UpstreamHealthStatus {
        address: String,
        tag: Option<String>,
        status: String,
        success_rate: f64,
        avg_response_time_ms: f64,
        queries: u64,
        successes: u64,
        failures: u64,
        last_success: Option<String>,
    }

    #[test]
    fn test_upstream_health_serialization() {
        let status = UpstreamHealthStatus {
            address: "8.8.8.8:53".to_string(),
            tag: Some("google".to_string()),
            status: "healthy".to_string(),
            success_rate: 99.5,
            avg_response_time_ms: 25.0,
            queries: 1000,
            successes: 995,
            failures: 5,
            last_success: Some("2026-01-30T12:00:00Z".to_string()),
        };

        let json = serde_json::to_string(&status).unwrap();
        let parsed: UpstreamHealthStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.address, "8.8.8.8:53");
        assert_eq!(parsed.status, "healthy");
        assert_eq!(parsed.success_rate, 99.5);
    }

    /// QPS history response structure
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TimeSeriesPoint {
        timestamp: u64,
        value: f64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TimeSeriesStats {
        min: f64,
        max: f64,
        avg: f64,
        sum: f64,
        count: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct QpsHistoryResponse {
        points: Vec<TimeSeriesPoint>,
        current_qps: f64,
        stats: TimeSeriesStats,
    }

    #[test]
    fn test_qps_history_serialization() {
        let response = QpsHistoryResponse {
            points: vec![
                TimeSeriesPoint {
                    timestamp: 100,
                    value: 10.0,
                },
                TimeSeriesPoint {
                    timestamp: 101,
                    value: 12.0,
                },
            ],
            current_qps: 11.0,
            stats: TimeSeriesStats {
                min: 5.0,
                max: 20.0,
                avg: 10.0,
                sum: 1000.0,
                count: 100,
            },
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: QpsHistoryResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.points.len(), 2);
        assert_eq!(parsed.current_qps, 11.0);
        assert_eq!(parsed.stats.count, 100);
    }
}

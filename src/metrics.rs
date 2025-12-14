//! Metrics collection and Prometheus exporter
//!
//! This module provides Prometheus metrics for DNS server monitoring.

use once_cell::sync::Lazy;
use prometheus::{
    HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};
use std::sync::Arc;

/// Global metrics registry
pub static METRICS_REGISTRY: Lazy<Arc<Registry>> = Lazy::new(|| Arc::new(Registry::new()));

/// DNS query counter by protocol
pub static DNS_QUERIES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        Opts::new("dns_queries_total", "Total number of DNS queries"),
        &["protocol", "query_type"],
    )
    .expect("Failed to create dns_queries_total metric");
    METRICS_REGISTRY
        .register(Box::new(counter.clone()))
        .expect("Failed to register dns_queries_total");
    counter
});

/// DNS response counter by status
pub static DNS_RESPONSES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        Opts::new("dns_responses_total", "Total number of DNS responses"),
        &["protocol", "status"],
    )
    .expect("Failed to create dns_responses_total metric");
    METRICS_REGISTRY
        .register(Box::new(counter.clone()))
        .expect("Failed to register dns_responses_total");
    counter
});

/// Query duration histogram
pub static QUERY_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "dns_query_duration_seconds",
            "DNS query processing duration in seconds",
        )
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
        ]),
        &["protocol"],
    )
    .expect("Failed to create query_duration_seconds metric");
    METRICS_REGISTRY
        .register(Box::new(histogram.clone()))
        .expect("Failed to register query_duration_seconds");
    histogram
});

/// Cache hit/miss counters
pub static CACHE_HITS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new("dns_cache_hits_total", "Total number of cache hits")
        .expect("Failed to create cache_hits_total metric");
    METRICS_REGISTRY
        .register(Box::new(counter.clone()))
        .expect("Failed to register cache_hits_total");
    counter
});

/// Total cache misses
pub static CACHE_MISSES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new("dns_cache_misses_total", "Total number of cache misses")
        .expect("Failed to create cache_misses_total metric");
    METRICS_REGISTRY
        .register(Box::new(counter.clone()))
        .expect("Failed to register cache_misses_total");
    counter
});

/// Cache size gauge
pub static CACHE_SIZE: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new("dns_cache_size", "Current number of entries in cache")
        .expect("Failed to create cache_size metric");
    METRICS_REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("Failed to register cache_size");
    gauge
});

/// Upstream query counter
pub static UPSTREAM_QUERIES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        Opts::new(
            "dns_upstream_queries_total",
            "Total number of upstream queries",
        ),
        &["upstream", "status"],
    )
    .expect("Failed to create upstream_queries_total metric");
    METRICS_REGISTRY
        .register(Box::new(counter.clone()))
        .expect("Failed to register upstream_queries_total");
    counter
});

/// Upstream response time histogram
pub static UPSTREAM_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "dns_upstream_duration_seconds",
            "Upstream query duration in seconds",
        )
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
        ]),
        &["upstream"],
    )
    .expect("Failed to create upstream_duration_seconds metric");
    METRICS_REGISTRY
        .register(Box::new(histogram.clone()))
        .expect("Failed to register upstream_duration_seconds");
    histogram
});

/// Active connections gauge
pub static ACTIVE_CONNECTIONS: Lazy<IntGaugeVec> = Lazy::new(|| {
    let gauge = IntGaugeVec::new(
        Opts::new("dns_active_connections", "Number of active connections"),
        &["protocol"],
    )
    .expect("Failed to create active_connections metric");
    METRICS_REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("Failed to register active_connections");
    gauge
});

/// Plugin execution counter
pub static PLUGIN_EXECUTIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        Opts::new(
            "dns_plugin_executions_total",
            "Total number of plugin executions",
        ),
        &["plugin", "status"],
    )
    .expect("Failed to create plugin_executions_total metric");
    METRICS_REGISTRY
        .register(Box::new(counter.clone()))
        .expect("Failed to register plugin_executions_total");
    counter
});

/// Get metrics as Prometheus text format
pub fn gather_metrics() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = METRICS_REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registry() {
        // Just verify metrics are initialized
        let _ = &*METRICS_REGISTRY;
        let _ = &*DNS_QUERIES_TOTAL;
        let _ = &*CACHE_HITS_TOTAL;
    }

    #[test]
    fn test_gather_metrics() {
        // Increment some metrics
        DNS_QUERIES_TOTAL.with_label_values(&["udp", "A"]).inc();
        CACHE_HITS_TOTAL.inc();

        // Gather metrics
        let metrics_text = gather_metrics();
        assert!(metrics_text.contains("dns_queries_total"));
        assert!(metrics_text.contains("dns_cache_hits_total"));
    }

    #[test]
    fn test_query_duration_histogram() {
        QUERY_DURATION_SECONDS
            .with_label_values(&["udp"])
            .observe(0.015);
        let metrics = gather_metrics();
        assert!(metrics.contains("dns_query_duration_seconds"));
    }
}

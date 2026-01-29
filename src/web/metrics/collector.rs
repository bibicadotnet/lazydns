//! Metrics collector
//!
//! Subscribes to the audit event bus and aggregates metrics for the dashboard.

use super::timeseries::{
    LatencyDistribution, LatencyDistributionSnapshot, TimeSeries, TimeSeriesStats,
};
use super::top_n::{TopN, TopNEntry};
use crate::Result;
use crate::plugins::audit::{QueryLogEntry, event_bus};
use crate::web::config::MetricsConfig;
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{info, trace};

/// Metrics collector that subscribes to audit events
pub struct MetricsCollector {
    /// Configuration
    config: MetricsConfig,
    /// Top domains tracker
    top_domains: TopN<String>,
    /// Top clients tracker
    top_clients: TopN<String>,
    /// Query rate (queries per second)
    qps: TimeSeries,
    /// Latency distribution
    latency: LatencyDistribution,
    /// Total queries processed
    total_queries: AtomicU64,
    /// Cache hits
    cache_hits: AtomicU64,
    /// Cache misses
    cache_misses: AtomicU64,
    /// Error responses (SERVFAIL, etc.)
    error_responses: AtomicU64,
    /// Blocked queries
    blocked_queries: AtomicU64,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(config: &MetricsConfig) -> Result<Self> {
        let window = Duration::from_secs(config.window_secs);

        Ok(Self {
            config: config.clone(),
            top_domains: TopN::new(config.top_n),
            top_clients: TopN::new(config.top_n),
            qps: TimeSeries::new(window, Duration::from_secs(1)),
            latency: LatencyDistribution::new(),
            total_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            error_responses: AtomicU64::new(0),
            blocked_queries: AtomicU64::new(0),
        })
    }

    /// Run the metrics collector (subscribes to event bus)
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let bus = match event_bus() {
            Some(bus) => bus,
            None => {
                info!("Event bus not initialized, metrics collector not starting");
                return Ok(());
            }
        };

        let mut subscriber = bus.subscribe_queries();
        info!("Metrics collector started");

        loop {
            match subscriber.recv().await {
                Some(entry) => {
                    trace!(qname = %entry.qname, "Processing query log entry");
                    self.process_query(&entry);
                }
                None => {
                    info!("Event bus closed, metrics collector stopping");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process a query log entry
    fn process_query(&self, entry: &QueryLogEntry) {
        // Increment total queries
        self.total_queries.fetch_add(1, Ordering::Relaxed);

        // Track QPS
        self.qps.increment();

        // Track domain if enabled
        if self.config.track_domains {
            // Normalize domain (lowercase, remove trailing dot)
            let domain = entry.qname.trim_end_matches('.').to_lowercase();
            self.top_domains.increment(domain);
        }

        // Track client if enabled
        if self.config.track_clients
            && let Some(client_ip) = entry.client_ip
        {
            self.top_clients.increment(client_ip.to_string());
        }

        // Track latency if enabled (use microsecond precision)
        if self.config.track_latency {
            // Prefer microsecond precision if available
            let latency_ms = if let Some(us) = entry.response_time_us {
                us as f64 / 1000.0
            } else if let Some(ms) = entry.response_time_ms {
                ms as f64
            } else {
                0.0
            };
            if latency_ms > 0.0
                || entry.response_time_us.is_some()
                || entry.response_time_ms.is_some()
            {
                self.latency.add(latency_ms);
            }
        }

        // Track cache hits/misses
        if let Some(cached) = entry.cached {
            if cached {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
            } else {
                self.cache_misses.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Track error responses
        if let Some(ref rcode) = entry.rcode
            && rcode != "NOERROR"
            && rcode != "NXDOMAIN"
        {
            self.error_responses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get top domains
    pub fn get_top_domains(&self) -> Vec<TopNEntry<String>> {
        self.top_domains.top_entries()
    }

    /// Get top clients
    pub fn get_top_clients(&self) -> Vec<TopNEntry<String>> {
        self.top_clients.top_entries()
    }

    /// Get QPS history
    pub fn get_qps_history(&self) -> Vec<super::timeseries::TimeSeriesPoint> {
        self.qps.points()
    }

    /// Get current QPS rate
    pub fn get_current_qps(&self) -> f64 {
        self.qps.rate()
    }

    /// Get QPS statistics
    pub fn get_qps_stats(&self) -> TimeSeriesStats {
        self.qps.stats()
    }

    /// Get latency distribution
    pub fn get_latency_distribution(&self) -> LatencyDistributionSnapshot {
        self.latency.distribution()
    }

    /// Get overview statistics
    pub fn get_overview(&self) -> MetricsOverview {
        let total = self.total_queries.load(Ordering::Relaxed);
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let errors = self.error_responses.load(Ordering::Relaxed);
        let blocked = self.blocked_queries.load(Ordering::Relaxed);

        let cache_hit_rate = if hits + misses > 0 {
            (hits as f64 / (hits + misses) as f64) * 100.0
        } else {
            0.0
        };

        MetricsOverview {
            total_queries: total,
            queries_per_second: self.get_current_qps(),
            cache_hit_rate,
            cache_hits: hits,
            cache_misses: misses,
            error_responses: errors,
            blocked_queries: blocked,
            unique_domains: self.top_domains.len() as u64,
            unique_clients: self.top_clients.len() as u64,
        }
    }

    /// Increment blocked queries counter
    pub fn record_blocked(&self) {
        self.blocked_queries.fetch_add(1, Ordering::Relaxed);
    }

    /// Clear all metrics
    pub fn clear(&self) {
        self.top_domains.clear();
        self.top_clients.clear();
        self.qps.clear();
        self.latency.clear();
        self.total_queries.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.error_responses.store(0, Ordering::Relaxed);
        self.blocked_queries.store(0, Ordering::Relaxed);
    }
}

/// Overview of all metrics
#[derive(Debug, Clone, Serialize)]
pub struct MetricsOverview {
    pub total_queries: u64,
    pub queries_per_second: f64,
    pub cache_hit_rate: f64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub error_responses: u64,
    pub blocked_queries: u64,
    pub unique_domains: u64,
    pub unique_clients: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> MetricsConfig {
        MetricsConfig {
            window_secs: 60,
            top_n: 10,
            track_clients: true,
            track_domains: true,
            track_latency: true,
        }
    }

    fn sample_entry() -> QueryLogEntry {
        QueryLogEntry::new(
            1234,
            "udp",
            "example.com".to_string(),
            "A".to_string(),
            "IN".to_string(),
        )
        .with_client_ip("192.168.1.1".parse().unwrap())
        .with_response("NOERROR", 1, 10)
        .with_cached(false)
    }

    #[test]
    fn test_process_query() {
        let collector = MetricsCollector::new(&sample_config()).unwrap();
        let entry = sample_entry();

        collector.process_query(&entry);

        assert_eq!(collector.total_queries.load(Ordering::Relaxed), 1);
        assert_eq!(collector.cache_misses.load(Ordering::Relaxed), 1);

        let top_domains = collector.get_top_domains();
        assert_eq!(top_domains.len(), 1);
        assert_eq!(top_domains[0].key, "example.com");
    }

    #[test]
    fn test_overview() {
        let collector = MetricsCollector::new(&sample_config()).unwrap();

        for i in 0..100 {
            let mut entry = sample_entry();
            entry.qname = format!("domain{}.com", i % 10);
            entry.cached = Some(i % 3 == 0);
            collector.process_query(&entry);
        }

        let overview = collector.get_overview();
        assert_eq!(overview.total_queries, 100);
        assert!(overview.cache_hit_rate > 0.0);
    }
}

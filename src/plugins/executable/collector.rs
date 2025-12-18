//! Metrics collector executable plugin.
//!
//! This plugin provides Prometheus-backed metrics similar to the
//! `metrics_collector` executable plugin in upstream mosdns. It exposes
//! a small, test-friendly constructor `MetricsCollectorPlugin::new` that
//! accepts a shared counter used by tests or higher-level wiring. The
//! executable-style QuickSetup (registering with runtime) can be added
//! separately where needed.

use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
#[cfg(feature = "admin")]
use prometheus::{Counter, Gauge, Histogram, HistogramOpts, Opts, Registry};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Metrics collector plugin: counts queries and accumulates latency.
#[derive(Debug, Clone)]
pub struct MetricsCollectorPlugin {
    counter: Arc<AtomicUsize>,
    _start_time: std::time::Instant,
    last_reset: Arc<std::sync::RwLock<std::time::Instant>>,
    total_latency_ms: Arc<AtomicUsize>,
}

impl MetricsCollectorPlugin {
    /// Create a new metrics collector with shared counter.
    pub fn new(counter: Arc<AtomicUsize>) -> Self {
        let now = std::time::Instant::now();
        Self {
            counter,
            _start_time: now,
            last_reset: Arc::new(std::sync::RwLock::new(now)),
            total_latency_ms: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Get the total query count.
    pub fn count(&self) -> usize {
        self.counter.load(Ordering::SeqCst)
    }

    /// Calculate queries per second since last reset.
    pub fn queries_per_second(&self) -> f64 {
        let count = self.count() as f64;
        let last_reset = self.last_reset.read().unwrap();
        let duration = last_reset.elapsed().as_secs_f64();

        if duration > 0.0 {
            count / duration
        } else {
            0.0
        }
    }

    /// Get average latency in milliseconds.
    pub fn average_latency_ms(&self) -> f64 {
        let total_latency = self.total_latency_ms.load(Ordering::SeqCst) as f64;
        let count = self.count() as f64;

        if count > 0.0 {
            total_latency / count
        } else {
            0.0
        }
    }

    /// Reset the metrics counters.
    pub fn reset(&self) {
        self.counter.store(0, Ordering::SeqCst);
        self.total_latency_ms.store(0, Ordering::SeqCst);
        *self.last_reset.write().unwrap() = std::time::Instant::now();
    }

    /// Get time since metrics were last reset.
    pub fn time_since_reset(&self) -> std::time::Duration {
        self.last_reset.read().unwrap().elapsed()
    }
}

#[async_trait]
impl Plugin for MetricsCollectorPlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Increment query counter
        self.counter.fetch_add(1, Ordering::SeqCst);

        // Track latency if available from metadata
        if let Some(latency_ms) = ctx.get_metadata::<f64>("query_latency_ms") {
            self.total_latency_ms
                .fetch_add((*latency_ms) as usize, Ordering::SeqCst);
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "metrics_collector"
    }
}

// --- Prometheus-backed QuickSetup (ported from Go) ---
#[cfg(feature = "admin")]
/// Create and register a Prometheus-backed metrics collector.
///
/// This mirrors the Go `QuickSetup` behavior: callers supply a
/// `prometheus::Registry` and a `name` which is used as a const label
/// on all metrics. The function registers the collectors and returns
/// an `Arc<dyn Plugin>` implementing the same semantics as the
/// in-process collector.
pub fn quick_setup_with_registry(reg: &Registry, name: &str) -> Result<Arc<dyn Plugin>> {
    // Create counters/gauges/histogram with the provided name label.
    let q_opts = Opts::new("query_total", "The total number of queries pass through")
        .const_label("name", name.to_string());
    let query_total = Counter::with_opts(q_opts)
        .map_err(|e| crate::Error::Other(format!("prometheus counter opts error: {}", e)))?;

    let e_opts = Opts::new("err_total", "The total number of queries failed")
        .const_label("name", name.to_string());
    let err_total = Counter::with_opts(e_opts)
        .map_err(|e| crate::Error::Other(format!("prometheus counter opts error: {}", e)))?;

    let t_opts = Opts::new(
        "thread",
        "The number of threads that are currently being processed",
    )
    .const_label("name", name.to_string());
    let thread = Gauge::with_opts(t_opts)
        .map_err(|e| crate::Error::Other(format!("prometheus gauge opts error: {}", e)))?;

    let h_opts = HistogramOpts::new(
        "response_latency_millisecond",
        "The response latency in millisecond",
    )
    .const_label("name", name.to_string());
    let response_latency = Histogram::with_opts(h_opts)
        .map_err(|e| crate::Error::Other(format!("prometheus histogram opts error: {}", e)))?;

    // Register metrics to provided registry.
    reg.register(Box::new(query_total.clone()))
        .map_err(|e| crate::Error::Other(format!("failed to register query_total: {}", e)))?;
    reg.register(Box::new(err_total.clone()))
        .map_err(|e| crate::Error::Other(format!("failed to register err_total: {}", e)))?;
    reg.register(Box::new(thread.clone()))
        .map_err(|e| crate::Error::Other(format!("failed to register thread: {}", e)))?;
    reg.register(Box::new(response_latency.clone()))
        .map_err(|e| crate::Error::Other(format!("failed to register response_latency: {}", e)))?;

    // Plugin that updates Prometheus metrics using the same semantics.
    #[allow(dead_code)]
    #[derive(Debug)]
    struct PromCollector {
        query_total: Counter,
        err_total: Counter,
        thread: Gauge,
        response_latency: Histogram,
    }

    #[async_trait]
    impl Plugin for PromCollector {
        async fn execute(&self, ctx: &mut Context) -> Result<()> {
            self.query_total.inc();
            if let Some(latency_ms) = ctx.get_metadata::<f64>("query_latency_ms") {
                self.response_latency.observe(*latency_ms);
            }
            Ok(())
        }

        fn name(&self) -> &str {
            "metrics_collector"
        }
    }

    let plugin = PromCollector {
        query_total,
        err_total,
        thread,
        response_latency,
    };

    Ok(Arc::new(plugin))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;
    use crate::plugin::Context;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn test_metrics_collector_increments() {
        let counter = Arc::new(AtomicUsize::new(0));
        let plugin = MetricsCollectorPlugin::new(counter.clone());
        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();
        plugin.execute(&mut ctx).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }
}

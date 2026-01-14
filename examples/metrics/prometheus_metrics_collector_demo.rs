//! Demo program showing how to use the PrometheusMetricsCollectorPlugin.
//!
//! This example demonstrates:
//! - Creating a Prometheus metrics collector instance
//! - Integrating it into a plugin sequence
//! - Accessing Prometheus metrics
//! - Exporting metrics in Prometheus format
//!
//! How to run:
//! ```bash
//! cargo run --features metrics --example prometheus_metrics_collector_demo
//! ```

#[cfg(feature = "metrics")]
use lazydns::Result;
#[cfg(feature = "metrics")]
use lazydns::dns::Message;
#[cfg(feature = "metrics")]
use lazydns::plugin::{Context, Plugin, Registry as PluginRegistry};
#[cfg(feature = "metrics")]
use lazydns::plugins::executable::PromMetricsCollectorPlugin;
#[cfg(feature = "metrics")]
use std::sync::Arc;

#[cfg(feature = "metrics")]
#[tokio::main]
async fn main() -> Result<()> {
    println!("Prometheus Metrics Collector Demo");
    println!("==================================");

    // Create a Prometheus metrics collector using global registry
    let metrics_plugin = PromMetricsCollectorPlugin::with_global_registry("demo_server")?;
    println!("✓ Created Prometheus metrics collector using global registry");

    // Create a simple registry and register the metrics plugin
    let mut plugin_registry = PluginRegistry::new();
    let plugin_arc = Arc::new(metrics_plugin.clone()) as Arc<dyn Plugin>;
    plugin_registry
        .register(plugin_arc)
        .expect("Failed to register metrics plugin");

    // Create some test DNS queries
    let test_queries = vec![
        ("example.com", false, Some(45.0)),    // Success with latency
        ("google.com", false, Some(120.0)),    // Success with higher latency
        ("nonexistent.domain", true, None),    // Error case
        ("cloudflare.com", false, Some(35.0)), // Success
    ];

    println!("\nProcessing DNS queries...");

    // Process some queries
    for (domain, has_error, latency) in &test_queries {
        let mut ctx = Context::new(Message::new());

        // Set error flag if this is an error case
        if *has_error {
            ctx.set_metadata("query_error", true);
        }

        // Set latency if available
        if let Some(latency_ms) = latency {
            ctx.set_metadata("query_latency_ms", *latency_ms);
        }

        // Simulate query processing
        metrics_plugin.execute(&mut ctx).await?;

        let status = if *has_error { "ERROR" } else { "SUCCESS" };
        let latency_str = latency.map_or("N/A".to_string(), |l| format!("{:.1}ms", l));
        println!(
            "  Processed query for {} (status: {}, latency: {})",
            domain, status, latency_str
        );
    }

    // Export metrics in Prometheus format using lazydns's gather_metrics
    println!("\nPrometheus Metrics Output:");
    println!("==========================");

    let metrics_output = lazydns::metrics::gather_metrics();
    println!("{}", metrics_output);

    println!("Demo completed successfully!");
    println!("\nNote: In a real application, you would typically:");
    println!("1. Use a shared Prometheus registry across your application");
    println!("2. Expose metrics via an HTTP endpoint (e.g., /metrics)");
    println!("3. Configure Prometheus to scrape your application");
    println!(
        "4. Look for metrics with names like: dns_query_total, dns_err_total, dns_response_latency_millisecond"
    );
    Ok(())
}

#[cfg(not(feature = "metrics"))]
fn main() {
    println!("This demo requires the 'metrics' feature to be enabled.");
    println!(
        "Build with: cargo run --features metrics --example prometheus_metrics_collector_demo"
    );
}

//! Demo program showing how to use the MetricsCollectorPlugin programmatically.
//!
//! This example demonstrates:
//! - Creating a metrics collector instance
//! - Integrating it into a plugin sequence
//! - Accessing collected metrics
//! - Resetting metrics counters
//!
//! How to run:
//! ```bash
//! cargo run --example metrics_collector_demo
//! ```

use lazydns::Result;
use lazydns::dns::Message;
use lazydns::plugin::{Context, Plugin, Registry};
use lazydns::plugins::executable::MetricsCollectorPlugin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Metrics Collector Demo");
    println!("======================");

    // Create a shared counter for the metrics collector
    let counter = Arc::new(AtomicUsize::new(0));
    let metrics_plugin = MetricsCollectorPlugin::new(Arc::clone(&counter));

    // Create a simple registry and register the metrics plugin
    let mut registry = Registry::new();
    registry
        .register(Arc::new(metrics_plugin.clone()) as Arc<dyn Plugin>)
        .expect("Failed to register metrics plugin");

    // Create some test DNS queries
    let test_queries = vec![
        "example.com",
        "google.com",
        "cloudflare.com",
        "github.com",
        "stackoverflow.com",
    ];

    println!("\nProcessing DNS queries...");

    // Process some queries
    for domain in &test_queries {
        let mut ctx = Context::new(Message::new());

        // Simulate query processing
        metrics_plugin.execute(&mut ctx).await?;

        // Add some fake latency data
        let latency_ms = 50.0 + (rand::random::<f64>() * 100.0);
        ctx.set_metadata("query_latency_ms", latency_ms);

        println!(
            "  Processed query for {} (latency: {:.1}ms)",
            domain, latency_ms
        );
    }

    // Display collected metrics
    println!("\nMetrics Summary:");
    println!("================");
    println!("Total queries: {}", metrics_plugin.count());
    println!(
        "Average latency: {:.2}ms",
        metrics_plugin.average_latency_ms()
    );
    println!(
        "Queries per second: {:.2}",
        metrics_plugin.queries_per_second()
    );
    println!(
        "Time since reset: {:.2}s",
        metrics_plugin.time_since_reset().as_secs_f64()
    );

    // Reset metrics
    println!("\nResetting metrics...");
    metrics_plugin.reset();

    println!("After reset:");
    println!("Total queries: {}", metrics_plugin.count());
    println!(
        "Average latency: {:.2}ms",
        metrics_plugin.average_latency_ms()
    );
    println!(
        "Queries per second: {:.2}",
        metrics_plugin.queries_per_second()
    );

    println!("\nDemo completed successfully!");

    Ok(())
}

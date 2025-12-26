# Metrics Collector Plugins Demo

This directory contains demo configurations and examples for the lazydns metrics collector plugins.

## Available Demos

### 1. In-Memory Metrics Collector (`metrics_collector.demo.yaml`)

A simple metrics collector that stores statistics in memory.

**Features:**
- Query count tracking
- Average latency calculation
- Queries per second rate
- Memory-based storage (no external dependencies)

**Usage:**
```bash
cargo run -- -c examples/collector/metrics_collector.demo.yaml -vv
```

**Test:**
```bash
dig @127.0.0.1 -p 5354 cloudflare.com A
```

### 2. Prometheus Metrics Collector (`prometheus_metrics_collector.demo.yaml`)

A Prometheus-compatible metrics collector that exposes metrics in Prometheus format.

**Features:**
- Prometheus counter for total queries
- Prometheus counter for error queries
- Prometheus gauge for active threads
- Prometheus histogram for response latency
- Standard Prometheus metric names and labels

**Prerequisites:**
- Build with metrics feature: `cargo build --features metrics`

**Usage:**
```bash
cargo run --features metrics -- -c examples/collector/prometheus_metrics_collector.demo.yaml -vv
```

**Test:**
```bash
dig @127.0.0.1 -p 5354 cloudflare.com A
```

### 3. Programmatic Examples

#### In-Memory Metrics (`metrics_collector_demo.rs`)
Demonstrates programmatic usage of the in-memory metrics collector.

**Run:**
```bash
cargo run --example metrics_collector_demo
```

#### Prometheus Metrics (`prometheus_metrics_collector_demo.rs`)
Demonstrates programmatic usage of the Prometheus metrics collector with metric export.

**Run:**
```bash
cargo run --features metrics --example prometheus_metrics_collector_demo
```

## Configuration Syntax

### In-Memory Metrics Collector
```yaml
plugins:
  - tag: metrics_collector
    type: sequence
    args:
      - exec: $forward
      - exec: metrics_collector
      - exec: accept
```

### Prometheus Metrics Collector
```yaml
plugins:
  - tag: prometheus_metrics
    type: sequence
    args:
      - exec: $forward
      - exec: prometheus_metrics_collector name=my_dns_server
      - exec: accept
```

## Metrics Exposed

### In-Memory Collector
- `count()`: Total query count
- `average_latency_ms()`: Average response latency
- `queries_per_second()`: Current QPS rate
- `reset()`: Reset all counters

### Prometheus Collector
- `query_total{name="..."}`: Counter for total queries
- `err_total{name="..."}`: Counter for failed queries
- `thread{name="..."}`: Gauge for active threads
- `response_latency_millisecond{name="..."}`: Histogram for latency

## Integration Examples

### Accessing Metrics Programmatically
```rust
use lazydns::plugins::executable::MetricsCollectorPlugin;

// Create collector
let counter = Arc::new(AtomicUsize::new(0));
let plugin = MetricsCollectorPlugin::new(counter);

// Access metrics
println!("Total queries: {}", plugin.count());
println!("Avg latency: {:.2}ms", plugin.average_latency_ms());
```

### Prometheus Integration
```rust
use lazydns::plugins::executable::PrometheusMetricsCollectorPlugin;
use prometheus::Registry;

// Create registry and collector
let registry = Registry::new();
let plugin = PrometheusMetricsCollectorPlugin::new(&registry, "my_server")?;

// Export metrics
let encoder = prometheus::TextEncoder::new();
let metrics = encoder.encode_to_string(&registry.gather())?;
println!("{}", metrics);
```

## Production Usage

For production deployments:

1. **Prometheus Collector**: Use shared registry across your application
2. **HTTP Endpoint**: Expose `/metrics` endpoint for Prometheus scraping
3. **Service Discovery**: Configure Prometheus to auto-discover your services
4. **Alerting**: Set up alerts based on query rates and error counts

## Troubleshooting

- **Missing metrics feature**: Use `--features metrics` when building
- **Port conflicts**: Change listen ports in demo configs if needed
- **Prometheus connection**: Ensure Prometheus can reach your metrics endpoint</content>
<parameter name="filePath">/home/mic/lazydns/examples/README_metrics.md
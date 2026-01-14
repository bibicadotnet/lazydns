# Memory Metrics Example

This example demonstrates lazydns's built-in process memory monitoring capabilities.

## Overview

lazydns automatically collects and exposes process memory metrics via Prometheus:
- **RSS** (Resident Set Size) - physical memory usage
- **VMS** (Virtual Memory Size) - total virtual memory
- **cgroup metrics** - container-aware memory usage and limits

## Production Usage

In production, enable memory metrics in your `config.yaml`:

```yaml
monitoring:
  enabled: true
  addr: "0.0.0.0:9090"
  memory_metrics:
    enabled: true
    interval_ms: 5000  # Sample every 5 seconds
```

Then configure Prometheus to scrape the `/metrics` endpoint:

```yaml
scrape_configs:
  - job_name: 'lazydns'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
```

## Metrics Explained

### `/proc` Metrics (Always Available)

- **`lazydns_process_resident_memory_bytes`**: Physical RAM used by the process
- **`lazydns_process_virtual_memory_bytes`**: Total virtual address space

### cgroup Metrics (Container Environments)

- **`lazydns_process_cgroup_memory_bytes`**: Current memory from cgroup perspective
- **`lazydns_process_cgroup_memory_limit_bytes`**: Memory limit set by container runtime

**Note**: cgroup metrics only appear when running in Docker, Kubernetes, or other containerized environments.

## Programmatic Usage

```rust
use lazydns::metrics::memory::{start_memory_metrics_collector, MemoryMetricsConfig};

// Create config
let config = MemoryMetricsConfig::default()
    .with_interval(5000)
    .with_enabled(true);

// Start collector
let handle = start_memory_metrics_collector(config);

// Metrics are now being collected and exposed via METRICS_REGISTRY
```

## See Also

- [MEMORY_METRICS.md](../../docs/MEMORY_METRICS.md) - Complete documentation
- [memory.yml](../../etc/prometheus/alerts/memory.yml) - Alerting rules
- [Prometheus Documentation](https://prometheus.io/docs/introduction/overview/)

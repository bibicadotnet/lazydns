# Memory Metrics Collection

lazydns provides comprehensive process memory monitoring with native container support through Prometheus metrics.

## Overview

Memory metrics are collected in real-time and exposed via the `/metrics` endpoint for Prometheus scraping. The implementation intelligently prioritizes container-aware metrics (cgroup) when available, ensuring accurate monitoring in both bare-metal and containerized deployments.

## Metrics Exposed

### Process Memory Metrics (from /proc)

| Metric Name | Type | Description | Source |
|-------------|------|-------------|--------|
| `lazydns_process_resident_memory_bytes` | Gauge | Resident Set Size (RSS) - physical memory used | `/proc/self/status` |
| `lazydns_process_virtual_memory_bytes` | Gauge | Virtual Memory Size (VmSize) - total virtual memory | `/proc/self/status` |

### Container Memory Metrics (from cgroup)

| Metric Name | Type | Description | Source |
|-------------|------|-------------|--------|
| `lazydns_process_cgroup_memory_bytes` | Gauge | Current memory usage from cgroup perspective | cgroup v2/v1 |
| `lazydns_process_cgroup_memory_limit_bytes` | Gauge | Memory limit set by cgroup (0 = unlimited) | cgroup v2/v1 |

**Priority**: When running in containers, `lazydns_process_cgroup_memory_bytes` is the preferred metric as it reflects the container's view of memory usage and respects cgroup limits.

## Configuration

### Basic Configuration

```yaml
monitoring:
  enabled: true
  addr: "0.0.0.0:9090"
  memory_metrics:
    enabled: true
    interval_ms: 5000  # Sampling interval (default: 5s)
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `monitoring.memory_metrics.enabled` | bool | `true` | Enable/disable memory metrics collection |
| `monitoring.memory_metrics.interval_ms` | u64 | `5000` | Sampling interval in milliseconds |

### Disabling Memory Metrics

```yaml
monitoring:
  enabled: true
  addr: "0.0.0.0:9090"
  memory_metrics:
    enabled: false
```

### Custom Sampling Interval

For high-frequency monitoring (not recommended for production):

```yaml
monitoring:
  memory_metrics:
    enabled: true
    interval_ms: 1000  # Sample every 1 second
```

**Recommendation**: Keep the default 5-second interval to balance monitoring granularity with system overhead.

## Container Support

### cgroup v2 (Modern Containers)

lazydns automatically detects cgroup v2 and reads from:
- `/sys/fs/cgroup/memory.current` - current usage
- `/sys/fs/cgroup/memory.max` - memory limit

Supported platforms:
- Docker with cgroup v2
- Kubernetes 1.25+
- Podman
- containerd

### cgroup v1 (Legacy Containers)

For older container runtimes, lazydns falls back to cgroup v1:
- `/sys/fs/cgroup/memory/memory.usage_in_bytes`
- `/sys/fs/cgroup/memory/memory.limit_in_bytes`

### Non-Container Environments

When cgroups are not detected (bare-metal, VMs), lazydns relies solely on `/proc/self/status` metrics (RSS and VMS).

## Prometheus Scraping

### Example Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'lazydns'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
    scrape_timeout: 10s
```

### Querying Metrics

**Current RSS (Resident Memory):**
```promql
lazydns_process_resident_memory_bytes
```

**Current Memory Usage (Container):**
```promql
lazydns_process_cgroup_memory_bytes
```

**Memory Usage Percentage (Container):**
```promql
(lazydns_process_cgroup_memory_bytes / lazydns_process_cgroup_memory_limit_bytes) * 100
```

**Memory Growth Rate (5m window):**
```promql
rate(lazydns_process_resident_memory_bytes[5m])
```

## Alerting Rules

### Recommended Alerts

Create `/etc/prometheus/alerts/lazydns_memory.yml`:

```yaml
groups:
  - name: lazydns_memory
    interval: 30s
    rules:
      # Alert: High memory usage (cgroup-aware)
      - alert: LazyDNSHighMemoryUsage
        expr: |
          (lazydns_process_cgroup_memory_bytes / lazydns_process_cgroup_memory_limit_bytes) > 0.85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "lazydns high memory usage"
          description: "lazydns is using {{ $value | humanizePercentage }} of its cgroup memory limit (> 85% for 5m)"

      # Alert: Memory usage near limit (cgroup-aware)
      - alert: LazyDNSMemoryNearLimit
        expr: |
          (lazydns_process_cgroup_memory_bytes / lazydns_process_cgroup_memory_limit_bytes) > 0.95
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "lazydns memory near limit"
          description: "lazydns is using {{ $value | humanizePercentage }} of its cgroup memory limit (> 95% for 2m)"

      # Alert: RSS growth (bare-metal)
      - alert: LazyDNSMemoryLeakSuspected
        expr: |
          rate(lazydns_process_resident_memory_bytes[1h]) > 1048576
        for: 6h
        labels:
          severity: warning
        annotations:
          summary: "lazydns possible memory leak"
          description: "RSS growing at {{ $value | humanize }}B/s for 6h (> 1MB/s sustained)"

      # Alert: Absolute RSS threshold
      - alert: LazyDNSHighRSS
        expr: lazydns_process_resident_memory_bytes > 2147483648  # 2GB
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "lazydns high RSS usage"
          description: "RSS is {{ $value | humanize }}B (> 2GB for 10m)"
```

## Grafana Dashboard

### Example Panel Queries

**Memory Usage Over Time:**
```promql
lazydns_process_resident_memory_bytes / 1024 / 1024  # Convert to MB
```

**Container Memory Utilization:**
```promql
(lazydns_process_cgroup_memory_bytes / lazydns_process_cgroup_memory_limit_bytes) * 100
```

**Memory Breakdown (Multi-series):**
```promql
label_replace(lazydns_process_resident_memory_bytes, "type", "RSS", "", "")
or
label_replace(lazydns_process_virtual_memory_bytes, "type", "VMS", "", "")
or
label_replace(lazydns_process_cgroup_memory_bytes, "type", "cgroup", "", "")
```

## Troubleshooting

### Metrics Not Appearing

1. **Verify monitoring is enabled:**
   ```bash
   curl http://localhost:9090/metrics | grep lazydns_process
   ```

2. **Check configuration:**
   ```yaml
   monitoring:
     enabled: true
     memory_metrics:
       enabled: true
   ```

3. **Check logs:**
   ```bash
   grep -i "memory metrics" /var/log/lazydns/lazydns.log
   ```

### cgroup Metrics Missing

**Symptom:** Only `/proc` metrics appear, no `cgroup` metrics.

**Cause:** Not running in a container or cgroup filesystem not mounted.

**Verification:**
```bash
# Check if cgroup v2 is available
ls -la /sys/fs/cgroup/memory.current

# Check if cgroup v1 is available
ls -la /sys/fs/cgroup/memory/memory.usage_in_bytes
```

**Expected behavior:** This is normal for bare-metal deployments. Only containers expose cgroup metrics.

### High Memory Usage Alerts

**Investigation steps:**

1. **Check cache size:**
   ```promql
   dns_cache_size
   ```

2. **Check query rate:**
   ```promql
   rate(dns_queries_total[5m])
   ```

3. **Analyze memory growth:**
   ```promql
   deriv(lazydns_process_resident_memory_bytes[1h])
   ```

4. **Review configuration:**
   - Cache limits (`max_size`, `max_entries`)
   - Number of upstream servers
   - Plugin memory footprint

## Performance Considerations

### Overhead

- **CPU**: Negligible (<0.1% additional CPU)
- **Memory**: ~4KB per sample (4 metrics × 1KB overhead)
- **I/O**: Minimal (reads small /proc and cgroup files every 5s)

### Sampling Interval Guidelines

| Use Case | Recommended Interval |
|----------|---------------------|
| Production | 5000ms (default) |
| High-volume DNS | 10000ms |
| Development/Debug | 1000ms |
| Load Testing | 500ms |

**Warning:** Intervals below 1000ms may introduce measurable overhead on high-load systems.

## Best Practices

1. **Enable by Default**: Memory metrics have minimal overhead and provide critical visibility.

2. **Use Container Metrics**: In Kubernetes/Docker, prioritize `lazydns_process_cgroup_memory_bytes` over RSS.

3. **Set Alerts**: Configure both percentage-based (cgroup) and absolute (RSS) alerts.

4. **Monitor Trends**: Track memory growth over time to detect leaks early.

5. **Correlate with Load**: Compare memory usage with `dns_queries_total` to understand per-query overhead.

6. **Review Regularly**: Check memory metrics during capacity planning.

## Example Deployment

### Docker Compose

```yaml
version: '3.8'
services:
  lazydns:
    image: lazydns:latest
    ports:
      - "53:53/udp"
      - "9090:9090"
    volumes:
      - ./config.yaml:/etc/lazydns/config.yaml
    environment:
      - RUST_LOG=info
    mem_limit: 512m  # cgroup limit will be visible in metrics
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lazydns
spec:
  template:
    spec:
      containers:
      - name: lazydns
        image: lazydns:latest
        resources:
          limits:
            memory: "512Mi"  # cgroup limit exposed via metrics
          requests:
            memory: "256Mi"
        ports:
        - containerPort: 9090
          name: metrics
---
apiVersion: v1
kind: Service
metadata:
  name: lazydns-metrics
  labels:
    app: lazydns
spec:
  ports:
  - port: 9090
    name: metrics
  selector:
    app: lazydns
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: lazydns
spec:
  selector:
    matchLabels:
      app: lazydns
  endpoints:
  - port: metrics
    interval: 15s
```

## References

- [Prometheus Best Practices](https://prometheus.io/docs/practices/naming/)
- [cgroup v2 Documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
- [Container Memory Management](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)

# RefreshCoordinator Configuration Guide

## Overview

The RefreshCoordinator manages a bounded worker pool for background cache refresh operations, replacing unbounded `tokio::spawn` calls with controlled resource usage.

## Key Benefits

1. **Bounded Resource Usage**: Fixed number of workers prevents thread explosion
2. **Deduplication**: Same key won't refresh twice concurrently
3. **Backpressure**: Queue capacity limits prevent memory overflow
4. **Statistics**: Track enqueued/processed/rejected tasks

## Configuration

### YAML Configuration

```yaml
plugins:
  - tag: my_cache
    type: cache
    args:
      size: 10000
      enable_lazycache: true
      lazycache_threshold: 0.05         # Refresh at 5% remaining TTL
      
      # RefreshCoordinator settings
      refresh_worker_count: 4           # Number of background workers (default: 4)
      refresh_queue_capacity: 1000      # Max pending tasks (default: 1000)
```

### Alternative: Stale-Serving with cache_ttl

```yaml
plugins:
  - tag: my_cache
    type: cache
    args:
      size: 10000
      cache_ttl: 300                    # Serve stale responses for 5 minutes
      
      # RefreshCoordinator settings
      refresh_worker_count: 8           # More workers for high-traffic
      refresh_queue_capacity: 2000      # Larger queue
```

## Tuning Guidelines

### Worker Count

| Scenario | Worker Count | Reasoning |
|----------|--------------|-----------|
| Low traffic (<100 qps) | 2-4 | Minimal overhead |
| Medium traffic (100-1000 qps) | 4-8 | Balance throughput and memory |
| High traffic (>1000 qps) | 8-16 | Maximize refresh throughput |

### Queue Capacity

| Scenario | Queue Capacity | Reasoning |
|----------|----------------|-----------|
| Small cache (<1000 entries) | 500-1000 | Low refresh rate |
| Medium cache (1000-10000 entries) | 1000-2000 | Default setting |
| Large cache (>10000 entries) | 2000-5000 | Handle refresh bursts |

## Statistics (Future)

The coordinator tracks comprehensive statistics:

```rust
pub struct RefreshStats {
    pub enqueued: u64,           // Total tasks enqueued
    pub processed: u64,          // Total tasks processed
    pub rejected: u64,           // Tasks rejected (queue full)
    pub dedup_skipped: u64,      // Tasks skipped (already processing)
    pub success: u64,            // Successful refreshes
    pub failed: u64,             // Failed refreshes
    pub timeout: u64,            // Timed out refreshes
}
```

Access via admin API (when implemented):
```bash
curl http://localhost:5380/admin/cache/stats
```

## Architecture

```
┌─────────────────────────────────────┐
│  CachePlugin (lazycache enabled)   │
│                                     │
│  1. Detect stale entry              │
│  2. Return cached response          │
│  3. Enqueue refresh task ──────────┐│
└─────────────────────────────────────┘│
                                      ││
┌─────────────────────────────────────┘│
│                                       │
▼                                       │
┌──────────────────────────────────────▼┐
│      RefreshCoordinator               │
├───────────────────────────────────────┤
│  - Bounded channel (queue_capacity)   │
│  - DashSet for deduplication          │
│  - Worker pool (worker_count)         │
│  - Statistics tracking                │
└───────────────────────────────────────┘
           │
           ▼
┌───────────────────────────────────────┐
│  Worker Pool (N workers)              │
│                                       │
│  Each worker:                         │
│  1. Dequeue task                      │
│  2. Execute DNS query                 │
│  3. Update cache (via plugin chain)   │
│  4. Remove from processing set        │
│  5. Record statistics                 │
└───────────────────────────────────────┘
```

## Future Extensibility

The task_queue module is designed for future extensions:

1. **File Reload Tasks**: Enqueue dataset reload operations
2. **Priority Queues**: Separate high/low priority tasks
3. **Adaptive Scaling**: Adjust worker count based on load
4. **Unified Coordinator**: Handle all background operations

## Troubleshooting

### Queue Full Warnings

If you see frequent "Refresh queue full" warnings:

1. Increase `refresh_queue_capacity`
2. Increase `refresh_worker_count` to drain faster
3. Adjust `lazycache_threshold` to reduce refresh frequency

### High Memory Usage

If memory usage is still high:

1. Reduce `refresh_queue_capacity`
2. Reduce `refresh_worker_count`
3. Monitor via `malloc_trim` hints in logs

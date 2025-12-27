# Collector Plugin

The `metrics_collector` plugin counts DNS queries and accumulates latency information. When built with the `metrics` feature it also provides a Prometheus-backed collector (`prom_metrics_collector`) that registers metrics in a Prometheus `Registry`.

This page documents the in-process collector and the optional Prometheus integration.

## What it provides

- A simple, test-friendly `MetricsCollectorPlugin` that maintains a shared counter and accumulated latency.
- When the `metrics` feature is enabled, a `PromMetricsCollectorPlugin` (it's little weird that metrics enable prometheus, but oh well) registers Prometheus metrics (counters, gauge, histogram) and exposes more detailed telemetry.
- Exec-style quick-setup helpers are provided for simple instantiation in runtime configs.

## Behavior

- Each executed plugin invocation increments a shared query counter.
- If `query_latency_ms` metadata is present (f64), the collector aggregates latency (sums) and exposes average latency via helper methods.
- The Prometheus variant records counters, error counters, a thread/activity gauge, and a latency histogram.

## Configuration

The basic collector does not require configuration beyond construction. For runtime quick-setup the exec prefix `metrics_collector` is recognized.

YAML example (exec quick setup):

```yaml
plugins:
  - exec: metrics_collector:
```

Prometheus-backed collector (requires `metrics` feature and a way to expose `/metrics`):

```yaml
plugins:
  - exec: prom_metrics_collector:name=my_dns_server
```

The `prom_metrics_collector` quick-setup accepts `name=<metric_name>` to scope/register metrics under a unique name.


## Prometheus integration

- When compiled with the `metrics` feature, `PromMetricsCollectorPlugin` registers metrics with a `prometheus::Registry` and provides the same execution behavior while exporting Prometheus metrics.
- Use the `name=<metric_name>` quick-setup to namespace metrics and avoid collisions.

## Metadata compatibility

- The collector reads `query_latency_ms` (f64) metadata to observe latency.
- The Prometheus collector also checks `query_error` (bool) metadata to increment an error counter.

## Troubleshooting

- If counts are not increasing: ensure the plugin instance is actually attached to the running pipeline and `execute()` is being called.
- For Prometheus metrics not appearing: confirm the `metrics` feature is enabled, the collector is registered with the correct registry, and the `/metrics` exposure endpoint is configured.

## Best practices

- Use the in-process collector in tests and lightweight deployments.
- Use the Prometheus-backed collector for production telemetry; provide a stable `name` to avoid metric name collisions.

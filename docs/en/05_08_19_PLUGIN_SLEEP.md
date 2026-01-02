# Sleep Plugin

`sleep` pauses processing for a configured duration. Useful for testing, simulating latency, or simple pacing.

## Exec quick-setup

Accepts durations like `100ms` or `2s`.

```yaml
plugins:
  - exec: sleep:100ms
  - exec: sleep:1s
```

## When to use

- Tests, controlled delays, and simulating slow upstreams.
- Use in rate-limiting or pacing scenarios to avoid overwhelming downstream systems.
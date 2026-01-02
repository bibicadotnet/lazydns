# Query Summary Plugin

`query_summary` builds a concise, human-readable summary of incoming questions and stores it in request metadata and logs an informational line.

## Args

- `metadata_key` (exec quick-setup string): the metadata key under which the summary is stored.

## Exec quick-setup

```yaml
plugins:
  - exec: query_summary:summary
```

## Behavior

- Joins question fragments `<qname> <qclass> <qtype>` with `; ` and stores the string in metadata.
- Emits an `info`-level log with the same summary.

## When to use

- Useful for compact request tracing and correlation with logs or metrics.
- The stored summary can be used by downstream plugins or logging systems for easier identification of requests.
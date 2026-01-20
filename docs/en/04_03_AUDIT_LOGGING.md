# Audit Logging

lazydns provides comprehensive audit logging for DNS queries and security events.

## Features

- **Query Logging**: Record DNS queries with optional response details
- **Sampling**: Reduce I/O by logging only a percentage of queries
- **Security Events**: Track rate limiting, blocked domains, upstream failures
- **Structured Output**: JSON format for SIEM integration
- **Async File I/O**: Non-blocking writes using tokio

## Configuration

The audit system is configured as a plugin in the `plugins` section.

```yaml
plugins:
  - tag: logger
    type: audit
    args:
      enabled: true
      
      # Query logging
      query_log:
        path: examples/audit/log/queries.log
        format: json              # json or text
        sampling_rate: 1.0        # Log all queries
        include_response: true    # Include response details
        include_client_ip: true   # Keep client IP (false to mask)
        buffer_size: 100          # Buffer before flush
        max_file_size: 10M        # 10MB before rotation
        max_files: 5              # Keep 5 rotated files

      # Security event logging
      security_events:
        enabled: true
        path: examples/audit/log/security.log
        events:                   # Filter events (empty = all)
          - rate_limit_exceeded
          - blocked_domain_query
          - upstream_failure
          - acl_denied
          - malformed_query
          - query_timeout
        include_query_details: true
```

## Query Log Format

### JSON Format (default)

```json
{
  "timestamp": "2025-01-19T12:34:56.789Z",
  "query_id": 12345,
  "client_ip": "192.168.1.100",
  "protocol": "udp",
  "qname": "example.com",
  "qtype": "A",
  "qclass": "IN",
  "rcode": "NOERROR",
  "answer_count": 2,
  "response_time_ms": 15,
  "cached": false,
  "answers": ["93.184.216.34"]
}
```

### Text Format

```
2025-01-19T12:34:56.789Z id=12345 client=192.168.1.100 proto=udp qname=example.com qtype=A rcode=NOERROR answers=2 time=15ms
```

## Security Events

| Event Type | Description |
|------------|-------------|
| `rate_limit_exceeded` | Client exceeded rate limit |
| `blocked_domain_query` | Query for a blocked domain |
| `upstream_failure` | Upstream DNS server failure |
| `acl_denied` | Query denied by ACL |
| `malformed_query` | Malformed DNS query received |
| `query_timeout` | Query timeout |

### Security Event JSON Format

```json
{
  "type": "security",
  "timestamp": "2025-01-19T12:34:56.789Z",
  "event_type": "rate_limit_exceeded",
  "message": "Client exceeded 100 queries/minute",
  "client_ip": "192.168.1.100",
  "qname": "example.com"
}
```

## Using the Audit Plugin

You can also use the `audit_log` plugin in your processing pipeline for more control:

```yaml
plugins:
  - tag: main
    type: sequence
    args:
      - exec: audit_log:queries           # Log query before forwarding
      - exec: $upstream
      - exec: audit_log:full              # Log with response

  # Or with custom tag
  - tag: logged_forward
    type: sequence
    args:
      - exec: audit_log:full,tag=upstream
      - exec: $dns_forward
```

### Plugin Options

| Option | Description |
|--------|-------------|
| `full` / `responses` | Include response details (default) |
| `queries` | Log queries only, no response details |
| `tag=VALUE` | Set a custom source tag |

## Sampling Strategy

For high-traffic servers, use sampling to reduce I/O:

```yaml
audit:
  enabled: true
  query_log:
    sampling_rate: 0.1  # Log 10% of queries randomly
```

Sampling uses random selection, so approximately 10% of queries will be logged. This provides a representative sample while significantly reducing disk I/O.

## Log Rotation

Query logs automatically rotate when they reach `max_file_size`:

- Current log: `queries.log`
- Rotated logs: `queries.log.1`, `queries.log.2`, etc.
- Oldest files are deleted when `max_files` limit is reached

## Performance Considerations

1. **Sampling**: Use `sampling_rate < 1.0` for high-traffic servers
2. **Buffering**: Queries are buffered before writing (configurable via `buffer_size`)
3. **Async I/O**: All writes are async and don't block query processing
4. **Separate Files**: Query logs and security events use separate files

## Integration with SIEM

The JSON output format is designed for easy SIEM integration:

### Elasticsearch

```bash
# Stream to Elasticsearch using Filebeat
filebeat -e -c filebeat.yml
```

filebeat.yml:
```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/lazydns/queries.log
    json.keys_under_root: true

output.elasticsearch:
  hosts: ["http://es.example.com:9200"]
  index: "lazydns-queries-%{+yyyy.MM.dd}"
```

### Splunk

Configure Splunk to monitor the log directory with JSON sourcetype:

```
[monitor:///var/log/lazydns/queries.log]
sourcetype = _json
index = dns_queries
```

### Syslog

For syslog export, use a log shipper like rsyslog or syslog-ng to forward the JSON logs.

## Programmatic Access

```rust
use lazydns::audit::{AUDIT_LOGGER, AuditEvent, SecurityEventType};

// Log a security event
AUDIT_LOGGER.log_security_event(
    SecurityEventType::RateLimitExceeded,
    "Client exceeded rate limit",
    Some(client_ip),
    Some(qname),
).await;

// Get statistics
let stats = AUDIT_LOGGER.stats();
println!("Queries logged: {}", stats.queries_logged);
println!("Queries sampled out: {}", stats.queries_sampled_out);
println!("Security events: {}", stats.security_events_logged);
```

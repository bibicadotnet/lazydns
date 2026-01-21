# Audit Logging

lazydns provides comprehensive audit logging for DNS queries and security events.

## Features

- **Query Logging**: Record DNS queries with optional response details
- **Sampling**: Reduce I/O by logging only a percentage of queries
- **Security Events**: Track rate limiting, blocked domains, upstream failures
- **Structured Output**: JSON format for SIEM integration
- **Async File I/O**: Non-blocking writes using tokio

## Configuration

The audit system is configured as a plugin in the `plugins` section. It supports a **unified configuration model** where buffer and rotation settings are defined globally and inherited by both logs.

### Basic Configuration

```yaml
plugins:
  - tag: audit
    type: audit
    args:
      enabled: true
      
      # Global buffer and rotation settings (inherited by both logs)
      buffer_size: 100          # Buffer before flush
      max_file_size: 10M        # 10MB before rotation
      max_files: 5              # Keep 5 rotated files
      
      # Query logging
      query_log:
        path: examples/audit/log/queries.log
        format: json              # json or text
        sampling_rate: 1.0        # Log all queries
        include_response: true    # Include response details
        include_client_ip: true   # Keep client IP (false to mask)
        # Optional: override global settings
        # buffer_size: 200
        # max_file_size: 20M
        # max_files: 10

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
        # Optional: override global settings
        # buffer_size: 50
        # max_file_size: 5M
        # max_files: 3
```

### Configuration Parameters

#### Global Parameters (Inherited by both logs)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `buffer_size` | usize | 100 | Number of entries to buffer before flushing to disk |
| `max_file_size` | u64 | 100M | Maximum log file size before rotation (supports K/M/G units) |
| `max_files` | u32 | 10 | Number of rotated files to keep |

#### Query Log Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | string | queries.log | Path to query log file |
| `format` | string | json | Output format: `json` or `text` |
| `sampling_rate` | f64 | 1.0 | Fraction of queries to log (0.0-1.0) |
| `include_response` | bool | true | Include response details |
| `include_client_ip` | bool | true | Include client IP in logs |
| `buffer_size` ⚙️ | Option<usize> | None | Override global setting |
| `max_file_size` ⚙️ | Option<u64> | None | Override global setting |
| `max_files` ⚙️ | Option<u32> | None | Override global setting |

#### Security Events Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | bool | true | Enable security event logging |
| `path` | string | security.log | Path to security log file |
| `events` | Vec<string> | [] | Events to log (empty = all) |
| `include_query_details` | bool | true | Include query details with events |
| `buffer_size` ⚙️ | Option<usize> | None | Override global setting |
| `max_file_size` ⚙️ | Option<u64> | None | Override global setting |
| `max_files` ⚙️ | Option<u32> | None | Override global setting |

⚙️ = Overridable parameter

### Parameter Inheritance

When a parameter is not specified at the log level (query_log or security_events), it inherits from the global audit level:

```
Resolution order:
1. Log-level setting (if specified)
2. Global audit setting (default fallback)
3. Code default (final fallback)
```

**Example: Aggressive query logging, conservative security logging**

```yaml
plugins:
  - tag: audit
    type: audit
    args:
      enabled: true
      # Conservative global defaults
      buffer_size: 50
      max_file_size: 10M
      max_files: 5
      
      query_log:
        path: queries.log
        format: json
        sampling_rate: 1.0
        # Override for aggressive query logging
        buffer_size: 500
        max_file_size: 100M
        max_files: 20
      
      security_events:
        enabled: true
        path: security.log
        events: []  # All events
        # Use global defaults (more conservative)
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

The audit plugin is **automatically executed** after each DNS query completes, without requiring manual addition to the processing sequence:

```yaml
plugins:
  - tag: audit
    type: audit
    args:
      enabled: true
      # ... config ...
  
  # Your normal processing sequence
  - tag: main
    type: sequence
    args:
      - exec: $validator
      - exec: $upstream        # Audit automatically runs after
      - matches: has_resp
        exec: accept           # Audit automatically runs after
```

**Key Benefits:**
- No need to manually add audit invocation to every sequence
- Consistent logging across all code paths
- Automatic execution even if sequence short-circuits

## Sampling Strategy

For high-traffic servers, use sampling to reduce I/O:

```yaml
plugins:
  - tag: audit
    type: audit
    args:
      enabled: true
      buffer_size: 500
      max_file_size: 100M
      max_files: 10
      
      query_log:
        path: queries.log
        format: json
        sampling_rate: 0.1  # Log 10% of queries randomly
        include_response: true
        include_client_ip: true
      
      security_events:
        enabled: true
        path: security.log
        events: []  # All security events (not sampled)
```

Sampling uses random selection, so approximately 10% of queries will be logged. This provides a representative sample while significantly reducing disk I/O.

**Note**: Security events are not sampled - all events are logged regardless of query sampling.

## Log Rotation

Both query logs and security event logs automatically rotate when they reach `max_file_size`:

### Rotation Behavior

```
When log file reaches max_file_size:
  1. Current file renamed to .1
  2. Existing .1 renamed to .2
  3. Existing .2 renamed to .3
  ...
  N. Oldest file (.max_files) deleted
  
Example (max_files=5):
  queries.log       (fresh, under limit)
  queries.log.1     (most recent rotation)
  queries.log.2
  queries.log.3
  queries.log.4
  queries.log.5     (oldest, will be deleted on next rotation)
```

### Storage Planning

Total disk space ≈ `max_file_size × max_files`

```
Example calculations:
  - max_file_size: 10M, max_files: 5 = ~50MB total
  - max_file_size: 50M, max_files: 10 = ~500MB total
  - max_file_size: 100M, max_files: 20 = ~2GB total
```

### Security Events Rotation (New)

Security event logs now support the same rotation mechanism as query logs, preventing unbounded disk usage for high-volume environments.

## Performance Considerations

1. **Sampling**: Use `sampling_rate < 1.0` for high-traffic servers
2. **Buffering**: Both queries and security events are buffered before writing (configurable via `buffer_size`)
   - Smaller values (10-50): Lower latency, more frequent writes
   - Larger values (100-1000): Better I/O efficiency, potential data loss if crash occurs
3. **Async I/O**: All writes are async and don't block query processing
4. **Separate Files**: Query logs and security events use separate files
5. **Unified Configuration**: Use global settings for consistency, override only when needed

### Recommended Settings

**Development/Testing:**
```yaml
buffer_size: 10
max_file_size: 5M
max_files: 3
```

**Low-Traffic Production:**
```yaml
buffer_size: 50
max_file_size: 10M
max_files: 5
```

**High-Traffic Production:**
```yaml
buffer_size: 500
max_file_size: 100M
max_files: 10
```

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

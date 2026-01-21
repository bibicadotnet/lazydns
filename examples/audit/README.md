# Audit Plugin Demo

This demo showcases the unified Audit plugin in lazydns, providing structured DNS query logging and comprehensive security event tracking.

## Overview

The audit plugin provides high-performance, asynchronous logging for both DNS queries and security-related events. It supports JSON output, log rotation, buffering, and privacy controls.

### Supported Security Events
- **rate_limit_exceeded**: Triggered when a client exceeds the limits defined in the `rate_limit` plugin.
- **blocked_domain_query**: Triggered when a query matches a blocklist in the `blackhole` plugin.
- **upstream_failure**: Triggered when an upstream DNS server returns an error or is unreachable.
- **query_timeout**: Triggered when an upstream DNS server fails to respond within the configured timeout.
- **malformed_query**: Triggered when a query fails validation (e.g., invalid domain format) in the `domain_validator` plugin.
- **acl_denied**: Triggered when a query is denied by the `acl` plugin.

## Quick Start

1. **Start the lazydns server** with the demo configuration:
   ```bash
   cargo run --features audit -- -c examples/audit/audit.demo.yaml
   ```

2. **Run the security event simulator** in another terminal:
   ```bash
   pip install dnspython
   # You may need to install it first: pip install dnspython
   python3 examples/audit/audit.demo.py
   ```

3. **Monitor the logs** in real-time:
   ```bash
   # View DNS query logs
   tail -f examples/audit/log/queries.log | jq '.'

   # View Security event logs
   tail -f examples/audit/log/security.log | jq '.'
   ```

## Configuration

The audit plugin is configured with two main sections: `query_log` and `security_events`.

### Query Logging (`query_log`)
- `path`: File path for query logs.
- `sampling_rate`: Percentage of queries to log (0.0 to 1.0).
- `include_response`: Whether to include RCODE and answer data.
- `include_client_ip`: Privacy toggle to mask client IP addresses.
- `buffer_size`: Number of entries to buffer before writing to disk.

### Security Events (`security_events`)
- `enabled`: Global toggle for security event tracking.
- `path`: File path for security logs.
- `events`: List of event types to log. Leave empty to log **all** events.
- `include_query_details`: Whether to include the triggering query info in the security log.

## Example Config Snippet

```yaml
- tag: audit
  type: audit
  args:
    enabled: true
    query_log:
      path: examples/audit/log/queries.log
      sampling_rate: 1.0
      include_client_ip: true
    security_events:
      enabled: true
      path: examples/audit/log/security.log
      events: [] # Log all security event types
```

## Demo Scenarios

The `audit.demo.py` script automatically triggers the following scenarios:

- **Normal Queries**: Standard lookups for common domains like `google.com`.
- **Blocked Domains**: Queries for `blocked-domain.local` which are blackholed.
- **Rate Limiting**: Sends a burst of 25 queries to exceed the 20/min limit.
- **Malformed Queries**: Sends invalid domain names (empty, too long, invalid characters).
- **Upstream Failures**: Queries `upstream-fail.test` (connection refused).
- **Upstream Timeouts**: Queries `timeout.test` (packet dropping IP).
- **ACL Denied**: Queries `acl-deny.test` which is explicitly denied by ACL rules.

## Privacy Features

Lazydns prioritizes privacy. By setting `include_client_ip: false` in the audit configuration, client IP addresses will be omitted from both the query logs and the security event logs, ensuring user anonymity while still allowing for operational monitoring.

---

For more details, see the inline comments in [examples/audit/audit.demo.yaml](audit.demo.yaml).

# Audit Plugin Auto-Execution: Usage Guide

## Quick Start

### 1. Enable Audit Feature
```bash
cargo build --features audit
```

### 2. Create Configuration (with Unified Config)
```yaml
# In your config.yaml

plugins:
  # Define audit plugin once
  - tag: audit
    type: audit
    args:
      enabled: true
      # Global buffer/rotation settings (inherited by both logs)
      buffer_size: 50
      max_file_size: 10M
      max_files: 5
      
      query_log:
        path: logs/queries.log
        format: json
        sampling_rate: 1.0
        # Optional: override global settings
        # buffer_size: 100
      
      security_events:
        enabled: true
        path: logs/security.log
        events: []  # Empty = all events

  # Define your sequence WITHOUT audit invocation
  - tag: sequence_main
    type: sequence
    args:
      - exec: $validator
      - exec: $upstream_dns
      - matches: has_resp
        exec: accept  # ← No audit here! (auto-executed)

  - tag: udp_server
    type: udp_server
    args:
      entry: sequence_main
      listen: :5353
```

### 3. Run Server
```bash
cargo run --features audit -- -c config.yaml
```

### 4. Test Query Logging
```bash
# In another terminal
dig @127.0.0.1 example.com

# Check logs
tail -f logs/queries.log | jq .
```

## Call Execution Flow

### Complete Request Lifecycle

```
┌─────────────────────────────────────────────────────────┐
│ 1. DNS Query Received (UDP/TCP/DoH/DoT/DoQ)            │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 2. RequestContext Created                               │
│    - DNS message parsed                                 │
│    - Client IP extracted                               │
│    - Protocol type identified                          │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 3. PluginHandler.handle() Starts                        │
│    [src/plugin/mod.rs]                                 │
│    - Metadata setup phase                              │
│      - ctx.set_metadata("client_ip", ...)              │
│      - ctx.set_metadata("protocol", ...)               │
│      - ctx.set_metadata("__plugin_registry", ...)      │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 4. MAIN SEQUENCE EXECUTION                              │
│    [User-configured sequence]                          │
│    - Validator plugin: checks domain format            │
│    - Forward plugin: queries upstream DNS              │
│    - Blackhole plugin: blocks domains                  │
│    - ... other plugins ...                             │
│    - Sequence completes with response OR empty         │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 5. POST-PROCESSING PHASE BEGINS                         │
│    (Automatic, even if sequence short-circuited)        │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 5a. Cache Write Hook                                    │
│     if ctx.has_response() {                             │
│       cache_plugin.execute(ctx)  // Store response      │
│     }                                                   │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 5b. Reverse Lookup Observation Hook                     │
│     if ctx.has_response() {                             │
│       reverse_lookup.save_ips_after(...)                │
│     }                                                   │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 5c. AUDIT LOGGING HOOK ← NEW AUTO-EXECUTION             │
│     #[cfg(feature = "audit")]                           │
│     {                                                   │
│       for each audit plugin in registry {               │
│         audit_plugin.execute(ctx)  // AUTO RUNS HERE    │
│       }                                                 │
│     }                                                   │
│                                                         │
│     Audit Plugin Internally:                           │
│     ├─ Reads ctx.request()     → Query details         │
│     ├─ Reads ctx.response()    → Response details      │
│     ├─ Reads metadata          → Client IP, protocol    │
│     ├─ Applies sampling_rate   → Filter queries        │
│     ├─ Writes to queries.log   → JSON formatted        │
│     └─ Writes to security.log  → Security events       │
│                                                         │
│     Audit logs include:                                 │
│     - Query: timestamp, qname, qtype, client_ip        │
│     - Response: rcode, answers, response_time_ms       │
│     - Events: rate_limit_exceeded, blocked_domain...   │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 6. Response Finalization                                │
│    - Set original request ID                           │
│    - Prepare for transmission                          │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 7. Response Sent to Client                              │
│    - Same response as before audit feature             │
│    - Audit running doesn't affect DNS resolution       │
└─────────────────────────────────────────────────────────┘
```

## Query Logging Explained

### What Gets Logged

```json
{
  "timestamp": "2026-01-21T10:30:45.123456Z",
  "query_id": 12345,
  "client_ip": "192.168.1.100",
  "protocol": "udp",
  "qname": "www.example.com",
  "qtype": "A",
  "qclass": "IN",
  "rcode": "NoError",
  "answer_count": 1,
  "response_time_ms": 42.5,
  "answers": [
    "93.184.216.34"
  ]
}
```

### How Sampling Works

```yaml
audit:
  query_log:
    sampling_rate: 0.1    # Log 10% of queries (randomly selected)
```

**Example with 100 queries:**
- ~10 randomly chosen queries are logged
- 90 queries are not logged
- Useful for high-traffic environments

```yaml
audit:
  query_log:
    sampling_rate: 1.0    # Log all queries (default)
```

## Security Events Explained

### Event Types and Triggers

#### 1. `rate_limit_exceeded`
**Triggered by:** `rate_limit` plugin  
**Condition:** Client exceeds configured query rate limit  
**Example:**
```yaml
- tag: rate_limiter
  type: rate_limit
  args:
    max_queries: 100      # Max 100 queries
    window_secs: 60       # per 60 seconds
```

When client sends 101 queries in 60 seconds → `rate_limit_exceeded` event

#### 2. `blocked_domain_query`
**Triggered by:** `blackhole` plugin  
**Condition:** Query matches a blocked domain  
**Example:**
```yaml
sequence:
  - matches: qname $blocked_domains
    exec: $blackhole
```

When query matches blocked_domains → `blocked_domain_query` event

#### 3. `upstream_failure`
**Triggered by:** `forward` plugin  
**Condition:** All upstream DNS servers fail  
**Example:**
```yaml
- tag: upstream_dns
  type: forward
  args:
    upstreams:
      - addr: udp://8.8.8.8
      - addr: udp://1.1.1.1
    max_attempts: 2
```

When both 8.8.8.8 and 1.1.1.1 fail → `upstream_failure` event

#### 4. `acl_denied`
**Triggered by:** `query_acl` plugin  
**Condition:** Query denied by ACL rules  
**Example:**
```yaml
sequence:
  - matches: qname $restricted_domains
    exec: $acl_deny_all    # ACL plugin denies
```

When ACL plugin returns REFUSED → `acl_denied` event

#### 5. `malformed_query`
**Triggered by:** `domain_validator` plugin  
**Condition:** DNS query format is invalid  
**Example:**
```yaml
sequence:
  - exec: $validator       # Validates query format
  - matches: has_resp
    exec: accept
```

When domain_validator detects invalid format → `malformed_query` event

#### 6. `query_timeout`
**Triggered by:** `forward` plugin (timeout handling)  
**Condition:** DNS resolution takes too long  
**Example:**
```yaml
- tag: upstream_dns
  type: forward
  args:
    timeout: 5            # 5 second timeout
```

When query takes >5 seconds → `query_timeout` event

### Event Filtering

```yaml
audit:
  security_events:
    enabled: true
    events:
      - rate_limit_exceeded
      - blocked_domain_query
      # Only these 2 types are logged
```

If you want to log ALL events:
```yaml
audit:
  security_events:
    enabled: true
    events: []            # Empty list = all events
```

### Event Output

```json
{
  "timestamp": "2026-01-21T10:30:45.200Z",
  "event_type": "blocked_domain_query",
  "severity": "warning",
  "message": "Query for blocked domain",
  "client_ip": "192.168.1.100",
  "query": {
    "qname": "malware.test",
    "qtype": "A",
    "client_ip": "192.168.1.100"
  }
}
```

## Configuration Examples

### Minimal Setup (Log Everything)
```yaml
plugins:
  - tag: audit
    type: audit
    args:
      query_log:
        path: logs/queries.log
      security_events:
        enabled: true
        path: logs/security.log

  - tag: main_sequence
    type: sequence
    args:
      - exec: $upstream_dns
      - matches: has_resp
        exec: accept

  - tag: udp_server
    type: udp_server
    args:
      entry: main_sequence
      listen: :5353
```

### High-Traffic Setup (Sample Queries)
```yaml
plugins:
  - tag: audit
    type: audit
    args:
      query_log:
        path: logs/queries.log
        sampling_rate: 0.01      # Log 1% of queries
        buffer_size: 100
        max_file_size: 100M
        max_files: 10
      security_events:
        enabled: true
        path: logs/security.log
        events: []               # All events
```

### Development Setup (Verbose)
```yaml
log:
  level: debug

plugins:
  - tag: audit
    type: audit
    args:
      query_log:
        path: logs/queries.log
        format: json
        sampling_rate: 1.0
        include_response: true
        include_client_ip: true
      security_events:
        enabled: true
        path: logs/security.log
        include_query_details: true
```

## Monitoring Audit Output

### Real-Time Query Log Monitoring
```bash
# Watch queries as they arrive
tail -f logs/queries.log | jq '.'

# Count queries per qname
tail -f logs/queries.log | jq -r '.qname' | sort | uniq -c | sort -rn

# Find slow queries (>100ms)
cat logs/queries.log | jq 'select(.response_time_ms > 100)'

# Count by response code
cat logs/queries.log | jq '.rcode' | sort | uniq -c
```

### Real-Time Security Event Monitoring
```bash
# Watch security events as they arrive
tail -f logs/security.log | jq '.'

# Count events by type
cat logs/security.log | jq '.event_type' | sort | uniq -c

# Find rate limit events
cat logs/security.log | jq 'select(.event_type == "rate_limit_exceeded")'

# Find blocked domains
cat logs/security.log | jq 'select(.event_type == "blocked_domain_query")'
```

## Troubleshooting

### Q: Audit plugin doesn't seem to be running
**A:** 
1. Check feature is enabled: `cargo run --features audit`
2. Check audit plugin is defined in config
3. Check log level: `log: level: debug` to see trace messages

### Q: Where are audit logs written?
**A:** Check your config's `audit.query_log.path` and `audit.security_events.path`

```bash
# Default locations
ls -lah logs/queries.log logs/security.log
```

### Q: Performance degradation with audit enabled?
**A:**
- Reduce sampling rate: `sampling_rate: 0.1`
- Increase buffer size: `buffer_size: 200`
- Check disk I/O is healthy: `iostat`

### Q: Audit logs are empty
**A:**
1. Verify queries are reaching the server: `tcpdump -i lo port 5353`
2. Check query count: `jq '.' logs/queries.log | wc -l`
3. Check sampling: With `sampling_rate: 0.1`, only 1 in 10 queries logged
4. Check file permissions: `ls -l logs/`

### Q: Want to disable audit without reconfiguring?
**A:** Remove `exec: $audit` from sequence (if manually added), or remove the audit plugin block entirely from config.

## Performance Tuning

### For High-Traffic Servers

```yaml
audit:
  query_log:
    sampling_rate: 0.01        # Only 1% of queries
    buffer_size: 500           # Flush every 500 entries
    max_file_size: 1G          # 1GB files
    max_files: 5               # Keep last 5 rotated files

  security_events:
    enabled: true
    events:                     # Only critical events
      - upstream_failure
      - acl_denied
      - query_timeout
```

### For Development/Testing

```yaml
audit:
  query_log:
    sampling_rate: 1.0         # All queries
    buffer_size: 10            # Flush frequently
    max_file_size: 10M         # Small files
    max_files: 3

  security_events:
    enabled: true
    events: []                 # All events
    include_query_details: true
```

## Integration with Monitoring

### Prometheus Metrics (Future)
```
# Would export metrics from audit logs
lazydns_query_total{qtype="A"} 1000
lazydns_query_time_seconds_bucket 0.001
lazydns_security_events_total{type="rate_limit_exceeded"} 5
```

### ELK Stack Integration
```bash
# Ingest audit logs to Elasticsearch
filebeat -c filebeat.yml \
  -E 'filebeat.inputs[0].paths=["/path/to/logs/queries.log"]' \
  -E 'output.elasticsearch.hosts=["localhost:9200"]'
```

### CloudWatch Logs
```bash
# Send to AWS CloudWatch
aws logs put-log-events \
  --log-group-name lazydns \
  --log-stream-name queries \
  --log-events file://logs/queries.log
```

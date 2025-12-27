# Admin API Usage Guide

The Admin API provides runtime management and monitoring capabilities for the Lazy DNS server without requiring a restart. This document covers all available endpoints, configuration, and usage examples.

## Table of Contents

- [Overview](#overview)
- [Configuration](#configuration)
- [Security Considerations](#security-considerations)
- [API Reference](#api-reference)
  - [Server Status](#server-status)
  - [Cache Statistics](#cache-statistics)
  - [Cache Control](#cache-control)
  - [Configuration Reload](#configuration-reload)
- [Examples](#examples)
  - [curl Examples](#curl-examples)
  - [Python Examples](#python-examples)
  - [HTTP Status Codes](#http-status-codes)
- [Monitoring Integration](#monitoring-integration)
- [Troubleshooting](#troubleshooting)

## Overview

The Admin API is a separate HTTP server that runs alongside your main DNS servers. It provides endpoints for:

- **Monitoring**: Check server status and cache performance metrics
- **Cache Management**: View cache statistics and clear the cache
- **Configuration**: Reload configuration without restarting the entire server

### Features

- Real-time cache statistics (size, hit rate, evictions)
- Cache control operations (clear)
- Configuration hot-reload
- Server status and version information
- Separate HTTP server (non-blocking)

### Limitations

- No built-in authentication (see [Security Considerations](#security-considerations))
- Configuration reload validates but doesn't automatically apply to running plugins
- Cache clear affects all domains immediately

## Configuration

### Basic Setup

Enable the Admin API in your `config.yaml`:

```yaml
admin:
  enabled: true
  addr: "127.0.0.1:8080"
```

### Configuration Options

| Option    | Type    | Default          | Description                  |
| --------- | ------- | ---------------- | ---------------------------- |
| `enabled` | boolean | `false`          | Enable/disable the admin API |
| `addr`    | string  | `127.0.0.1:8080` | Listen address and port      |

### Environment Variables

You can override the admin configuration using environment variables:

```bash
# Enable the admin API
export ADMIN_ENABLED=true

# Set the listen address
export ADMIN_ADDR=0.0.0.0:8080

# Start the server
lazydns
```

Supported boolean values for `ADMIN_ENABLED`: `true`, `1`, `yes` (case-insensitive)

### Examples

#### Localhost Only (Default - Recommended for Production)

```yaml
admin:
  enabled: true
  addr: "127.0.0.1:8080"
```

#### Internal Network

```yaml
admin:
  enabled: true
  addr: "192.168.1.100:8080"
```

#### All Interfaces (Use with Caution)

```yaml
admin:
  enabled: true
  addr: "0.0.0.0:8080"
```

## Security Considerations

**Important**: The Admin API has **no built-in authentication**. Anyone who can connect to the configured address can:

- Clear the cache (affecting performance)
- Reload configuration (potentially with malicious config)
- Read server status and metrics

### Security Recommendations

1. **Bind to Localhost**: Use `127.0.0.1:8080` (default) for single-machine setups
2. **Firewall Rules**: Restrict access via network-level firewall
3. **Reverse Proxy with Auth**: Use a reverse proxy (nginx, HAProxy) with authentication:
   ```nginx
   location /api/ {
       auth_basic "Admin API";
       auth_basic_user_file /etc/nginx/.htpasswd;
       proxy_pass http://127.0.0.1:8080;
   }
   ```
4. **VPN/Private Network**: Run the server on a private network, access via VPN
5. **Application-Level Auth**: Implement auth in a reverse proxy layer

### Example: nginx Reverse Proxy with Basic Auth

```nginx
server {
    listen 8443 ssl http2;
    server_name admin.example.com;

    # SSL configuration
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;

    location / {
        auth_basic "Admin API";
        auth_basic_user_file /etc/nginx/.htpasswd;

        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## API Reference

### Server Status

**Endpoint**: `GET /api/server/status`

Returns basic information about the server's operational status.

#### Request

```bash
curl http://127.0.0.1:8080/api/server/status
```

#### Response

```json
{
  "status": "running",
  "version": "0.2.8"
}
```

#### HTTP Status Codes

- `200 OK` - Server is operational

#### Use Cases

- Health checks
- Monitoring dashboards
- Uptime verification

---

### Cache Statistics

**Endpoint**: `GET /api/cache/stats`

Retrieves detailed statistics about cache performance and utilization.

#### Request

```bash
curl http://127.0.0.1:8080/api/cache/stats
```

#### Response

```json
{
  "size": 245,
  "hits": 5800,
  "misses": 1200,
  "evictions": 42,
  "hit_rate": 82.86
}
```

#### Response Fields

| Field       | Type   | Description                            |
| ----------- | ------ | -------------------------------------- |
| `size`      | number | Current number of entries in the cache |
| `hits`      | number | Total cache hits since server start    |
| `misses`    | number | Total cache misses since server start  |
| `evictions` | number | Entries removed by LRU eviction policy |
| `hit_rate`  | number | Cache hit rate as percentage (0-100)   |

#### HTTP Status Codes

- `200 OK` - Statistics retrieved successfully
- `404 Not Found` - Cache plugin not configured
- `500 Internal Server Error` - Plugin access failed

#### Interpretation

The hit rate tells you how often cached results are used:

```
hit_rate = (hits / (hits + misses)) * 100
```

- **90%+ hit rate**: Excellent cache effectiveness
- **70-90% hit rate**: Good cache performance
- **< 70% hit rate**: Consider optimization or cache size increase

#### Use Cases

- Performance monitoring
- Cache effectiveness analysis
- Capacity planning
- SLA reporting

---

### Cache Control

**Endpoint**: `POST /api/cache/control`

Perform control operations on the cache system.

#### Request

**Clear Cache**

```bash
curl -X POST http://127.0.0.1:8080/api/cache/control \
  -H "Content-Type: application/json" \
  -d '{"action": "clear"}'
```

#### Request Body

```json
{
  "action": "clear"
}
```

#### Response (Success)

```json
{
  "message": "Cache cleared successfully"
}
```

#### Response (Error)

```json
{
  "error": "Cache not configured"
}
```

#### HTTP Status Codes

- `200 OK` - Operation completed successfully
- `400 Bad Request` - Unknown action or invalid request
- `404 Not Found` - Cache not configured
- `500 Internal Server Error` - Plugin access failed

#### Supported Actions

| Action  | Description                       |
| ------- | --------------------------------- |
| `clear` | Remove all entries from the cache |

#### Use Cases

- Flush cache after configuration changes
- Test cache behavior
- Emergency cache clearing
- Performance testing

#### Important Notes

- Cache clear is **immediate** and affects all domains
- All cached DNS records will be re-fetched
- May cause **temporary increased latency** during refetch
- No cache invalidation granularity (no per-domain clear)

---

### Configuration Reload

**Endpoint**: `POST /api/config/reload`

Reload configuration from a file and validate it. This is a **hot-reload** operation that updates the in-memory configuration.

#### Request

**With Custom Path**

```bash
curl -X POST http://127.0.0.1:8080/api/config/reload \
  -H "Content-Type: application/json" \
  -d '{"path": "/etc/lazydns/config.yaml"}'
```

**With Default Path**

```bash
curl -X POST http://127.0.0.1:8080/api/config/reload \
  -H "Content-Type: application/json" \
  -d '{"path": null}'
```

Or:

```bash
curl -X POST http://127.0.0.1:8080/api/config/reload \
  -H "Content-Type: application/json" \
  -d '{}'
```

#### Request Body

```json
{
  "path": "/etc/lazydns/config.yaml"
}
```

#### Response (Success)

```json
{
  "message": "Configuration reloaded from /etc/lazydns/config.yaml"
}
```

#### Response (Error)

```json
{
  "error": "Configuration validation failed: invalid port number"
}
```

#### HTTP Status Codes

- `200 OK` - Configuration reloaded and validated successfully
- `400 Bad Request` - Configuration validation failed
- `500 Internal Server Error` - Failed to load file

#### Behavior

1. Loads the configuration file from disk
2. Validates the configuration structure
3. Updates the in-memory configuration
4. **Does not restart plugins** (requires full server restart for some changes)

#### Configuration Fields That Take Effect Immediately

- Log level and settings
- Admin server settings
- Some plugin parameters

#### Configuration Fields That Require Server Restart

- Server bindings (listen addresses)
- TLS certificates
- Plugin chain definitions

#### Use Cases

- Adjust log levels without restart
- Enable/disable features
- Update allow/blocklists
- Modify timeouts

#### Important Notes

- Configuration changes are **best-effort**
- Some changes (like server listen addresses) require a full restart
- The endpoint validates syntax but doesn't test actual functionality
- Always test configuration changes in a dev environment first

---

## Examples

### curl Examples

#### Check if server is running

```bash
curl -s http://127.0.0.1:8080/api/server/status | jq .
```

#### Get cache statistics and parse with jq

```bash
curl -s http://127.0.0.1:8080/api/cache/stats | jq .
```

#### Get only the hit rate

```bash
curl -s http://127.0.0.1:8080/api/cache/stats | jq .hit_rate
```

#### Clear cache and show result

```bash
curl -s -X POST http://127.0.0.1:8080/api/cache/control \
  -H "Content-Type: application/json" \
  -d '{"action": "clear"}' | jq .
```

#### Monitor cache in real-time (every 5 seconds)

```bash
watch -n 5 'curl -s http://127.0.0.1:8080/api/cache/stats | jq .'
```

#### Reload config with error checking

```bash
response=$(curl -s -w "\n%{http_code}" -X POST \
  http://127.0.0.1:8080/api/config/reload \
  -H "Content-Type: application/json" \
  -d '{}')

body=$(echo "$response" | head -n -1)
code=$(echo "$response" | tail -n 1)

if [ "$code" = "200" ]; then
  echo "Config reloaded successfully"
  echo "$body" | jq .
else
  echo "Config reload failed with code $code"
  echo "$body" | jq .error
fi
```

### Python Examples

#### Simple Health Check

```python
import requests
import json

def check_server_health():
    try:
        response = requests.get('http://127.0.0.1:8080/api/server/status')
        response.raise_for_status()
        data = response.json()
        print(f"Server Status: {data['status']}")
        print(f"Version: {data['version']}")
        return True
    except requests.RequestException as e:
        print(f"Health check failed: {e}")
        return False

check_server_health()
```

#### Monitor Cache Performance

```python
import requests
import time

def monitor_cache(interval=10):
    while True:
        try:
            response = requests.get('http://127.0.0.1:8080/api/cache/stats')
            stats = response.json()

            print(f"Cache Size: {stats['size']}")
            print(f"Hit Rate: {stats['hit_rate']:.2f}%")
            print(f"Total Hits: {stats['hits']}")
            print(f"Total Misses: {stats['misses']}")
            print(f"Evictions: {stats['evictions']}")
            print("-" * 40)

            time.sleep(interval)
        except Exception as e:
            print(f"Error: {e}")
            break

# Monitor cache every 10 seconds
monitor_cache(10)
```

#### Clear Cache with Retry Logic

```python
import requests
import time

def clear_cache(max_retries=3):
    for attempt in range(max_retries):
        try:
            response = requests.post(
                'http://127.0.0.1:8080/api/cache/control',
                json={'action': 'clear'},
                timeout=5
            )

            if response.status_code == 200:
                print("Cache cleared successfully")
                return True
            elif response.status_code == 404:
                print("Cache not configured")
                return False
            else:
                print(f"Error: {response.json()['error']}")
                return False

        except requests.RequestException as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(1)

    return False

clear_cache()
```

#### Reload Configuration Safely

```python
import requests
import json

def reload_config(path=None, wait_seconds=5):
    """Reload config and verify it succeeded"""
    try:
        response = requests.post(
            'http://127.0.0.1:8080/api/config/reload',
            json={'path': path},
            timeout=10
        )

        if response.status_code == 200:
            print(f"✓ {response.json()['message']}")
            return True
        elif response.status_code == 400:
            error = response.json()['error']
            print(f"✗ Validation Error: {error}")
            return False
        else:
            error = response.json()['error']
            print(f"✗ Error: {error}")
            return False

    except requests.RequestException as e:
        print(f"✗ Request failed: {e}")
        return False

# Reload default config
reload_config()

# Or reload a specific config file
reload_config('/etc/lazydns/config.yaml')
```

#### Comprehensive Admin Client

```python
import requests
from dataclasses import dataclass
from typing import Optional

@dataclass
class CacheStats:
    size: int
    hits: int
    misses: int
    evictions: int
    hit_rate: float

class AdminClient:
    def __init__(self, base_url='http://127.0.0.1:8080'):
        self.base_url = base_url
        self.session = requests.Session()

    def status(self) -> dict:
        """Get server status"""
        response = self.session.get(f'{self.base_url}/api/server/status')
        response.raise_for_status()
        return response.json()

    def cache_stats(self) -> CacheStats:
        """Get cache statistics"""
        response = self.session.get(f'{self.base_url}/api/cache/stats')
        response.raise_for_status()
        data = response.json()
        return CacheStats(**data)

    def clear_cache(self) -> bool:
        """Clear the cache"""
        response = self.session.post(
            f'{self.base_url}/api/cache/control',
            json={'action': 'clear'}
        )
        return response.status_code == 200

    def reload_config(self, path: Optional[str] = None) -> bool:
        """Reload configuration"""
        response = self.session.post(
            f'{self.base_url}/api/config/reload',
            json={'path': path}
        )
        return response.status_code == 200

# Usage
client = AdminClient()

# Check status
print(client.status())

# Get cache stats
stats = client.cache_stats()
print(f"Hit Rate: {stats.hit_rate:.2f}%")

# Clear cache
client.clear_cache()

# Reload config
client.reload_config('/etc/lazydns/config.yaml')
```

### HTTP Status Codes

| Code  | Meaning               | Common Causes                                    |
| ----- | --------------------- | ------------------------------------------------ |
| `200` | OK                    | Request succeeded                                |
| `400` | Bad Request           | Invalid action, malformed JSON, validation error |
| `404` | Not Found             | Cache not configured, plugin not available       |
| `500` | Internal Server Error | Plugin downcast failed, file I/O errors          |

#### Status Code Decision Tree

```
Request fails?
├─ Network error → Retry with backoff
├─ 404 Not Found → Check configuration
├─ 400 Bad Request → Check request format and action
├─ 500 Internal Server Error → Check logs and plugin status
└─ 200 OK → Operation succeeded
```

## Monitoring Integration

### Prometheus Integration

The Admin API complements the separate [Monitoring Server](MONITORING_USAGE.md) which provides:

- **Admin API** (this): Runtime management and real-time statistics
- **Monitoring Server**: Prometheus-compatible metrics at `/metrics`

For production monitoring, use both:

```yaml
admin:
  enabled: true
  addr: "127.0.0.1:8080"

monitoring:
  enabled: true
  addr: "127.0.0.1:9090"
```

#### Example Prometheus Scrape Config

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "lazydns"
    static_configs:
      - targets: ["localhost:9090"]
```

### Grafana Dashboards

You can create dashboards using metrics from the monitoring server:

- `dns_queries_total` - Total DNS queries
- `dns_responses_total` - DNS responses by status
- `dns_query_duration_seconds` - Query latency histogram
- `dns_cache_hits_total` - Cache hits
- `dns_cache_misses_total` - Cache misses
- `dns_cache_size` - Current cache size

For real-time management, use Admin API endpoints directly in dashboard plugins.

#### Cache metrics mapping & Prometheus usage

The cache subsystem exposes the following Prometheus metrics when the crate is built with the `metrics` feature (enabled by default):

- **`dns_cache_hits_total`** (counter): total number of cache hits recorded by the `CachePlugin`.
- **`dns_cache_misses_total`** (counter): total number of cache misses recorded by the `CachePlugin`.
- **`dns_cache_size`** (gauge): current number of entries in the cache (updated on insert/evict/clear).

Notes:

- These metrics are updated by the `CachePlugin` implementation and are only available when the `metrics` feature is enabled.
- The Admin API endpoint `GET /api/cache/stats` returns a snapshot (size, hits, misses, evictions, hit_rate). Use Prometheus metrics for time-series and alerting, and the Admin API for on-demand inspection or control.

##### Useful PromQL examples

- Instant cache hit rate (5m window):

```promql
(sum(rate(dns_cache_hits_total[5m]))
  / (sum(rate(dns_cache_hits_total[5m])) + sum(rate(dns_cache_misses_total[5m]))))
```

- Alert when hit rate is below 70% for 5 minutes:

```yaml
- alert: LowCacheHitRate
  expr: (sum(rate(dns_cache_hits_total[5m]))
    / (sum(rate(dns_cache_hits_total[5m])) + sum(rate(dns_cache_misses_total[5m])))) < 0.7
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Cache hit rate below 70%"
    description: "Cache hit rate is below 70% for at least 5 minutes."
```

- Monitor cache size and alert when it grows unexpectedly (example):

```yaml
- alert: HighCacheSize
  expr: max(dns_cache_size) > 10000
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Cache size exceeds threshold"
    description: "Cache size is larger than expected (threshold = 10000)."
```

##### Cross-check with Admin API

For quick, on-demand verification you can cross-check Prometheus metrics against the Admin API snapshot:

```bash
curl http://127.0.0.1:8080/api/cache/stats | jq .
# compare size/hits/misses with Prometheus values for sanity checks
```

### Alerting Examples

#### Alert: Low Cache Hit Rate

```yaml
- alert: LowCacheHitRate
  expr: cache_hit_rate < 0.7
  for: 5m
  annotations:
    summary: "Cache hit rate below 70%"
```

#### Alert: High Cache Evictions

```yaml
- alert: HighEvictions
  expr: increase(cache_evictions_total[5m]) > 1000
  for: 5m
  annotations:
    summary: "High number of cache evictions"
```

## Troubleshooting

### Connection Refused

**Problem**: `curl: (7) Failed to connect`

**Causes**:

- Admin API not enabled in config
- Wrong address/port
- Firewall blocking connection

**Solution**:

```bash
# Verify enabled in config
grep -A 2 'admin:' config.yaml

# Check if port is listening
netstat -tlnp | grep 8080

# Check firewall
sudo ufw allow 8080
```

### 404 Not Found on Cache Endpoints

**Problem**: `{"error": "Cache not configured"}`

**Causes**:

- Cache plugin not enabled
- Cache plugin disabled in configuration

**Solution**:

```yaml
# Ensure cache is in plugin chain
plugins:
  - type: cache
    args:
      size: 10000
```

### Configuration Reload Validation Fails

**Problem**: `{"error": "Configuration validation failed: ..."`

**Causes**:

- YAML syntax errors
- Invalid field values
- Missing required fields

**Solution**:

```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Check for common issues
grep -n ': $' config.yaml  # Missing values
grep -n $'\t' config.yaml  # Tabs instead of spaces
```

### High Latency After Cache Clear

**Problem**: DNS queries slow after clearing cache

**Expected Behavior**: This is normal. Cache clear forces upstream queries for all domains.

**Solution**:

- Clear cache during low-traffic periods
- Monitor cache hit rate before clearing: `curl http://127.0.0.1:8080/api/cache/stats`
- Use selective configuration reloads instead of full cache clear when possible

### Admin API Not Responding

**Problem**: Admin API hangs or times out

**Diagnostic Steps**:

```bash
# Test connectivity
timeout 5 curl -v http://127.0.0.1:8080/api/server/status

# Check server logs
tail -f /var/log/lazydns/main.log

# Check system resources
ps aux | grep lazydns
free -h
df -h
```

### Unicode/Special Characters in Error Messages

If you see mojibake (garbled characters) in responses, it's likely a terminal encoding issue:

```bash
# Force UTF-8
export LANG=en_US.UTF-8
curl http://127.0.0.1:8080/api/cache/stats | jq .
```

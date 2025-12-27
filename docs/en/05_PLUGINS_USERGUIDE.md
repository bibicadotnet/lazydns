# Plugins Guide (User)

## Plugin System Overview
Explain plugin execution flow, priorities, and common plugin types:
- `query` plugins (manipulate DNS queries/responses)
- `exec` plugins (side-effecting tasks)
- `flow` plugins (control flow)


### Example plugin sequence (ASCII)
This sequence shows a typical plugin chain where `hosts` provides immediate answers, `cache` handles cached responses, and `forward` sends queries to upstream resolvers when needed.

```
Client
  |
  v
 [Listener]
  |
  v
[Request Handler]
  |
  v
+--------------------------+
| Plugin: hosts            |  => If match -> Respond (short-circuit)
+--------------------------+
  |
  v
+--------------------------+
| Plugin: cache            |  => If cached -> Respond
+--------------------------+
  |
  v
+--------------------------+
| Plugin: forward          |  => Query upstream and return response
+--------------------------+
  |
  v
 Response -> Client
```


## Built-in Plugins
Short pages or subsections for major plugins with purpose & example config:
- `forward` — forward queries to upstreams
- `cache` — hierarchical cache with TTL handling
- `hosts` — static hosts mapping
- `acl` — allow/deny by client IP
- `geoip` / `geosite` — geo-based rules
- `dataset.*` — domain/ip sets
- `executable.*` — exec-style plugins (downloader, ipset, nftset)

## Example plugin configuration
```yaml
plugins:
  - tag: cache
    type: cache
    config:
      min_ttl: 30
```

## Ordering & Priority
How priorities and plugin lists affect execution.

---

TODO: Link each built-in plugin to deeper docs pages.
# Plugins Guide (User)

## Plugin System Overview
Explain plugin execution flow, priorities, and common plugin types:
- `query` plugins (manipulate DNS queries/responses)
- `exec` plugins (side-effecting tasks)
- `flow` plugins (control flow)

## Key concepts
- Plugin types:
  - **Query** plugins operate on request/response path and may return a DNS response.
  - **Exec** plugins perform side-effecting actions (e.g., update ipset, download files).
  - **Flow** plugins control execution (e.g., jump/goto/return semantics).
- **Plugin factory / builder**: registration mechanism that allows plugins to be discovered and built from configuration.
- **Datasets**: text-based domain and IP lists used by dataset plugins; support for auto-reload and merging of files/inline expressions.

## Example plugin sequence (ASCII)
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
This pipeline is intentionally simple: listeners hand requests to a single handler which executes an ordered set of plugins. Plugins may short-circuit the pipeline by producing a response (e.g., `hosts` or `cache`) or let the request continue to upstreams.



## Built-in Plugins
Short pages or subsections for major plugins with purpose & example config:
- [`forward`](05_02_PLUGIN_FORWARD.md) — forward queries to upstreams
- [`cache`](05_03_PLUGIN_CACHE.md) — hierarchical cache with TTL handling and LazyCache
- [`hosts`](05_01_PLUGIN_HOSTS.md) — static hosts mapping
- [`acl`](05_04_PLUGIN_ACL.md) — allow/deny by client IP
- [`geoip`](05_05_PLUGIN_GEOIP_GEOSITE.md) — IP-based country tagging (GeoIP)
- [`geosite`](05_05_PLUGIN_GEOIP_GEOSITE.md) — domain category tagging (GeoSite)
- [`cron`](05_06_PLUGIN_CRON.md) — scheduled background jobs (HTTP, command, invoke-plugin)
- `dataset.*` — domain/ip sets
  * [`domain_set`](05_07_01_PLUGIN_DOMAIN_SET.md) — domain matching dataset (full/domain/regexp/keyword)
  * [`ipset`](05_07_02_PLUGIN_IP_SET.md) — extract A/AAAA addresses and materialize ipset entries
- `executable.*` — exec-style plugins (downloader, ipset, nftset)
  * [`arbitrary`](05_08_01_PLUGIN_ARBITRARY.md) — return predefined DNS records for matching queries
  * [`blackhole`](05_08_02_PLUGIN_BLACK_HOLE.md) — return configured A/AAAA answers (sinkhole aliases)
  * [`collector`](05_08_03_PLUGIN_COLLECTOR.md) — simple in-process query counter; optional Prometheus collector when built with `metrics` feature



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
# Introduction

## Overview
lazydns is a lightweight, plugin-driven DNS server(smartdns/ dns-relay) designed for flexibility and performance. It supports multiple listener types (UDP, TCP, DoH, DoT, DoQ), a composable plugin pipeline, and extensible dataset formats (domain sets, IP sets, geosite). lazydns is suitable for local resolvers, DNS forwarding with caching, and policy-based filtering.

## Key features
- Modular plugin architecture (query / flow / exec plugins)
- Declarative configuration with hot-reload support
- Extensible datasets (domain/ip/geosite) with auto-reload
- High-performance I/O: async listeners for UDP/TCP and modern DNS transports
- Built-in demos and example configs to get started quickly

## Architecture (ASCII diagram)
The following ASCII diagram shows the main request flow and components in lazydns:

```
Client(s)
   |
   v
+-----------------------------------------+
|        Listeners (UDP/TCP/DoH/DoT/DoQ)  |
+-----------------------------------------+
   |
   v
+-----------------------------------------+
|      Request Handler / Dispatcher       |
+-----------------------------------------+
   |
   v
+-----------------------------------------+
|           Plugin Pipeline (ordered)     |
|  - query plugins  (inspect/modify/resp) |
|  - flow plugins   (control execution)   |
|  - exec plugins   (side effects / tasks)|
+-----------------------------------------+
   |
   v
+----------------+    +--------------------+
|  Upstreams     |<---|  Datasets / Caches  |
| (remote DNS)   |    |  (domain/ip/geo)    |
+----------------+    +--------------------+
   |
   v
 Response -> Client(s)
```

This pipeline is intentionally simple: listeners hand requests to a single handler which executes an ordered set of plugins. Plugins may short-circuit the pipeline by producing a response (e.g., `hosts` or `cache`) or let the request continue to upstreams.

## Key concepts
- Plugin types:
  - **Query** plugins operate on request/response path and may return a DNS response.
  - **Flow** plugins control execution (e.g., jump/goto/return semantics).
  - **Exec** plugins perform side-effecting actions (e.g., update ipset, download files).
- **Plugin factory / builder**: registration mechanism that allows plugins to be discovered and built from configuration.
- **Datasets**: text-based domain and IP lists used by dataset plugins; support for auto-reload and merging of files/inline expressions.

## Quick links
- [Quickstart](02_QUICKSTART.MD)
- [Core configuration](04_CONFIGURATION.MD)
- [Plugin guide](05_PLUGINS_USER_GUIDE.MD)



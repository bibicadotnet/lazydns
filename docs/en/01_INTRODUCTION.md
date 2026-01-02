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

## Quick links
- [Quickstart](02_QUICKSTART.md)
- [Core configuration](04_CONFIGURATION.md)
- [Plugin guide](05_PLUGINS_USER_GUIDE.md)



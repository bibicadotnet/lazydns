# Changelog & Releases

This file contains high-level release notes and migration guidance.

## Release v0.2.70 - 2026-01-22

**Performance Optimization**
- feat(server): add semaphore for limiting concurrent connections in TCP and UDP servers
- feat(plugins): add background cleanup tasks for RateLimitPlugin and ReverseLookupPlugin
- fix(audit): change query and security event channels to bounded to prevent memory exhaustion
- feat(arc_str): optimize DNS structures by replacing String with Arc<str> for efficient cloning and add benchmark for performance comparison

**Monitoring & Metrics**
- feat(audit): enhance audit logging with unified configuration and automatic execution
- feat(audit): implement async file-based audit logging with query and security event tracking
- feat(metrics): add DNS cache hit rate and domain validation cache hit rate metrics
- feat(metrics): add cache miss tracking and Prometheus metrics collector demo and memory metrics support

**Network Protocols**
- feat(doh, dot): enhance request context with client address support

**Development Tools**
- test(loader): reduce flakiness in roundtrip test by clearing environment overrides
- test(cgroup): add comprehensive tests for cgroup memory statistics and version detection
- test(rate_limit): enhance server readiness check and improve test reliability
- test(doq, dot, wire): add unit tests for server configuration and request handling and DNSSEC
- test(coverage): add unit tests and debug implementations for various plugins
- refactor(errors): enhance error handling with structured variants across plugins
- refactor(docker): update file paths in Dockerfile and Dockerfile.local.scratch to use /etc/lazydns

**Documentation**
- docs(ports): change admin port to 8000, metrics to 8001 by default

**Dependencies**
- chore(deps): bump criterion from 0.5.1 to 0.8.1
- chore(deps): bump thiserror from 2.0.17 to 2.0.18
- chore(deps): bump quote from 1.0.42 to 1.0.43
- chore(deps): bump serde_json from 1.0.148 to 1.0.149
- chore(deps): bump time from 0.3.44 to 0.3.45

## Release v0.2.63 - 2026-01-12

Short: Patch fixing logging/rotation compatibility and small rotation improvements.

- logs moved to `lazylog` crate for better maintenance and features.
- improved size-based rotation (copy+truncate) and made size units case-insensitive (K/M/G).
- introduced `lazydns-macros` crate for procedural macros (future use).
- Added cache eviction metrics for better monitoring.
- add grafana dashboard json config.


## Release v0.2.60 - 2026-01-03

Summary: feature and refactor release focused on plugin tagging, domain validation, cache improvements, fuzzing infrastructure, and developer tooling enhancements.

Highlights
- Domain Validator: added a new `domain-validator` plugin with LRU caching and metrics to validate domain labels and edge-cases (single-character labels) and included a demo configuration.
- Plugins: added tag support configurable from YAML, improved plugin logging, and implemented `display_name` for clearer logs.
- Graceful reloads & shutdown: file-watcher support for integrated a `Shutdown` trait for graceful plugin termination; added integration smoke tests for config reload and shutdown.
- Cache internals: replaced `DashMap` with an LRU cache for improved memory management and eviction behavior; fixed double-counting of cache misses and reduced noisy log levels.
- Fuzzing: added fuzz testing workflows and helper scripts (`fuzz/run_all.sh`) plus CI workflow improvements for fuzz target discovery and artifact collection.
- Tooling & deps: bumped `lru` to 0.16.2 and other dependency updates; CI and workflow fixes for reproducible matrix generation.
- Docs: updated server and logging documentations and improved developer contribution guidelines.

Important notes & migration
- The `domain-validator` plugin introduces new configuration and demo entries; review `examples/` and docs before enabling in production.
- Some internal data-structure changes (LRU replacement) may change memory characteristics; monitor cache metrics after upgrading.


## Release v0.2.52 - 2025-12-30

- bugfix: logging to file with rotate with localtime, not UTC
- chore(deps): bump reqwest from 0.11.27 to 0.12.28 by @dependabot[bot] in #12
- chore(deps): bump base64 from 0.21.7 to 0.22.1 by @dependabot[bot] in #11
- chore(deps): bump serde_json from 1.0.145 to 1.0.148 by @dependabot[bot] in #13
- chore(deps): bump tracing from 0.1.43 to 0.1.44 by @dependabot[bot] in #14
Highlights
- Documentation: added Arch Linux installation instructions (AUR) and updated DNS-over-TLS and server settings documentation.

## Release v0.2.50 - 2025-12-28

Summary: maintenance release with Prometheus crate upgrade, packaging/workflow improvements for cross-architecture .deb artifacts, several bug fixes, test hardening, and updated installation documentation.

Highlights
- Prometheus: upgraded to `prometheus` v0.14.0 and adapted code and tests to the updated API (label value handling and proto internals). Tests no longer rely on private proto internals and use the TextEncoder for assertions.
- Fixes: corrected Prometheus label usage and fixed a missed counter increment in the forward plugin.
- Tests: updated and hardened Prometheus-related tests; full test suite passes locally after fixes.
- Packaging & CI: added deb packages in CI for amd64 and arm64.
- Docs: added a comprehensive installation guide with `cargo install`, Debian/Ubuntu APT instructions (including Raspberry Pi OS arm64), Homebrew tap usage, and a Docker run example.

Important notes & migration
- Prometheus v0.14 raises the MSRV to Rust 1.81 — upgrade your toolchain if you use an older Rust version.
- If you previously pinned `prometheus = "0.13"`, update to `0.14` or keep the older pin and revert the code changes accordingly.

Files/areas changed in this release (non-exhaustive):
- `Cargo.toml` (package.metadata.deb variant for CI packaging)
- `.github/workflows/release.yml` (cargo-deb install + per-target packaging flags)
- `src/plugins/forward.rs` (fix label value usage and counter increment)
- `src/plugins/executable/collector.rs` (test updates to use TextEncoder; metrics-related fixes)
- `docs/en/03_INSTALLATION.md` (new installation instructions)

For more details, see the individual commits and PRs included in this release.



## Key Features (v0.2.43)

### Intelligent Cache System

- **LazyCache with Stale-Serving**: Background refresh cache with `cache_ttl` support for serving expired results during upstream failures
- **Performance**: Significantly improved DNS resolution speed and cache hit rates
- **Metrics**: Integrated Prometheus metrics for cache performance monitoring

### Comprehensive Monitoring

- **Prometheus Integration**: Cache metrics, query statistics, and health checks
- **Admin Interface**: Graceful shutdown and runtime configuration management

### Advanced Condition Matching

- **Flexible Rules**: Support for qclass, rcode, has_cname, and complex rule combinations
- **Granular Control**: Fine-tuned DNS traffic routing and filtering

### Environment Variable Configuration

- **Runtime Config**: `METRICS_ADDR`, `METRICS_ENABLED`, `ADMIN_ADDR`, `ADMIN_ENABLED`
- **Deployment Friendly**: Container-ready configuration via environment variables or `.env` files

### Optimized Build System

- **Multi-Profile**: Minimal (<2MB) and full (<4MB) builds with UPX compression
- **Cross-Platform**: Linux, macOS, Windows, FreeBSD across multiple architectures
- **Compact Binaries**: Highly optimized Rust binaries for efficient deployment
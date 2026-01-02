# Changelog & Releases

This file contains high-level release notes and migration guidance.

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
# LazyDNS

<!-- Repository badges -->

[![Rust](https://img.shields.io/badge/rust-2024--edition-orange)](https://www.rust-lang.org/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://opensource.org/licenses/GPL-3.0)
[![CI](https://github.com/lazywalker/lazydns/actions/workflows/ci.yml/badge.svg)](https://github.com/lazywalker/lazydns/actions)
[![crates.io](https://img.shields.io/crates/v/lazydns.svg)](https://crates.io/crates/lazydns)
[![docs.rs](https://docs.rs/lazydns/badge.svg)](https://docs.rs/lazydns)
[![codecov](https://codecov.io/gh/lazywalker/lazydns/branch/master/graph/badge.svg)](https://codecov.io/gh/lazywalker/lazydns)
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-brightgreen.svg)](https://github.com/lazywalker/lazydns/network/updates)
[![Maintenance](https://img.shields.io/maintenance/yes/2025)](https://github.com/lazywalker/lazydns)

## 🎯 Project Goal

Implement a Rust version of mosdns with **100% feature parity or better**, featuring:

- ✅ Full test coverage
- ✅ Complete code documentation
- 🚀 Superior performance through Rust's zero-cost abstractions
- 🔒 Memory safety guarantees

## 📚 Documentation

- **[Implementation](docs/IMPLEMENTATION.md)** - Phased implementation roadmap
- **[Environment Overrides](docs/ENV_OVERRIDE.md)** - Configuration via environment variables
- **[Cache Configuration](docs/CACHE_CONFIG_GUIDE.md)** - Advanced caching setup

## 🏃 Current Status:

- [x] DNS Protocol & Servers (UDP/TCP/DoT/DoH/DoQ)
- [x] Plugin System & Core Plugins
- [x] **LazyCache with Stale-Serving** - Background refresh cache with TTL support
- [x] **Environment Variable Configuration** - Runtime config via METRICS_ADDR, ADMIN_ADDR, etc.
- [x] **Prometheus Monitoring** - Metrics collection, health checks, and admin interface
- [x] **Advanced Condition Matching** - Flexible rule-based DNS query processing with 30+ matching plugins (Hosts, Domain, IP, GeoIP, GeoSite ...)
- [x] Caching with LRU eviction
- [x] Encrypted DNS (DoT RFC 7858, DoH RFC 8484, DoQ RFC 9250)
- [x] Multi-profile builds (minimal/full) with UPX compression
- [x] Documentation and Docker packaging

## ✨ Key Features (v0.2.31)

### 🚀 Intelligent Cache System

- **LazyCache with Stale-Serving**: Background refresh cache with `cache_ttl` support for serving expired results during upstream failures
- **Performance**: Significantly improved DNS resolution speed and cache hit rates
- **Metrics**: Integrated Prometheus metrics for cache performance monitoring

### 📊 Comprehensive Monitoring

- **Prometheus Integration**: Cache metrics, query statistics, and health checks
- **Admin Interface**: Graceful shutdown and runtime configuration management

### 🎛️ Advanced Condition Matching

- **Flexible Rules**: Support for qclass, rcode, has_cname, and complex rule combinations
- **Granular Control**: Fine-tuned DNS traffic routing and filtering

### ⚙️ Environment Variable Configuration

- **Runtime Config**: `METRICS_ADDR`, `METRICS_ENABLED`, `ADMIN_ADDR`, `ADMIN_ENABLED`
- **Deployment Friendly**: Container-ready configuration via environment variables or `.env` files

### 🏗️ Optimized Build System

- **Multi-Profile**: Minimal (<2MB) and full (<4MB) builds with UPX compression
- **Cross-Platform**: Linux, macOS, Windows, FreeBSD across multiple architectures
- **Compact Binaries**: Highly optimized Rust binaries for efficient deployment

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🙏 Acknowledgments

- [mosdns](https://github.com/IrineSistiana/mosdns) - The original inspiration
- [hickory-dns](https://github.com/hickory-dns/hickory-dns) - Rust DNS library
- The Rust community

## 📮 Contact

- GitHub Issues: [lazydns issues](https://github.com/lazywalker/lazydns/issues)

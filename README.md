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

- **[Implementation](doc/implementation.md)** - Phased implementation roadmap

## 🏃 Current Status:

- [x] DNS Protocol & Servers (UDP/TCP/DoT/DoH/DoQ)
- [x] Plugin System & Core Plugins
- [x] Caching with LRU eviction
- [x] 30+ Matching Plugins (Hosts, Domain, IP, GeoIP, GeoSite ...)
- [x] Encrypted DNS (DoT RFC 7858, DoH RFC 8484)
- [x] Documentation and Docker packaging


## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🙏 Acknowledgments

- [mosdns](https://github.com/IrineSistiana/mosdns) - The original inspiration
- [hickory-dns](https://github.com/hickory-dns/hickory-dns) - Rust DNS library
- The Rust community

## 📮 Contact

- GitHub Issues: [lazydns issues](https://github.com/lazywalker/lazydns/issues)

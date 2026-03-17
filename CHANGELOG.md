# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-03-17

### Fixed

- Bump MSRV from 1.75 to 1.85 (required by `reqwest` transitive dependencies)

## [0.1.1] - 2026-03-17 [yanked]

### Fixed

- Incorrect MSRV (set to 1.82, but dependencies require 1.83+)

## [0.1.0] - 2026-03-17

### Added

- Multi-protocol public IP detection: DNS, HTTP/HTTPS, STUN (RFC 5389)
- Built-in providers from trusted sources: Google, Cloudflare, AWS, OpenDNS
- IPv4 and IPv6 support with per-provider version capability
- Three resolution strategies: `First` (sequential fallback), `Race` (fastest wins), `Consensus` (multi-provider agreement)
- Builder-pattern configuration via `Config::builder()`
- Convenience functions: `get_ip()`, `get_ipv4()`, `get_ipv6()`, `get_ip_with()`
- Custom provider support via the `Provider` trait
- Performance-optimized default provider order (UDP-first, IPv4+IPv6 preferred)
- Zero-dependency DNS and STUN implementations (raw UDP sockets)
- Cargo features: `dns`, `stun`, `http` (all default), `native-tls` (optional)
- Structured diagnostics via `tracing`
- Examples: `simple`, `custom_providers`, `benchmark`

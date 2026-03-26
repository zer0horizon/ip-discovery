# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-03-26

### Changed

- **BREAKING:** Removed `async_trait` and `tracing` dependencies
- **BREAKING:** All public enums are now `#[non_exhaustive]`
- **BREAKING:** Removed unused `Error::Timeout` and `Error::NoProviders` variants
- **BREAKING:** `Error::ConsensusNotReached` now includes provider errors
- **BREAKING:** Removed inner STUN timeout; resolver timeout is now the single source of truth
- Updated `getrandom` to v0.4

### Fixed

- Corrected DNS buffer size RFC reference (RFC 8020 → RFC 6891)

### Documentation

- Added limitations and security notes to DNS and STUN modules

## [0.2.0] - 2026-03-18

### Changed

- **BREAKING:** `http` feature is no longer enabled by default. Only `dns` and `stun` are default, keeping the crate zero-dependency for network libraries. Enable HTTP explicitly with `features = ["http"]` or use `features = ["all"]`.
- Added `all` convenience feature to enable all protocols

### Fixed

- Fix `ancount` read from wrong DNS header offset (was reading `qdcount` at bytes 4-5 instead of `ancount` at bytes 6-7)
- Fix question section skipping to handle compression pointers and multiple questions via `qdcount` loop
- Fix infinite loop in TXT record parsing when text-length exceeds `rdlength` bounds

## [0.1.5] - 2026-03-18 [yanked]

### Fixed

- Fix `ancount` read from wrong DNS header offset (was reading `qdcount` at bytes 4-5 instead of `ancount` at bytes 6-7)
- Fix question section skipping to handle compression pointers and multiple questions via `qdcount` loop
- Fix infinite loop in TXT record parsing when text-length exceeds `rdlength` bounds

## [0.1.4] - 2026-03-17

### Fixed

- Remove `doc_auto_cfg` feature gate (removed in Rust 1.92, merged into `doc_cfg`)

## [0.1.3] - 2026-03-17

### Fixed

- Add `docs.rs` metadata to enable documentation generation with all features
- Add `doc_auto_cfg` for automatic feature gate annotations in documentation

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

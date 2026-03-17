# ip-discovery

[![Crates.io](https://img.shields.io/crates/v/ip-discovery.svg)](https://crates.io/crates/ip-discovery)
[![docs.rs](https://docs.rs/ip-discovery/badge.svg)](https://docs.rs/ip-discovery)
[![MIT/Apache-2.0](https://img.shields.io/crates/l/ip-discovery.svg)](./LICENSE-MIT)

Detect your public IP address using DNS, STUN, or HTTP — with built-in fallback across trusted providers.

## Features

- DNS and STUN via raw UDP sockets (zero network library dependencies)
- HTTP/HTTPS via [reqwest](https://docs.rs/reqwest) (optional)
- Built-in providers from Google, Cloudflare, AWS, and OpenDNS
- IPv4 and IPv6
- Sequential fallback, race, or consensus strategies
- Custom providers via the `Provider` trait
- Async, built on [tokio](https://tokio.rs)

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
ip-discovery = "0.1"
tokio = { version = "1", features = ["full"] }
```

Then:

```rust
use ip_discovery::get_ip;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let result = get_ip().await?;
    println!("{} via {} in {:?}", result.ip, result.provider, result.latency);
    Ok(())
}
```

You can also request a specific IP version:

```rust
use ip_discovery::{get_ipv4, get_ipv6};

let v4 = get_ipv4().await?;
let v6 = get_ipv6().await?;
```

## Configuration

The defaults (Cloudflare STUN → Cloudflare DNS → Google STUN/DNS → HTTP fallback; 10s timeout) work well for most cases. If you need more control:

```rust
use ip_discovery::{Config, Strategy, Protocol, BuiltinProvider, get_ip_with};
use std::time::Duration;

// DNS only, race all DNS providers
let config = Config::builder()
    .protocols(&[Protocol::Dns])
    .strategy(Strategy::Race)
    .timeout(Duration::from_secs(5))
    .build();

let result = get_ip_with(config).await?;
```

```rust
// Pick specific providers
let config = Config::builder()
    .providers(&[
        BuiltinProvider::CloudflareDns,
        BuiltinProvider::GoogleStun,
    ])
    .build();
```

```rust
// Consensus — require at least 2 providers to agree
let config = Config::builder()
    .strategy(Strategy::Consensus { min_agree: 2 })
    .build();
```

## Strategies

| Strategy | Description |
|----------|-------------|
| `First` *(default)* | Try providers in order, return first success |
| `Race` | Query all concurrently, return fastest |
| `Consensus { min_agree }` | Require N providers to agree on the same IP |

## Providers

All built-in providers are from tier-1 infrastructure companies:

| Provider | Protocol | IPv4 | IPv6 |
|----------|----------|:----:|:----:|
| Google STUN (`stun.l.google.com`) | STUN | ✅ | ✅ |
| Google STUN 1 (`stun1.l.google.com`) | STUN | ✅ | ✅ |
| Google STUN 2 (`stun2.l.google.com`) | STUN | ✅ | ✅ |
| Cloudflare STUN (`stun.cloudflare.com`) | STUN | ✅ | ✅ |
| Google DNS (`o-o.myaddr.l.google.com`) | DNS | ✅ | ✅ |
| Cloudflare DNS (`whoami.cloudflare`) | DNS | ✅ | ✅ |
| OpenDNS (`myip.opendns.com`) | DNS | ✅ | ❌ |
| Cloudflare HTTP (`1.1.1.1/cdn-cgi/trace`) | HTTP | ✅ | ❌ |
| AWS (`checkip.amazonaws.com`) | HTTP | ✅ | ❌ |

## Cargo Features

| Feature | Default | Description |
|---------|:-------:|-------------|
| `dns` | ✅ | DNS detection (raw UDP, no extra deps) |
| `stun` | ✅ | STUN detection (raw UDP, no extra deps) |
| `http` | ✅ | HTTP detection (pulls in `reqwest` + `rustls`) |
| `native-tls` | ❌ | Use OS-native TLS instead of rustls |

If you only need DNS and STUN, you can skip the HTTP dependency entirely:

```toml
ip-discovery = { version = "0.1", default-features = false, features = ["dns", "stun"] }
```

## Performance

STUN and DNS use raw UDP — no TLS handshake — so they're typically 2–3× faster than HTTP.
Default provider order prioritizes UDP-based protocols with IPv4 + IPv6 support first, then falls back to IPv4-only HTTP providers.

> **💡 Tip:** Latency varies significantly by region and network environment. Run the benchmark on
> your own infrastructure to find the optimal provider and strategy for your use case.

```bash
# Run the benchmark to find the best config for your network
cargo run --example benchmark --all-features
```

## Logging

Uses [`tracing`](https://docs.rs/tracing) for diagnostics:

```rust
tracing_subscriber::fmt()
    .with_env_filter("ip_discovery=debug")
    .init();
```

## Examples

```bash
cargo run --example simple
cargo run --example custom_providers
cargo run --example benchmark
```

## MSRV

Rust **1.85** or later.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT), at your option.

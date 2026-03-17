//! # ip-discovery
//!
//! A lightweight, high-performance Rust library for detecting public IP addresses
//! via DNS, HTTP, and STUN protocols with fallback support.
//!
//! ## Features
//!
//! - **Multi-protocol support**: DNS, HTTP/HTTPS, STUN (RFC 5389)
//! - **Trusted providers**: Google, Cloudflare, AWS, OpenDNS
//! - **Fallback mechanism**: Automatic retry with different providers
//! - **Flexible strategies**: First success, race (fastest), or consensus
//! - **Zero-dependency protocols**: DNS and STUN use raw UDP sockets
//! - **Async-first**: Built on tokio for high performance
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use ip_discovery::{get_ip, get_ipv4, get_ipv6};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Get any IP address (IPv4 or IPv6)
//!     if let Ok(result) = get_ip().await {
//!         println!("Public IP: {} (via {})", result.ip, result.provider);
//!     }
//!
//!     // Get IPv4 specifically
//!     if let Ok(result) = get_ipv4().await {
//!         println!("IPv4: {}", result.ip);
//!     }
//! }
//! ```
//!
//! ## Custom Configuration
//!
//! ```rust,no_run
//! use ip_discovery::{Config, Strategy, Protocol, BuiltinProvider, get_ip_with};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Use only DNS providers with race strategy
//!     let config = Config::builder()
//!         .protocols(&[Protocol::Dns])
//!         .strategy(Strategy::Race)
//!         .timeout(Duration::from_secs(5))
//!         .build();
//!
//!     if let Ok(result) = get_ip_with(config).await {
//!         println!("IP: {} (latency: {:?})", result.ip, result.latency);
//!     }
//!
//!     // Or pick specific providers
//!     let config = Config::builder()
//!         .providers(&[
//!             BuiltinProvider::CloudflareDns,
//!             BuiltinProvider::GoogleStun,
//!         ])
//!         .build();
//!
//!     if let Ok(result) = get_ip_with(config).await {
//!         println!("IP: {}", result.ip);
//!     }
//! }
//! ```

#![warn(missing_docs)]

mod config;
mod error;
mod provider;
mod resolver;
mod types;

#[cfg(feature = "dns")]
pub mod dns;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "stun")]
pub mod stun;

pub use config::{Config, ConfigBuilder, Strategy};
pub use error::{Error, ProviderError};
pub use provider::Provider;
pub use resolver::Resolver;
pub use types::{BuiltinProvider, IpVersion, Protocol, ProviderResult};

/// Get public IP address using default configuration.
///
/// Uses all available protocols with the [`Strategy::First`] fallback strategy
/// and a 10-second per-provider timeout.
///
/// # Errors
///
/// Returns [`Error::AllProvidersFailed`] if every provider fails.
pub async fn get_ip() -> Result<ProviderResult, Error> {
    let config = Config::default();
    get_ip_with(config).await
}

/// Get public IPv4 address using default configuration.
///
/// # Errors
///
/// Returns [`Error::AllProvidersFailed`] if no provider returns an IPv4 address.
pub async fn get_ipv4() -> Result<ProviderResult, Error> {
    let config = Config::builder().version(IpVersion::V4).build();
    get_ip_with(config).await
}

/// Get public IPv6 address using default configuration.
///
/// # Errors
///
/// Returns [`Error::NoProvidersForVersion`] if no provider supports IPv6.
pub async fn get_ipv6() -> Result<ProviderResult, Error> {
    let config = Config::builder().version(IpVersion::V6).build();
    get_ip_with(config).await
}

/// Get public IP address with a custom [`Config`].
///
/// # Errors
///
/// Returns an [`Error`] variant depending on the strategy and provider results.
pub async fn get_ip_with(config: Config) -> Result<ProviderResult, Error> {
    let resolver = Resolver::new(config);
    resolver.resolve().await
}

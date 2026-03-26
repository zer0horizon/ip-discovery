//! Configuration for IP detection.
//!
//! Use [`Config::builder()`] to create a customized configuration,
//! or [`Config::default()`] for sensible defaults (all protocols, first-success strategy).

use crate::provider::BoxedProvider;
use crate::types::{BuiltinProvider, IpVersion, Protocol};
use std::time::Duration;

/// Strategy for resolving the public IP across multiple providers.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub enum Strategy {
    /// Try providers sequentially, return the first success.
    #[default]
    First,
    /// Race all providers concurrently, return the fastest success.
    Race,
    /// Query all providers, require multiple to agree on the same IP.
    ///
    /// Values of `min_agree` below 2 are clamped to 2 at build time,
    /// since consensus with fewer than 2 providers is meaningless.
    Consensus {
        /// Minimum number of providers that must return the same IP (≥ 2).
        min_agree: usize,
    },
}

/// Configuration for IP detection
pub struct Config {
    /// List of providers to use
    pub(crate) providers: Vec<BoxedProvider>,
    /// Timeout for each provider
    pub(crate) timeout: Duration,
    /// IP version preference
    pub(crate) version: IpVersion,
    /// Resolution strategy
    pub(crate) strategy: Strategy,
}

impl Default for Config {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl Config {
    /// Create a new configuration builder
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }
}

/// Builder for [`Config`].
///
/// Created via [`Config::builder()`]. Call methods to customize, then
/// [`.build()`](ConfigBuilder::build) to produce the final [`Config`].
pub struct ConfigBuilder {
    custom_providers: Vec<BoxedProvider>,
    timeout: Duration,
    version: IpVersion,
    strategy: Strategy,
    provider_filter: Option<ProviderFilter>,
}

/// Filter to select which providers to include
enum ProviderFilter {
    /// Only providers of specified protocols
    Protocols(Vec<Protocol>),
    /// Specific built-in providers
    Select(Vec<BuiltinProvider>),
}

impl ConfigBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            custom_providers: Vec::new(),
            timeout: Duration::from_secs(10),
            version: IpVersion::Any,
            strategy: Strategy::First,
            provider_filter: None,
        }
    }

    /// Filter providers by protocol (e.g., DNS, HTTP, STUN)
    ///
    /// # Example
    /// ```rust,no_run
    /// use ip_discovery::{Config, Protocol};
    ///
    /// let config = Config::builder()
    ///     .protocols(&[Protocol::Dns, Protocol::Stun])
    ///     .build();
    /// ```
    pub fn protocols(mut self, protocols: &[Protocol]) -> Self {
        self.provider_filter = Some(ProviderFilter::Protocols(protocols.to_vec()));
        self
    }

    /// Select specific built-in providers
    ///
    /// # Example
    /// ```rust,no_run
    /// use ip_discovery::{Config, BuiltinProvider};
    ///
    /// let config = Config::builder()
    ///     .providers(&[
    ///         BuiltinProvider::CloudflareDns,
    ///         BuiltinProvider::GoogleStun,
    ///     ])
    ///     .build();
    /// ```
    pub fn providers(mut self, providers: &[BuiltinProvider]) -> Self {
        self.provider_filter = Some(ProviderFilter::Select(providers.to_vec()));
        self
    }

    /// Add a custom provider (advanced usage)
    ///
    /// Custom providers are added alongside any filter-selected providers.
    pub fn add_provider(mut self, provider: BoxedProvider) -> Self {
        self.custom_providers.push(provider);
        self
    }

    /// Set timeout for each provider
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set IP version preference
    pub fn version(mut self, version: IpVersion) -> Self {
        self.version = version;
        self
    }

    /// Set resolution strategy.
    ///
    /// For [`Strategy::Consensus`], `min_agree` is clamped to at least 2.
    pub fn strategy(mut self, strategy: Strategy) -> Self {
        self.strategy = match strategy {
            Strategy::Consensus { min_agree } => Strategy::Consensus {
                min_agree: min_agree.max(2),
            },
            other => other,
        };
        self
    }

    /// Build the configuration
    pub fn build(mut self) -> Config {
        let mut providers: Vec<BoxedProvider> = match self.provider_filter.take() {
            Some(ProviderFilter::Protocols(protocols)) => BuiltinProvider::ALL
                .iter()
                .filter(|p| protocols.contains(&p.protocol()))
                .map(|p| p.to_boxed())
                .collect(),
            Some(ProviderFilter::Select(selected)) => {
                selected.into_iter().map(|p| p.to_boxed()).collect()
            }
            None if self.custom_providers.is_empty() => {
                BuiltinProvider::ALL.iter().map(|p| p.to_boxed()).collect()
            }
            None => Vec::new(),
        };

        // Append any custom providers added via add_provider()
        providers.append(&mut self.custom_providers);

        Config {
            providers,
            timeout: self.timeout,
            version: self.version,
            strategy: self.strategy,
        }
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

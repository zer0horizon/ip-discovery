//! Resolution engine that coordinates providers and applies strategies.
//!
//! This module is the core orchestrator: it takes a [`Config`](crate::Config),
//! queries providers according to the chosen [`Strategy`](crate::Strategy),
//! and returns a [`ProviderResult`].

use crate::config::{Config, Strategy};
use crate::error::{Error, ProviderError};
use crate::types::ProviderResult;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Coordinates IP detection across configured providers.
///
/// Created via [`Resolver::new()`] with a [`Config`](crate::Config).
/// Call [`resolve()`](Resolver::resolve) to perform the lookup.
pub struct Resolver {
    config: Config,
}

impl Resolver {
    /// Create a new resolver with the given configuration
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Resolve the public IP address using the configured strategy.
    ///
    /// # Errors
    ///
    /// - [`Error::NoProvidersForVersion`] — no provider supports the requested IP version.
    /// - [`Error::AllProvidersFailed`] — every provider either failed or timed out.
    /// - [`Error::ConsensusNotReached`] — (consensus strategy) too few providers agreed.
    pub async fn resolve(&self) -> Result<ProviderResult, Error> {
        let has_matching = self
            .config
            .providers
            .iter()
            .any(|p| p.supports_version(self.config.version));

        if !has_matching {
            return Err(Error::NoProvidersForVersion);
        }

        match self.config.strategy {
            Strategy::First => self.resolve_first().await,
            Strategy::Race => self.resolve_race().await,
            Strategy::Consensus { min_agree } => {
                let min = min_agree.max(2);
                self.resolve_consensus(min).await
            }
        }
    }

    /// Try providers in order, return first success
    async fn resolve_first(&self) -> Result<ProviderResult, Error> {
        let mut errors = Vec::new();

        for provider in self
            .config
            .providers
            .iter()
            .filter(|p| p.supports_version(self.config.version))
        {
            let start = Instant::now();
            debug!(provider = provider.name(), "trying provider");

            match timeout(self.config.timeout, provider.get_ip(self.config.version)).await {
                Ok(Ok(ip)) => {
                    let latency = start.elapsed();
                    debug!(
                        provider = provider.name(),
                        ip = %ip,
                        latency = ?latency,
                        "got IP from provider"
                    );
                    return Ok(ProviderResult {
                        ip,
                        provider: provider.name().to_string(),
                        protocol: provider.protocol(),
                        latency,
                    });
                }
                Ok(Err(e)) => {
                    warn!(provider = provider.name(), error = %e, "provider failed");
                    errors.push(e);
                }
                Err(_) => {
                    warn!(provider = provider.name(), "provider timed out");
                    errors.push(ProviderError::message(provider.name(), "timeout"));
                }
            }
        }

        Err(Error::AllProvidersFailed(errors))
    }

    /// Race all providers, return fastest result
    async fn resolve_race(&self) -> Result<ProviderResult, Error> {
        use futures_util::future::select_all;

        let version = self.config.version;
        let timeout_duration = self.config.timeout;

        let futures: Vec<_> = self
            .config
            .providers
            .iter()
            .filter(|p| p.supports_version(version))
            .map(|provider| {
                let provider_name = provider.name().to_string();
                let protocol = provider.protocol();
                let start = Instant::now();
                let fut = provider.get_ip(version);

                Box::pin(async move {
                    match timeout(timeout_duration, fut).await {
                        Ok(Ok(ip)) => {
                            let latency = start.elapsed();
                            Ok(ProviderResult {
                                ip,
                                provider: provider_name,
                                protocol,
                                latency,
                            })
                        }
                        Ok(Err(e)) => Err(e),
                        Err(_) => Err(ProviderError::message(provider_name, "timeout")),
                    }
                })
            })
            .collect();

        if futures.is_empty() {
            return Err(Error::NoProvidersForVersion);
        }

        let mut futures = futures;
        let mut errors = Vec::new();

        while !futures.is_empty() {
            let (result, _index, remaining) = select_all(futures).await;
            futures = remaining;

            match result {
                Ok(provider_result) => {
                    debug!(
                        provider = %provider_result.provider,
                        ip = %provider_result.ip,
                        latency = ?provider_result.latency,
                        "race won"
                    );
                    return Ok(provider_result);
                }
                Err(e) => {
                    errors.push(e);
                }
            }
        }

        Err(Error::AllProvidersFailed(errors))
    }

    /// Query all providers and require consensus
    async fn resolve_consensus(&self, min_agree: usize) -> Result<ProviderResult, Error> {
        use futures_util::future::join_all;

        let version = self.config.version;
        let timeout_duration = self.config.timeout;

        let futures: Vec<_> = self
            .config
            .providers
            .iter()
            .filter(|p| p.supports_version(version))
            .map(|provider| {
                let provider_name = provider.name().to_string();
                let protocol = provider.protocol();
                let start = Instant::now();
                let fut = provider.get_ip(version);

                async move {
                    match timeout(timeout_duration, fut).await {
                        Ok(Ok(ip)) => {
                            let latency = start.elapsed();
                            Some(ProviderResult {
                                ip,
                                provider: provider_name,
                                protocol,
                                latency,
                            })
                        }
                        _ => None,
                    }
                }
            })
            .collect();

        if futures.is_empty() {
            return Err(Error::NoProvidersForVersion);
        }

        let results: Vec<Option<ProviderResult>> = join_all(futures).await;

        let mut ip_results: HashMap<IpAddr, Vec<ProviderResult>> = HashMap::new();
        for result in results.into_iter().flatten() {
            ip_results.entry(result.ip).or_default().push(result);
        }

        let mut best: Option<(IpAddr, usize)> = None;
        for (ip, providers) in &ip_results {
            if providers.len() >= min_agree {
                match &best {
                    None => best = Some((*ip, providers.len())),
                    Some((_, current_len)) if providers.len() > *current_len => {
                        best = Some((*ip, providers.len()))
                    }
                    _ => {}
                }
            }
        }

        match best {
            Some((ip, _)) => {
                // Safety: `best` was chosen from `ip_results`, so the key always exists
                let providers = ip_results.remove(&ip).unwrap_or_default();
                let Some(fastest) = providers.into_iter().min_by_key(|p| p.latency) else {
                    return Err(Error::ConsensusNotReached {
                        required: min_agree,
                        got: 0,
                    });
                };
                debug!(
                    ip = %ip,
                    provider = %fastest.provider,
                    "consensus reached"
                );
                Ok(fastest)
            }
            None => {
                let max_agreement = ip_results.values().map(|v| v.len()).max().unwrap_or(0);
                Err(Error::ConsensusNotReached {
                    required: min_agree,
                    got: max_agreement,
                })
            }
        }
    }
}

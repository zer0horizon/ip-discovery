//! Provider trait and boxed type alias.
//!
//! All IP detection backends (DNS, HTTP, STUN) implement [`Provider`].
//! Custom providers can also be created by implementing this trait.

use crate::error::ProviderError;
use crate::types::{IpVersion, Protocol};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

/// Trait for IP detection providers
pub trait Provider: Send + Sync {
    /// Provider name for identification
    fn name(&self) -> &str;

    /// Protocol used by this provider
    fn protocol(&self) -> Protocol;

    /// Whether this provider supports IPv4
    fn supports_v4(&self) -> bool {
        true
    }

    /// Whether this provider supports IPv6
    fn supports_v6(&self) -> bool {
        false
    }

    /// Check if provider supports the given IP version
    fn supports_version(&self, version: IpVersion) -> bool {
        match version {
            IpVersion::V4 => self.supports_v4(),
            IpVersion::V6 => self.supports_v6(),
            IpVersion::Any => self.supports_v4() || self.supports_v6(),
        }
    }

    /// Get the public IP address
    fn get_ip(
        &self,
        version: IpVersion,
    ) -> Pin<Box<dyn Future<Output = Result<IpAddr, ProviderError>> + Send + '_>>;
}

/// Type-erased provider, used internally to store heterogeneous providers.
pub type BoxedProvider = Box<dyn Provider>;

/// Stub provider returned when a protocol feature (dns/http/stun) is not enabled.
/// Always returns an error explaining which feature is missing.
pub(crate) struct DisabledProvider(pub(crate) String);

impl Provider for DisabledProvider {
    fn name(&self) -> &str {
        &self.0
    }

    fn protocol(&self) -> Protocol {
        Protocol::Http // doesn't matter, will always error
    }

    fn get_ip(
        &self,
        _version: IpVersion,
    ) -> Pin<Box<dyn Future<Output = Result<IpAddr, ProviderError>> + Send + '_>> {
        let name = self.0.clone();
        Box::pin(async move {
            Err(ProviderError::message(
                &name,
                "provider feature not enabled",
            ))
        })
    }
}

//! STUN protocol implementation for public IP detection
//!
//! Implements a minimal RFC 5389 STUN client for detecting public IP addresses.
//!
//! # Limitations
//!
//! - **No retransmission**: RFC 5389 §7.2.1 recommends retransmitting requests
//!   with exponential backoff (RTO ≥ 500 ms). This implementation sends a single
//!   binding request; packet loss is handled by the resolver's fallback strategy.
//!
//! # Security
//!
//! Transaction IDs are generated with [`getrandom`] (OS-level CSPRNG),
//! per RFC 8489 requirements.

mod message;
pub(crate) mod providers;

pub use providers::{default_providers, provider_names};

use crate::error::ProviderError;
use crate::provider::Provider;
use crate::types::{IpVersion, Protocol};
use message::{StunMessage, StunMethod};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use tokio::net::UdpSocket;

/// STUN provider for IP detection
#[derive(Debug, Clone)]
pub struct StunProvider {
    name: String,
    server: String,
    port: u16,
}

impl StunProvider {
    /// Create a new STUN provider
    pub fn new(name: impl Into<String>, server: impl Into<String>, port: u16) -> Self {
        Self {
            name: name.into(),
            server: server.into(),
            port,
        }
    }

    /// Perform STUN binding request
    async fn binding_request(&self, version: IpVersion) -> Result<IpAddr, ProviderError> {
        // Resolve server address
        let server_addr = format!("{}:{}", self.server, self.port);
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&server_addr)
            .await
            .map_err(|e| ProviderError::new(&self.name, e))?
            .collect();

        // Filter by IP version
        let addr = addrs
            .iter()
            .find(|a| match version {
                IpVersion::V4 => a.is_ipv4(),
                IpVersion::V6 => a.is_ipv6(),
                IpVersion::Any => true,
            })
            .ok_or_else(|| {
                ProviderError::message(&self.name, "no suitable address for IP version")
            })?;

        // Create local socket
        let local_addr = if addr.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };

        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| ProviderError::new(&self.name, e))?;

        socket
            .connect(addr)
            .await
            .map_err(|e| ProviderError::new(&self.name, e))?;

        // Build and send STUN binding request
        let request = StunMessage::new(StunMethod::Request);
        let request_bytes = request.encode();

        socket
            .send(&request_bytes)
            .await
            .map_err(|e| ProviderError::new(&self.name, e))?;

        // Receive response
        let mut buf = [0u8; 576]; // Minimum MTU
        let len = socket
            .recv(&mut buf)
            .await
            .map_err(|e| ProviderError::new(&self.name, e))?;

        // Parse response
        let response =
            StunMessage::decode(&buf[..len]).map_err(|e| ProviderError::message(&self.name, e))?;

        // Verify transaction ID
        if response.transaction_id() != request.transaction_id() {
            return Err(ProviderError::message(
                &self.name,
                "transaction ID mismatch",
            ));
        }

        // Extract mapped address
        response
            .get_mapped_address()
            .ok_or_else(|| ProviderError::message(&self.name, "no mapped address in response"))
    }
}

impl Provider for StunProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> Protocol {
        Protocol::Stun
    }

    fn supports_v4(&self) -> bool {
        true
    }

    fn supports_v6(&self) -> bool {
        true
    }

    fn get_ip(
        &self,
        version: IpVersion,
    ) -> Pin<Box<dyn Future<Output = Result<IpAddr, ProviderError>> + Send + '_>> {
        Box::pin(self.binding_request(version))
    }
}

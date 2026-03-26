//! DNS protocol implementation for public IP detection
//!
//! Uses DNS TXT/A records from special domains to detect public IP.
//! This implementation uses raw UDP sockets instead of external DNS libraries.
//!
//! # Security
//!
//! Transaction IDs are generated with [`getrandom`] (OS-level CSPRNG),
//! preventing DNS transaction ID spoofing attacks.

mod protocol;
pub(crate) mod providers;

pub use providers::{default_providers, provider_names};

use crate::error::ProviderError;
use crate::provider::Provider;
use crate::types::{IpVersion, Protocol};
use protocol::{build_query, parse_response, DnsClass, RecordType};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use tokio::net::UdpSocket;

/// Record type for DNS query
#[derive(Debug, Clone, Copy)]
pub enum DnsRecordType {
    /// A/AAAA record (direct IP)
    Address,
    /// TXT record (IP as text)
    Txt,
}

/// DNS provider configuration
#[derive(Debug, Clone)]
pub struct DnsProvider {
    name: String,
    query_domain: String,
    resolver_addr: SocketAddr,
    resolver_addr_v6: Option<SocketAddr>,
    record_type: DnsRecordType,
    dns_class: DnsClass,
    supports_v4: bool,
    supports_v6: bool,
}

impl DnsProvider {
    /// Create a new DNS provider
    pub fn new(
        name: impl Into<String>,
        query_domain: impl Into<String>,
        resolver_addr: SocketAddr,
        record_type: DnsRecordType,
    ) -> Self {
        Self {
            name: name.into(),
            query_domain: query_domain.into(),
            resolver_addr,
            resolver_addr_v6: None,
            record_type,
            dns_class: DnsClass::In,
            supports_v4: true,
            supports_v6: false,
        }
    }

    /// Set DNS class (for special queries like Cloudflare CHAOS)
    pub fn with_class(mut self, class: DnsClass) -> Self {
        self.dns_class = class;
        self
    }

    /// Set IPv6 support
    pub fn with_v6(mut self, supports: bool) -> Self {
        self.supports_v6 = supports;
        self
    }

    /// Set IPv6 resolver address
    ///
    /// When requesting IPv6, the query is sent to this resolver so the
    /// DNS server sees the client's IPv6 source address.
    pub fn with_v6_resolver(mut self, addr: SocketAddr) -> Self {
        self.resolver_addr_v6 = Some(addr);
        self.supports_v6 = true;
        self
    }

    /// Query for IP address using raw UDP
    async fn query(&self, version: IpVersion) -> Result<IpAddr, ProviderError> {
        // Pick resolver: use IPv6 resolver when requesting v6 if available
        let resolver = match version {
            IpVersion::V6 => self.resolver_addr_v6.unwrap_or(self.resolver_addr),
            _ => self.resolver_addr,
        };

        // Determine record type based on version and configured type
        let record_type = match self.record_type {
            DnsRecordType::Address => match version {
                IpVersion::V6 => RecordType::Aaaa,
                _ => RecordType::A,
            },
            DnsRecordType::Txt => RecordType::Txt,
        };

        // Build query packet
        let query = build_query(&self.query_domain, record_type, self.dns_class)
            .map_err(|e| ProviderError::new(&self.name, e))?;

        // Create UDP socket
        let bind_addr = if resolver.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| ProviderError::new(&self.name, e))?;

        // Send query
        socket
            .send_to(&query, resolver)
            .await
            .map_err(|e| ProviderError::new(&self.name, e))?;

        // Receive response
        let mut buf = [0u8; 1232]; // DNS Flag Day 2020 safe UDP size (RFC 6891 EDNS0)
        let len = socket
            .recv(&mut buf)
            .await
            .map_err(|e| ProviderError::new(&self.name, e))?;

        // Parse response
        let results = parse_response(&buf[..len], record_type)
            .map_err(|e| ProviderError::message(&self.name, e))?;

        // Extract IP from results
        for result in results {
            // Handle potential CIDR notation or prefixed text
            for part in result.split_whitespace() {
                let ip_str = part.split('/').next().unwrap_or(part);
                if let Ok(ip) = IpAddr::from_str(ip_str) {
                    // Filter by version if needed
                    match version {
                        IpVersion::V4 if ip.is_ipv4() => return Ok(ip),
                        IpVersion::V6 if ip.is_ipv6() => return Ok(ip),
                        IpVersion::Any => return Ok(ip),
                        _ => continue,
                    }
                }
            }
        }

        Err(ProviderError::message(
            &self.name,
            "no valid IP in DNS response",
        ))
    }
}

impl Provider for DnsProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> Protocol {
        Protocol::Dns
    }

    fn supports_v4(&self) -> bool {
        self.supports_v4
    }

    fn supports_v6(&self) -> bool {
        self.supports_v6
    }

    fn get_ip(
        &self,
        version: IpVersion,
    ) -> Pin<Box<dyn Future<Output = Result<IpAddr, ProviderError>> + Send + '_>> {
        Box::pin(self.query(version))
    }
}

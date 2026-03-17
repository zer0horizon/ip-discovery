//! Integration tests - require network access
//!
//! Run with: `cargo test --test integration -- --ignored`

use ip_discovery::{get_ip, get_ip_with, get_ipv4, Config, Protocol, Strategy};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires network"]
async fn test_get_ip_default() {
    let result = get_ip().await;
    assert!(result.is_ok(), "get_ip() failed: {:?}", result.err());
    let result = result.unwrap();
    assert!(!result.ip.is_loopback());
    assert!(!result.ip.is_unspecified());
    assert!(!result.provider.is_empty());
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_get_ipv4() {
    let result = get_ipv4().await;
    assert!(result.is_ok(), "get_ipv4() failed: {:?}", result.err());
    assert!(result.unwrap().ip.is_ipv4());
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_stun_only() {
    let config = Config::builder()
        .protocols(&[Protocol::Stun])
        .timeout(Duration::from_secs(5))
        .build();
    let result = get_ip_with(config).await;
    assert!(result.is_ok(), "STUN failed: {:?}", result.err());
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_dns_only() {
    let config = Config::builder()
        .protocols(&[Protocol::Dns])
        .timeout(Duration::from_secs(5))
        .build();
    let result = get_ip_with(config).await;
    assert!(result.is_ok(), "DNS failed: {:?}", result.err());
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_http_only() {
    let config = Config::builder()
        .protocols(&[Protocol::Http])
        .timeout(Duration::from_secs(10))
        .build();
    let result = get_ip_with(config).await;
    assert!(result.is_ok(), "HTTP failed: {:?}", result.err());
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_race_strategy() {
    let config = Config::builder()
        .strategy(Strategy::Race)
        .timeout(Duration::from_secs(10))
        .build();
    let result = get_ip_with(config).await;
    assert!(result.is_ok(), "Race failed: {:?}", result.err());
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_consensus_strategy() {
    let config = Config::builder()
        .strategy(Strategy::Consensus { min_agree: 2 })
        .timeout(Duration::from_secs(10))
        .build();
    let result = get_ip_with(config).await;
    assert!(result.is_ok(), "Consensus failed: {:?}", result.err());
}

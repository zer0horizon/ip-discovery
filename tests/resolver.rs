//! Unit tests for the resolver module — strategies, error paths, and helpers.

#[cfg(test)]
mod resolver_tests {
    use ip_discovery::{
        Config, Error, IpVersion, Protocol, Provider, ProviderError, Resolver, Strategy,
    };
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::time::Duration;

    // ── Mock providers ──────────────────────────────────────────────

    /// A provider that always returns the configured IP after an optional delay.
    struct MockProvider {
        name: String,
        ip: IpAddr,
        delay: Duration,
        v4: bool,
        v6: bool,
    }

    impl MockProvider {
        fn ok(name: &str, ip: IpAddr) -> Box<dyn Provider> {
            Box::new(Self {
                name: name.to_string(),
                ip,
                delay: Duration::ZERO,
                v4: true,
                v6: false,
            })
        }

        fn ok_delayed(name: &str, ip: IpAddr, delay: Duration) -> Box<dyn Provider> {
            Box::new(Self {
                name: name.to_string(),
                ip,
                delay,
                v4: true,
                v6: false,
            })
        }

        fn v6_only(name: &str, ip: IpAddr) -> Box<dyn Provider> {
            Box::new(Self {
                name: name.to_string(),
                ip,
                delay: Duration::ZERO,
                v4: false,
                v6: true,
            })
        }
    }

    impl Provider for MockProvider {
        fn name(&self) -> &str {
            &self.name
        }
        fn protocol(&self) -> Protocol {
            Protocol::Dns
        }
        fn supports_v4(&self) -> bool {
            self.v4
        }
        fn supports_v6(&self) -> bool {
            self.v6
        }
        fn get_ip(
            &self,
            _version: IpVersion,
        ) -> Pin<Box<dyn Future<Output = Result<IpAddr, ProviderError>> + Send + '_>> {
            let ip = self.ip;
            let delay = self.delay;
            Box::pin(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                Ok(ip)
            })
        }
    }

    /// A provider that always fails.
    struct FailProvider {
        name: String,
        msg: String,
    }

    impl FailProvider {
        fn boxed(name: &str, msg: &str) -> Box<dyn Provider> {
            Box::new(Self {
                name: name.to_string(),
                msg: msg.to_string(),
            })
        }
    }

    impl Provider for FailProvider {
        fn name(&self) -> &str {
            &self.name
        }
        fn protocol(&self) -> Protocol {
            Protocol::Stun
        }
        fn get_ip(
            &self,
            _version: IpVersion,
        ) -> Pin<Box<dyn Future<Output = Result<IpAddr, ProviderError>> + Send + '_>> {
            let name = self.name.clone();
            let msg = self.msg.clone();
            Box::pin(async move { Err(ProviderError::message(name, msg)) })
        }
    }

    /// A provider that hangs forever (for timeout testing).
    struct HangProvider {
        name: String,
    }

    impl HangProvider {
        fn boxed(name: &str) -> Box<dyn Provider> {
            Box::new(Self {
                name: name.to_string(),
            })
        }
    }

    impl Provider for HangProvider {
        fn name(&self) -> &str {
            &self.name
        }
        fn protocol(&self) -> Protocol {
            Protocol::Http
        }
        fn get_ip(
            &self,
            _version: IpVersion,
        ) -> Pin<Box<dyn Future<Output = Result<IpAddr, ProviderError>> + Send + '_>> {
            Box::pin(async move {
                // Never completes
                std::future::pending().await
            })
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn config_with(providers: Vec<Box<dyn Provider>>, strategy: Strategy) -> Config {
        let mut builder = Config::builder()
            .strategy(strategy)
            .timeout(Duration::from_secs(2));

        for p in providers {
            builder = builder.add_provider(p);
        }
        builder.build()
    }

    // ── Strategy::First ─────────────────────────────────────────────

    #[tokio::test]
    async fn first_returns_first_success() {
        let config = config_with(
            vec![
                MockProvider::ok("A", ip(1, 1, 1, 1)),
                MockProvider::ok("B", ip(2, 2, 2, 2)),
            ],
            Strategy::First,
        );
        let result = Resolver::new(config).resolve().await.unwrap();
        assert_eq!(result.ip, ip(1, 1, 1, 1));
        assert_eq!(result.provider, "A");
    }

    #[tokio::test]
    async fn first_skips_failed_returns_second() {
        let config = config_with(
            vec![
                FailProvider::boxed("Bad", "down"),
                MockProvider::ok("Good", ip(3, 3, 3, 3)),
            ],
            Strategy::First,
        );
        let result = Resolver::new(config).resolve().await.unwrap();
        assert_eq!(result.ip, ip(3, 3, 3, 3));
        assert_eq!(result.provider, "Good");
    }

    #[tokio::test]
    async fn first_all_fail_returns_all_errors() {
        let config = config_with(
            vec![
                FailProvider::boxed("A", "err1"),
                FailProvider::boxed("B", "err2"),
            ],
            Strategy::First,
        );
        let err = Resolver::new(config).resolve().await.unwrap_err();
        match err {
            Error::AllProvidersFailed(errors) => {
                assert_eq!(errors.len(), 2);
                assert!(errors[0].to_string().contains("err1"));
                assert!(errors[1].to_string().contains("err2"));
            }
            other => panic!("expected AllProvidersFailed, got: {other}"),
        }
    }

    #[tokio::test]
    async fn first_timeout_is_collected_as_error() {
        let config = config_with(
            vec![
                HangProvider::boxed("Slow"),
                MockProvider::ok("Fast", ip(4, 4, 4, 4)),
            ],
            Strategy::First,
        );
        // Should timeout on Slow, then succeed on Fast
        let result = Resolver::new(config).resolve().await.unwrap();
        assert_eq!(result.ip, ip(4, 4, 4, 4));
    }

    // ── Strategy::Race ──────────────────────────────────────────────

    #[tokio::test]
    async fn race_returns_fastest() {
        let config = config_with(
            vec![
                MockProvider::ok_delayed("Slow", ip(1, 1, 1, 1), Duration::from_millis(100)),
                MockProvider::ok("Fast", ip(2, 2, 2, 2)),
            ],
            Strategy::Race,
        );
        let result = Resolver::new(config).resolve().await.unwrap();
        assert_eq!(result.ip, ip(2, 2, 2, 2));
        assert_eq!(result.provider, "Fast");
    }

    #[tokio::test]
    async fn race_with_one_failure_still_succeeds() {
        let config = config_with(
            vec![
                FailProvider::boxed("Bad", "down"),
                MockProvider::ok("Good", ip(5, 5, 5, 5)),
            ],
            Strategy::Race,
        );
        let result = Resolver::new(config).resolve().await.unwrap();
        assert_eq!(result.ip, ip(5, 5, 5, 5));
    }

    #[tokio::test]
    async fn race_all_fail() {
        let config = config_with(
            vec![
                FailProvider::boxed("A", "err1"),
                FailProvider::boxed("B", "err2"),
                FailProvider::boxed("C", "err3"),
            ],
            Strategy::Race,
        );
        let err = Resolver::new(config).resolve().await.unwrap_err();
        match err {
            Error::AllProvidersFailed(errors) => assert_eq!(errors.len(), 3),
            other => panic!("expected AllProvidersFailed, got: {other}"),
        }
    }

    #[tokio::test]
    async fn race_timeout_plus_success() {
        let config = config_with(
            vec![
                HangProvider::boxed("Hangs"),
                MockProvider::ok("Works", ip(6, 6, 6, 6)),
            ],
            Strategy::Race,
        );
        let result = Resolver::new(config).resolve().await.unwrap();
        assert_eq!(result.ip, ip(6, 6, 6, 6));
    }

    // ── Strategy::Consensus ─────────────────────────────────────────

    #[tokio::test]
    async fn consensus_reached() {
        let config = config_with(
            vec![
                MockProvider::ok("A", ip(1, 1, 1, 1)),
                MockProvider::ok("B", ip(1, 1, 1, 1)),
                MockProvider::ok("C", ip(2, 2, 2, 2)),
            ],
            Strategy::Consensus { min_agree: 2 },
        );
        let result = Resolver::new(config).resolve().await.unwrap();
        assert_eq!(result.ip, ip(1, 1, 1, 1));
    }

    #[tokio::test]
    async fn consensus_not_reached() {
        let config = config_with(
            vec![
                MockProvider::ok("A", ip(1, 1, 1, 1)),
                MockProvider::ok("B", ip(2, 2, 2, 2)),
                MockProvider::ok("C", ip(3, 3, 3, 3)),
            ],
            Strategy::Consensus { min_agree: 2 },
        );
        let err = Resolver::new(config).resolve().await.unwrap_err();
        match err {
            Error::ConsensusNotReached {
                required,
                got,
                errors,
            } => {
                assert_eq!(required, 2);
                assert_eq!(got, 1);
                assert!(errors.is_empty()); // all providers succeeded, just disagreed
            }
            other => panic!("expected ConsensusNotReached, got: {other}"),
        }
    }

    #[tokio::test]
    async fn consensus_errors_are_reported() {
        let config = config_with(
            vec![
                MockProvider::ok("A", ip(1, 1, 1, 1)),
                FailProvider::boxed("B", "connection refused"),
                FailProvider::boxed("C", "dns timeout"),
            ],
            Strategy::Consensus { min_agree: 2 },
        );
        let err = Resolver::new(config).resolve().await.unwrap_err();
        match err {
            Error::ConsensusNotReached {
                required,
                got,
                errors,
            } => {
                assert_eq!(required, 2);
                assert_eq!(got, 1); // only A returned an IP
                assert_eq!(errors.len(), 2); // B and C both failed
                let error_msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
                assert!(error_msgs.iter().any(|m| m.contains("connection refused")));
                assert!(error_msgs.iter().any(|m| m.contains("dns timeout")));
            }
            other => panic!("expected ConsensusNotReached, got: {other}"),
        }
    }

    #[tokio::test]
    async fn consensus_picks_fastest_in_winning_group() {
        let config = config_with(
            vec![
                MockProvider::ok_delayed("Slow", ip(1, 1, 1, 1), Duration::from_millis(50)),
                MockProvider::ok("Fast", ip(1, 1, 1, 1)),
            ],
            Strategy::Consensus { min_agree: 2 },
        );
        let result = Resolver::new(config).resolve().await.unwrap();
        assert_eq!(result.ip, ip(1, 1, 1, 1));
        assert_eq!(result.provider, "Fast");
    }

    #[tokio::test]
    async fn consensus_picks_largest_group() {
        let config = config_with(
            vec![
                MockProvider::ok("A", ip(1, 1, 1, 1)),
                MockProvider::ok("B", ip(2, 2, 2, 2)),
                MockProvider::ok("C", ip(2, 2, 2, 2)),
                MockProvider::ok("D", ip(2, 2, 2, 2)),
            ],
            Strategy::Consensus { min_agree: 2 },
        );
        let result = Resolver::new(config).resolve().await.unwrap();
        // Group {2.2.2.2: [B,C,D]} has 3 members vs {1.1.1.1: [A]} has 1
        assert_eq!(result.ip, ip(2, 2, 2, 2));
    }

    // ── Error paths ─────────────────────────────────────────────────

    #[tokio::test]
    async fn no_providers_for_version() {
        // All providers are v4-only, but we request v6
        let config = {
            let mut builder = Config::builder()
                .version(IpVersion::V6)
                .timeout(Duration::from_secs(1));
            builder = builder.add_provider(MockProvider::ok("A", ip(1, 1, 1, 1)));
            builder.build()
        };
        let err = Resolver::new(config).resolve().await.unwrap_err();
        assert!(matches!(err, Error::NoProvidersForVersion));
    }

    #[tokio::test]
    async fn v6_provider_matches_v6_request() {
        let v6 = "2001:db8::1".parse::<IpAddr>().unwrap();
        let config = {
            let mut builder = Config::builder()
                .version(IpVersion::V6)
                .timeout(Duration::from_secs(1));
            builder = builder.add_provider(MockProvider::v6_only("IPv6", v6));
            builder.build()
        };
        let result = Resolver::new(config).resolve().await.unwrap();
        assert_eq!(result.ip, v6);
    }

    // ── min_agree clamping ──────────────────────────────────────────

    #[tokio::test]
    async fn min_agree_clamped_to_2_at_build() {
        // min_agree=1 should be clamped to 2 by the builder, so a single
        // provider agreeing with itself is NOT enough for consensus.
        let config = config_with(
            vec![
                MockProvider::ok("A", ip(1, 1, 1, 1)),
                MockProvider::ok("B", ip(2, 2, 2, 2)),
            ],
            Strategy::Consensus { min_agree: 1 },
        );
        // With clamping to 2: neither IP has 2 agreements → ConsensusNotReached
        let err = Resolver::new(config).resolve().await.unwrap_err();
        assert!(matches!(err, Error::ConsensusNotReached { .. }));
    }

    #[tokio::test]
    async fn min_agree_2_passes_with_clamping() {
        // min_agree=1 is clamped to 2, and two providers agree → success
        let config = config_with(
            vec![
                MockProvider::ok("A", ip(8, 8, 8, 8)),
                MockProvider::ok("B", ip(8, 8, 8, 8)),
            ],
            Strategy::Consensus { min_agree: 1 },
        );
        let result = Resolver::new(config).resolve().await.unwrap();
        assert_eq!(result.ip, ip(8, 8, 8, 8));
    }

    // ── Latency tracking ────────────────────────────────────────────

    #[tokio::test]
    async fn latency_is_nonzero_for_delayed_provider() {
        let config = config_with(
            vec![MockProvider::ok_delayed(
                "Delayed",
                ip(1, 1, 1, 1),
                Duration::from_millis(20),
            )],
            Strategy::First,
        );
        let result = Resolver::new(config).resolve().await.unwrap();
        assert!(result.latency >= Duration::from_millis(15));
    }

    // ── ConsensusNotReached Display ─────────────────────────────────

    #[test]
    fn consensus_error_display_includes_error_count() {
        let err = Error::ConsensusNotReached {
            required: 3,
            got: 1,
            errors: vec![
                ProviderError::message("A", "timeout"),
                ProviderError::message("B", "refused"),
            ],
        };
        let msg = format!("{err}");
        assert!(msg.contains("3"), "should show required count");
        assert!(msg.contains("1"), "should show got count");
        assert!(msg.contains("2 provider errors"), "should show error count");
    }

    // ── Protocol reported correctly ─────────────────────────────────

    #[tokio::test]
    async fn result_protocol_matches_provider() {
        let config = config_with(
            vec![MockProvider::ok("TestDns", ip(1, 2, 3, 4))],
            Strategy::First,
        );
        let result = Resolver::new(config).resolve().await.unwrap();
        assert_eq!(result.protocol, Protocol::Dns); // MockProvider returns Dns
    }
}

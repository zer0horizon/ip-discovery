//! Unit tests for config, error, and HTTP module

#[cfg(test)]
mod config_tests {
    use ip_discovery::{BuiltinProvider, Config, IpVersion, Protocol, Strategy};
    use std::time::Duration;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        // Default should work without panicking
        let _ = config;
    }

    #[test]
    fn test_builder_default() {
        let config = Config::builder().build();
        let _ = config;
    }

    #[test]
    fn test_builder_timeout() {
        let config = Config::builder().timeout(Duration::from_secs(3)).build();
        let _ = config;
    }

    #[test]
    fn test_builder_version_v4() {
        let config = Config::builder().version(IpVersion::V4).build();
        let _ = config;
    }

    #[test]
    fn test_builder_version_v6() {
        let config = Config::builder().version(IpVersion::V6).build();
        let _ = config;
    }

    #[test]
    fn test_builder_strategy_race() {
        let config = Config::builder().strategy(Strategy::Race).build();
        let _ = config;
    }

    #[test]
    fn test_builder_strategy_consensus() {
        let config = Config::builder()
            .strategy(Strategy::Consensus { min_agree: 3 })
            .build();
        let _ = config;
    }

    #[test]
    fn test_builder_protocol_filter() {
        let config = Config::builder().protocols(&[Protocol::Dns]).build();
        let _ = config;
    }

    #[test]
    fn test_builder_specific_providers() {
        let config = Config::builder()
            .providers(&[BuiltinProvider::CloudflareDns, BuiltinProvider::GoogleStun])
            .build();
        let _ = config;
    }

    #[test]
    fn test_builder_all_options() {
        let config = Config::builder()
            .protocols(&[Protocol::Stun, Protocol::Dns])
            .strategy(Strategy::Race)
            .version(IpVersion::V4)
            .timeout(Duration::from_secs(5))
            .build();
        let _ = config;
    }
}

#[cfg(test)]
mod error_tests {
    use ip_discovery::{Error, ProviderError};

    #[test]
    fn test_error_display_timeout() {
        let err = Error::Timeout;
        assert_eq!(format!("{}", err), "operation timed out");
    }

    #[test]
    fn test_error_display_no_providers() {
        let err = Error::NoProviders;
        assert_eq!(format!("{}", err), "no providers configured");
    }

    #[test]
    fn test_error_display_no_version() {
        let err = Error::NoProvidersForVersion;
        assert!(format!("{}", err).contains("IP version"));
    }

    #[test]
    fn test_error_display_consensus() {
        let err = Error::ConsensusNotReached {
            required: 3,
            got: 1,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("3"));
        assert!(msg.contains("1"));
    }

    #[test]
    fn test_provider_error_display() {
        let err = ProviderError::message("TestProvider", "connection refused");
        let msg = format!("{}", err);
        assert!(msg.contains("TestProvider"));
        assert!(msg.contains("connection refused"));
    }

    #[test]
    fn test_provider_error_new() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
        let err = ProviderError::new("Google DNS", io_err);
        let msg = format!("{}", err);
        assert!(msg.contains("Google DNS"));
    }

    #[test]
    fn test_all_providers_failed() {
        let errors = vec![
            ProviderError::message("A", "fail1"),
            ProviderError::message("B", "fail2"),
        ];
        let err = Error::AllProvidersFailed(errors);
        let msg = format!("{}", err);
        assert!(msg.contains("all providers failed"));
    }
}

#[cfg(test)]
mod types_tests {
    use ip_discovery::{BuiltinProvider, IpVersion, Protocol};

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", Protocol::Dns), "DNS");
        assert_eq!(format!("{}", Protocol::Http), "HTTP");
        assert_eq!(format!("{}", Protocol::Stun), "STUN");
    }

    #[test]
    fn test_builtin_provider_protocol() {
        assert_eq!(BuiltinProvider::GoogleStun.protocol(), Protocol::Stun);
        assert_eq!(BuiltinProvider::CloudflareDns.protocol(), Protocol::Dns);
        assert_eq!(BuiltinProvider::Aws.protocol(), Protocol::Http);
    }

    #[test]
    fn test_builtin_provider_display() {
        assert_eq!(format!("{}", BuiltinProvider::GoogleStun), "Google STUN");
        assert_eq!(
            format!("{}", BuiltinProvider::CloudflareDns),
            "Cloudflare DNS"
        );
        assert_eq!(format!("{}", BuiltinProvider::Aws), "AWS");
    }

    #[test]
    fn test_builtin_provider_all() {
        assert_eq!(BuiltinProvider::ALL.len(), 9);
    }

    #[test]
    fn test_ip_version_default() {
        let version = IpVersion::default();
        assert_eq!(version, IpVersion::Any);
    }
}

#[cfg(feature = "http")]
#[cfg(test)]
mod http_tests {
    use ip_discovery::http::{parse_cloudflare_trace, parse_plain_text};

    #[test]
    fn test_parse_plain_text_ipv4() {
        let ip = parse_plain_text("1.2.3.4\n");
        assert!(ip.is_some());
        assert_eq!(ip.unwrap().to_string(), "1.2.3.4");
    }

    #[test]
    fn test_parse_plain_text_ipv6() {
        let ip = parse_plain_text("2001:db8::1\n");
        assert!(ip.is_some());
    }

    #[test]
    fn test_parse_plain_text_invalid() {
        let ip = parse_plain_text("not an ip");
        assert!(ip.is_none());
    }

    #[test]
    fn test_parse_plain_text_empty() {
        let ip = parse_plain_text("");
        assert!(ip.is_none());
    }

    #[test]
    fn test_parse_cloudflare_trace() {
        let response = "fl=123abc\nip=203.0.113.1\nts=1234567890\n";
        let ip = parse_cloudflare_trace(response);
        assert!(ip.is_some());
        assert_eq!(ip.unwrap().to_string(), "203.0.113.1");
    }

    #[test]
    fn test_parse_cloudflare_trace_no_ip() {
        let response = "fl=123abc\nts=1234567890\n";
        let ip = parse_cloudflare_trace(response);
        assert!(ip.is_none());
    }

    #[test]
    fn test_parse_cloudflare_trace_ipv6() {
        let response = "fl=abc\nip=2001:db8::1\nts=123\n";
        let ip = parse_cloudflare_trace(response);
        assert!(ip.is_some());
    }
}

use ip_discovery::{
    BuiltinProvider as RustBuiltinProvider, Config, IpVersion as RustIpVersion,
    Protocol as RustProtocol, Strategy as RustStrategy,
};
use napi_derive::napi;
use std::time::Duration;

#[napi]
pub enum IpVersion {
    V4,
    V6,
    Any,
}

#[napi]
pub enum Strategy {
    First,
    Race,
    Consensus,
}

#[napi]
pub enum Protocol {
    Dns,
    Http,
    Stun,
}

#[napi]
pub enum BuiltinProvider {
    GoogleStun,
    GoogleStun1,
    GoogleStun2,
    CloudflareStun,
    GoogleDns,
    CloudflareDns,
    OpenDns,
    CloudflareHttp,
    Aws,
}

#[napi(object)]
pub struct JsProviderResult {
    pub ip: String,
    pub provider: String,
    pub protocol: String,
    pub latency_ms: u32,
}

#[napi(object)]
pub struct JsConfig {
    pub timeout_ms: Option<u32>,
    pub version: Option<IpVersion>,
    pub strategy: Option<Strategy>,
    pub protocols: Option<Vec<Protocol>>,
    pub providers: Option<Vec<BuiltinProvider>>,
}

#[napi]
pub async fn get_ip(config: Option<JsConfig>) -> napi::Result<JsProviderResult> {
    let mut builder = Config::builder();

    if let Some(cfg) = config {
        if let Some(timeout_ms) = cfg.timeout_ms {
            builder = builder.timeout(Duration::from_millis(timeout_ms as u64));
        }

        if let Some(version) = cfg.version {
            let rust_version = match version {
                IpVersion::V4 => RustIpVersion::V4,
                IpVersion::V6 => RustIpVersion::V6,
                IpVersion::Any => RustIpVersion::Any,
            };
            builder = builder.version(rust_version);
        }

        if let Some(strategy) = cfg.strategy {
            let rust_strategy = match strategy {
                Strategy::First => RustStrategy::First,
                Strategy::Race => RustStrategy::Race,
                // Clamping consensus min_agree to 2 (minimum meaningful threshold).
                Strategy::Consensus => RustStrategy::Consensus { min_agree: 2 },
            };
            builder = builder.strategy(rust_strategy);
        }

        if let Some(protocols) = cfg.protocols {
            let mut mapped_protocols = Vec::new();
            for p in protocols {
                let proto = match p {
                    Protocol::Dns => RustProtocol::Dns,
                    Protocol::Http => RustProtocol::Http,
                    Protocol::Stun => RustProtocol::Stun,
                };
                mapped_protocols.push(proto);
            }
            builder = builder.protocols(&mapped_protocols);
        }

        if let Some(providers) = cfg.providers {
            let mut mapped_providers = Vec::new();
            for p in providers {
                let prov = match p {
                    BuiltinProvider::GoogleStun => RustBuiltinProvider::GoogleStun,
                    BuiltinProvider::GoogleStun1 => RustBuiltinProvider::GoogleStun1,
                    BuiltinProvider::GoogleStun2 => RustBuiltinProvider::GoogleStun2,
                    BuiltinProvider::CloudflareStun => RustBuiltinProvider::CloudflareStun,
                    BuiltinProvider::GoogleDns => RustBuiltinProvider::GoogleDns,
                    BuiltinProvider::CloudflareDns => RustBuiltinProvider::CloudflareDns,
                    BuiltinProvider::OpenDns => RustBuiltinProvider::OpenDns,
                    BuiltinProvider::CloudflareHttp => RustBuiltinProvider::CloudflareHttp,
                    BuiltinProvider::Aws => RustBuiltinProvider::Aws,
                };
                mapped_providers.push(prov);
            }
            builder = builder.providers(&mapped_providers);
        }
    }

    let rust_config = builder.build();
    match ip_discovery::get_ip_with(rust_config).await {
        Ok(res) => Ok(JsProviderResult {
            ip: res.ip.to_string(),
            provider: res.provider,
            protocol: format!("{}", res.protocol),
            latency_ms: res.latency.as_millis() as u32,
        }),
        Err(e) => Err(napi::Error::new(
            napi::Status::GenericFailure,
            format!("IP discovery failed: {}", e),
        )),
    }
}

#[napi]
pub async fn get_ipv4() -> napi::Result<JsProviderResult> {
    match ip_discovery::get_ipv4().await {
        Ok(res) => Ok(JsProviderResult {
            ip: res.ip.to_string(),
            provider: res.provider,
            protocol: format!("{}", res.protocol),
            latency_ms: res.latency.as_millis() as u32,
        }),
        Err(e) => Err(napi::Error::new(
            napi::Status::GenericFailure,
            format!("IPv4 discovery failed: {}", e),
        )),
    }
}

#[napi]
pub async fn get_ipv6() -> napi::Result<JsProviderResult> {
    match ip_discovery::get_ipv6().await {
        Ok(res) => Ok(JsProviderResult {
            ip: res.ip.to_string(),
            provider: res.provider,
            protocol: format!("{}", res.protocol),
            latency_ms: res.latency.as_millis() as u32,
        }),
        Err(e) => Err(napi::Error::new(
            napi::Status::GenericFailure,
            format!("IPv6 discovery failed: {}", e),
        )),
    }
}

#[napi]
pub fn get_private_ip() -> Option<String> {
    ip_discovery::get_private_ip().map(|ip| ip.to_string())
}

#[napi]
pub fn get_private_ipv6() -> Option<String> {
    ip_discovery::get_private_ipv6().map(|ip| ip.to_string())
}

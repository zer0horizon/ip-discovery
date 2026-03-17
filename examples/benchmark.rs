//! Comprehensive benchmark — compare protocols, providers, strategies, and IP versions.
//!
//! Run with:
//!   cargo run --example benchmark --all-features

use ip_discovery::{get_ip_with, BuiltinProvider, Config, IpVersion, Protocol, Strategy};
use std::time::{Duration, Instant};

const ITERATIONS: u32 = 5;

#[tokio::main]
async fn main() {
    println!("╔══════════════════════════════════════════════╗");
    println!("║       Public IP Detection Benchmark          ║");
    println!("╚══════════════════════════════════════════════╝\n");
    println!("Iterations per test: {ITERATIONS}\n");

    // ── Section 1: Per-Provider Benchmark (IPv4) ────────────────────────
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  SECTION 1: Per-Provider Benchmark (IPv4)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let providers = [
        // STUN
        ("Google STUN", BuiltinProvider::GoogleStun),
        ("Google STUN 1", BuiltinProvider::GoogleStun1),
        ("Google STUN 2", BuiltinProvider::GoogleStun2),
        ("Cloudflare STUN", BuiltinProvider::CloudflareStun),
        // DNS
        ("Google DNS", BuiltinProvider::GoogleDns),
        ("Cloudflare DNS", BuiltinProvider::CloudflareDns),
        ("OpenDNS", BuiltinProvider::OpenDns),
        // HTTP
        ("Cloudflare HTTP", BuiltinProvider::CloudflareHttp),
        ("AWS", BuiltinProvider::Aws),
    ];

    for (label, provider) in &providers {
        benchmark_provider(label, *provider, IpVersion::V4).await;
    }

    // ── Section 2: Per-Provider Benchmark (IPv6) ────────────────────────
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  SECTION 2: Per-Provider Benchmark (IPv6)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    for (label, provider) in &providers {
        benchmark_provider(label, *provider, IpVersion::V6).await;
    }

    // ── Section 3: Protocol Comparison (IPv4 vs IPv6) ───────────────────
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  SECTION 3: Protocol Comparison (IPv4 vs IPv6)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    for protocol in [Protocol::Stun, Protocol::Dns, Protocol::Http] {
        println!("── {protocol} ──");
        println!("  IPv4:");
        benchmark_protocol(protocol, IpVersion::V4).await;
        println!("  IPv6:");
        benchmark_protocol(protocol, IpVersion::V6).await;
        println!();
    }

    // ── Section 4: Strategy Comparison ──────────────────────────────────
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  SECTION 4: Strategy Comparison (IPv4)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("── First (sequential fallback) ──");
    benchmark_strategy(Strategy::First, IpVersion::V4).await;

    println!("\n── Race (fastest wins) ──");
    benchmark_strategy(Strategy::Race, IpVersion::V4).await;

    println!("\n── Consensus (min_agree=2) ──");
    benchmark_strategy(Strategy::Consensus { min_agree: 2 }, IpVersion::V4).await;

    println!("\n── Consensus (min_agree=3) ──");
    benchmark_strategy(Strategy::Consensus { min_agree: 3 }, IpVersion::V4).await;

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  SECTION 5: Strategy Comparison (IPv6)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("── First (sequential fallback) ──");
    benchmark_strategy(Strategy::First, IpVersion::V6).await;

    println!("\n── Race (fastest wins) ──");
    benchmark_strategy(Strategy::Race, IpVersion::V6).await;

    println!("\n── Consensus (min_agree=2) ──");
    benchmark_strategy(Strategy::Consensus { min_agree: 2 }, IpVersion::V6).await;

    println!("\n╔══════════════════════════════════════════════╗");
    println!("║                Benchmark Done                ║");
    println!("╚══════════════════════════════════════════════╝");
}

// ── Per-provider benchmark ──────────────────────────────────────────────────

async fn benchmark_provider(label: &str, provider: BuiltinProvider, version: IpVersion) {
    let version_label = version_str(version);
    println!("  {label} ({version_label}):");

    // Warm-up run (not counted)
    let warmup_config = Config::builder()
        .providers(&[provider])
        .version(version)
        .timeout(Duration::from_secs(5))
        .build();
    let _ = get_ip_with(warmup_config).await;

    let mut times = Vec::new();
    let mut last_ip = String::new();

    for i in 0..ITERATIONS {
        let config = Config::builder()
            .providers(&[provider])
            .version(version)
            .timeout(Duration::from_secs(5))
            .build();

        let start = Instant::now();
        match get_ip_with(config).await {
            Ok(result) => {
                let elapsed = start.elapsed();
                times.push(elapsed);
                last_ip = result.ip.to_string();
                println!("    Run {}: {} in {:?}", i + 1, result.ip, elapsed);
            }
            Err(e) => {
                println!("    Run {}: ✗ {e}", i + 1);
            }
        }
    }

    if times.is_empty() {
        println!("    → No successful runs\n");
    } else {
        print_stats(&times, &last_ip);
        println!();
    }
}

// ── Protocol benchmark ──────────────────────────────────────────────────────

async fn benchmark_protocol(protocol: Protocol, version: IpVersion) {
    let mut times = Vec::new();

    for i in 0..ITERATIONS {
        let config = Config::builder()
            .protocols(&[protocol])
            .version(version)
            .timeout(Duration::from_secs(10))
            .build();

        let start = Instant::now();
        match get_ip_with(config).await {
            Ok(result) => {
                let elapsed = start.elapsed();
                times.push(elapsed);
                println!(
                    "    Run {}: {} via {} in {:?}",
                    i + 1,
                    result.ip,
                    result.provider,
                    elapsed
                );
            }
            Err(e) => {
                println!("    Run {}: ✗ {e}", i + 1);
            }
        }
    }

    if times.is_empty() {
        println!("    → No successful runs");
    } else {
        print_stats(&times, "");
    }
}

// ── Strategy benchmark ──────────────────────────────────────────────────────

async fn benchmark_strategy(strategy: Strategy, version: IpVersion) {
    let mut times = Vec::new();

    for i in 0..ITERATIONS {
        let config = Config::builder()
            .strategy(strategy)
            .version(version)
            .timeout(Duration::from_secs(10))
            .build();

        let start = Instant::now();
        match get_ip_with(config).await {
            Ok(result) => {
                let elapsed = start.elapsed();
                times.push(elapsed);
                println!(
                    "    Run {}: {} via {} ({}) in {:?}",
                    i + 1,
                    result.ip,
                    result.provider,
                    result.protocol,
                    elapsed
                );
            }
            Err(e) => {
                println!("    Run {}: ✗ {e}", i + 1);
            }
        }
    }

    if times.is_empty() {
        println!("    → No successful runs");
    } else {
        print_stats(&times, "");
    }
}

// ── Statistics ──────────────────────────────────────────────────────────────

fn print_stats(times: &[Duration], ip: &str) {
    let n = times.len();
    if n == 0 {
        return;
    }

    let total: Duration = times.iter().sum();
    let avg = total / n as u32;
    let min = match times.iter().min() {
        Some(v) => *v,
        None => return,
    };
    let max = match times.iter().max() {
        Some(v) => *v,
        None => return,
    };

    let mut sorted = times.to_vec();
    sorted.sort();
    let median = sorted[n / 2];
    let p95 = sorted[(n as f64 * 0.95).ceil() as usize - 1];

    println!("    ─────────────────────────────────────");
    if !ip.is_empty() {
        println!("    IP: {ip}");
    }
    println!(
        "    Successes: {n}/{ITERATIONS} | Avg: {avg:?} | Med: {median:?} | Min: {min:?} | Max: {max:?} | P95: {p95:?}"
    );
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn version_str(v: IpVersion) -> &'static str {
    match v {
        IpVersion::V4 => "IPv4",
        IpVersion::V6 => "IPv6",
        IpVersion::Any => "Any",
    }
}

//! castellan — a DNS-driven nftables egress firewall for devcontainers.
//!
//! The keeper of the gate: it resolves only allow-listed domains and, as it does, injects
//! their addresses into nftables sets so egress is permitted exactly to what was just
//! resolved. Wildcards/regex replace the static host list, and re-resolution self-heals
//! CDN IP rotation.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

pub mod config;
pub mod dns;
pub mod meta;
pub mod nft;
pub mod setup;
pub mod verify;

#[derive(Parser)]
#[command(name = "castellan", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the long-lived DNS proxy daemon. Self-bootstrapping: it binds, installs the
    /// default-drop + DNS-intercept ruleset, repoints resolv.conf, then serves.
    Daemon(DaemonArgs),
    /// End-to-end verification of the firewall.
    Verify(VerifyArgs),
    /// Parse and validate an allow-list file, then optionally test names against it.
    Check(CheckArgs),
}

#[derive(Args)]
struct DaemonArgs {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:53")]
    listen: SocketAddr,
    /// Upstream DNS server IP(s). Comma-separated; `:port` ignored. Omit to autodetect
    /// from `/etc/resolv.conf` (or the backup, on a restart).
    #[arg(long, value_delimiter = ',')]
    upstream: Vec<String>,
    /// Pattern file path.
    #[arg(long, default_value = setup::PATTERNS_FALLBACK)]
    patterns: PathBuf,
    /// Readiness file to write once listening.
    #[arg(long, default_value = setup::READY_PATH)]
    ready: PathBuf,
    /// Minimum nft element timeout (seconds), regardless of DNS TTL.
    #[arg(long, default_value_t = 120)]
    ttl_floor: u64,
    /// Maximum nft element timeout (seconds).
    #[arg(long, default_value_t = 3600)]
    ttl_ceiling: u64,
}

#[derive(Args)]
struct VerifyArgs {
    /// Hosts that must be unreachable.
    #[arg(long, value_delimiter = ',', default_value = "example.com")]
    blocked: Vec<String>,
    /// Hosts that must be reachable.
    #[arg(long, value_delimiter = ',', default_value = "api.github.com")]
    allowed: Vec<String>,
}

#[derive(Args)]
struct CheckArgs {
    /// Pattern file to validate.
    #[arg(long, default_value = setup::PATTERNS_FALLBACK)]
    patterns: std::path::PathBuf,
    /// DNS names to test against the loaded patterns.
    #[arg(value_name = "NAME")]
    names: Vec<String>,
}

/// Parse `--upstream` values (each `ip` or `ip:port`) into IP addresses.
fn parse_upstreams(values: &[String]) -> Result<Vec<IpAddr>> {
    let mut out = Vec::new();
    for v in values {
        // Accept "ip", "ip:port", or "[v6]:port".
        let ip_str = if let Ok(sa) = v.parse::<SocketAddr>() {
            sa.ip().to_string()
        } else {
            v.trim_start_matches('[').trim_end_matches(']').to_string()
        };
        let ip: IpAddr = ip_str
            .parse()
            .with_context(|| format!("invalid upstream address: {v}"))?;
        out.push(ip);
    }
    Ok(out)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Daemon(a) => {
            let upstreams = parse_upstreams(&a.upstream)?;
            dns::run_daemon(dns::DaemonOpts {
                listen: a.listen,
                upstreams,
                patterns_path: a.patterns,
                ready_path: a.ready,
                ttl_floor_secs: a.ttl_floor,
                ttl_ceiling_secs: a.ttl_ceiling,
            })
            .await
        }
        Command::Verify(a) => verify::run(&a.blocked, &a.allowed).await,
        Command::Check(a) => check(&a),
    }
}

fn check(args: &CheckArgs) -> Result<()> {
    let cfg = config::Config::load(&args.patterns)
        .with_context(|| format!("failed to parse {}", args.patterns.display()))?;
    let p = &cfg.patterns;
    println!("{}: {} pattern(s)", args.patterns.display(), p.len());
    println!("  exact:    {}", p.exact_count());
    println!("  suffix:   {}", p.suffix_count());
    println!("  wildcard: {}", p.wildcard_count());
    println!("  regex:    {}", p.regex_count());
    if !cfg.ip_lists.is_empty() {
        println!("  JsonList: {} URL(s)", cfg.ip_lists.len());
    }
    if !args.names.is_empty() {
        println!();
        let width = args.names.iter().map(|n| n.len()).max().unwrap_or(20).max(20);
        for name in &args.names {
            let verdict = if p.is_allowed(name) { "ALLOW" } else { "BLOCK" };
            println!("{name:<width$}  {verdict}");
        }
    }
    Ok(())
}

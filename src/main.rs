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

mod config;
mod dns;
mod meta;
mod nft;
mod setup;
mod verify;

#[derive(Parser)]
#[command(name = "castellan", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build and apply the default-drop nftables ruleset (DNS interception NOT yet active).
    Setup(SetupArgs),
    /// Add the NAT redirect that routes egress DNS through the local resolver. Run only
    /// after the daemon is listening.
    EnableIntercept(SetupArgs),
    /// Run the long-lived DNS proxy daemon.
    Daemon(DaemonArgs),
    /// End-to-end verification of the firewall.
    Verify(VerifyArgs),
}

#[derive(Args)]
struct SetupArgs {
    /// Upstream DNS server IP(s) the daemon forwards to. Comma-separated; `:port` ignored.
    #[arg(long, value_delimiter = ',', required = true)]
    upstream: Vec<String>,
    /// Port the local resolver listens on.
    #[arg(long, default_value_t = 53)]
    port: u16,
}

#[derive(Args)]
struct DaemonArgs {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:53")]
    listen: SocketAddr,
    /// Upstream DNS server IP(s). Comma-separated; `:port` ignored.
    #[arg(long, value_delimiter = ',', required = true)]
    upstream: Vec<String>,
    /// Pattern file path. Defaults to the workspace copy, falling back to the baked copy.
    #[arg(long)]
    patterns: Option<PathBuf>,
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
        Command::Setup(a) => {
            let upstreams = parse_upstreams(&a.upstream)?;
            setup::apply_ruleset(upstreams, a.port, false).await
        }
        Command::EnableIntercept(a) => {
            let upstreams = parse_upstreams(&a.upstream)?;
            setup::apply_ruleset(upstreams, a.port, true).await
        }
        Command::Daemon(a) => {
            let upstreams = parse_upstreams(&a.upstream)?;
            let patterns_path = a.patterns.unwrap_or_else(setup::patterns_path);
            dns::run_daemon(dns::DaemonOpts {
                listen: a.listen,
                upstreams,
                patterns_path,
                ready_path: a.ready,
                ttl_floor_secs: a.ttl_floor,
                ttl_ceiling_secs: a.ttl_ceiling,
            })
            .await
        }
        Command::Verify(a) => verify::run(&a.blocked, &a.allowed).await,
    }
}

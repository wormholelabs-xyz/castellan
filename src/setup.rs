//! `setup` and `enable-intercept`: build the nftables ruleset and flip DNS interception.
//!
//! Split into two phases so DNS keeps working while the daemon starts:
//!   1. `setup` installs default-drop egress + static seeds, and allows the daemon to
//!      reach the upstream directly. Clients can still resolve via the upstream here.
//!   2. `enable-intercept` (run only after the daemon is listening) adds the NAT redirect
//!      that routes all egress :53 through the local resolver.

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

use crate::config::Config;
use crate::meta;
use crate::nft::{Nft, RulesetParams};

/// Where the running daemon advertises readiness.
pub const READY_PATH: &str = "/run/castellan/ready";
/// Cached IP ranges written by `setup` and read by `enable-intercept` to avoid
/// re-fetching through the now-active default-drop firewall.
const IP_RANGES_CACHE: &str = "/run/castellan/ip-ranges.json";

#[derive(Serialize, Deserialize)]
struct CachedRanges {
    v4: Vec<Ipv4Net>,
    v6: Vec<Ipv6Net>,
}
/// Workspace pattern file (authoritative — template users edit this).
pub const PATTERNS_WORKSPACE: &str = "/workspace/.devcontainer/allowed-domains.txt";
/// Baked fallback pattern file.
pub const PATTERNS_FALLBACK: &str = "/usr/local/share/castellan/allowed-domains.txt";

/// Resolve which pattern file to use (workspace wins, baked copy is the fallback).
pub fn patterns_path() -> PathBuf {
    let ws = PathBuf::from(PATTERNS_WORKSPACE);
    if ws.exists() {
        ws
    } else {
        PathBuf::from(PATTERNS_FALLBACK)
    }
}

/// Build and apply the full ruleset. `intercept` controls whether the DNS-redirect NAT
/// chain is installed.
pub async fn apply_ruleset(
    upstreams: Vec<IpAddr>,
    resolver_port: u16,
    intercept: bool,
) -> Result<()> {
    let nft = Nft::default();
    nft.check_available()
        .await
        .context("nftables is not usable in this container")?;

    let host_networks = detect_host_networks().await?;
    info!(?host_networks, "detected host networks");

    let config = Config::load(&patterns_path()).context("loading allow-list config")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("castellan/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building HTTP client")?;

    // During `setup` (intercept=false) the firewall is not yet active, so we can reach
    // external URLs freely.  During `enable-intercept` the default-drop rules are already
    // live and would block those same requests, so we read from the cache written above.
    let (static_v4, static_v6) = if intercept {
        let cache = std::fs::read_to_string(IP_RANGES_CACHE).with_context(|| {
            format!("reading IP ranges cache {IP_RANGES_CACHE} (was `setup` run first?)")
        })?;
        let cached: CachedRanges =
            serde_json::from_str(&cache).context("parsing IP ranges cache")?;
        info!(
            v4 = cached.v4.len(),
            v6 = cached.v6.len(),
            "loaded IP ranges from cache"
        );
        (cached.v4, cached.v6)
    } else {
        let mut all_v4: Vec<Ipv4Net> = Vec::new();
        let mut all_v6: Vec<Ipv6Net> = Vec::new();

        for spec in &config.ip_lists {
            info!(url = %spec.url, keys = ?spec.keys, "fetching JSON IP list");
            match meta::fetch_ip_list(&client, spec).await {
                Ok(ranges) => {
                    info!(
                        url = %spec.url,
                        v4 = ranges.v4.len(),
                        v6 = ranges.v6.len(),
                        "seeding IP ranges"
                    );
                    all_v4.extend(ranges.v4);
                    all_v6.extend(ranges.v6);
                }
                Err(e) => {
                    warn!(url = %spec.url, "failed to fetch JSON IP list: {e:#}");
                }
            }
        }

        let v4 = Ipv4Net::aggregate(&all_v4);
        let v6 = Ipv6Net::aggregate(&all_v6);

        // Persist so `enable-intercept` can reuse without fetching through the live firewall.
        std::fs::create_dir_all("/run/castellan").context("creating /run/castellan")?;
        let json = serde_json::to_string(&CachedRanges {
            v4: v4.clone(),
            v6: v6.clone(),
        })
        .context("serializing IP ranges cache")?;
        std::fs::write(IP_RANGES_CACHE, json).context("writing IP ranges cache")?;

        (v4, v6)
    };

    let params = RulesetParams {
        upstreams,
        host_networks,
        static_v4,
        static_v6,
        resolver_port,
        intercept,
    };
    nft.apply_ruleset(&params)
        .await
        .context("applying nftables ruleset")?;

    if intercept {
        enable_route_localnet()?;
    }
    info!(intercept, "ruleset applied");
    Ok(())
}

/// Detect host networks to allow, mirroring the legacy script: the /24 of the default
/// gateway.
async fn detect_host_networks() -> Result<Vec<String>> {
    let out = Command::new("ip")
        .args(["route"])
        .stderr(Stdio::piped())
        .output()
        .await
        .context("running `ip route`")?;
    let routes = String::from_utf8_lossy(&out.stdout);

    let mut nets = Vec::new();
    for line in routes.lines() {
        // e.g. "default via 172.17.0.1 dev eth0"
        if let Some(rest) = line.strip_prefix("default via ") {
            if let Some(gw) = rest.split_whitespace().next() {
                if let Ok(IpAddr::V4(v4)) = gw.parse::<IpAddr>() {
                    let o = v4.octets();
                    nets.push(format!("{}.{}.{}.0/24", o[0], o[1], o[2]));
                }
            }
        }
    }
    Ok(nets)
}

/// Verify the sysctl required for DNAT to loopback is active (set via --sysctl at container
/// creation; writing to /proc/sys is not possible without SYS_ADMIN).
fn enable_route_localnet() -> Result<()> {
    let val = std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/route_localnet")
        .context("reading net.ipv4.conf.all.route_localnet")?;
    anyhow::ensure!(
        val.trim() == "1",
        "net.ipv4.conf.all.route_localnet is not set; add \
         --sysctl=net.ipv4.conf.all.route_localnet=1 to the container runArgs"
    );
    Ok(())
}

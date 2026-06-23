//! Firewall bootstrap: build and atomically apply the nftables ruleset.
//!
//! There is no longer a two-phase `setup` / `enable-intercept` dance. The daemon binds its
//! listener socket first, then calls [`apply_ruleset`], which installs default-drop egress
//! **and** the DNS-redirect NAT chain in a single atomic transaction — so interception is
//! never enabled before the resolver is listening, and default-drop is never enforced
//! before the allow-set population path (interception) is live.

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use ipnet::{Ipv4Net, Ipv6Net};
use tokio::process::Command;
use tracing::{info, warn};

use crate::config::Config;
use crate::meta;
use crate::nft::{Nft, RulesetParams};

/// Where the running daemon advertises readiness.
pub const READY_PATH: &str = "/run/castellan/ready";
/// Backup of the original Docker-assigned `/etc/resolv.conf`, written the first time we
/// take it over so subsequent (re)starts can still recover the real upstream resolver(s).
const RESOLV_CONF: &str = "/etc/resolv.conf";
const RESOLV_BACKUP: &str = "/etc/resolv.conf.castellan";

/// Baked pattern file (copied into the image at build time).
pub const PATTERNS_FALLBACK: &str = "/usr/local/share/castellan/allowed-domains.txt";

/// Fetch the static seed ranges and atomically apply the full default-drop + DNS-intercept
/// ruleset. Called once per cold start, after the daemon's listener socket is already bound
/// (so the redirect never points at a dead port) but while egress is still open (so the
/// seed fetch below can reach the JSON endpoints).
pub async fn apply_ruleset(upstreams: Vec<IpAddr>, resolver_port: u16) -> Result<()> {
    let nft = Nft::default();
    nft.check_available()
        .await
        .context("nftables is not usable in this container")?;

    let host_networks = detect_host_networks().await?;
    info!(?host_networks, "detected host networks");

    let config =
        Config::load(&PathBuf::from(PATTERNS_FALLBACK)).context("loading allow-list config")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("castellan/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building HTTP client")?;

    // Egress is still open at this point (the ruleset below is what locks it down), so we
    // can reach these JSON endpoints directly.
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

    let params = RulesetParams {
        upstreams,
        host_networks,
        static_v4: Ipv4Net::aggregate(&all_v4),
        static_v6: Ipv6Net::aggregate(&all_v6),
        resolver_port,
    };
    nft.apply_ruleset(&params)
        .await
        .context("applying nftables ruleset")?;

    enable_route_localnet()?;
    info!("ruleset applied");
    Ok(())
}

/// Resolve the real upstream nameserver(s).
///
/// On a fresh container `/etc/resolv.conf` holds the Docker-assigned resolver(s); we back
/// them up so we can recover them later. On a restart we have already rewritten resolv.conf
/// to point at ourselves (`127.0.0.1`), so we read the upstream(s) from the backup instead —
/// reading the live file would make the daemon try to resolve through itself.
///
/// The backup is only ever written from real (non-`127.0.0.1`) upstreams, so a missing
/// backup can never be "recovered" into a self-referential one — that case fails loudly.
pub fn resolve_upstreams() -> Result<Vec<IpAddr>> {
    let current =
        std::fs::read_to_string(RESOLV_CONF).with_context(|| format!("reading {RESOLV_CONF}"))?;

    // If the live file still names real resolver(s), they are the source of truth: persist
    // them (sanitized to real upstreams only) so a later run — after we have repointed
    // resolv.conf at ourselves — can still recover them. We never write a backup that points
    // at 127.0.0.1, which would later forward the daemon to itself.
    let current_upstreams = upstreams_in(&current);
    if !current_upstreams.is_empty() {
        let backup: String = current_upstreams
            .iter()
            .map(|ip| format!("nameserver {ip}\n"))
            .collect();
        std::fs::write(RESOLV_BACKUP, backup)
            .with_context(|| format!("writing {RESOLV_BACKUP}"))?;
        info!(upstreams = ?current_upstreams, "resolved upstream nameserver(s) from {RESOLV_CONF}");
        return Ok(current_upstreams);
    }

    // The live file names no real resolver (we have already taken it over). Recover the real
    // upstream(s) from the backup. If there is no backup, the original resolver is genuinely
    // unknown — fail loudly rather than fabricating a self-referential one.
    let backup = std::fs::read_to_string(RESOLV_BACKUP).with_context(|| {
        format!(
            "{RESOLV_CONF} names no upstream resolver (only 127.0.0.1) and no backup exists \
             at {RESOLV_BACKUP} to recover from — the original resolver is unknown"
        )
    })?;
    let upstreams = upstreams_in(&backup);
    anyhow::ensure!(
        !upstreams.is_empty(),
        "backup {RESOLV_BACKUP} names no usable upstream resolver"
    );
    info!(
        ?upstreams,
        "resolved upstream nameserver(s) from {RESOLV_BACKUP}"
    );
    Ok(upstreams)
}

/// Parse the real upstream resolver(s) out of resolv.conf-format text: every `nameserver
/// <ip>` line except our own listener (`127.0.0.1`). Loopback resolvers like Docker's
/// embedded `127.0.0.11` are kept — those are legitimate upstreams.
fn upstreams_in(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(parse_nameserver)
        .filter(|ip| *ip != IpAddr::from([127, 0, 0, 1]))
        .collect()
}

/// Parse the IP out of a `nameserver <ip>` line, ignoring everything else.
fn parse_nameserver(line: &str) -> Option<IpAddr> {
    let mut fields = line.split_whitespace();
    if fields.next() != Some("nameserver") {
        return None;
    }
    fields.next()?.parse().ok()
}

/// Point `/etc/resolv.conf` at the local resolver. Idempotent: a no-op once already done.
/// The NAT redirect already intercepts all egress :53, so this is belt-and-suspenders for
/// resolver libraries that bypass NAT (e.g. dialing the loopback path directly).
pub fn repoint_resolv_conf() -> Result<()> {
    std::fs::write(RESOLV_CONF, "nameserver 127.0.0.1\n")
        .with_context(|| format!("repointing {RESOLV_CONF} at the local resolver"))
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

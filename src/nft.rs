//! nftables backend: builds the egress ruleset and injects resolved IPs into the
//! dynamic allow-sets.
//!
//! We shell out to the `nft` binary rather than using a netlink crate: per-element
//! TTL timeouts (the core feature) are first-class and well-documented in the CLI but
//! poorly supported over raw netlink. All mutations are fed via `nft -f -` (stdin), so
//! each apply is a single atomic transaction.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use ipnet::{Ipv4Net, Ipv6Net};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// The single `inet` table holding all of our chains and sets.
pub const TABLE: &str = "castellan";
pub const SET_ALLOWED_V4: &str = "allowed_v4";
pub const SET_ALLOWED_V6: &str = "allowed_v6";
const SET_STATIC_V4: &str = "static_v4";
const SET_STATIC_V6: &str = "static_v6";

/// Inputs needed to build the ruleset.
pub struct RulesetParams {
    /// Upstream DNS server addresses the daemon forwards to (their `:53` is allowed out).
    pub upstreams: Vec<IpAddr>,
    /// Host networks to allow unconditionally (e.g. the Docker host /24), as CIDR strings.
    pub host_networks: Vec<String>,
    /// Static IPv4 CIDRs to seed (e.g. GitHub meta ranges).
    pub static_v4: Vec<Ipv4Net>,
    /// Static IPv6 CIDRs to seed.
    pub static_v6: Vec<Ipv6Net>,
    /// Port the local resolver listens on (used by the DNS-redirect rule).
    pub resolver_port: u16,
    /// When true, install the NAT chain that transparently redirects egress :53 to the
    /// local resolver. Enabled only after the daemon is confirmed listening.
    pub intercept: bool,
}

/// Handle to the `nft` binary. Cheap to clone (holds only the binary path).
#[derive(Clone)]
pub struct Nft {
    bin: String,
}

impl Default for Nft {
    fn default() -> Self {
        Self {
            bin: "nft".to_string(),
        }
    }
}

impl Nft {
    /// Verify `nft` works and the host kernel exposes the nf_tables subsystem. Produces
    /// an actionable error rather than a cryptic netlink failure.
    pub async fn check_available(&self) -> Result<()> {
        let out = Command::new(&self.bin)
            .arg("list")
            .arg("tables")
            .output()
            .await
            .with_context(|| {
                format!(
                    "failed to run `{}` — is the nftables package installed?",
                    self.bin
                )
            })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!(
                "`nft list tables` failed ({}). The host kernel likely does not expose \
                 nf_tables (modules cannot be loaded from inside the container). stderr: {}",
                out.status,
                stderr.trim()
            );
        }
        Ok(())
    }

    /// True if our table currently exists.
    pub async fn table_exists(&self) -> Result<bool> {
        let out = Command::new(&self.bin)
            .args(["list", "table", "inet", TABLE])
            .output()
            .await
            .context("running `nft list table`")?;
        Ok(out.status.success())
    }

    /// Feed an nft script to `nft -f -`.
    async fn run_script(&self, script: &str) -> Result<()> {
        let mut child = Command::new(&self.bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning `{} -f -`", self.bin))?;

        child
            .stdin
            .take()
            .expect("stdin piped")
            .write_all(script.as_bytes())
            .await
            .context("writing nft script to stdin")?;

        let out = child.wait_with_output().await.context("waiting for nft")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!(
                "nft script failed ({}): {}\n--- script ---\n{}",
                out.status,
                stderr.trim(),
                script
            );
        }
        Ok(())
    }

    /// Build and atomically (re)apply the entire ruleset.
    pub async fn apply_ruleset(&self, p: &RulesetParams) -> Result<()> {
        self.run_script(&build_ruleset(p)).await
    }

    /// Inject resolved addresses into the dynamic allow-sets with the given timeout.
    /// Re-adding an existing element refreshes its timeout, which is how IP rotation
    /// self-heals. Both families are added in one transaction.
    pub async fn add_addrs(
        &self,
        v4: &[Ipv4Addr],
        v6: &[Ipv6Addr],
        timeout_secs: u64,
    ) -> Result<()> {
        let mut script = String::new();
        if !v4.is_empty() {
            let elems = v4
                .iter()
                .map(|a| format!("{a} timeout {timeout_secs}s"))
                .collect::<Vec<_>>()
                .join(", ");
            script.push_str(&format!(
                "add element inet {TABLE} {SET_ALLOWED_V4} {{ {elems} }}\n"
            ));
        }
        if !v6.is_empty() {
            let elems = v6
                .iter()
                .map(|a| format!("{a} timeout {timeout_secs}s"))
                .collect::<Vec<_>>()
                .join(", ");
            script.push_str(&format!(
                "add element inet {TABLE} {SET_ALLOWED_V6} {{ {elems} }}\n"
            ));
        }
        if script.is_empty() {
            return Ok(());
        }
        self.run_script(&script).await
    }
}

/// Render the full ruleset as an nft script.
fn build_ruleset(p: &RulesetParams) -> String {
    let mut s = String::new();

    // Replace the table wholesale, atomically. `delete` of a missing table errors, so
    // create-then-delete guarantees it exists first (a common nft idiom).
    s.push_str(&format!("table inet {TABLE} {{}}\n"));
    s.push_str(&format!("delete table inet {TABLE}\n"));
    s.push_str(&format!("table inet {TABLE} {{\n"));

    // Dynamic, DNS-populated sets (per-element timeouts).
    s.push_str(&format!(
        "  set {SET_ALLOWED_V4} {{ type ipv4_addr; flags timeout; }}\n"
    ));
    s.push_str(&format!(
        "  set {SET_ALLOWED_V6} {{ type ipv6_addr; flags timeout; }}\n"
    ));

    // Static CIDR sets (never expire).
    s.push_str(&format!(
        "  set {SET_STATIC_V4} {{ type ipv4_addr; flags interval;"
    ));
    if !p.static_v4.is_empty() {
        let elems = p
            .static_v4
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(" elements = {{ {elems} }};"));
    }
    s.push_str(" }\n");

    s.push_str(&format!(
        "  set {SET_STATIC_V6} {{ type ipv6_addr; flags interval;"
    ));
    if !p.static_v6.is_empty() {
        let elems = p
            .static_v6
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(" elements = {{ {elems} }};"));
    }
    s.push_str(" }\n");

    // Input chain: default drop, allow established/loopback/host-network.
    s.push_str("  chain input {\n");
    s.push_str("    type filter hook input priority 0; policy drop;\n");
    s.push_str("    ct state established,related accept\n");
    s.push_str("    iif \"lo\" accept\n");
    for net in &p.host_networks {
        if net.contains(':') {
            s.push_str(&format!("    ip6 saddr {net} accept\n"));
        } else {
            s.push_str(&format!("    ip saddr {net} accept\n"));
        }
    }
    s.push_str("  }\n");

    // Output chain: default drop; this is the egress enforcement point.
    s.push_str("  chain output {\n");
    s.push_str("    type filter hook output priority 0; policy drop;\n");
    s.push_str("    ct state established,related accept\n");
    s.push_str("    oif \"lo\" accept\n");
    // Allow the daemon to reach the real upstream resolver(s).
    for up in &p.upstreams {
        if up.is_loopback() {
            continue; // loopback (e.g. Docker 127.0.0.11) is already covered by `oif lo`
        }
        match up {
            IpAddr::V4(a) => {
                s.push_str(&format!("    ip daddr {a} udp dport 53 accept\n"));
                s.push_str(&format!("    ip daddr {a} tcp dport 53 accept\n"));
            }
            IpAddr::V6(a) => {
                s.push_str(&format!("    ip6 daddr {a} udp dport 53 accept\n"));
                s.push_str(&format!("    ip6 daddr {a} tcp dport 53 accept\n"));
            }
        }
    }
    for net in &p.host_networks {
        if net.contains(':') {
            s.push_str(&format!("    ip6 daddr {net} accept\n"));
        } else {
            s.push_str(&format!("    ip daddr {net} accept\n"));
        }
    }
    s.push_str("    tcp dport 22 accept\n"); // SSH, parity with the legacy script
    s.push_str(&format!("    ip daddr @{SET_STATIC_V4} accept\n"));
    s.push_str(&format!("    ip6 daddr @{SET_STATIC_V6} accept\n"));
    s.push_str(&format!("    ip daddr @{SET_ALLOWED_V4} accept\n"));
    s.push_str(&format!("    ip6 daddr @{SET_ALLOWED_V6} accept\n"));
    s.push_str("  }\n");

    // NAT chain: transparently redirect all egress DNS to the local resolver so even
    // processes with a hardcoded resolver get their queries seen (and thus their IPs
    // authorized). The daemon itself (uid 0) is exempted so its upstream queries escape.
    if p.intercept {
        s.push_str("  chain nat_output {\n");
        s.push_str("    type nat hook output priority -100; policy accept;\n");
        s.push_str("    meta skuid 0 return\n"); // daemon runs as root → forwards directly
        s.push_str("    ip daddr 127.0.0.0/8 return\n");
        s.push_str("    ip6 daddr ::1 return\n");
        s.push_str(&format!(
            "    meta l4proto {{ tcp, udp }} th dport 53 redirect to :{}\n",
            p.resolver_port
        ));
        s.push_str("  }\n");
    }

    s.push_str("}\n");
    s
}

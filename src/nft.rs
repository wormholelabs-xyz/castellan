//! nftables backend: builds the egress ruleset and injects resolved IPs into the
//! dynamic allow-sets.
//!
//! We shell out to the `nft` binary rather than using a netlink crate: per-element
//! TTL timeouts (the core feature) are first-class and well-documented in the CLI but
//! poorly supported over raw netlink. All mutations are fed via `nft -f -` (stdin), so
//! each apply is a single atomic transaction.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Stdio;

use anyhow::{Context, Result, bail};
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
    /// Empty unless `--allow-host-network` was given.
    pub host_networks: Vec<String>,
    /// Allow outbound TCP port 22 to any address (`--allow-ssh`).
    pub allow_ssh: bool,
    /// The uid the daemon runs as. Only sockets of this uid may reach the upstream
    /// resolver(s) directly; everything else has to go through the daemon.
    pub daemon_uid: u32,
    /// Static IPv4 CIDRs to seed (e.g. GitHub meta ranges).
    pub static_v4: Vec<Ipv4Net>,
    /// Static IPv6 CIDRs to seed.
    pub static_v6: Vec<Ipv6Net>,
    /// Port the local resolver listens on (used by the DNS-redirect rule).
    pub resolver_port: u16,
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

    /// True if DNS interception is already live, i.e. our `nat_output` redirect chain
    /// exists. The daemon uses this to tell a cold start (build the whole ruleset) from a
    /// warm restart (leave the populated dynamic allow-sets untouched).
    pub async fn intercept_active(&self) -> Result<bool> {
        let out = Command::new(&self.bin)
            .args(["list", "chain", "inet", TABLE, "nat_output"])
            .output()
            .await
            .context("running `nft list chain`")?;
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
    let uid = p.daemon_uid;
    s.push_str("  chain output {\n");
    s.push_str("    type filter hook output priority 0; policy drop;\n");
    s.push_str("    ct state established,related accept\n");
    // A loopback upstream (Docker's embedded resolver, 127.0.0.11) answers any name and any
    // record type, so reaching it directly is a DNS tunnel around the allow-list. Only the
    // daemon may talk to it. Matched on the address alone: Docker DNATs :53 to a random
    // port, which a client could dial directly. Must precede `oif lo accept`.
    for up in &p.upstreams {
        if !up.is_loopback() {
            continue;
        }
        match up {
            IpAddr::V4(a) => s.push_str(&format!("    ip daddr {a} meta skuid != {uid} drop\n")),
            IpAddr::V6(a) => s.push_str(&format!("    ip6 daddr {a} meta skuid != {uid} drop\n")),
        }
    }
    s.push_str("    oif \"lo\" accept\n");
    // DNS that `nat_output` redirected to the resolver. The redirect reroutes the packet to
    // loopback, but `oif` still reports the interface chosen before NAT, so the rule above
    // does not match it.
    s.push_str(&format!(
        "    ip daddr 127.0.0.1 meta l4proto {{ tcp, udp }} th dport {} accept\n",
        p.resolver_port
    ));
    // Allow the daemon, and only the daemon, to reach the real upstream resolver(s).
    for up in &p.upstreams {
        if up.is_loopback() {
            continue; // covered by `oif lo`, behind the guard above
        }
        match up {
            IpAddr::V4(a) => s.push_str(&format!(
                "    meta skuid {uid} ip daddr {a} meta l4proto {{ tcp, udp }} th dport 53 accept\n"
            )),
            IpAddr::V6(a) => s.push_str(&format!(
                "    meta skuid {uid} ip6 daddr {a} meta l4proto {{ tcp, udp }} th dport 53 accept\n"
            )),
        }
    }
    for net in &p.host_networks {
        if net.contains(':') {
            s.push_str(&format!("    ip6 daddr {net} accept\n"));
        } else {
            s.push_str(&format!("    ip daddr {net} accept\n"));
        }
    }
    if p.allow_ssh {
        s.push_str("    tcp dport 22 accept\n");
    }
    s.push_str(&format!("    ip daddr @{SET_STATIC_V4} accept\n"));
    s.push_str(&format!("    ip6 daddr @{SET_STATIC_V6} accept\n"));
    s.push_str(&format!("    ip daddr @{SET_ALLOWED_V4} accept\n"));
    s.push_str(&format!("    ip6 daddr @{SET_ALLOWED_V6} accept\n"));
    s.push_str("  }\n");

    // NAT chain: transparently redirect all egress DNS to the local resolver so even
    // processes with a hardcoded resolver get their queries seen (and thus their IPs
    // authorized). The daemon's own uid is exempted so its upstream queries escape, and so is
    // root: Docker's embedded resolver (127.0.0.11) forwards from sockets of its own, owned by
    // the Docker daemon, from inside this namespace. Redirected, those would loop back to us.
    // The exemption is only from the redirect: root gets no other access (the loopback guard
    // above refuses it the embedded resolver, and the upstream accept rules are the daemon's).
    // Installed in the same atomic transaction as the default-drop output chain: the daemon
    // binds its socket before applying this ruleset, so the redirect never hits a dead port.
    s.push_str("  chain nat_output {\n");
    s.push_str("    type nat hook output priority -100; policy accept;\n");
    if uid == 0 {
        s.push_str("    meta skuid 0 return\n");
    } else {
        s.push_str(&format!("    meta skuid {{ 0, {uid} }} return\n"));
    }
    s.push_str("    ip daddr 127.0.0.0/8 return\n");
    s.push_str("    ip6 daddr ::1 return\n");
    s.push_str(&format!(
        "    meta l4proto {{ tcp, udp }} th dport 53 redirect to :{}\n",
        p.resolver_port
    ));
    s.push_str("  }\n");

    s.push_str("}\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(upstream: &str) -> RulesetParams {
        RulesetParams {
            upstreams: vec![upstream.parse().unwrap()],
            host_networks: vec![],
            allow_ssh: false,
            daemon_uid: 0,
            static_v4: vec![],
            static_v6: vec![],
            resolver_port: 53,
        }
    }

    #[test]
    fn loopback_upstream_is_guarded_before_the_loopback_accept() {
        let r = build_ruleset(&params("127.0.0.11"));
        let guard = r.find("ip daddr 127.0.0.11 meta skuid != 0 drop").unwrap();
        assert!(guard < r.find("oif \"lo\" accept").unwrap());
    }

    #[test]
    fn only_the_daemon_reaches_a_routed_upstream() {
        let r = build_ruleset(&params("10.0.0.2"));
        assert!(r.contains(
            "meta skuid 0 ip daddr 10.0.0.2 meta l4proto { tcp, udp } th dport 53 accept"
        ));
        assert!(!r.contains("\n    ip daddr 10.0.0.2"));
    }

    #[test]
    fn an_unprivileged_daemon_and_root_skip_the_redirect() {
        let mut p = params("127.0.0.11");
        p.daemon_uid = 65532;
        let r = build_ruleset(&p);
        assert!(r.contains("meta skuid { 0, 65532 } return"));
        assert!(r.contains("ip daddr 127.0.0.11 meta skuid != 65532 drop"));
        // Root is exempt from the redirect only: it is not the one allowed to the upstream.
        assert!(!r.contains("meta skuid 0 ip daddr"));
        assert!(build_ruleset(&params("127.0.0.11")).contains("meta skuid 0 return"));
    }

    #[test]
    fn host_network_and_ssh_are_off_unless_asked_for() {
        let mut p = params("127.0.0.11");
        let r = build_ruleset(&p);
        assert!(!r.contains("dport 22"));
        assert!(!r.contains("saddr"));
        p.allow_ssh = true;
        p.host_networks = vec!["172.18.0.0/24".into()];
        let r = build_ruleset(&p);
        assert!(r.contains("tcp dport 22 accept"));
        assert!(r.contains("ip saddr 172.18.0.0/24 accept"));
        assert!(r.contains("ip daddr 172.18.0.0/24 accept"));
    }
}

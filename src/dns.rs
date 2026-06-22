//! The DNS proxy daemon: matches queries against the allow-list, forwards allowed ones
//! to the real upstream, injects the resolved IPs into the nftables allow-sets, and only
//! then returns the answer to the client.
//!
//! Injecting **before** responding is the single most important correctness rule: the
//! kernel commits the set element when `nft` returns, so the IP is permitted by the time
//! the client issues `connect()`. This closes the resolve→connect race.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_proto::op::{Header, HeaderCounts, MessageType, Metadata, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo, Server};
use hickory_server::zone_handler::MessageResponseBuilder;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};

use crate::config::PatternSet;
use crate::nft::Nft;

/// Options for the long-lived daemon.
pub struct DaemonOpts {
    pub listen: SocketAddr,
    /// Upstream resolver(s). Empty ⇒ autodetect from `/etc/resolv.conf` (or its backup).
    pub upstreams: Vec<IpAddr>,
    pub patterns_path: PathBuf,
    pub ready_path: PathBuf,
    pub ttl_floor_secs: u64,
    pub ttl_ceiling_secs: u64,
}

struct Handler {
    patterns: Arc<PatternSet>,
    resolver: TokioResolver,
    nft: Nft,
    ttl_floor_secs: u64,
    ttl_ceiling_secs: u64,
}

#[async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let info = match request.request_info() {
            Ok(info) => info,
            Err(_) => {
                return self
                    .reply_error(request, response_handle, ResponseCode::FormErr)
                    .await
            }
        };
        let name = info.query.name().to_string();
        let qtype = info.query.query_type();

        // We resolve only A/AAAA. Refusing everything else (including SVCB/HTTPS type 65)
        // keeps the nft sets authoritative: clients fall back to A/AAAA, which we control.
        if qtype != RecordType::A && qtype != RecordType::AAAA {
            debug!(%name, ?qtype, "refusing non-address query type");
            return self
                .reply_error(request, response_handle, ResponseCode::Refused)
                .await;
        }

        if !self.patterns.is_allowed(&name) {
            debug!(%name, "denied: no matching allow pattern");
            return self
                .reply_error(request, response_handle, ResponseCode::Refused)
                .await;
        }

        let lookup = match self.resolver.lookup(name.as_str(), qtype).await {
            Ok(l) => l,
            Err(e) => {
                // Fail closed: an answer we can't authorize would be dropped anyway, and
                // SERVFAIL is a clearer signal than handing back unreachable IPs.
                warn!(%name, error = %e, "upstream lookup failed");
                return self
                    .reply_error(request, response_handle, ResponseCode::ServFail)
                    .await;
            }
        };

        // Collect resolved addresses and the minimum TTL across the answer.
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut min_ttl = u32::MAX;
        for record in lookup.answers() {
            match &record.data {
                RData::A(a) => {
                    v4.push(a.0);
                    min_ttl = min_ttl.min(record.ttl);
                }
                RData::AAAA(aaaa) => {
                    v6.push(aaaa.0);
                    min_ttl = min_ttl.min(record.ttl);
                }
                _ => {}
            }
        }

        if !v4.is_empty() || !v6.is_empty() {
            let timeout = self.clamp_ttl(min_ttl);
            if let Err(e) = self.nft.add_addrs(&v4, &v6, timeout).await {
                // Fail closed: if we can't authorize the IPs, don't return them.
                error!(%name, error = %e, "failed to inject IPs into nftables");
                return self
                    .reply_error(request, response_handle, ResponseCode::ServFail)
                    .await;
            }
            info!(%name, v4 = v4.len(), v6 = v6.len(), timeout, "authorized");
        }

        // Build and send the success response (the IPs are now authorized).
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.recursion_available = true;
        metadata.response_code = ResponseCode::NoError;
        let response = builder.build(
            metadata,
            lookup.answers(),
            empty_records(),
            empty_records(),
            empty_records(),
        );
        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                error!(%name, error = %e, "failed to send DNS response");
                serv_fail_info(request)
            }
        }
    }
}

impl Handler {
    fn clamp_ttl(&self, ttl: u32) -> u64 {
        (ttl as u64).clamp(self.ttl_floor_secs, self.ttl_ceiling_secs)
    }

    /// Send a bare error response (no records) and return its info.
    async fn reply_error<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        code: ResponseCode,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let response = builder.error_msg(&request.metadata, code);
        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                error!(error = %e, "failed to send error response");
                serv_fail_info(request)
            }
        }
    }
}

/// An empty record iterator with the right element type for `MessageResponseBuilder::build`.
fn empty_records<'a>() -> std::iter::Empty<&'a Record> {
    std::iter::empty()
}

/// Fallback `ResponseInfo` for the rare case where sending the response itself fails.
fn serv_fail_info(request: &Request) -> ResponseInfo {
    let mut metadata = Metadata::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    metadata.response_code = ResponseCode::ServFail;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}

/// Build a forwarding resolver bound to explicit upstream(s). We never read the
/// (rewritten) `/etc/resolv.conf`, which would make the daemon resolve through itself.
fn build_resolver(upstreams: &[IpAddr]) -> Result<TokioResolver> {
    let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
    for ip in upstreams {
        let connections = vec![
            ConnectionConfig::new(ProtocolConfig::Udp),
            ConnectionConfig::new(ProtocolConfig::Tcp),
        ];
        config.add_name_server(NameServerConfig::new(*ip, true, connections));
    }
    let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .context("building resolver")?;
    Ok(resolver)
}

/// Run the daemon until the server shuts down. The daemon owns the entire bootstrap so the
/// ordering is race-free without an external sequencer (see the module docs in `setup.rs`):
///
///   1. resolve the real upstream(s),
///   2. bind the listener socket(s) — *before* any interception exists,
///   3. on a cold start, fetch seeds and atomically apply default-drop + DNS interception,
///   4. point resolv.conf at ourselves,
///   5. signal readiness and serve.
///
/// A warm restart (the `nat_output` chain is already in the kernel) skips step 3 so the
/// dynamic allow-sets populated by the previous run are preserved.
pub async fn run_daemon(opts: DaemonOpts) -> Result<()> {
    let nft = Nft::default();

    // 1. Upstream(s): explicit flag wins, otherwise read resolv.conf (or its backup).
    let upstreams = if opts.upstreams.is_empty() {
        crate::setup::resolve_upstreams()?
    } else {
        opts.upstreams
    };

    let patterns = PatternSet::load(&opts.patterns_path)?;
    info!(
        "loaded {} allow patterns from {}",
        patterns.len(),
        opts.patterns_path.display()
    );
    if patterns.is_empty() {
        warn!("allow-list is empty — all DNS queries will be refused");
    }
    for src in patterns.regex_sources() {
        debug!("regex pattern: {src}");
    }

    let resolver = build_resolver(&upstreams).context("building upstream resolver")?;
    info!(?upstreams, "forwarding to upstream resolver(s)");

    let handler = Handler {
        patterns: Arc::new(patterns),
        resolver,
        nft: nft.clone(),
        ttl_floor_secs: opts.ttl_floor_secs,
        ttl_ceiling_secs: opts.ttl_ceiling_secs,
    };

    let mut server = Server::new(handler);

    // 2. Bind before interception is enabled so the :53 redirect never hits a dead port.
    let udp = UdpSocket::bind(opts.listen)
        .await
        .with_context(|| format!("binding UDP {}", opts.listen))?;
    let tcp = TcpListener::bind(opts.listen)
        .await
        .with_context(|| format!("binding TCP {}", opts.listen))?;
    server.register_socket(udp);
    server.register_listener(tcp, Duration::from_secs(10), 65_535);

    // 3. Cold start only: build the ruleset. On a warm restart the ruleset (and its
    //    populated dynamic allow-sets) is already live, so we leave it untouched.
    if nft.intercept_active().await? {
        info!("interception already active — warm restart, keeping the live ruleset");
    } else {
        info!("cold start — applying default-drop + DNS-intercept ruleset");
        crate::setup::apply_ruleset(upstreams, opts.listen.port())
            .await
            .context("applying firewall ruleset")?;
    }

    // 4. Take over DNS resolution (belt-and-suspenders alongside the NAT redirect).
    crate::setup::repoint_resolv_conf()?;

    // 5. Signal readiness, then serve.
    if let Some(parent) = opts.ready_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&opts.ready_path, b"ready\n")
        .with_context(|| format!("writing readiness file {}", opts.ready_path.display()))?;

    info!("castellan resolver listening on {}", opts.listen);
    server.block_until_done().await.context("server error")?;
    Ok(())
}

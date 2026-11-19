# Castellan

Castellan is a DNS-driven egress firewall for development containers. It acts as the
container's DNS resolver: every lookup is matched against an allow-list, and the addresses
of allowed names are injected into [nftables](https://nftables.org) sets as they resolve, so
egress is permitted to exactly what was just looked up — and nothing else.

It was built to harden the [Claude Code devcontainer](https://docs.anthropic.com/en/docs/claude-code/devcontainer),
replacing its one-shot iptables+ipset script, but it works for any container that wants a
default-deny egress policy keyed on domain names.

## Why

The conventional approach — resolve a fixed list of hostnames once at startup and pin the
resulting IPs — has two problems Castellan fixes:

- **No wildcards.** Every subdomain has to be enumerated. With Castellan,
  `*.gallery.vsassets.io` covers them all; full regex is supported too.
- **Stale IPs.** CDNs rotate addresses constantly, so a one-shot resolve silently breaks
  egress when the IP changes. Castellan authorizes addresses as they are resolved and lets
  them expire on their DNS TTL, so rotation self-heals.

## How it works

1. **`castellan daemon`** is self-bootstrapping. On startup it binds its listener socket first,
   then atomically installs the default-drop egress and DNS-redirect nftables ruleset (so the
   redirect never points at a dead port), fetches any static seed ranges (e.g. GitHub's published
   IP ranges), and begins serving. (It repoints `/etc/resolv.conf` at itself too, unless it was
   started with `--no-resolv-conf`, which the sidecar layout does: the daemon is not root.)
2. For each DNS query the daemon matches the name against
   [`.devcontainer/allowed-domains.txt`](.devcontainer/allowed-domains.txt).
   Allowed names are forwarded to the real upstream resolver; the resolved A/AAAA addresses
   are injected into the nftables allow-sets (with a timeout derived from the DNS TTL)
   **before** the answer is returned to the client, closing the resolve→connect race.
   Unlisted names are refused.
3. Only the daemon may talk to the upstream resolver. Docker's embedded resolver
   (`127.0.0.11`) answers any name and record type, so every other process is kept away
   from it, on any port.
4. Everything else is dropped. A supervisor restarts the daemon if it crashes — Castellan
   fails **closed**: if it isn't running, no new egress is authorized (existing connections
   survive via conntrack).

```
client ──DNS:53──▶ [nft redirect] ──▶ castellan daemon ──┬─ match allow-list
                                                          ├─ forward to real upstream
                                                          ├─ inject IPs ─▶ nft set (timeout=TTL)
                                                          └─ return answer
client ──HTTPS──▶ [nft output: default drop] ── accept iff dst ∈ allow-sets
```

## The allow-list

Edit [`.devcontainer/allowed-domains.txt`](.devcontainer/allowed-domains.txt). Each line's
type is determined by its prefix:

| Syntax                                            | Matches                                              |
|---------------------------------------------------|------------------------------------------------------|
| `api.anthropic.com`                               | exact host (case-insensitive)                        |
| `.sentry.io`                                      | `sentry.io` and any subdomain `*.sentry.io`          |
| `*.gallery.vsassets.io`                           | any subdomain (one or more labels) of the suffix     |
| `re:^[a-z0-9-]+\.pkg\.dev$`                       | regex, matched against the whole lowercased name     |
| `JsonList(https://api.github.com/meta, [web, api])` | fetch JSON; seed IP ranges into the static allow-set |

Blank lines and everything after `#` are ignored.

## Running it

Castellan is supported in one layout: as a **sidecar**. The firewall is a container of its own
that owns the network namespace, the container it confines joins that namespace, and that
container starts only once the firewall is enforcing. Nothing in the confined container holds
`NET_ADMIN` or has `sudo`, so nothing there can flush the ruleset or stop the daemon. This
repository's own devcontainer is the reference: [`.devcontainer/`](.devcontainer/).

| Service       | Runs as          | Capabilities | Does                                                            |
|---------------|------------------|--------------|-----------------------------------------------------------------|
| `firewall`    | `castellan`      | `NET_ADMIN`  | `castellan daemon`, under a supervisor that restarts it         |
| `resolv-init` | root, once       | none         | points the shared `resolv.conf` at the daemon (root owns it)    |
| `dev`         | your user        | none         | your workload, in the firewall's namespace, with `no-new-privileges` |

```yaml
services:
  firewall:
    build: { context: ., target: firewall }   # castellan + nftables + the allow-list; see below
    user: castellan
    init: true
    cap_drop: [ALL]
    cap_add: [NET_ADMIN]
    sysctls:
      net.ipv4.conf.all.route_localnet: "1"
      net.ipv4.ip_unprivileged_port_start: "0"
    healthcheck:
      test: ["CMD", "test", "-f", "/run/castellan/ready"]
      interval: 2s
      retries: 30

  resolv-init:
    build: { context: ., target: firewall }
    user: "0:0"
    cap_drop: [ALL]
    network_mode: "service:firewall"
    entrypoint: ["/bin/sh", "-c", "echo 'nameserver 127.0.0.1' > /etc/resolv.conf"]
    restart: "no"
    depends_on:
      firewall: { condition: service_healthy, restart: true }

  dev:
    build: .
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    network_mode: "service:firewall"
    depends_on:
      firewall: { condition: service_healthy, restart: true }
      resolv-init: { condition: service_completed_successfully, restart: true }
```

The firewall's image downloads the release binary, checks it, and gives it its one capability:

```dockerfile
FROM debian:bookworm-slim AS firewall
ARG CASTELLAN_VERSION
ARG CASTELLAN_CHECKSUM_AMD64
ARG CASTELLAN_CHECKSUM_ARM64
RUN apt-get update && apt-get install -y --no-install-recommends \
      nftables iproute2 curl ca-certificates libcap2-bin && rm -rf /var/lib/apt/lists/*
# Get the checksums by running `sha256sum` on each tarball on the releases page.
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "${ARCH}" = "amd64" ]; then \
      TARBALL="castellan-linux-x86_64.tar.gz"; CHECKSUM="${CASTELLAN_CHECKSUM_AMD64}"; \
    else \
      TARBALL="castellan-linux-aarch64.tar.gz"; CHECKSUM="${CASTELLAN_CHECKSUM_ARM64}"; \
    fi && \
    curl -fsSLo /tmp/castellan.tar.gz \
      "https://github.com/wormholelabs-xyz/castellan/releases/download/v${CASTELLAN_VERSION}/${TARBALL}" && \
    echo "${CHECKSUM}  /tmp/castellan.tar.gz" | sha256sum -c - && \
    tar --no-same-owner -xzf /tmp/castellan.tar.gz -C /usr/local/bin castellan && \
    rm /tmp/castellan.tar.gz
RUN groupadd --system --gid 65532 castellan && \
    useradd --system --uid 65532 --gid castellan --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin castellan
RUN mkdir -p /usr/local/share/castellan /run/castellan
COPY allowed-domains.txt /usr/local/share/castellan/allowed-domains.txt
COPY castellan-supervisor.sh /usr/local/bin/castellan-supervisor.sh
RUN chmod 0644 /usr/local/share/castellan/allowed-domains.txt && \
    chmod 0755 /usr/local/bin/castellan /usr/local/bin/castellan-supervisor.sh && \
    chown castellan:castellan /run/castellan
# Docker does not give a non-root user a capability added with `cap_add`, so the daemon and nft
# get CAP_NET_ADMIN from the files.
RUN set -eux; \
    setcap cap_net_admin=ep /usr/local/bin/castellan; \
    setcap cap_net_admin=ep "$(readlink -f "$(command -v nft)")"; \
    getcap /usr/local/bin/castellan "$(readlink -f "$(command -v nft)")"; \
    apt-get purge -y libcap2-bin; rm -rf /var/lib/apt/lists/*
USER castellan
ENTRYPOINT ["/usr/local/bin/castellan-supervisor.sh"]
```

Copy [`castellan-supervisor.sh`](.devcontainer/castellan-supervisor.sh) and write your
allow-list ([The allow-list](#the-allow-list)); a minimal one that covers GitHub:

```
JsonList(https://api.github.com/meta, [web, api, git])
.github.com
.githubusercontent.com
```

Things that matter, each of which [`check-sidecar.sh`](.devcontainer/check-sidecar.sh) checks
for this repository's layout:

- **`dev` starts only once the firewall is healthy** (it writes `/run/castellan/ready` after
  binding, installing the ruleset and starting to serve), and after `resolv-init` has run: there
  is no moment at which a process in `dev` has open egress or the wrong resolver.
- **The firewall is not root and has one capability.** `cap_drop: [ALL]` and `NET_ADMIN`, given to
  the binaries as file capabilities. So no `no-new-privileges` on it, which would ignore them.
- **Share nothing else with `dev`**: no volumes, `pid` or `ipc`. The binary, the supervisor and the
  allow-list are the firewall image's, and `dev` cannot see them.
- **No restart policy on the firewall.** A restarted container gets a new network namespace and
  `dev` would be left in the old one. The supervisor restarts a daemon that crashes without
  restarting the container.
- **Nothing in `dev` may be able to become root.** `cap_drop: [ALL]`, `no-new-privileges`, no
  `sudo`. uid 0 is exempt from the DNS redirect (see [Security notes](#security-notes)).

## Requirements

- Linux with the **`nf_tables`** kernel subsystem, which the host provides: modules cannot be loaded
  from inside a container, so the daemon checks for it up front and fails loudly if it is missing.
- `NET_ADMIN` in the firewall container, for `nft`. No other capability, and no `NET_RAW`:
  Castellan opens no raw socket.
- `net.ipv4.conf.all.route_localnet=1` on the namespace (the DNS redirect goes to loopback), and
  `net.ipv4.ip_unprivileged_port_start=0` (the daemon binds `127.0.0.1:53` as an ordinary user).
  Docker only lets the namespace's owner, the firewall, set them.
- File capabilities on `castellan` and `nft`, so an image format and a filesystem that keep
  extended attributes. On a first run, check that the daemon holds the capability and no more:
  `CapEff` in its `/proc/<pid>/status` should be `0000000000001000`.

## Operations

- Daemon logs: `docker logs <project>-firewall-1`.
- Inspect live state: `docker exec <project>-firewall-1 nft list table inet castellan`.
- Check it end to end: `docker exec <project>-firewall-1 castellan verify`.
- A daemon crash is handled by the supervisor, which restarts it within a second; until then no new
  name resolves, and existing connections survive.
- Recover after a bad allow-list edit: fix it, validate it from the dev container with
  `cargo run -- check --patterns .devcontainer/allowed-domains.txt [name ...]`, then rebuild.
- Apply a code or allow-list change: rebuild the devcontainer (the allow-list is baked into the
  firewall image).
- If DNS fails on first start, `check-firewall.sh` (the `postStartCommand`) says so. Docker's
  embedded resolver forwards to the host's resolver from inside the namespace, and with
  `--allow-host-network` off that traffic may be dropped. Add the flag in the firewall's
  environment, `CASTELLAN_EXTRA_ARGS: --allow-host-network`, to test it.

## Unconditional allowances

Both are off by default; each is a daemon flag, passed through `CASTELLAN_EXTRA_ARGS`.

| Flag                   | Allows                                                              |
|------------------------|---------------------------------------------------------------------|
| `--allow-host-network` | all traffic to and from the default gateway's /24 (the Docker host and other containers on its bridge) |
| `--allow-ssh`          | outbound TCP port 22 to any address                                 |

SSH to an allow-listed name (for example `github.com`) needs neither: its resolved addresses are
allowed on every port. The daemon also takes `--no-resolv-conf` (the supervisor passes it, since
`resolv-init` does that job as root), `--upstream`, `--ttl-floor` and `--ttl-ceiling`; see
`castellan daemon --help`.

## Security notes

See [SECURITY.md](SECURITY.md) for the full threat model. In brief:

- Castellan assumes the confined container holds **no capabilities and cannot become root**. A
  process with `CAP_NET_ADMIN` in the firewall's network namespace can flush the nftables ruleset
  and bypass the firewall. The sidecar layout keeps that capability out of the confined container.
- The daemon that parses DNS packets from the confined container is **not root**: it runs as an
  unprivileged uid and holds `CAP_NET_ADMIN` and nothing else. It still needs that capability to add
  resolved addresses to the allow-sets, so a compromised daemon could open egress. It cannot write
  the binary, the supervisor or the allow-list, but what it does to the ruleset lasts until the
  firewall container is recreated: a daemon the supervisor restarts keeps the live ruleset.
- It intercepts DNS at the system resolver; DNS-over-HTTPS/TLS, hardcoded IPs, and connections to
  already-authorized IPs bypass it.
- It controls *where* traffic goes, not *what* it contains: exfiltration to allowed destinations
  is out of scope.

## Development

The container ships a pinned Rust toolchain (rustc, cargo, rustfmt, clippy). Standard
workflow:

```sh
cargo build      # build
cargo test       # unit tests (pattern matching)
cargo clippy     # lints
```


⚠ **This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.** See the License for the specific language governing permissions and limitations under the License. Or plainly spoken — this is a security-critical piece of software that sits between your container and the network. Mistakes happen, and a bad allow-list entry can silently block your package manager, strand your build tools, or leave your DNS resolver pointing at itself. Firewalls that fail closed are powerful and unforgiving — use with care.

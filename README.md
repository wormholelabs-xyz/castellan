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
   IP ranges), repoints `/etc/resolv.conf` at itself, and begins serving.
2. For each DNS query the daemon matches the name against
   [`.devcontainer/allowed-domains.txt`](.devcontainer/allowed-domains.txt).
   Allowed names are forwarded to the real upstream resolver; the resolved A/AAAA addresses
   are injected into the nftables allow-sets (with a timeout derived from the DNS TTL)
   **before** the answer is returned to the client, closing the resolve→connect race.
   Unlisted names are refused.
3. Everything else is dropped. A supervisor restarts the daemon if it crashes — Castellan
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

In the devcontainer it is fully automatic: the `castellan` binary is built from source during
`docker build` and baked into the image. The firewall starts at container create and is
re-established on every restart (`postCreateCommand` / `postStartCommand` both run
`sudo /usr/local/bin/init-firewall.sh`).

To apply code or allow-list changes, verify the build compiles first, then rebuild the devcontainer:

```sh
cargo build --release                                               # verify it compiles
castellan check --patterns .devcontainer/allowed-domains.txt       # validate allow-list
# then: rebuild devcontainer
```

The allow-list is baked into the image at build time; edits to `.devcontainer/allowed-domains.txt` require a devcontainer rebuild to take effect.

To validate allow-list changes without running the daemon:

```sh
castellan check
castellan check --patterns .devcontainer/allowed-domains.txt api.anthropic.com evil.com
```

The CLI subcommands (`daemon`, `verify`, `check`) can also be run directly; see `castellan --help`.

## Requirements

- Linux with `NET_ADMIN` (the devcontainer adds `--cap-add=NET_ADMIN --cap-add=NET_RAW`).
- The **host kernel must expose `nf_tables`** — true on modern Docker Desktop and recent
  Linux kernels. Kernel modules cannot be loaded from inside a container, so `setup` checks
  for nftables up front and fails loudly if it is unavailable.

## Operations

- Daemon logs: `/var/log/castellan.log`.
- Inspect live state: `sudo nft list table inet castellan`.
- Recover after a daemon crash: `sudo /usr/local/bin/init-firewall.sh` (the supervisor also restarts it automatically).
- Recover after a bad allow-list edit: fix `.devcontainer/allowed-domains.txt`, validate with `castellan check`, then rebuild the devcontainer (the allow-list is baked into the image).
- Apply a code or allow-list change: rebuild the devcontainer.

## Using Castellan in your own devcontainer

Castellan is designed to be embedded in any devcontainer that needs a default-deny egress
policy. Pre-built binaries for `linux/amd64`, `linux/amd64-musl`, `linux/aarch64`, and `linux/aarch64-musl` are published with each
[GitHub release](https://github.com/wormholelabs-xyz/castellan/releases).

### 1. Copy the supporting scripts

Copy these two files from this repository into your project's `.devcontainer/` directory:

- [`.devcontainer/init-firewall.sh`](.devcontainer/init-firewall.sh) — installs the binary and (re)starts the supervised daemon
- [`.devcontainer/castellan-supervisor.sh`](.devcontainer/castellan-supervisor.sh) — restarts the daemon if it crashes (fail-closed: no daemon → no new egress)

### 2. Add a download layer to your Dockerfile

Add a stage that fetches and verifies the release binary, then copy it into your main stage.
Get the SHA256 checksums by downloading each tarball from the
[releases page](https://github.com/wormholelabs-xyz/castellan/releases) and running
`sha256sum` on it.

```dockerfile
# Stage: download and verify the castellan binary
FROM debian:bookworm-slim AS castellan
ARG CASTELLAN_VERSION=0.1.0
ARG CASTELLAN_CHECKSUM_AMD64=<sha256 of castellan-linux-x86_64.tar.gz>
ARG CASTELLAN_CHECKSUM_ARM64=<sha256 of castellan-linux-aarch64.tar.gz>
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "${ARCH}" = "amd64" ]; then \
      TARBALL="castellan-linux-x86_64.tar.gz"; CHECKSUM="${CASTELLAN_CHECKSUM_AMD64}"; \
    else \
      TARBALL="castellan-linux-aarch64.tar.gz"; CHECKSUM="${CASTELLAN_CHECKSUM_ARM64}"; \
    fi && \
    curl -fsSLo /tmp/castellan.tar.gz \
      "https://github.com/wormholelabs-xyz/castellan/releases/download/v${CASTELLAN_VERSION}/${TARBALL}" && \
    echo "${CHECKSUM}  /tmp/castellan.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/castellan.tar.gz -C /tmp castellan && \
    install -m 0755 /tmp/castellan /usr/local/bin/castellan

# Your main stage
FROM your-base-image

# ... your existing setup ...

# Install castellan — binary from the download stage, scripts from your .devcontainer
COPY --from=castellan /usr/local/bin/castellan /usr/local/bin/castellan
COPY init-firewall.sh castellan-supervisor.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/castellan-supervisor.sh

# Allow the non-root container user to start the firewall (replace YOUR_USER accordingly)
RUN echo "YOUR_USER ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh" \
      > /etc/sudoers.d/castellan-firewall && \
    chmod 0440 /etc/sudoers.d/castellan-firewall
# The COPY + chmod above already sets root ownership on init-firewall.sh and
# castellan-supervisor.sh. Do not change their owner or mode — the sudoers grant
# gives effective root to anyone who can write those paths.
```

### 3. Configure devcontainer.json

Add the required capabilities and sysctl, and wire up the two lifecycle hooks:

```json
{
  "runArgs": [
    "--cap-add=NET_ADMIN",
    "--cap-add=NET_RAW",
    "--sysctl=net.ipv4.conf.all.route_localnet=1"
  ],
  "postCreateCommand": "sudo /usr/local/bin/init-firewall.sh",
  "postStartCommand":  "sudo /usr/local/bin/init-firewall.sh"
}
```

`postCreateCommand` runs once when the container is first created. `postStartCommand`
re-establishes the firewall on every container restart — the nftables ruleset lives in
the network namespace and is lost when the container stops.

### 4. Write your allow-list

Create `.devcontainer/allowed-domains.txt` in your project. Pass it to the daemon via
`--patterns` (or bake it into the image at `PATTERNS_FALLBACK`).

A minimal starting point that covers GitHub access:

```
# GitHub — git/gh/clone over HTTPS.
# JsonList seeds GitHub's published IP ranges into the static nftables allow-set.
JsonList(https://api.github.com/meta, [web, api, git])
.github.com
.githubusercontent.com
.githubassets.com

# Add your project-specific domains below:
```

See [The allow-list](#the-allow-list) section above for the full syntax reference.

## Security notes

See [SECURITY.md](SECURITY.md) for the full threat model. In brief:

- Castellan assumes the in-container attacker is **non-root and lacks `CAP_NET_ADMIN`**. A process with either can flush the nftables ruleset and bypass the firewall.
- It intercepts DNS at the system resolver; DNS-over-HTTPS/TLS, hardcoded IPs, and connections to already-authorized IPs bypass it.
- It controls *where* traffic goes, not *what* it contains — exfiltration to allowed destinations is out of scope.

The sudoers grant (`NOPASSWD: /usr/local/bin/init-firewall.sh`) gives effective root to anyone who can write that path; `init-firewall.sh` and `castellan-supervisor.sh` must be root-owned and non-writable. The full directory chain from `/usr/local/share/` down to `allowed-domains.txt` must be root-owned and non-writable too — in Unix, write access to any ancestor directory is enough to rename the `castellan/` directory aside and substitute a different allow-list.

## Development

The container ships a pinned Rust toolchain (rustc, cargo, rustfmt, clippy). Standard
workflow:

```sh
cargo build      # build
cargo test       # unit tests (pattern matching)
cargo clippy     # lints
```


⚠ **This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.** See the License for the specific language governing permissions and limitations under the License. Or plainly spoken — this is a security-critical piece of software that sits between your container and the network. Mistakes happen, and a bad allow-list entry can silently block your package manager, strand your build tools, or leave your DNS resolver pointing at itself. Firewalls that fail closed are powerful and unforgiving — use with care.

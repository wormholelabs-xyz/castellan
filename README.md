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

1. **`castellan setup`** installs a default-drop nftables ruleset and seeds static allow-sets
   (GitHub's published ranges from `api.github.com/meta`, the host network).
2. **`castellan daemon`** runs as the container's DNS resolver. For each query it matches the
   name against [`.devcontainer/allowed-domains.txt`](.devcontainer/allowed-domains.txt).
   Allowed names are forwarded to the real upstream resolver; the resolved A/AAAA addresses
   are injected into the nftables allow-sets (with a timeout derived from the DNS TTL)
   **before** the answer is returned to the client, closing the resolve→connect race.
   Unlisted names are refused.
3. **`castellan enable-intercept`** transparently redirects all egress port-53 traffic through
   the local resolver, so even a process with a hardcoded resolver still has its lookups seen.
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

| Syntax                       | Matches                                              |
|------------------------------|------------------------------------------------------|
| `api.anthropic.com`          | exact host (case-insensitive)                        |
| `.sentry.io`                 | `sentry.io` and any subdomain `*.sentry.io`          |
| `*.gallery.vsassets.io`      | any subdomain (one or more labels) of the suffix     |
| `re:^[a-z0-9-]+\.pkg\.dev$`  | regex, matched against the whole lowercased name     |

Blank lines and everything after `#` are ignored.

## Running it

In the devcontainer it is fully automatic: `cargo build --release` then
`init-firewall.sh` run at container create (`postCreateCommand`), and the firewall is
re-established on every container start (`postStartCommand`).

To apply allow-list or code changes manually:

```sh
cargo build --release
sudo /usr/local/bin/init-firewall.sh
```

The CLI subcommands (`setup`, `enable-intercept`, `daemon`, `verify`) can also be run
directly; see `castellan --help`.

## Requirements

- Linux with `NET_ADMIN` (the devcontainer adds `--cap-add=NET_ADMIN --cap-add=NET_RAW`).
- The **host kernel must expose `nf_tables`** — true on modern Docker Desktop and recent
  Linux kernels. Kernel modules cannot be loaded from inside a container, so `setup` checks
  for nftables up front and fails loudly if it is unavailable.

## Operations

- Daemon logs: `/var/log/castellan.log`.
- Inspect live state: `sudo nft list table inet castellan`.
- Recover after a crash or a bad edit: `cargo build --release && sudo /usr/local/bin/init-firewall.sh`.

## Development

The container ships a pinned Rust toolchain (rustc, cargo, rustfmt, clippy). Standard
workflow:

```sh
cargo build      # build
cargo test       # unit tests (pattern matching)
cargo clippy     # lints
```

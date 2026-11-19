# Security

## Threat model

Castellan defends against a **process inside the confined container that tries to reach the
network without its destination appearing in the allow-list**. It assumes that container holds no
capabilities and cannot become root, and it is supported only as a sidecar: the firewall runs in a
container of its own, which owns the network namespace the confined container joins (see the
[README](README.md#running-it)).

**What Castellan protects against**

- Outbound connections to arbitrary IPs from a process in the confined container.
- DNS lookups for names not on the allow-list: they are refused at the resolver, and no address is
  authorized.
- Stale-IP bypass: addresses are injected into the nftables allow-set only after a matching DNS
  query resolves, closing the resolve→connect race.
- DNS tunnelling through the upstream resolver: only the daemon's uid may reach it, Docker's
  embedded resolver (`127.0.0.11`) included, on any port.
- Reaching the Docker host or other containers on its bridge, unless `--allow-host-network` is
  given, and port 22 on arbitrary addresses, unless `--allow-ssh` is.
- Tampering with the firewall from the confined container: the daemon, supervisor and allow-list
  are in another container's filesystem, which shares no volume or PID namespace with it.
- A compromised daemon persisting on disk: it runs as an unprivileged uid and cannot write the
  binary, the supervisor script or the allow-list.

**Assumptions about the confined container**

- It holds no capabilities and cannot become root (`cap_drop: [ALL]`, `no-new-privileges`, no
  `sudo` or setuid path to root).
- Nothing in it runs as the daemon's uid (65532). The ruleset identifies the daemon by socket uid,
  and both containers share one network namespace, so a process with that uid would be treated as
  the daemon and could reach the upstream resolver directly.
- It shares the network namespace's sysctls, `net.ipv4.ip_unprivileged_port_start=0` included, so
  it can bind `127.0.0.1:53` if the daemon is not holding it (for example during the supervisor's
  one-second restart). That fails closed: only the daemon adds addresses to the allow-sets, so a
  squatter can stop resolution but authorize nothing.

**What Castellan does NOT protect against**

- A process with `CAP_NET_ADMIN` in the firewall's network namespace: it can flush the ruleset.
  This includes the daemon itself if it is compromised: the daemon holds `CAP_NET_ADMIN` (it adds
  every resolved address to the allow-set with `nft`), so an attacker who gets code execution in it
  can open egress. A daemon the supervisor restarts keeps the live ruleset (and whatever was added
  to it); only recreating the firewall container, which rebuilds the namespace, clears it.
- Root in the shared namespace, with or without capabilities. uid 0 is exempt from the DNS redirect
  (Docker's embedded resolver forwards from root-owned sockets, and redirected they would loop), but
  gets no access from that: it is refused the embedded resolver and every upstream address, and its
  other traffic meets the default-drop ruleset. The confined container's `cap_drop`,
  `no-new-privileges` and lack of `sudo` are what keep it from being root at all.
- DNS-over-HTTPS, DNS-over-TLS, or any other mechanism that resolves names without going through
  the system resolver. If a process resolves a name via a DoH/DoT endpoint that is on the
  allow-list, that resolution bypasses Castellan's interception.
- Connections to IPs that are already in the allow-set (e.g. from a prior TTL-valid resolution).
  Any process can connect to an authorized IP for the remainder of that TTL window.
- An allowed name that resolves to an address you did not mean to allow, a private, link-local or
  Docker-host address included. Whoever controls the zone of an allow-listed name decides what it
  resolves to, and Castellan authorizes the answer as it comes. Keep wildcards and regexes to
  zones you trust.
- Data carried in DNS queries for *allowed* names (labels under an allow-listed wildcard whose zone
  someone else controls), and data exfiltration to allowed destinations in general. Castellan
  controls *where* traffic goes, not *what* it contains.
- Raw IP connections that never touch DNS. If code hardcodes an IP address, and that IP happens to
  be in the allow-set (or in a `JsonList` seed range), it will be permitted without any name lookup.

## File capabilities

Docker does not give a non-root user a capability it adds with `cap_add`, so `castellan` and `nft`
carry `CAP_NET_ADMIN` as a file capability, set in the firewall image. Anything that runs as the
daemon's uid in the firewall container can therefore use `nft` with that capability. Only the
supervisor and the daemon run there; do not add anything else to that image or exec into it as that
uid with a shell you would not trust. Do not set `no-new-privileges` on the firewall container: it
makes the kernel ignore the file capabilities, and the daemon fails to start.

## Allow-list file permissions

The allow-list and its directory chain, in the firewall image, must be root-owned and not writable
by the daemon's uid (it is the image's own, and `check-sidecar.sh` checks the Dockerfile that makes
it). In Unix, renaming a directory entry only requires write permission on its parent, so a
writable `/usr/local/share/castellan/` would let its owner substitute another allow-list.

```sh
docker exec <project>-firewall-1 stat -c "%a %U:%G %n" \
  /usr/local/share /usr/local/share/castellan /usr/local/share/castellan/allowed-domains.txt \
  /usr/local/bin/castellan /usr/local/bin/castellan-supervisor.sh
# expected: 755 root:root, 755 root:root, 644 root:root, 755 root:root, 755 root:root
```

## Reporting vulnerabilities

There is no formal disclosure process at this time. Please open a GitHub issue with the label
`security` for any findings.

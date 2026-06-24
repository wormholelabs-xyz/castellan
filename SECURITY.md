# Security

## Threat model

Castellan defends against a **non-privileged, non-root process** inside the container that tries to reach the network without its destination appearing in the allow-list. Specifically:

**What Castellan protects against**

- Outbound connections to arbitrary IPs from a process running as a non-root user without `CAP_NET_ADMIN` or `CAP_NET_RAW`.
- DNS lookups for names not on the allow-list — these are refused at the resolver level before any IP is authorized.
- Stale-IP bypass: addresses are injected into the nftables allow-set only after a matching DNS query resolves, closing the resolve→connect race window.

**What Castellan does NOT protect against**

- A process that has gained root or `CAP_NET_ADMIN`/`CAP_NET_RAW` inside the container — it can flush the nftables ruleset and bypass the firewall entirely.
- DNS-over-HTTPS, DNS-over-TLS, or any other mechanism that resolves names without going through the system resolver. If a process resolves a name via a DoH/DoT endpoint that happens to be on the allow-list, that name resolution bypasses Castellan's interception.
- Connections to IPs that are already in the allow-set (e.g. from a prior TTL-valid resolution). Any process can connect to an authorized IP for the remainder of that TTL window.
- Data exfiltration to allowed destinations. Castellan controls *where* traffic goes, not *what* it contains.
- Raw IP connections that never touch DNS. If code hardcodes an IP address, and that IP happens to be in the allow-set (or in a `JsonList` seed range), it will be permitted without any name lookup.

## sudoers grant

The recommended setup grants passwordless root via a sudoers entry:

```
node ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh
```

Anyone who can overwrite `/usr/local/bin/init-firewall.sh` effectively has root. **`init-firewall.sh` and `castellan-supervisor.sh` must be owned by root and not writable by the container user** (mode `0755`, owner `root:root`). The reference Dockerfile already does this; verify that any custom image does too.

## Allow-list file permissions

The allow-list and its full directory chain must be owned by root and not writable by the container user:

| Path | Required mode |
|------|--------------|
| `/usr/local/share/` | `755 root:root` |
| `/usr/local/share/castellan/` | `755 root:root` |
| `/usr/local/share/castellan/allowed-domains.txt` | `644 root:root` |

In Unix, renaming a directory entry only requires write permission on its parent. A container user with write access to `/usr/local/share/` could rename `/usr/local/share/castellan` aside, create a replacement directory with an arbitrary allow-list, and reload the firewall via the sudoers grant — without ever touching a root-owned file.

Verify the full chain with:

```sh
stat -c "%a %U:%G %n" \
  /usr/local/share \
  /usr/local/share/castellan \
  /usr/local/share/castellan/allowed-domains.txt
# expected: 755 root:root, 755 root:root, 644 root:root
```

## Reporting vulnerabilities

There is no formal disclosure process at this time. Please open a GitHub issue with the label `security` for any findings.

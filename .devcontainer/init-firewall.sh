#!/bin/bash
# Orchestrates the castellan DNS-driven egress firewall. Run as root (via sudo).
#
# Replaces the legacy iptables+ipset script. The heavy lifting lives in the `castellan`
# Rust binary; this script only sequences the steps so DNS never points at a resolver
# that isn't listening yet:
#
#   1. capture the real upstream resolver (before we repoint resolv.conf)
#   2. install the default-drop nftables ruleset (DNS still flows direct to upstream)
#   3. start the supervised resolver daemon and wait for it to bind
#   4. enable DNS interception and repoint resolv.conf at the local resolver
#   5. verify
#
# Idempotent: safe to run on both postCreate and postStart. On a container restart the
# network namespace (and thus the nftables ruleset) is fresh, so we rebuild from scratch.
set -euo pipefail
IFS=$'\n\t'

BINARY=/usr/local/bin/castellan
BUILT=/workspace/target/release/castellan
SUPERVISOR=/usr/local/bin/castellan-supervisor.sh
READY=/run/castellan/ready
LOG=/var/log/castellan.log
PORT=53

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: must run as root (use sudo)" >&2
  exit 1
fi

# Install the freshly-built binary (built as the non-root user at postCreate). The binary
# lives in /usr/local/bin (root-owned) so the sudoers grant can't be abused via a swapped
# workspace file.
if [ -x "$BUILT" ]; then
  install -m 0755 "$BUILT" "$BINARY"
fi
if [ ! -x "$BINARY" ]; then
  echo "ERROR: $BINARY not found — run 'cargo build --release' first" >&2
  exit 1
fi

# 1. Capture the upstream resolver(s) from resolv.conf BEFORE we touch it.
#    On a container restart resolv.conf already points at 127.0.0.1 (written by a prior
#    run), so we keep a backup of the original Docker-assigned resolvers and read from it
#    whenever the file has been taken over.
RESOLV_BACKUP=/etc/resolv.conf.castellan
if grep -qE '^nameserver[[:space:]]+127\.0\.0\.1$' /etc/resolv.conf && [ -f "$RESOLV_BACKUP" ]; then
  UPSTREAM=$(grep -E '^nameserver' "$RESOLV_BACKUP" | awk '{print $2}' | paste -sd, -)
else
  UPSTREAM=$(grep -E '^nameserver' /etc/resolv.conf | awk '{print $2}' | paste -sd, -)
  cp /etc/resolv.conf "$RESOLV_BACKUP"
fi
if [ -z "$UPSTREAM" ]; then
  echo "ERROR: no upstream nameserver found in /etc/resolv.conf" >&2
  exit 1
fi
echo "Upstream DNS resolver(s): $UPSTREAM"

# 2. Base ruleset: default-drop egress, static seeds, allow upstream:53 directly.
"$BINARY" setup --upstream "$UPSTREAM" --port "$PORT"

# 3. (Re)start the supervised daemon.
rm -f "$READY"
pkill -f "$SUPERVISOR" 2>/dev/null || true
pkill -f "$BINARY daemon" 2>/dev/null || true
mkdir -p "$(dirname "$READY")"
UPSTREAM="$UPSTREAM" PORT="$PORT" setsid "$SUPERVISOR" >/dev/null 2>&1 </dev/null &

# Wait (up to ~10s) for the resolver to bind and advertise readiness.
for _ in $(seq 1 50); do
  [ -f "$READY" ] && break
  sleep 0.2
done
if [ ! -f "$READY" ]; then
  echo "ERROR: resolver did not become ready in time. Recent log:" >&2
  tail -n 20 "$LOG" 2>/dev/null || true
  exit 1
fi
echo "Resolver is ready."

# 4. Enable transparent DNS interception, then repoint resolv.conf at the resolver.
"$BINARY" enable-intercept --upstream "$UPSTREAM" --port "$PORT"
echo "nameserver 127.0.0.1" > /etc/resolv.conf

# 5. Verify end-to-end.
"$BINARY" verify

echo "castellan firewall is active."

#!/usr/bin/env bash
# Checks, without a container, the properties of the sidecar layout that keep the firewall out
# of the agent's reach. Run in CI. It reads docker-compose.yml, devcontainer.json and the
# Dockerfile, and fails if any of these changes:
#
#   dev          has no capability and cannot gain one, and joins the firewall's network namespace
#                only once the firewall is healthy and the resolver is repointed
#   firewall     is not root, holds NET_ADMIN and nothing else, owns the network namespace, and
#                shares no file or process with dev
#   resolv-init  is root with no capability, and shares nothing but the namespace
#   the images   dev has no sudo, iptables or nftables; the firewall's files carry the capability
#
# Requires: bash, awk, grep, sed, paste, sort, jq
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="$HERE/docker-compose.yml"
fail=0
bad() {
  echo "::error::$*"
  fail=1
}

# A service's block in the compose file: from its key to the next service's.
service() { awk -v s="  $1:" '/^  [a-z][a-z-]*:$/ { on = ($0 == s) } on' "$COMPOSE"; }
# Its `cap_add` entries (block or flow form), without a trailing comment, sorted, on one line.
adds() {
  awk '/^    cap_add: \[/ { l = $0; sub(/^[^[]*\[/, "", l); sub(/\].*$/, "", l); gsub(/,/, " ", l); print l; next }
       /^    cap_add:$/ { on = 1; next }
       on && /^      - / { sub(/^      - (CAP_)?/, ""); sub(/ *#.*$/, ""); print; next } { on = 0 }' |
    tr ' ' '\n' | grep -v '^$' | sort | paste -sd' ' - || true
}
has() { printf '%s\n' "$1" | grep -qxF -- "$2"; }
# The `condition:` under `depends_on: <dependency>:`.
condition() { printf '%s\n' "$1" | grep -A1 -xF "      $2:" | sed -n '2p' | sed 's/^ *condition: //'; }

dev="$(service dev)"
fw="$(service firewall)"
init="$(service resolv-init)"
for pair in "dev:$dev" "firewall:$fw" "resolv-init:$init"; do
  [ -n "${pair#*:}" ] || bad "docker-compose.yml: no ${pair%%:*} service"
done

# dev
has "$dev" '    cap_drop: [ALL]' || bad "dev does not have \`cap_drop: [ALL]\`"
[ -z "$(printf '%s\n' "$dev" | adds)" ] || bad "dev adds capabilities back: $(printf '%s\n' "$dev" | adds)"
has "$dev" '    security_opt: [no-new-privileges:true]' || bad "dev does not set exactly \`security_opt: [no-new-privileges:true]\`"
has "$dev" '    network_mode: "service:firewall"' || bad "dev does not join the firewall's network namespace (\`network_mode: \"service:firewall\"\`)"
[ "$(condition "$dev" firewall)" = service_healthy ] || bad "dev does not wait for the firewall to be healthy, so it could start with open egress"
[ "$(condition "$dev" resolv-init)" = service_completed_successfully ] || bad "dev does not wait for resolv-init to complete, so its DNS could bypass the firewall"
printf '%s\n' "$dev" | grep -qE '^    (privileged|pid|ipc|userns_mode|cgroup|devices):' &&
  bad "dev sets privileged, pid, ipc, userns_mode, cgroup or devices"

# firewall
has "$fw" '    user: castellan' || bad "the firewall does not run as \`user: castellan\` (it needs no root)"
has "$fw" '    cap_drop: [ALL]' || bad "the firewall does not have \`cap_drop: [ALL]\`"
[ "$(printf '%s\n' "$fw" | adds)" = NET_ADMIN ] || bad "the firewall holds '$(printf '%s\n' "$fw" | adds)', not exactly NET_ADMIN"
printf '%s\n' "$fw" | grep -q '^    build: \*firewall-build$' || has "$(sed -n '/^x-firewall-build:/,/^$/p' "$COMPOSE")" '  target: firewall' ||
  bad "the firewall does not build the Dockerfile's \`firewall\` target"
printf '%s\n' "$fw" | grep -qE '^    (privileged|network_mode|pid|ipc|volumes|ports|devices|userns_mode|cgroup|security_opt|restart|depends_on):' &&
  bad "the firewall sets privileged, network_mode, pid, ipc, volumes, ports, devices, userns_mode, cgroup, security_opt (it would ignore its file capabilities), restart or depends_on"
printf '%s\n' "$fw" | grep -qxF '      net.ipv4.conf.all.route_localnet: "1"' || bad "the firewall does not set net.ipv4.conf.all.route_localnet"

# resolv-init
has "$init" '    user: "0:0"' || bad "resolv-init is not \`user: \"0:0\"\` (resolv.conf is root's)"
has "$init" '    cap_drop: [ALL]' || bad "resolv-init does not have \`cap_drop: [ALL]\`"
[ -z "$(printf '%s\n' "$init" | adds)" ] || bad "resolv-init holds capabilities"
has "$init" '    network_mode: "service:firewall"' || bad "resolv-init does not join the firewall's network namespace"
[ "$(condition "$init" firewall)" = service_healthy ] || bad "resolv-init does not wait for the firewall to be healthy, so it could repoint resolv.conf at a resolver that is not up"
printf '%s\n' "$init" | grep -qE '^    (privileged|pid|ipc|volumes|ports|devices|userns_mode|cgroup):' &&
  bad "resolv-init shares more than the network namespace"

# devcontainer.json adds no capability and starts the whole set.
J="$HERE/devcontainer.json"
for key in privileged capAdd features runArgs postCreateCommand; do
  jq -e --arg k "$key" 'has($k)' "$J" >/dev/null && bad "devcontainer.json: \`$key\` can give the dev container capabilities or processes of its own"
done
jq -e '.runServices | (index("firewall") != null and index("resolv-init") != null and index("dev") != null)' "$J" >/dev/null ||
  bad "devcontainer.json: runServices does not start dev, firewall and resolv-init"
jq -e '.postStartCommand == "/usr/local/bin/check-firewall.sh"' "$J" >/dev/null || bad "devcontainer.json: postStartCommand is not /usr/local/bin/check-firewall.sh"

# Dockerfile
D="$HERE/Dockerfile"
last="$(grep -n '^FROM ' "$D" | tail -1 | cut -d: -f1)"
final="$(tail -n +"$last" "$D" | grep -v '^[[:space:]]*#' || true)"
printf '%s\n' "$final" | grep -qE '(^|[^a-z-])(sudo|sudoers|iptables|nftables)([^a-z-]|$)' &&
  bad "Dockerfile: the dev stage installs or mentions sudo, sudoers, iptables or nftables"
printf '%s\n' "$final" | grep -qE 'chmod 0755 .*/usr/local/bin/check-firewall\.sh' || bad "Dockerfile: the dev stage does not set check-firewall.sh's mode"
fwline="$(grep -n -E '^FROM .* AS firewall$' "$D" | head -1 | cut -d: -f1 || true)"
if [ -z "$fwline" ] || [ "$fwline" -ge "$last" ]; then
  bad "Dockerfile: no \`firewall\` stage before the last one"
else
  stage="$(sed -n "${fwline},$((last - 1))p" "$D" | grep -v '^[[:space:]]*#' || true)"
  printf '%s\n' "$stage" | grep -qE 'setcap cap_net_admin=ep /usr/local/bin/castellan;' || bad "Dockerfile: the firewall stage does not grant castellan CAP_NET_ADMIN as a file capability"
  printf '%s\n' "$stage" | grep -qF 'setcap cap_net_admin=ep "$NFT"' || bad "Dockerfile: the firewall stage does not grant nft CAP_NET_ADMIN as a file capability"
  printf '%s\n' "$stage" | grep -qE 'useradd .*--uid 65532 --gid castellan ' || bad "Dockerfile: the firewall stage does not create the \`castellan\` user with uid 65532"
  printf '%s\n' "$stage" | grep -qxF 'USER castellan' || bad "Dockerfile: the firewall stage does not end as USER castellan"
  printf '%s\n' "$stage" | grep -qE 'chown castellan:castellan /run/castellan$' || bad "Dockerfile: /run/castellan is not the daemon's"
fi
[ -x "$HERE/check-firewall.sh" ] || bad "check-firewall.sh is missing or not executable"

[ "$fail" = 0 ] && echo "ok  dev has no capability and no sudo; the firewall is unprivileged with NET_ADMIN only"
exit "$fail"

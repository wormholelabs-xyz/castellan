#!/bin/bash
# Checks that the egress firewall is enforcing, from inside the dev container: a host the
# allow-list does not name must be unreachable, and one it does name reachable.
#
# The firewall is the `firewall` service (castellan, in its own container, whose network
# namespace this container joins). This container starts only once that one is healthy, so this
# is a second look from the agent's side: a firewall that reported healthy without enforcing would
# leave egress open, and a failure here fails the start loudly. Dev Containers runs this as
# `postStartCommand`, as `node` and outside the agent's sandbox, so it is baked into the image
# root-owned (Dockerfile) and not run from the workspace.
#
# It runs as the agent's uid, in a home the agent writes, so nothing the agent can write or set
# may change what it decides or what it reads. curl reads $HOME/.curlrc, $CURL_HOME/.curlrc and
# $XDG_CONFIG_HOME/curlrc, and honours proxy and CA variables: a config file could black-hole one
# host so that the check passes, or add transfers of its own that run here, outside the sandbox,
# with the reach of a process that can read ~/.ssh. So curl runs with an empty environment
# (`env -i`, which also leaves it no HOME) and with -q, which ignores config files, by absolute
# paths; and the two hosts and the wait are constants here, not read from the environment.
#
# The two hosts are castellan's own defaults for `castellan verify` (the allow-list names
# api.github.com). It waits for the state it wants, up to WAIT seconds, rather than judging the
# first look: the allowed host can take a moment to answer.
#
# Requires: curl, env, sleep
set -u

BLOCKED=example.com
ALLOWED=api.github.com
WAIT=90

# An HTTPS connection to $1 within 3 s. A name the allow-list does not name is refused by castellan's
# resolver, so curl fails at once ("could not resolve"); the timeout is for a name that resolves
# and then gets no answer. `-q` must be curl's first argument.
reach() {
  /usr/bin/env -i /usr/bin/curl -q --noproxy '*' --connect-timeout 3 -sS -o /dev/null "https://$1" >/dev/null 2>&1
}

deadline=$((SECONDS + WAIT))
while :; do
  if ! reach "$BLOCKED" && reach "$ALLOWED"; then
    echo "ok  the firewall is enforcing: $BLOCKED is unreachable, $ALLOWED is reachable"
    exit 0
  fi
  [ "$SECONDS" -ge "$deadline" ] && break
  /usr/bin/sleep 2
done

echo "::error::the egress firewall is not enforcing (waited ${WAIT}s)" >&2
if reach "$BLOCKED"; then
  echo "  $BLOCKED is REACHABLE: the firewall container is not running, or has not installed its ruleset." >&2
  echo "  Egress is open. Look at: docker logs <project>-firewall-1 (and that the service is up)." >&2
else
  echo "  $BLOCKED is unreachable, as it should be." >&2
fi
if ! reach "$ALLOWED"; then
  echo "  $ALLOWED is NOT reachable: DNS or the allow-list is broken, or this machine is offline." >&2
fi
exit 1

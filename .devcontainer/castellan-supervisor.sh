#!/bin/bash
# Supervises the castellan DNS resolver daemon, restarting it on crash.
#
# The entry point of the firewall container (docker-compose.yml, `firewall`). There is no init
# system in it, so this loop is the fail-closed safety net: if the daemon dies, no new DNS
# resolution happens (existing connections survive via conntrack), and this restarts it within
# ~1s. It logs to stdout, so `docker logs` shows it. The service has no restart policy of its
# own: a restarted container gets a new network namespace, and `dev`, which joined the old one,
# would be left without a network.
#
# Runs as an unprivileged user. The daemon gets CAP_NET_ADMIN from file capabilities, and does
# not rewrite resolv.conf (the `resolv-init` service does, once): --no-resolv-conf.
#
# PORT (default 53) is where the daemon listens, on 127.0.0.1. UPSTREAM (default 127.0.0.11,
# Docker's embedded resolver, which is what this container's resolv.conf names) is passed
# explicitly, since resolv.conf is repointed at the daemon and it would otherwise find no
# upstream. CASTELLAN_EXTRA_ARGS adds daemon flags (for example --allow-host-network); set it
# in docker-compose.yml, not here.
set -u

BINARY=/usr/local/bin/castellan
READY=/run/castellan/ready
PORT="${PORT:-53}"
UPSTREAM="${UPSTREAM:-127.0.0.11}"

child=
# `docker stop` sends SIGTERM to this script (through the init). Stop the daemon with it, rather
# than leave it for the kill that follows the grace period.
trap 'kill "$child" 2>/dev/null; exit 0' TERM INT

echo "[$(date)] supervisor starting (port=${PORT}, upstream=${UPSTREAM})"
while true; do
  # The ready file is the container's health. Remove it before each launch, and again as soon as
  # the daemon exits: one left behind would report a daemon that is not serving.
  rm -f "$READY"
  echo "[$(date)] launching castellan daemon"
  # CASTELLAN_EXTRA_ARGS is split into words on purpose.
  # shellcheck disable=SC2086
  "$BINARY" daemon --listen "127.0.0.1:${PORT}" --upstream "$UPSTREAM" --no-resolv-conf ${CASTELLAN_EXTRA_ARGS:-} &
  child=$!
  wait "$child"
  rc=$?
  rm -f "$READY"
  echo "[$(date)] daemon exited (rc=${rc}); restarting in 1s"
  sleep 1
done

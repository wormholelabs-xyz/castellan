# Reads and writes the pinned build arguments in docker-compose.yml. Sourced by
# fetch-vscode-extension-shas.sh and sync-claude-code-version.sh, which set SCRIPT_DIR first.
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

# get_arg KEY: the pinned value, or nothing.
get_arg() {
  sed -n -E "s/^ +$1: \"?([^\"]*)\"?\$/\1/p" "${COMPOSE_FILE}" | head -n 1
}

# set_arg KEY VALUE: replaces the value of the one `KEY: ...` line, or fails.
set_arg() {
  local n tmp
  n="$(grep -c -E "^ +$1: " "${COMPOSE_FILE}" || true)"
  if [ "${n}" != 1 ]; then
    echo "ERROR: expected exactly one '$1:' line in ${COMPOSE_FILE}, found ${n}" >&2
    return 1
  fi
  tmp="$(mktemp "${COMPOSE_FILE}.XXXXXX")"
  sed -E "s|^( +)$1: .*\$|\1$1: \"$2\"|" "${COMPOSE_FILE}" > "${tmp}"
  mv "${tmp}" "${COMPOSE_FILE}"
}

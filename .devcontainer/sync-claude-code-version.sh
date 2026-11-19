#!/usr/bin/env bash
set -euo pipefail

# Sets CLAUDE_CODE_VERSION (and its per-arch checksums) in
# .devcontainer/docker-compose.yml to match CLAUDE_CODE_EXT_VERSION, so the
# standalone CLI and the VS Code extension stay on the same release.
#
# Run fetch-vscode-extension-shas.sh first if you also want to bump the extension.
#
# Usage: .devcontainer/sync-claude-code-version.sh [version]
#   version  Optional override; defaults to CLAUDE_CODE_EXT_VERSION.
#
# Requires: curl, jq

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib-pins.sh
. "${SCRIPT_DIR}/lib-pins.sh"

version="${1:-$(get_arg CLAUDE_CODE_EXT_VERSION)}"
if [ -z "${version}" ]; then
  echo "ERROR: CLAUDE_CODE_EXT_VERSION not found in ${COMPOSE_FILE}" >&2
  exit 1
fi

manifest_url="https://downloads.claude.ai/claude-code-releases/${version}/manifest.json"
echo "Fetching ${manifest_url}" >&2
manifest="$(curl -fsSL "${manifest_url}")"

amd64="$(jq -r '.platforms["linux-x64"].checksum // empty' <<< "${manifest}")"
arm64="$(jq -r '.platforms["linux-arm64"].checksum // empty' <<< "${manifest}")"
if [ -z "${amd64}" ] || [ -z "${arm64}" ]; then
  echo "ERROR: manifest for ${version} is missing linux-x64 or linux-arm64 checksum" >&2
  exit 1
fi

set_arg CLAUDE_CODE_VERSION "${version}"
set_arg CLAUDE_CODE_CHECKSUM_AMD64 "${amd64}"
set_arg CLAUDE_CODE_CHECKSUM_ARM64 "${arm64}"

echo "Done — CLAUDE_CODE_VERSION=${version}" >&2

#!/usr/bin/env bash
set -euo pipefail

# Sets CLAUDE_CODE_VERSION (and its per-arch checksums) in
# .devcontainer/devcontainer.json to match CLAUDE_CODE_EXT_VERSION, so the
# standalone CLI and the VS Code extension stay on the same release.
#
# Run fetch-vscode-extension-shas.sh first if you also want to bump the extension.
#
# Usage: .devcontainer/sync-claude-code-version.sh [version]
#   version  Optional override; defaults to CLAUDE_CODE_EXT_VERSION.
#
# Requires: curl, jq

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEVCONTAINER_JSON="${SCRIPT_DIR}/devcontainer.json"

_tmp=""
trap '[ -n "${_tmp}" ] && rm -f "${_tmp}"' EXIT

version="${1:-$(jq -r '.build.args.CLAUDE_CODE_EXT_VERSION // empty' "${DEVCONTAINER_JSON}")}"
if [ -z "${version}" ]; then
  echo "ERROR: CLAUDE_CODE_EXT_VERSION not found in ${DEVCONTAINER_JSON}" >&2
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

_tmp=$(mktemp "${DEVCONTAINER_JSON}.XXXXXX")
jq --arg ver "${version}" --arg amd64 "${amd64}" --arg arm64 "${arm64}" \
   '.build.args.CLAUDE_CODE_VERSION = $ver
    | .build.args.CLAUDE_CODE_CHECKSUM_AMD64 = $amd64
    | .build.args.CLAUDE_CODE_CHECKSUM_ARM64 = $arm64' \
   "${DEVCONTAINER_JSON}" > "${_tmp}"
mv "${_tmp}" "${DEVCONTAINER_JSON}"
_tmp=""

echo "Done — CLAUDE_CODE_VERSION=${version}" >&2

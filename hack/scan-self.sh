#!/usr/bin/env bash
#
# scan-self.sh — dogfood guardian against this repository in an ISOLATED HOME,
# so a test run never writes to your real ~/.local/state, cache, or config.
#
# Usage:
#   hack/scan-self.sh                      # offline project scan of this repo
#   hack/scan-self.sh --json               # same, JSON envelope
#   hack/scan-self.sh deep --root . --json # full override (args pass through to `scan`)
#
# With no arguments it runs: scan project --root <repo> --no-fetch
# Any arguments you pass replace that default and go straight to `guardian scan`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SBX="$(mktemp -d -t guardian-self-XXXXXX)"
trap 'chmod -R u+w "$SBX" 2>/dev/null || true; rm -rf "$SBX"' EXIT

# Isolate only guardian's own state/cache/config via XDG dirs. We deliberately
# do NOT override HOME, so the Go toolchain keeps using the real module/build
# cache (sandboxing HOME would pull read-only module-cache files into $SBX and
# break cleanup).
export XDG_STATE_HOME="$SBX/state" XDG_CACHE_HOME="$SBX/cache" XDG_CONFIG_HOME="$SBX/config"

if [ "$#" -eq 0 ]; then
  set -- project --root "$REPO_ROOT" --no-fetch
fi

cd "$REPO_ROOT"
go run ./cmd/guardian scan "$@"

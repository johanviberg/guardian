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
trap 'rm -rf "$SBX"' EXIT

if [ "$#" -eq 0 ]; then
  set -- project --root "$REPO_ROOT" --no-fetch
fi

cd "$REPO_ROOT"
HOME="$SBX" XDG_STATE_HOME="$SBX/state" XDG_CACHE_HOME="$SBX/cache" \
  go run ./cmd/guardian scan "$@"

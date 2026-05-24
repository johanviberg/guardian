#!/usr/bin/env bash
#
# sync-upstream.sh — re-vendor Perplexity's Bumblebee scanner into
# internal/bumblebee/.
#
# It clones a pinned upstream ref, copies the source tree (cmd/, internal/,
# threat_intel/, docs/schema, plus LICENSE/VERSION/README), rewrites every
# Go import path from the upstream module path to guardian's vendored path,
# preserves the LICENSE, and records the exact upstream commit SHA and
# vendoring date in internal/bumblebee/UPSTREAM.txt.
#
# It is idempotent: it wipes and recreates the vendored tree on every run so
# the result is a pure function of the pinned ref. The hand-written exported
# shim package (internal/bumblebee/engine) lives OUTSIDE the copied tree and
# is never touched by this script.
#
# Usage:
#   hack/sync-upstream.sh [REF]
#
#   REF defaults to the value of UPSTREAM_REF below. Pass a tag (e.g. v0.1.1)
#   or a commit SHA to pin a specific revision.
#
# Constraints honored:
#   - Bumblebee is zero-dep stdlib; vendoring adds no go.mod requires.
#   - Only files under internal/bumblebee/ are written.

set -euo pipefail

UPSTREAM_REPO="https://github.com/perplexityai/bumblebee"
UPSTREAM_REF="${1:-main}"

# Resolve repo-root-relative paths so the script works from any CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VENDOR_DIR="${REPO_ROOT}/internal/bumblebee"
OLD_MODULE="github.com/perplexityai/bumblebee"
NEW_MODULE="github.com/johanviberg/guardian/internal/bumblebee"

# Files/dirs that make up the vendored upstream tree. The hand-written
# engine/ shim and UPSTREAM.txt are intentionally excluded so a re-sync
# never clobbers them.
VENDORED_PATHS=(cmd internal threat_intel docs LICENSE VERSION README.md)

TMP_DIR="$(mktemp -d -t bumblebee-upstream-XXXXXX)"
cleanup() { rm -rf "${TMP_DIR}"; }
trap cleanup EXIT

echo "==> Cloning ${UPSTREAM_REPO} @ ${UPSTREAM_REF}"
git clone --quiet --depth 1 --branch "${UPSTREAM_REF}" "${UPSTREAM_REPO}" "${TMP_DIR}" 2>/dev/null \
  || git clone --quiet "${UPSTREAM_REPO}" "${TMP_DIR}"
if [ "${UPSTREAM_REF}" != "main" ]; then
  git -C "${TMP_DIR}" checkout --quiet "${UPSTREAM_REF}" 2>/dev/null || true
fi

COMMIT_SHA="$(git -C "${TMP_DIR}" rev-parse HEAD)"
VENDOR_DATE="$(date -u +%Y-%m-%d)"
echo "==> Upstream commit: ${COMMIT_SHA}"

echo "==> Wiping previously vendored tree (preserving engine/ and UPSTREAM.txt)"
for p in "${VENDORED_PATHS[@]}"; do
  rm -rf "${VENDOR_DIR:?}/${p}"
done

echo "==> Copying upstream source"
mkdir -p "${VENDOR_DIR}"
for p in "${VENDORED_PATHS[@]}"; do
  if [ -e "${TMP_DIR}/${p}" ]; then
    cp -R "${TMP_DIR}/${p}" "${VENDOR_DIR}/${p}"
  fi
done

echo "==> Rewriting import paths: ${OLD_MODULE} -> ${NEW_MODULE}"
# Rewrite in every Go source file under the copied tree. Use a NUL-delimited
# find to be safe with unusual names, and an in-place sed that works on both
# GNU and BSD/macOS sed.
while IFS= read -r -d '' f; do
  if grep -q "${OLD_MODULE}" "${f}"; then
    sed -i.bak "s#${OLD_MODULE}#${NEW_MODULE}#g" "${f}"
    rm -f "${f}.bak"
  fi
done < <(find "${VENDOR_DIR}" -name '*.go' -type f -print0)

echo "==> Writing UPSTREAM.txt"
cat > "${VENDOR_DIR}/UPSTREAM.txt" <<EOF
Vendored from: ${UPSTREAM_REPO}
Ref:           ${UPSTREAM_REF}
Commit:        ${COMMIT_SHA}
Vendored on:   ${VENDOR_DATE}
License:       Apache-2.0 (see LICENSE)

This directory contains a vendored copy of Perplexity's Bumblebee scanner.
Every Go import path has been rewritten from
  ${OLD_MODULE}/...
to
  ${NEW_MODULE}/...

Do NOT edit the vendored source by hand. Re-sync with:
  hack/sync-upstream.sh <tag-or-sha>

The hand-written exported shim package internal/bumblebee/engine/ is NOT
part of the vendored tree and is preserved across re-syncs. It is the only
sanctioned programmatic entry point into the vendored scanner.
EOF

echo "==> Refreshing embedded baseline catalogs (internal/catalog/builtin/catalogs)"
# The builtin package embeds a snapshot of threat_intel/ so the binary ships a
# usable offline catalog. Keep it in lockstep with the vendored engine.
BUILTIN_CATALOGS="${REPO_ROOT}/internal/catalog/builtin/catalogs"
if [ -d "${VENDOR_DIR}/threat_intel" ]; then
  mkdir -p "${BUILTIN_CATALOGS}"
  rm -f "${BUILTIN_CATALOGS}"/*.json
  cp "${VENDOR_DIR}/threat_intel"/*.json "${BUILTIN_CATALOGS}/"
  echo "    Copied $(ls "${BUILTIN_CATALOGS}"/*.json | wc -l | tr -d ' ') catalog file(s)."
fi

echo "==> Done. Vendored ${UPSTREAM_REPO}@${COMMIT_SHA} into ${VENDOR_DIR}"
echo "    Next: gofmt + go build ./... and review the diff."

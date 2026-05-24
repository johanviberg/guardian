# Guardian — Design

**Date:** 2026-05-24
**Status:** Validated design (pre-implementation)
**Working name:** `guardian` (rename sets the Go module path)

## Summary

`guardian` is a single Go binary (Go 1.25+) that wraps a vendored fork of
Perplexity's [Bumblebee](https://github.com/perplexityai/bumblebee) scanner as
its scan engine and layers on catalog management, local scan history, scheduling,
and notifications. It is a **shareable, local-first OSS developer tool** — no
hosted backend, no cloud control plane.

Mental model: **Bumblebee answers "what's on this machine?"; guardian answers
"is any of it risky, what changed, and who should know?"**

### What Bumblebee actually provides (verified against source)

- Go 1.25+, **zero non-stdlib deps**, Apache-2.0.
- Read-only inventory collector. Commands: `scan`, `roots`, `version`, `selftest`.
- Profiles: `baseline` (global/user roots, extensions, MCP configs), `project`
  (configured dev dirs), `deep` (explicit `--root`, incident response).
- Output is **NDJSON only**, two record types: *package records* (inventory) and
  *finding records* (exposure matches).
- Detection is pure **exact `(ecosystem, name, version)` matching** against a JSON
  exposure catalog (`schema_version` + `entries`). No signing, no built-in
  enrichment.
- All scanner/catalog/finding types live under `internal/` — **not importable**
  as an external module.

### Scope decisions

- **Ambition:** shareable OSS dev tool — single binary, local-first, no backend.
- **Integration:** vendor/fork Bumblebee source in-tree (Apache-2.0 permits it)
  with a tracked upstream re-sync process. Chosen over `go get` (blocked by
  `internal/`) and over shelling out (wanted typed records + single binary).
- **v1 capabilities:** catalog auto-fetch + freshness, scan history + diff,
  scheduling + service install, notifications.
- **Platforms:** macOS + Linux + Windows, first-class.
- **Deferred to v2:** enrichment (OSV/Socket scoring). No cloud control plane ever
  in this product.

## Architecture

```
guardian/
  cmd/guardian/            # CLI entry (Cobra)
  internal/scanner/        # wraps vendored bumblebee; RunScan(profile,roots,catalog) -> []Record
  internal/bumblebee/      # VENDORED upstream source (Apache-2.0, NOTICE preserved)
  internal/catalog/        # fetch, cache, version, freshness check
  internal/store/          # SQLite (modernc.org/sqlite, pure-Go, no cgo)
  internal/policy/         # finding -> severity/class + exit codes
  internal/diff/           # compare run N vs N-1
  internal/notify/         # terminal, desktop, webhook/slack (platform-isolated)
  internal/service/        # launchd / systemd / Windows install generators
  internal/report/         # human + JSON renderers
  internal/config/         # config file + flags + env
  hack/sync-upstream.sh    # re-vendor bumblebee, record commit SHA
  docs/                    # OUTPUT_SCHEMA.md, CATALOG_FORMAT.md, EXIT_CODES.md
```

**Key boundary:** everything talks to a `scanner.Scanner` interface, not to
bumblebee directly. The vendored fork sits behind it, so upstream re-syncs stay
contained to one adapter package and the scanner is swappable later at no cost.

**Dependency budget:** Cobra (CLI), `modernc.org/sqlite` (pure-Go DB → clean
cross-compilation for all three OSes), stdlib otherwise. **No cgo.**

## Commands

```
guardian scan [baseline|project|deep]   # one-shot; --root, --catalog, --json, --findings-only
guardian status                          # last scan, catalog freshness, current exposures
guardian diff [--since <run|duration>]   # what's new/resolved vs a prior run
guardian catalog update|list|show        # fetch/inspect exposure catalogs
guardian run                             # daemon: scheduler + lockfile watchers
guardian service install|uninstall       # writes launchd/systemd/Windows unit (+ --cron)
guardian suppress <id> --until <dur>     # acknowledge a finding with expiry
guardian doctor                          # checks perms, catalog freshness, scanner selftest
guardian version
```

Profiles map directly to Bumblebee's `baseline`/`project`/`deep`. Every command
accepts `--json`; default is human-readable.

## Data flow (one scan)

```
1. resolve config + profile + roots
2. catalog: ensure fresh (fetch if stale, unless --no-fetch / offline)
3. scanner.RunScan(profile, roots, catalogPath)
      -> vendored bumblebee produces NDJSON (package + finding records)
      -> parse into typed []Record
4. policy.Classify(findings) -> {confirmed-malicious, vulnerable, informational} + severity
5. store.SaveRun(run, components, findings)   # SQLite
6. diff.Against(previousRun)                   # new / resolved / persisting
7. report.Render(...)  (human or JSON)
8. notify.Dispatch(newCritical)  (daemon mode / --notify)
9. exit code from policy (0 ok, 1 findings, 2 critical) for CI/cron
```

The daemon (`run`) is the same pipeline on a timer: `baseline` every N minutes,
plus optional lockfile-watch triggering a `project` scan on change. `deep` is
never automatic.

**Catalog source:** default to Bumblebee's `threat_intel/` catalogs fetched over
HTTPS (repo/release), pluggable to a custom URL. v1 verifies **schema + sha256
checksum**, not signatures (no PKI to manage).

## Data model (SQLite)

DB at `~/.local/state/guardian/guardian.db` (OS-appropriate path).

```
scan_runs(id, started_at, finished_at, profile, roots_json,
          catalog_version, host, scanner_version, exit_code)
components(id, run_id→scan_runs, ecosystem, name, version,
           source_file, confidence)          -- inventory (package records)
findings(id, run_id→scan_runs, catalog_id, ecosystem, name, version,
         severity, evidence_type, confidence, class, source_file)
catalog_versions(version PK, fetched_at, entry_count, sha256, source_url)
suppressions(id, ecosystem, name, version_range, reason, expires_at, created_at)
```

- `components` rows pruned after a retention window (default 30 days); findings
  kept longer.
- Raw NDJSON of the latest run written to `runs/<id>.ndjson` for evidence/replay.
- v2 enrichment slots in via a future `enrichments` table + `findings.class`
  without a painful migration.

## Diff & policy

**Diff** keys findings on `(catalog_id, ecosystem, name, version, source_file)`
and set-differences run N vs N−1 → **new / resolved / persisting**. Powers
`status` ("3 new criticals since yesterday") and `diff`.

**Classification** (simple Go, not Rego in v1):
- `confirmed-malicious` — exact catalog match, `severity: critical`.
- `vulnerable` — catalog match, lower severity.
- `informational` — inventory-only signals.

**Suppressions** with expiry: `guardian suppress <id> --until 7d`. Suppressed
findings are still stored, just downranked and excluded from notifications and
exit-code escalation.

**Exit codes:** `0` clean · `1` non-critical findings · `2` confirmed-malicious /
critical — so cron and CI can gate on it.

## Notifications

`internal/notify`, behind a `Notifier` interface, fanning out to enabled channels:

- **Terminal** — always; the rendered report.
- **Desktop** — `osascript` (macOS), `notify-send` (Linux), PowerShell toast
  (Windows). Each isolated in `*_platform.go` with build tags; no-op fallback so a
  scan never hard-fails over a notification.
- **Webhook/Slack** — POST JSON to a configured URL (Slack incoming-webhook shape
  supported directly), stdlib `net/http`, no SDK.

Fire only on **new** critical/malicious findings (from the diff), not on every
persisting one. Configurable threshold + quiet hours.

## Service install

`internal/service` generates and loads a native unit (no third-party supervisor):

- macOS → `~/Library/LaunchAgents/<id>.plist` + `launchctl bootstrap`.
- Linux → `~/.config/systemd/user/guardian.service` + `systemctl --user enable --now`.
- Windows → registered Scheduled Task via `schtasks` (simpler/less privileged
  than a Service).
- **Cron fallback** → `guardian service install --cron` installs crontab lines.

Default invokes `guardian run` (daemon); `--cron` instead schedules repeated
one-shot `guardian scan baseline`.

## Upstream sync

`hack/sync-upstream.sh`: clone a pinned `perplexityai/bumblebee` tag, copy its
tree into `internal/bumblebee/`, rewrite the module import path, preserve
`LICENSE`/`NOTICE`, record the source commit SHA in
`internal/bumblebee/UPSTREAM.txt`. A CI job periodically checks for new upstream
tags and opens a PR. The `scanner` adapter is the only thing an upstream API
change can break.

## Config & agent output

**Config** (`internal/config`): single `guardian.yaml` under
`$XDG_CONFIG_HOME/guardian/` (OS-appropriate), precedence **flags > env
(`GUARDIAN_*`) > file > defaults**. Covers scan roots, profile schedule, catalog
source URL + freshness TTL, notification channels/thresholds/quiet-hours,
retention windows. `guardian doctor` reports the effective merged config.

**Agent-friendly output** (first-class):
- `--json` on every command emits a stable, versioned envelope:
  `{"schema_version", "command", "generated_at", "data": {...}}`.
- `scan`/`status`/`diff` JSON include typed findings, classification, diff
  buckets, catalog version, and exit-code rationale.
- Raw per-run NDJSON kept on disk for evidence/replay.
- **Structured docs:** `OUTPUT_SCHEMA.md`, `CATALOG_FORMAT.md`, `EXIT_CODES.md`
  give humans and agents a contract.

## Testing strategy

- **scanner adapter:** golden-file tests on canned NDJSON fixtures (incl.
  malformed lines); one integration test running the vendored `selftest`.
- **store:** temp SQLite, migration round-trip, retention-pruning tests.
- **diff/policy:** table-driven unit tests (highest-value, deterministic).
- **catalog:** `httptest` server for fetch/freshness/checksum + offline-mode.
- **notify/service:** interface-level fakes; platform files behind build tags with
  per-OS smoke tests in a GitHub Actions matrix (macOS/Linux/Windows).
- **CLI:** end-to-end golden tests asserting exit codes + JSON envelope shape.

## Phasing

- **v1:** vendored scanner + catalog auto-fetch/freshness + history/diff (SQLite) +
  scheduling/service install (3 OSes) + notifications + JSON/docs.
- **v2:** enrichment (OSV first — free/public; Socket behind an API key),
  remediation hints, richer suppression UX.
- **Not in this product:** cloud control plane, fleet dashboards, findings upload,
  ticketing.

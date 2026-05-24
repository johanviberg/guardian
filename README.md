# guardian

> Local-first supply-chain sentinel for developer machines. A single Go binary that
> wraps [Perplexity's Bumblebee](https://github.com/perplexityai/bumblebee) scanner and
> adds catalog management, scan history, scheduling, and notifications.

Bumblebee answers *"what packages, extensions, and tools are on this machine?"*
**guardian** answers *"is any of it known-malicious right now, what changed since last
time, and who should know?"* — entirely on your machine. No account, no telemetry, no
hosted backend.

> **Status:** v1, pre-release. Module path `github.com/rmxventures/guardian` is a working
> placeholder.

## Security posture

guardian is a security tool, so its own behavior is conservative by design:

- **Read-only.** The vendored Bumblebee engine only *reads* package metadata, lockfiles,
  extension manifests, and MCP configs. guardian never installs, removes, modifies, or
  executes the packages it inspects.
- **Local-first & offline-capable.** A baseline exposure catalog is **embedded in the
  binary**, so a scan works on a fresh machine with no network. Catalog refresh over the
  network is optional and explicit.
- **No telemetry.** Nothing is sent anywhere unless *you* configure a webhook/Slack
  notifier. There is no phone-home, no analytics, no usage collection.
- **No cgo.** Pure-Go (incl. `modernc.org/sqlite`) → reproducible, statically-linkable
  cross-platform builds with a smaller native attack surface.
- **Deterministic detection.** Findings are exact `(ecosystem, name, version)` matches
  against a reviewed catalog — no fuzzy heuristics raising false alarms.

See [SECURITY.md](SECURITY.md) for the vulnerability-reporting policy and threat model.

## Install

```sh
go install github.com/rmxventures/guardian/cmd/guardian@latest
```

Or build from source:

```sh
git clone https://github.com/johanviberg/guardian
cd guardian
go build -o guardian ./cmd/guardian
```

Requires Go 1.26+. Supports macOS, Linux, and Windows.

## Quick start

```sh
# One-shot scan of a project, machine-readable output
guardian scan project --root ~/code/myrepo --json

# Scan everything on the machine (baseline profile), human-readable
guardian scan baseline

# What's new/resolved since the last scan?
guardian diff

# Current exposures + catalog freshness + last scan time
guardian status

# Validate environment, catalog, and config
guardian doctor
```

## Commands

| Command | What it does |
|---|---|
| `scan [baseline\|project\|deep]` | Run a scan. `baseline` = global/user roots; `project` = `--root` dirs; `deep` = incident sweep. |
| `status` | Host, catalog freshness, last scan, current exposures. |
| `diff [--since <run\|dur>]` | New / resolved / persisting findings vs a prior run. |
| `catalog update\|list\|show` | Fetch and inspect exposure catalogs. |
| `run` | Scheduling daemon (periodic scans + notifications). |
| `service install\|uninstall` | Native launchd / systemd / Scheduled Task unit (or `--cron`). |
| `suppress <eco> <name> <version>` | Acknowledge a finding, optionally `--until <duration>`. |
| `doctor` | Environment, catalog, and config health checks. |
| `version` | guardian and scan-engine versions. |

Every command accepts `--json` for a stable, versioned output envelope (see below).

## Exit codes

guardian's exit code gates cron jobs and CI:

| Code | Meaning |
|---|---|
| `0` | Clean — no actionable findings (suppressed findings never escalate). |
| `1` | Findings present, none confirmed-malicious. |
| `2` | At least one **confirmed-malicious / critical** finding. |

```sh
# Fail a CI step only on confirmed-malicious packages:
guardian scan project --root . || [ $? -lt 2 ]
```

## JSON output

`--json` emits a stable envelope (`schema_version` is bumped only on breaking changes):

```json
{
  "schema_version": 1,
  "command": "scan",
  "generated_at": "2026-05-24T16:20:53Z",
  "data": {
    "profile": "deep",
    "catalog_version": "20260524-7332ac36a139",
    "component_count": 1,
    "findings": [
      {
        "catalog_id": "mini-shai-hulud-2026-npm-beproduct-nestjs-auth",
        "severity": "critical",
        "class": "confirmed-malicious",
        "ecosystem": "npm",
        "name": "@beproduct/nestjs-auth",
        "version": "0.1.18",
        "source_file": "/path/package-lock.json"
      }
    ]
  }
}
```

Output schemas, the catalog format, and exit codes are documented under [`docs/`](docs/).

## Running as a service

```sh
# macOS launchd / Linux systemd / Windows Scheduled Task
guardian service install

# Conservative environments: install a cron entry instead
guardian service install --cron
```

## Exposure catalogs

A catalog is JSON with a string `schema_version` and an `entries` array; detection is
exact `(ecosystem, name, version)` matching. guardian ships an embedded baseline catalog
and can refresh from a configurable source. See
[`docs/CATALOG_FORMAT.md`](docs/CATALOG_FORMAT.md).

## Architecture

```
cmd/guardian          CLI (cobra) — wires the pipeline
internal/scanner      Scanner interface; VendoredScanner drives the engine
internal/bumblebee    Vendored Bumblebee fork (Apache-2.0) + exported engine shim
internal/catalog      Fetch/cache/validate catalogs (+ embedded baseline)
internal/store        SQLite history, suppressions, retention (pure-Go, no cgo)
internal/policy       Classification + suppression + 0/1/2 exit codes
internal/diff         Run-to-run finding diff
internal/notify       Terminal / desktop / webhook+Slack notifiers
internal/service      launchd / systemd / Scheduled Task / cron generators
internal/report       Human + versioned-JSON renderers
internal/config       Config (yaml.v3): flags > env > file > defaults
```

Everything talks to the `scanner.Scanner` interface, never to Bumblebee directly, so the
engine is swappable and upstream re-syncs stay contained to one package.

Full design: [`docs/plans/2026-05-24-guardian-design.md`](docs/plans/2026-05-24-guardian-design.md).

## Upstream Bumblebee

Bumblebee is vendored in-tree (`internal/bumblebee/`, see `UPSTREAM.txt` for the pinned
commit) because its scanner packages live under `internal/` and cannot be imported as an
external module. Re-sync to a newer upstream tag with:

```sh
hack/sync-upstream.sh <tag-or-sha>
```

This also refreshes the embedded baseline catalogs.

## License

guardian is distributed under the Apache License 2.0. The vendored Bumblebee source
retains its original Apache-2.0 `LICENSE`; see `internal/bumblebee/LICENSE` and
`internal/bumblebee/UPSTREAM.txt` for attribution.

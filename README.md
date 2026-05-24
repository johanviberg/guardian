# guardian

> Local-first supply-chain sentinel for developer machines. A single Go binary that
> wraps [Perplexity's Bumblebee](https://github.com/perplexityai/bumblebee) scanner and
> adds catalog management, scan history, scheduling, and notifications.

Bumblebee answers *"what packages, extensions, and tools are on this machine?"*
**guardian** answers *"is any of it known-malicious right now, what changed since last
time, and who should know?"* — entirely on your machine. No account, no telemetry, no
hosted backend.

> **Status:** v1, pre-release. Module path: `github.com/johanviberg/guardian`.

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
go install github.com/johanviberg/guardian/cmd/guardian@latest
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
and can refresh from one or more configurable sources. Sources are merged by union — same
advisory id across sources gets its versions unioned and its severity set to the highest.
See [`docs/CATALOG_FORMAT.md`](docs/CATALOG_FORMAT.md).

### Multi-source feeds

Combine the public upstream feed with a private signed feed in `guardian.yaml`:

```yaml
catalog:
  sources:
    - name: upstream
      url: https://api.github.com/repos/perplexityai/bumblebee/contents/threat_intel?ref=main
      verify: off                      # upstream is unsigned

    - name: internal
      url: https://feeds.internal.example.com/catalog.json
      verify: require                  # must have a valid minisign signature
      public_key: /etc/guardian/internal-feed.pub
```

Each source caches independently under `catalog.cache_dir/sources/<name>/`; the merged
result is written to `catalog.cache_dir/catalog.json`. The embedded baseline is always
merged in as an implicit, unsigned, infallible source (offline-first on fresh machines).

The single-source shorthand (`source_url`, `verify`, `public_key` at the top level of
`catalog:`) still works when `sources` is absent.

### Optional signature verification

guardian verifies fetched feeds against a trusted
[minisign](https://jedisct1.github.io/minisign/) public key (verify-only; sign with the
standard `minisign` CLI). A detached signature lives next to each file as a sibling
`<file>.minisig`. Configure `verify` per-source (`off` default, `warn`, `require`).

In `require` mode a missing or invalid signature **aborts the update and caches nothing**;
in `warn` mode it logs a warning and proceeds. The default upstream feed is unsigned, so
`off` is the default. See
[`docs/CATALOG_FORMAT.md`](docs/CATALOG_FORMAT.md#signature-verification-optional) for
signing steps.

## Enrichment

guardian can optionally enrich a scan with known-vulnerability data from the public
[OSV.dev](https://osv.dev) database. **Enrichment is opt-in and off by default.**

Enable it per-run with `--enrich`:

```sh
guardian scan deep --enrich
```

or persistently in `guardian.yaml`:

```yaml
enrich:
  enabled: true          # default false
  sources: [osv]         # default [osv]
  fail_on: ""            # "" = informational (default); or a severity to gate on
  cache_ttl: 24h         # how long advisory details are cached locally
```

Environment overrides: `GUARDIAN_ENRICH_ENABLED=true`, `GUARDIAN_ENRICH_FAIL_ON=high`.

**What it queries.** For each *supported* component (npm, PyPI, Go, RubyGems, Packagist)
that has a concrete version, guardian sends `{ecosystem, name, version}` to `api.osv.dev`
(batched), then fetches advisory details for matches. Unsupported ecosystems (editor/IDE and
browser extensions, MCP, etc.) and version-less components are skipped. No API key is needed.
Advisory details are cached locally so repeat scans don't re-fetch, and enrichment is
fail-open: an offline or rate-limited OSV is a warning, not a scan failure.

**Gating.** OSV findings are classified `vulnerable` (never `confirmed-malicious`) and are
**informational by default** — they appear in output and the JSON `findings[]` but do **not**
change the exit code. Set `enrich.fail_on` to a severity to make OSV findings at or above
that severity escalate the exit code to `1`. Catalog gating (exit `2` for confirmed-malicious,
`1` for catalog-vulnerable) is unchanged. See [SECURITY.md](SECURITY.md#enrichment-optional-off-by-default)
for the enrichment threat model.

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

## Releases

Releases are cut by pushing a semver tag; everything else is automated and signed.

```sh
git tag v1.2.3
git push origin v1.2.3
```

The [`release` workflow](.github/workflows/release.yml) then runs GoReleaser
([`.goreleaser.yaml`](.goreleaser.yaml)) to:

- build reproducible, pure-Go (`CGO_ENABLED=0`) binaries for darwin/linux/windows
  on amd64/arm64 (build timestamps pinned to the commit),
- produce per-archive **SBOMs** (syft) and a sha256 `checksums.txt`,
- **cosign keyless-sign** the checksums file (Sigstore OIDC — no long-lived keys),
- emit a first-party **SLSA build-provenance attestation** for each binary,
- publish all of the above to the GitHub Release.

### Verifying a download

Verify the cosign keyless signature over the checksums file (which covers every
artifact by sha256):

```sh
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/johanviberg/guardian/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt

# Then confirm your downloaded artifact is listed in the verified checksums:
sha256sum --check --ignore-missing checksums.txt
```

Verify the SLSA build provenance of the binary against this repo:

```sh
gh attestation verify ./guardian --repo johanviberg/guardian
```

## License

guardian is distributed under the Apache License 2.0. The vendored Bumblebee source
retains its original Apache-2.0 `LICENSE`; see `internal/bumblebee/LICENSE` and
`internal/bumblebee/UPSTREAM.txt` for attribution.

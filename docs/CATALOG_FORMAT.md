# Exposure catalog format

An exposure catalog is a JSON document listing known-bad `(ecosystem, package, version)`
tuples. Detection is **exact matching** — a component on the machine is a finding only if
its ecosystem, name, and one of the listed versions match an entry exactly. This format is
the one the vendored Bumblebee engine consumes; guardian validates the same shape.

## Schema

```json
{
  "schema_version": "0.1.0",
  "entries": [
    {
      "id": "mini-shai-hulud-2026-npm-beproduct-nestjs-auth",
      "name": "@beproduct/nestjs-auth (Mini/Shai-Hulud May 2026 compromised)",
      "ecosystem": "npm",
      "package": "@beproduct/nestjs-auth",
      "versions": ["0.1.18", "0.1.19", "0.1.17"],
      "severity": "critical"
    }
  ]
}
```

### Top-level

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `schema_version` | string | yes | e.g. `"0.1.0"`. **Must be a string**, not a number. When merging a directory of catalogs, all files must declare the same `schema_version`. |
| `entries` | array | yes | May be empty (a valid placeholder catalog). |

Unknown top-level keys (e.g. a `_comment`) are ignored for forward-compatibility.

### Entry

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `id` | string | yes | Stable advisory identifier, echoed onto findings as `catalog_id`. |
| `ecosystem` | string | yes | `npm`, `pypi`, `go`, `rubygems`, `composer`, `vscode`, … |
| `package` | string | yes | Package/extension name, matched exactly. |
| `versions` | string[] | yes | Non-empty. A component matches if its version equals **any** entry here. |
| `name` | string | no | Free-form human label, echoed onto the finding. |
| `severity` | string | no | Free-form label (`critical`, `high`, `info`, …). Not restricted to an enum; echoed onto the finding. guardian's policy treats `critical` as confirmed-malicious. |

Unknown per-entry keys are ignored.

## Files vs directories

A catalog source may be a single `.json` file **or a directory** of `.json` files. The
upstream Bumblebee project publishes many per-advisory files under `threat_intel/`; both
the engine and guardian load a directory by merging all `*.json` entries (with a
consistent `schema_version` across files).

## How guardian sources catalogs

- **Embedded baseline:** a snapshot of the upstream catalogs ships inside the binary, so a
  scan works offline on first run with no configuration.
- **Cached/fetched:** `guardian catalog update` fetches a fresher catalog from the
  configured source (default: the upstream `threat_intel/` directory via the GitHub
  Contents API) into the local cache, validates it, and records a sha256.
- **Override:** `guardian scan --catalog <path>` uses a specific file or directory
  verbatim, with no fetch.

Freshness is governed by a TTL (config `catalog.freshness_ttl`); `guardian status` and
`guardian doctor` report whether the active catalog is fresh or stale.

## Validation

guardian rejects a catalog that: isn't a JSON object with `schema_version` + `entries`;
has a non-string `schema_version`; or contains an entry missing `id`, `ecosystem`,
`package`, or with an empty `versions` list. Severity values are **not** validated against
an enum.

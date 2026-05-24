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

## Signature verification (optional)

guardian can verify fetched catalog feeds against a trusted
[minisign](https://jedisct1.github.io/minisign/) public key. It is **verify-only and
compatible with the standard `minisign` CLI** (and OpenBSD `signify` detached signatures);
guardian never signs. Both legacy/pure (`Ed`) and prehashed (`ED`, BLAKE2b-512) signatures
are supported, and the minisign **trusted comment** is verified via its global signature.

### Convention: sibling `.minisig`

A detached signature lives next to the file it signs, with a `.minisig` suffix:

- **Single-file source** (`source_url` ends in `.json`): guardian fetches
  `<source_url>.minisig`.
- **Directory source** (GitHub Contents API listing): for each `X.json` in the listing,
  guardian looks for `X.json.minisig` **in the same listing** and fetches its `download_url`.

Verification runs on the **exact bytes that will be cached**, before anything is written to
the cache.

### Config

| Key | Env | Values | Notes |
|-----|-----|--------|-------|
| `catalog.verify` | `GUARDIAN_CATALOG_VERIFY` | `off` (default), `warn`, `require` | See modes below. |
| `catalog.public_key` | `GUARDIAN_CATALOG_PUBLIC_KEY` | path **or** inline key | Required when `verify: require`. Accepts a path to a minisign `.pub` file or the inline key text; guardian auto-detects which. |

Modes:

- **`off`** — skip verification entirely (the default upstream feed is unsigned).
- **`warn`** — verify when a signature is available; on a missing or invalid signature, log
  a warning and proceed.
- **`require`** — every catalog file must have a valid signature from the trusted key; any
  missing/invalid/wrong-key signature **aborts the update and caches nothing**.

### Signing a feed (with the standard `minisign` CLI)

```sh
# one-time: generate a keypair
minisign -G -p feed.pub -s feed.key

# sign each published catalog file (produces <file>.minisig next to it)
minisign -Sm catalog.json -s feed.key
# ...repeat for every X.json in a directory feed
```

Publish each `X.json` alongside its `X.json.minisig`, then point guardian at the feed:

```yaml
catalog:
  source_url: https://example.com/feeds/catalog.json   # or a directory listing
  verify: require
  public_key: /etc/guardian/feed.pub                   # path, or inline "RWQ..." key text
```

## Validation

guardian rejects a catalog that: isn't a JSON object with `schema_version` + `entries`;
has a non-string `schema_version`; or contains an entry missing `id`, `ecosystem`,
`package`, or with an empty `versions` list. Severity values are **not** validated against
an enum.

# JSON output schema

Every command accepts `--json`, which emits a single stable, versioned envelope to
stdout. Human-readable output (the default) is for terminals; `--json` is the contract for
agents, CI, and scripts.

## Envelope

```json
{
  "schema_version": 1,
  "command": "scan",
  "generated_at": "2026-05-24T16:20:53Z",
  "data": { }
}
```

| Field | Type | Notes |
|-------|------|-------|
| `schema_version` | int | Currently `1`. Bumped only on a breaking change to the envelope or any `data` shape. Additive fields are not breaking. |
| `command` | string | The command that produced this output (`scan`, `status`, `diff`, `catalog.update`, …). |
| `generated_at` | string | RFC 3339 UTC timestamp. |
| `data` | object | Command-specific payload (see below). |

Consumers should branch on `command` and tolerate unknown additive fields.

## Finding object

Findings appear in several payloads and share this shape:

```json
{
  "catalog_id": "mini-shai-hulud-2026-npm-beproduct-nestjs-auth",
  "severity": "critical",
  "class": "confirmed-malicious",
  "ecosystem": "npm",
  "name": "@beproduct/nestjs-auth",
  "version": "0.1.18",
  "source_file": "/path/package-lock.json",
  "evidence_type": "exact-version-match",
  "confidence": 1,
  "suppressed": false,
  "source": "catalog"
}
```

`class` is guardian's policy classification: `confirmed-malicious`, `vulnerable`, or
`informational`. `severity` is the catalog-supplied label. `suppressed` is `true` when an
active suppression matched (such findings do not escalate the exit code).

`source` identifies the producing subsystem: `catalog` (the default — exposure-catalog
matches) or `osv` (optional OSV vulnerability enrichment). An absent or empty `source` is
treated as `catalog` by consumers.

`summary` (optional, omitted when empty) is a short human-readable description, populated by
enrichment with the advisory summary.

OSV enrichment findings always have `class: vulnerable` and `source: osv` (with
`evidence_type: osv`) — they are never `confirmed-malicious`, and they are informational:
they do not escalate the exit code unless `enrich.fail_on` is configured. A representative
enrichment finding:

```json
{
  "catalog_id": "CVE-2021-23337",
  "severity": "high",
  "class": "vulnerable",
  "ecosystem": "npm",
  "name": "lodash",
  "version": "4.17.15",
  "source_file": "/proj/package-lock.json",
  "evidence_type": "osv",
  "confidence": 1,
  "suppressed": false,
  "source": "osv",
  "summary": "Command injection in lodash"
}
```

## `data` per command

### `scan`

```json
{
  "profile": "deep",
  "host": "host.local",
  "catalog_version": "20260524-7332ac36a139",
  "scanned_at": "2026-05-24T16:20:53Z",
  "component_count": 1,
  "findings": [ /* Finding[] */ ],
  "counts": { "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0 },
  "exit_code": 2
}
```

`counts` tallies the actionable (non-suppressed) findings by severity. `exit_code`
mirrors the process exit code (see [EXIT_CODES.md](EXIT_CODES.md)).

### `status`

```json
{
  "host": "host.local",
  "catalog_version": "20260524-7332ac36a139",
  "catalog_fresh": false,
  "last_scan_at": "2026-05-24T16:20:53Z",
  "findings": [ /* current exposures: Finding[] */ ],
  "counts": { "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0 }
}
```

### `diff`

```json
{
  "new":        [ /* Finding[] */ ],
  "resolved":   [ /* Finding[] */ ],
  "persisting": [ /* Finding[] */ ]
}
```

`new` are findings absent from the prior run, `resolved` were present before and are now
gone, `persisting` are unchanged. Findings are keyed by
`(catalog_id, ecosystem, name, version, source_file)`.

### `catalog.update` / `catalog.list` / `catalog.show`

Report the cached catalog metadata (version, fetched-at, sha256, entry count, source URL).

## Raw NDJSON

In addition to the JSON envelope, the raw NDJSON emitted by the scan engine for the latest
run is retained on disk for evidence/replay. The envelope above is the normalized,
stable interface; the raw NDJSON is the engine's native format and may change with
upstream.

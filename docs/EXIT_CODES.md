# Exit codes

`guardian scan` (and the other finding-producing commands) return an exit code that
encodes the most severe actionable result, so cron jobs and CI can gate on it without
parsing output.

| Code | Name | Meaning |
|------|------|---------|
| `0` | clean | No escalating findings. Suppressed and (by default) OSV-enrichment findings never escalate. |
| `1` | findings | Escalating findings present, none confirmed-malicious (catalog-`vulnerable`, or OSV findings promoted via `enrich.fail_on`). |
| `2` | malicious | At least one **confirmed-malicious / critical** catalog finding. |

Any other non-zero code is an operational error (bad flags, unreadable config, no usable
catalog, I/O failure) — not a finding result. Errors are written to stderr.

## How the code is decided

1. Findings are classified (`confirmed-malicious`, `vulnerable`, `informational`).
2. Active suppressions are applied; suppressed findings are excluded from escalation.
3. The exit code is the maximum over the remaining findings:
   - any `confirmed-malicious` → `2`
   - else any **catalog** finding → `1`
   - else → `0`

## OSV enrichment findings

Findings from optional OSV enrichment (`source: osv`, always `class: vulnerable`) are
**informational by default** — they appear in output and the JSON `findings[]` but do
**not** change the exit code, regardless of severity. They escalate only when you set a
threshold:

- `enrich.fail_on: <severity>` (or `GUARDIAN_ENRICH_FAIL_ON=<severity>`) makes an OSV
  finding at or above that severity escalate the exit code to `1`.
- Catalog gating (`2` for confirmed-malicious, `1` for catalog-`vulnerable`) is unchanged.

So with `enrich.fail_on` unset, `guardian scan --enrich` can report vulnerabilities while
still exiting `0`; set `fail_on: high` to fail CI on high/critical CVEs.

## Gating examples

```sh
# Fail only on confirmed-malicious packages (treat plain findings as a warning):
guardian scan project --root . || [ $? -lt 2 ]

# Fail on any finding at all:
guardian scan project --root .

# Pre-commit / CI: scan, but never block (record only):
guardian scan project --root . || true
```

The `doctor` command uses the same convention: it exits non-zero (`2`) when a critical
health check fails, `0` when all checks pass (non-fatal warnings, e.g. a stale catalog on
a fresh machine, do not fail it).

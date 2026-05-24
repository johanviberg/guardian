# Exit codes

`guardian scan` (and the other finding-producing commands) return an exit code that
encodes the most severe actionable result, so cron jobs and CI can gate on it without
parsing output.

| Code | Name | Meaning |
|------|------|---------|
| `0` | clean | No actionable findings. Suppressed findings never escalate the exit code. |
| `1` | findings | One or more findings are present, but none are confirmed-malicious. |
| `2` | malicious | At least one **confirmed-malicious / critical** finding. |

Any other non-zero code is an operational error (bad flags, unreadable config, no usable
catalog, I/O failure) — not a finding result. Errors are written to stderr.

## How the code is decided

1. Findings are classified (`confirmed-malicious`, `vulnerable`, `informational`).
2. Active suppressions are applied; suppressed findings are excluded from escalation.
3. The exit code is the maximum over the remaining findings:
   - any `confirmed-malicious` → `2`
   - else any finding → `1`
   - else → `0`

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

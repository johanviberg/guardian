# Security Policy

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately via GitHub's [private vulnerability
reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" under the repository's **Security** tab), or email the
maintainer.

Please include:

- affected version / commit,
- a description and, if possible, a minimal reproduction,
- the impact you observed.

We aim to acknowledge reports within **3 business days** and to provide a remediation
timeline after triage. Coordinated disclosure is appreciated; we will credit reporters
who wish to be named.

## Scope

In scope:

- The `guardian` binary and all `internal/` packages.
- The build, release, and upstream-vendoring tooling (`hack/`, CI workflows).

The vendored Bumblebee engine (`internal/bumblebee/`) is upstream code. Vulnerabilities
specific to it should also be reported to
[perplexityai/bumblebee](https://github.com/perplexityai/bumblebee); we will pull fixes
in via `hack/sync-upstream.sh`.

## Threat model

guardian inspects potentially untrusted inputs (lockfiles, package metadata, extension
manifests, exposure catalogs) on a developer's machine. Its design constraints:

- **Read-only inspection.** guardian and the vendored engine never install, modify,
  execute, or network-fetch the packages they inspect. The only outbound network calls
  guardian itself makes are: (a) optional exposure-catalog refresh from a configured
  source, and (b) optional user-configured webhook/Slack notifications. Both are off by
  default for offline use (`--no-fetch`, no notifier configured).
- **No code execution from scanned content.** Catalog and lockfile parsing is pure data
  decoding; malformed input is rejected or skipped, never evaluated.
- **No privilege escalation.** Service installation targets per-user units
  (LaunchAgents, `systemctl --user`, user Scheduled Tasks) — no root/admin daemon.
- **Local, unencrypted state.** Scan history and suppressions live in a local SQLite DB
  under your user state directory. It is not encrypted at rest; protect it with normal
  filesystem permissions. It contains an inventory of your installed packages — treat it
  as you would any local dev metadata.
- **Catalog trust.** Findings are only as trustworthy as the catalog. v1 validates
  catalog **schema and content** and (for cached copies) records a sha256, but does not
  yet verify cryptographic **signatures**. Pin your catalog source to a trusted location.

## Supply-chain hardening of this project

Because guardian is itself a supply-chain tool, the project applies the practices it
advocates:

- **No cgo**, pure-Go dependencies — smaller native attack surface, reproducible builds.
- **Minimal dependency footprint** (cobra, modernc.org/sqlite, yaml.v3, stdlib).
- **Minimal third-party CI Actions.** CI uses only first-party GitHub Actions
  (`actions/checkout`, `actions/setup-go`, `github/codeql-action`); security scanners are
  installed from source at pinned-by-`go.mod` toolchain rather than via third-party
  marketplace actions.
- **Continuous scanning in CI:** `govulncheck` (Go vulnerability DB), `gosec` (static
  analysis), `staticcheck`, `go vet`, CodeQL, and guardian **dogfooding itself** on every
  push (see `.github/workflows/ci.yml`).
- **Least-privilege workflows:** `permissions: contents: read` by default,
  `persist-credentials: false` on checkout.
- **Dependabot** keeps Go modules and GitHub Actions patched.

## Supported versions

Until a 1.0 release, only the latest commit on the default branch receives security
fixes.

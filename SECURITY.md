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
- **Catalog trust.** Findings are only as trustworthy as the catalog. guardian always
  validates catalog **schema and content** and records a sha256 for cached copies. It
  additionally supports **opt-in [minisign](https://jedisct1.github.io/minisign/)-compatible
  Ed25519 signature verification** of fetched catalog feeds, controlled by
  `catalog.verify`:
  - `off` (default) — no signature checking. The default upstream Bumblebee feed is
    **unsigned**, so verification is off out of the box.
  - `warn` — verify when a sibling `.minisig` signature is available; on a missing or
    invalid signature, log a warning and proceed.
  - `require` — every fetched catalog file must carry a valid signature from the trusted
    key (`catalog.public_key`); any missing, malformed, wrong-key, or invalid signature
    **aborts the update and writes nothing to the cache** (verification happens on the
    exact bytes that would be cached, before caching).

  guardian is **verify-only**: maintainers sign feeds with the standard `minisign` CLI and
  publish a detached `<file>.minisig` next to each catalog file. Point `catalog.public_key`
  at the trusted public key (a file path or an inline key) and set `catalog.verify: require`
  when sourcing from a self-signed feed. Still pin your catalog source to a trusted location.

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

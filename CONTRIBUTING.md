# Contributing

Thanks for taking the time to contribute. guardian is a security tool, so we
keep the bar high for correctness, auditability, and supply-chain hygiene.

## Before you start

- **Security vulnerabilities.** See [SECURITY.md](SECURITY.md) — do **not** open
  a public issue.
- **Feature ideas and bugs.** Open a GitHub issue first so we can agree on the
  direction before you write code. We'd rather say "yes, and here's how" than
  reject a thoughtful PR.

## Quick start

```sh
make tools                                          # staticcheck, gosec, govulncheck (pinned versions)
go install github.com/gitleaks/gitleaks@latest      # optional but recommended
lefthook install                                    # pre-commit hooks
```

`make tools` installs the lint/security tools at the exact versions CI uses
(pinned in the [`Makefile`](Makefile) and mirrored in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)), so local runs match the
gate. Bump those versions in both places when you upgrade a tool.

Requires Go 1.26+. The vendored Bumblebee engine (`internal/bumblebee/`) is
zero-dep stdlib and never adds `go.mod` requirements.

## Development workflow

Everyday commands live in the [`Makefile`](Makefile):

```sh
make build            # go build -o guardian ./cmd/guardian
make test             # go test -race ./...
make lint             # gofmt-check + go vet + staticcheck
make sec              # gosec + govulncheck
make ci               # everything CI runs locally: lint + sec + test + self-scan
make fmt              # gofmt our packages (not the vendored tree)
make run              # dogfood: scan this repo with embedded catalog
make scan-self        # isolated-home self-scan (writes nowhere real)
```

### Testing

- Run `make test` before pushing. All tests use the race detector.
- New features must come with tests. The test suite lives alongside the code in
  `internal/` — we don't maintain a separate `test/` directory.
- Tests that make network calls are gated on a `GUARDIAN_INTEGRATION` env var
  or use `-short` for offline-only unit tests.

### Linting and analysis

CI runs five checks on every push. Run them locally:

```sh
make lint   # gofmt + go vet + staticcheck (our packages only)
make sec    # gosec + govulncheck (excludes vendored tree)
```

1. **gofmt** — no tabs-to-spaces, no trailing whitespace. The vendored tree is
   upstream code and is excluded.
2. **go vet** — no exceptions.
3. **staticcheck** — our packages only.
4. **gosec** — static security analysis.
5. **govulncheck** — Go vulnerability database against the compiled binary.

### Pre-commit hooks

The repo ships a [`lefthook.yml`](lefthook.yml) that runs:

- **gitleaks** — scans staged changes for secrets before they reach history.
- **gofmt** — staged Go files must be clean (excludes `internal/bumblebee/`).

Install with `lefthook install`. CI treats leaks and unformatted code as
failures.

## Architecture at a glance

```
cmd/guardian          CLI (cobra) — wires the pipeline
internal/scanner      Scanner interface; VendoredScanner drives the engine
internal/bumblebee    Vendored Bumblebee fork (Apache-2.0) + engine shim
internal/catalog      Multi-source fetch/cache/merge/verify (+ embedded baseline)
internal/enrich       OSV vulnerability enrichment (opt-in)
internal/store        SQLite history, suppressions, retention (pure-Go, no cgo)
internal/policy       Classification + suppression + gated exit codes
internal/diff         Run-to-run finding diff
internal/notify       Terminal / desktop / webhook+Slack notifiers
internal/service      launchd / systemd / Scheduled Task / cron generators
internal/report       Human + versioned-JSON renderers
internal/config       Config (yaml.v3): flags > env > file > defaults
```

The `scanner.Scanner` interface is the central abstraction — everything talks
to it, never to Bumblebee directly, so the engine is swappable.

## Working with the vendored engine

Bumblebee lives under `internal/bumblebee/` as a vendored copy of
[perplexityai/bumblebee](https://github.com/perplexityai/bumblebee).

- **Do not edit the vendored source by hand.** It is overwritten on every
  upstream sync.
- To re-sync to a newer upstream ref:

  ```sh
  hack/sync-upstream.sh <tag-or-sha>
  ```

  This clones the ref, rewrites import paths, refreshes the embedded baseline
  catalogs under `internal/catalog/builtin/catalogs/`, and writes the new
  commit SHA into `internal/bumblebee/UPSTREAM.txt`.
- The exported entry point is `internal/bumblebee/engine/` — a hand-written
  shim that lives outside the copied tree and is preserved across syncs.
- If you need to change scanner behaviour, change the `Scanner` interface in
  `internal/scanner/` or the engine shim, not the upstream source.

## Commit messages

We use conventional commits loosely. The format is:

```
<type>: <short description>

<optional body>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, `sec`.
Write the body in imperative mood, wrap at 72 characters, and explain *why*
when it's not obvious.

Well-known scopes (optional): `scanner`, `catalog`, `store`, `notify`,
`service`, `diff`, `policy`, `enrich`, `config`, `release`.

## Pull request process

1. Open a GitHub issue for discussion before starting work (unless it's a
   trivial fix).
2. Create a topic branch from `main`.
3. Run `make ci` locally — it must pass.
4. Open a PR against `main` with a title matching the commit-message style.
5. CI runs automatically: build + test on macOS, Linux, and Windows; lint;
   security scan; and a guardian dogfood-scan of the repo itself.
6. A maintainer reviews. Expect at least one round of feedback.
7. Squash-merge into `main` when approved. The merge commit title becomes the
   squashed message, so keep the PR title descriptive.

### PR checklist

- [ ] `make ci` passes
- [ ] New code is tested (unit tests in the relevant `internal/` package)
- [ ] Public API changes are reflected in docs (CLI help text, `docs/` Markdown)
- [ ] Commit messages follow the conventional format
- [ ] No secrets, credentials, or tokens in the diff (gitleaks checks this)

## Releases

Releases are cut by pushing a semver tag to `main`:

```sh
git tag v1.2.3
git push origin v1.2.3
```

This triggers the [`release`](.github/workflows/release.yml) workflow which
builds reproducible binaries for darwin/linux/windows on amd64/arm64, produces
SBOMs (syft), cosign keyless-signs the checksums file, and attaches SLSA build
provenance attestations — all without manual intervention.

Pre-release tags (`v1.2.3-rc1`, `v1.2.3-beta`) publish as GitHub pre-releases.

## Docs

- User-facing docs live in [`docs/`](docs/). If your PR changes CLI output,
  schema, exit codes, or the catalog format, update the relevant doc.
- Design docs are under `docs/plans/` and are kept as a record of decisions.
- CLI help text is generated by cobra from command annotations — update those
  rather than duplicating help in Markdown.

## Code of conduct

This project adheres to the [CNCF Community Code of Conduct](CODE_OF_CONDUCT.md).
Be respectful, assume good faith, and focus on the technical problem.

## Getting help

- Open a GitHub Discussion for questions and ideas.
- Use `guardian doctor` to validate your local environment if something isn't
  working.
- Read the design doc at `docs/plans/2026-05-24-guardian-design.md` for deeper
  architectural context.

# Go-live: GitHub repo settings runbook (`gh`)

These settings can't live in the repo — they're applied to the GitHub repository itself.
This runbook **confirms** current state and **sets** the secure defaults via `gh`. Every
command is idempotent; re-running is safe.

> Prereqs: `gh auth status` shows you logged in as `johanviberg` with `repo` +
> `admin:repo_hook` scope. Run `gh auth refresh -s admin:org,repo,read:project` if a call
> 403s on a scope.

> **Shortcut:** sections 1–6 (the safe, idempotent toggles) are scripted in
> [`hack/go-live.sh`](../hack/go-live.sh). Preview with `DRY_RUN=1 hack/go-live.sh`, then
> run `hack/go-live.sh` to apply. Section 0 (create remote, flip to public) and the UI
> fork-PR toggle in §4 stay manual because they're irreversible. The sections below remain
> the source of truth for what the script does.

```sh
# Set once per shell.
OWNER=johanviberg
REPO=guardian
R="repos/$OWNER/$REPO"
```

---

## 0. Publish the repo (first time only)

The local repo has no remote yet. Create it **private first**, push, verify CI is green,
then flip to public — so the world never sees a half-configured repo.

```sh
# Create empty private remote and push current main.
gh repo create "$OWNER/$REPO" --private --source=. --remote=origin --push

# ... let CI / CodeQL run once, confirm green, finish section B ...

# Flip to public when ready (irreversible exposure of all history — gitleaks already clean).
gh repo edit "$OWNER/$REPO" --visibility public --accept-visibility-change-consequences
```

---

## 1. Secret scanning + push protection

Free and auto-enabled on public repos, but set explicitly so it survives visibility flips.

```sh
# Confirm
gh api "$R" --jq '.security_and_analysis'

# Set
gh api -X PATCH "$R" -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
```

## 2. Dependabot alerts + automated security updates

`.github/dependabot.yml` only schedules version bumps; alerts and auto security PRs are
repo toggles.

```sh
# Confirm (204 = on, 404 = off)
gh api "$R/vulnerability-alerts" --silent && echo "alerts: ON" || echo "alerts: OFF"

# Set
gh api -X PUT "$R/vulnerability-alerts"          # Dependabot alerts
gh api -X PUT "$R/automated-security-fixes"       # auto security-update PRs
```

## 3. Private vulnerability reporting

Activates the GitHub-native "Report a vulnerability" button that `SECURITY.md` points to.

```sh
# Confirm
gh api "$R/private-vulnerability-reporting" --jq '.enabled'

# Set
gh api -X PUT "$R/private-vulnerability-reporting"
```

## 4. Actions token hardening

Default the `GITHUB_TOKEN` to read-only (workflows already elevate per-job) and forbid
Actions from approving PRs.

```sh
# Confirm
gh api "$R/actions/permissions/workflow"

# Set
gh api -X PUT "$R/actions/permissions/workflow" \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
```

> **Fork-PR approval (UI step):** there is no stable REST endpoint for the per-repo
> "Require approval for first-time contributors" toggle. Set it at
> **Settings → Actions → General → Fork pull request workflows** → *Require approval for
> first-time contributors* (or stricter). Do this before accepting outside PRs.

## 5. Branch protection ruleset for `main`

Modern rulesets (not legacy branch protection). Requires PR review, blocks force-push and
deletion, and gates on status checks.

> **Status-check names:** the contexts below match the current job names in
> `ci.yml`/`codeql.yml`. Confirm them against a real run before applying — list with:
> `gh api "$R/commits/main/check-runs" --jq '.check_runs[].name'`
> (expect `test (ubuntu-latest)`, `lint & vet`, `security scan`,
> `workflow audit (zizmor)`, `guardian self-scan`, `CodeQL`).

```sh
# Confirm existing rulesets
gh api "$R/rulesets" --jq '.[] | {id, name, target, enforcement}'

# Create the main-branch ruleset
gh api -X POST "$R/rulesets" --input - <<'JSON'
{
  "name": "protect-main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    { "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true
      }
    },
    { "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          { "context": "test (ubuntu-latest)" },
          { "context": "lint & vet" },
          { "context": "security scan" },
          { "context": "workflow audit (zizmor)" },
          { "context": "guardian self-scan" },
          { "context": "CodeQL" }
        ]
      }
    }
  ]
}
JSON
```

> Solo maintainer note: `required_approving_review_count: 1` plus
> `require_code_owner_review: true` (the code owner being you, per `.github/CODEOWNERS`)
> means you can't merge your own PRs without a second account/reviewer. If that's too
> strict for now, set the count to `0` and `require_code_owner_review` to `false` — you
> still get the PR gate, status checks, and force-push/deletion protection. Re-tighten
> both once a second maintainer exists.

## 6. Tag protection for release tags

Stop `v*` release tags from being moved or deleted (your signed releases depend on
immutable tags).

```sh
gh api -X POST "$R/rulesets" --input - <<'JSON'
{
  "name": "protect-release-tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [ { "type": "deletion" }, { "type": "non_fast_forward" } ]
}
JSON
```

---

## Verify everything at the end

```sh
gh api "$R" --jq '{visibility, security: .security_and_analysis}'
gh api "$R/private-vulnerability-reporting" --jq '{pvr: .enabled}'
gh api "$R/actions/permissions/workflow"
gh api "$R/rulesets" --jq '.[] | {name, target, enforcement}'
gh api "$R/vulnerability-alerts" --silent && echo "dependabot alerts: ON"
```

Expected end state: visibility `public`; secret scanning + push protection `enabled`;
PVR `true`; default workflow permissions `read`; two active rulesets (`protect-main`,
`protect-release-tags`); Dependabot alerts ON.

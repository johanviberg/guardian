#!/usr/bin/env bash
# go-live.sh — apply guardian's secure GitHub repo settings, idempotently.
#
# This is the executable form of docs/go-live-github-settings.md sections 1-6:
# the *safe, repeatable* toggles. It deliberately does NOT create the remote or
# flip visibility to public — those are irreversible and stay manual (see
# section 0 of the runbook). Re-running this script is safe.
#
# Usage:
#   hack/go-live.sh [owner/repo]      # apply (default: johanviberg/guardian)
#   DRY_RUN=1 hack/go-live.sh         # print what would change, touch nothing
#
# Prereqs: gh CLI authenticated with repo + admin:repo_hook scope.
#   gh auth status
set -euo pipefail

SLUG="${1:-johanviberg/guardian}"
R="repos/${SLUG}"
DRY_RUN="${DRY_RUN:-0}"

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
run() {
  if [ "$DRY_RUN" = "1" ]; then
    printf '   [dry-run] gh %s\n' "$*"
  else
    gh "$@"
  fi
}

# Create a ruleset by name only if one with that name doesn't already exist,
# so re-runs don't pile up duplicates.
ensure_ruleset() {
  local name="$1" json="$2"
  if gh api "$R/rulesets" --jq '.[].name' 2>/dev/null | grep -qx "$name"; then
    note "ruleset '$name' already present — leaving as-is (edit in the UI or delete to recreate)"
    return
  fi
  note "creating ruleset '$name'"
  if [ "$DRY_RUN" = "1" ]; then
    printf '   [dry-run] POST %s/rulesets <<json\n%s\n' "$R" "$json"
  else
    printf '%s' "$json" | gh api -X POST "$R/rulesets" --input -
  fi
}

note "target repo: $SLUG (dry-run=$DRY_RUN)"
gh api "$R" --jq '.full_name + " (visibility: " + .visibility + ")"'

# 1. Secret scanning + push protection.
note "secret scanning + push protection"
run api -X PATCH "$R" \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'

# 2. Dependabot alerts + automated security fixes.
note "dependabot alerts + automated security fixes"
run api -X PUT "$R/vulnerability-alerts"
run api -X PUT "$R/automated-security-fixes"

# 3. Private vulnerability reporting.
note "private vulnerability reporting"
run api -X PUT "$R/private-vulnerability-reporting"

# 4. Actions token hardening: read-only default, no PR approvals from Actions.
note "actions GITHUB_TOKEN: read-only default"
run api -X PUT "$R/actions/permissions/workflow" \
  -f default_workflow_permissions=read \
  -F can_approve_pull_request_reviews=false

# 5. Branch protection ruleset for the default branch.
ensure_ruleset "protect-main" '{
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
}'

# 6. Tag protection for release tags.
ensure_ruleset "protect-release-tags" '{
  "name": "protect-release-tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [ { "type": "deletion" }, { "type": "non_fast_forward" } ]
}'

note "done. Verify:"
note "  gh api $R --jq '{visibility, security: .security_and_analysis}'"
note "  gh api $R/rulesets --jq '.[] | {name, target, enforcement}'"
echo
note "Still manual (irreversible): UI fork-PR approval toggle (runbook §4) and the"
note "visibility flip to public (runbook §0)."

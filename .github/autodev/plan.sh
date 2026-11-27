#!/usr/bin/env bash
# Decides what the autodev agent does in this run and prepares the context.
#
#   skip     an autodev pull request is open and waiting (CI running or
#            green, no changes requested); nothing to do today
#   fix      the open autodev pull request has failing checks or requested
#            changes; the agent continues on its branch
#   new      no open autodev pull request; the agent takes the first open
#            task from ROADMAP.md on a new branch
#   propose  the roadmap is complete; the agent opens one issue with
#            proposals, unless such an issue is already open
#
# Writes mode, branch and pr to $GITHUB_OUTPUT and context files to .autodev/.
# Needs GH_TOKEN with pull-requests, checks and actions read, issues write.
set -euo pipefail

LABEL=autodev
CONTEXT=.autodev
mkdir -p "$CONTEXT"

out() { echo "$1=$2" >>"$GITHUB_OUTPUT"; }
say() { echo "$1" | tee -a "$GITHUB_STEP_SUMMARY"; }

gh label create "$LABEL" --color 5319e7 \
  --description "Opened by the autodev workflow" --force >/dev/null

open_pr=$(gh pr list --label "$LABEL" --state open --limit 1 \
  --json number,headRefName,headRefOid,reviewDecision)

if [ "$(jq length <<<"$open_pr")" -gt 0 ]; then
  number=$(jq -r '.[0].number' <<<"$open_pr")
  branch=$(jq -r '.[0].headRefName' <<<"$open_pr")
  head=$(jq -r '.[0].headRefOid' <<<"$open_pr")
  decision=$(jq -r '.[0].reviewDecision // ""' <<<"$open_pr")

  if [[ ! "$branch" =~ ^autodev/[A-Za-z0-9._-]+$ ]]; then
    say "Open autodev pull request #$number has an unexpected branch name; skipping."
    out mode skip
    exit 0
  fi

  # Exit codes of 'gh pr checks' encode the state; the JSON is what counts.
  buckets=$(gh pr checks "$number" --json bucket --jq '[.[].bucket] | join(" ")' 2>/dev/null || true)

  if [[ " $buckets " == *" fail "* || "$decision" == "CHANGES_REQUESTED" ]]; then
    gh pr view "$number" --json number,title,body,isDraft,reviews,comments >"$CONTEXT/pr.json"
    gh api --paginate "repos/$GITHUB_REPOSITORY/pulls/$number/comments" >"$CONTEXT/review-comments.json"
    gh run list --commit "$head" --json databaseId,name,conclusion \
      --jq '.[] | select(.conclusion == "failure") | "\(.databaseId) \(.name)"' |
      while read -r id name; do
        gh run view "$id" --log-failed | tail -c 100000 >"$CONTEXT/ci-${name//[^A-Za-z0-9]/_}-$id.log" || true
      done
    git switch "$branch"
    say "Continuing autodev pull request #$number (checks: ${buckets:-none}; review: ${decision:-none})."
    out mode fix
    out branch "$branch"
    out pr "$number"
  else
    say "Autodev pull request #$number is open and waiting (checks: ${buckets:-none}); skipping today."
    out mode skip
  fi
  exit 0
fi

if grep -qE '^\s*- \[ \]' ROADMAP.md; then
  branch="autodev/$(date -u +%Y%m%d)-$GITHUB_RUN_NUMBER"
  git switch -c "$branch"
  say "Next task: $(grep -m1 -E '^\s*- \[ \]' ROADMAP.md | cut -c1-160)"
  out mode new
  out branch "$branch"
  exit 0
fi

if [ "$(gh issue list --label "$LABEL" --state open --json number --jq length)" -gt 0 ]; then
  say "The roadmap is complete and the proposals issue is still open; skipping."
  out mode skip
else
  say "The roadmap is complete; asking for proposals."
  out mode propose
fi

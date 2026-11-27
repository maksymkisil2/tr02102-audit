#!/usr/bin/env bash
# Checks what the agent left behind, independently of what it reports.
# Fails the run, so the problem shows up as a red workflow, when:
#   - no pull request (new, fix) or issue (propose) with the autodev label exists
#   - a pushed commit is not authored by the maintainer or has a co-author trailer
set -euo pipefail

MODE=$1 BRANCH=${2:-} AUTHOR=$3
fail() { echo "::error::$1"; echo "- ❌ $1" >>"$GITHUB_STEP_SUMMARY"; exit 1; }
ok() { echo "$1"; echo "- ✅ $1" >>"$GITHUB_STEP_SUMMARY"; }

if [ "$MODE" = propose ]; then
  [ "$(gh issue list --label autodev --state open --json number --jq length)" -gt 0 ] ||
    fail "The roadmap is complete, but no proposals issue was opened."
  ok "Proposals issue is open."
  exit 0
fi

pr=$(gh pr list --head "$BRANCH" --label autodev --state open --json number,url --jq '.[0].url // ""')
[ -n "$pr" ] || fail "No open autodev pull request for branch $BRANCH."
ok "Pull request: $pr"

# Read the branch as pushed. The repository is public, so no credential is used.
git fetch --quiet "https://github.com/${GITHUB_REPOSITORY}.git" \
  "+refs/heads/main:refs/autodev/main" "+refs/heads/$BRANCH:refs/autodev/branch"
range=refs/autodev/main..refs/autodev/branch

authors=$(git log --format='%an' "$range" | sort -u)
[ "$authors" = "$AUTHOR" ] || fail "Unexpected commit authors on $BRANCH: $(echo "$authors" | tr '\n' ' ')"
if git log --format=%B "$range" | grep -qiE '^[[:space:]]*co-authored-by:'; then
  fail "A commit on $BRANCH has a Co-Authored-By trailer."
fi
ok "$(git rev-list --count "$range") commit(s), all authored by $AUTHOR, no co-author trailers."

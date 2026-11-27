#!/usr/bin/env bash
# Installs gitleaks and two git hooks for the autodev agent, so the rules
# below hold whatever the agent does:
#   commit-msg  removes Co-Authored-By trailers from every commit message
#   pre-push    refuses pushes to main, branch deletions, and any pushed
#               commit that gitleaks reports as containing a secret
set -euo pipefail

GITLEAKS_VERSION=8.30.1
bin="$RUNNER_TEMP/autodev-bin"
mkdir -p "$bin"

(
  cd "$RUNNER_TEMP"
  base="https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION"
  archive="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
  curl -fsSLO "$base/$archive"
  curl -fsSLO "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
  sha256sum --check --ignore-missing "gitleaks_${GITLEAKS_VERSION}_checksums.txt"
  tar -xzf "$archive" -C "$bin" gitleaks
)

hooks=$(git rev-parse --git-path hooks)
mkdir -p "$hooks"

cat >"$hooks/commit-msg" <<'EOF'
#!/bin/sh
# autodev: commits carry no co-author trailers.
grep -viE '^[[:space:]]*co-authored-by:' "$1" >"$1.tmp" || true
mv "$1.tmp" "$1"
EOF

cat >"$hooks/pre-push" <<EOF
#!/bin/sh
# autodev: never push to main, never delete, never push a secret.
zero=0000000000000000000000000000000000000000
while read -r local_ref local_sha remote_ref remote_sha; do
  case "\$remote_ref" in
    refs/heads/main|refs/heads/master)
      echo "autodev: pushing to \$remote_ref is not allowed" >&2; exit 1 ;;
  esac
  if [ "\$local_sha" = "\$zero" ]; then
    echo "autodev: deleting \$remote_ref is not allowed" >&2; exit 1
  fi
  if [ "\$remote_sha" = "\$zero" ]; then range="origin/main..\$local_sha"; else range="\$remote_sha..\$local_sha"; fi
  if git log --format=%B "\$range" | grep -qiE '^[[:space:]]*co-authored-by:'; then
    echo "autodev: a commit in \$range has a Co-Authored-By trailer" >&2; exit 1
  fi
  if ! "$bin/gitleaks" git --no-banner --redact --log-opts="\$range" .; then
    echo "autodev: gitleaks found a secret in \$range; remove it from the history before pushing" >&2; exit 1
  fi
done
exit 0
EOF

chmod +x "$hooks/commit-msg" "$hooks/pre-push"
echo "gitleaks $("$bin/gitleaks" version) and git hooks installed"

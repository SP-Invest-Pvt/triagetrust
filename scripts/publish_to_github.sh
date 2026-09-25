#!/usr/bin/env bash
# Create the GitHub repo and push, using the GitHub CLI (https://cli.github.com, then `gh auth login`).
set -euo pipefail
cd "$(dirname "$0")/.."
NAME=${1:-$(basename "$PWD")}
[ -d .git ] || git init -q -b main
OWNER=$(gh api user -q .login)
perl -pi -e "s#OWNER/#${OWNER}/#g" README.md
git add -A
git commit -qm "Initial commit" || true
gh repo create "$NAME" --public --source . --push --description "$(head -n 3 README.md | tail -n 1)"

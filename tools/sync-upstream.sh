#!/usr/bin/env bash
set -euo pipefail
if ! git diff --quiet || ! git diff --cached --quiet || [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then echo "Working tree is not clean." >&2; exit 1; fi
git remote get-url upstream >/dev/null 2>&1 || { echo "Remote 'upstream' is missing." >&2; exit 1; }
git fetch upstream
git log HEAD..upstream/main --oneline
echo "New upstream commits: $(git rev-list --count HEAD..upstream/main)"
if [[ "${1:-}" == "--merge-dev" ]]; then
  [[ "$(git branch --show-current)" == "dev" ]] || { echo "--merge-dev requires dev branch." >&2; exit 1; }
  git merge --no-ff upstream/main
elif [[ $# -gt 0 ]]; then echo "Usage: $0 [--merge-dev]" >&2; exit 1; fi

#!/usr/bin/env bash
# Publish this folder to GitHub. Usage: scripts/publish_github.sh <github-user> [repo-name]
# You authenticate yourself (gh auth login, or HTTPS + Personal Access Token). Nothing is stored by this script.
set -euo pipefail
USER_NAME="${1:?usage: $0 <github-user> [repo-name]}"
REPO="${2:-SENTINEL-X}"
cd "$(dirname "$0")/.."
python3 -m unittest discover -s tests -t . -p "test_*.py" >/dev/null && echo "[+] tests OK"
[ -d .git ] || git init -b main
git config user.name  >/dev/null || { echo "Set: git config --global user.name  \"THEEVVEN\""; exit 1; }
git config user.email >/dev/null || { echo "Set: git config --global user.email \"you@example.com\""; exit 1; }
git add -A
git commit -m "SENTINEL-X v$(python3 -c 'import sentinel_x;print(sentinel_x.__version__)')" || true
if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
  gh repo create "$USER_NAME/$REPO" --public --source=. --remote=origin --push \
     --description "AI-assisted digital forensics & incident investigation (defensive, read-only)"
else
  git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$USER_NAME/$REPO.git"
  echo "[!] Create an EMPTY repo named $REPO on github.com first, then the push below asks for your username + token."
  git push -u origin main
fi
echo "[+] Done: https://github.com/$USER_NAME/$REPO"
